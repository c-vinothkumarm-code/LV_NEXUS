"""Shared reliability layer: retries (429 with Retry-After, 5xx, timeouts), no retry on 403, circuit breaker per provider
(permission gaps never trip it, expired credentials trip it at once), per-scope gate, rate limiter, masking, JSON logs,
run report on the execution log, and the collectors that were failing in the field (Azure cost detail, Entra)."""
from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import select

from app.core.logging import JsonFormatter, RedactingFilter, mask
from app.models import AutomationExecutionLog, AutomationJob, CloudSubscription, JobStatus
from app.models.platform import CostDetailRecord
from app.scheduler.engine import JobContext, JobResult, run_job
from app.services import reliability as rel
from app.services.azure.rest import AzureRest
from app.services.finops.detail import AzureCostDetail, run_cost_detail
from app.services.soc.entra import EntraActivityCollector, run_entra_activity
from app.services.vuln.common import HttpError


class Flaky:
    def __init__(self, errors, result="ok"):
        self.errors, self.result, self.calls = list(errors), result, 0

    def __call__(self):
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        return self.result


def test_retries_transient_errors_and_honours_retry_after():
    slept = []
    f = Flaky([HttpError(429, "Too Many Requests", retry_after=7), HttpError(503, "busy"), TimeoutError("read timed out")])
    ctx, tok = rel.start_run("t")
    try:
        assert rel.call("azure", "query", f, sleep=slept.append) == "ok"
        assert f.calls == 4 and slept[0] == 7 and len(slept) == 3
        st = ctx.report()["api"]["azure:query"]
        assert st["retries"] == 3 and st["errors"] == 0 and st["calls"] == 4
    finally:
        rel.end_run(tok)


@pytest.mark.parametrize("exc,kind", [(HttpError(403, "AuthorizationFailed"), "permission"), (HttpError(404, "ResourceNotFound"), "not_found"),
                                      (RuntimeError("ExpiredToken: The security token included in the request is expired"), "auth_expired"),
                                      (RuntimeError("SERVICE_DISABLED: API has not been used"), "not_enabled")])
def test_non_transient_errors_are_not_retried(exc, kind):
    f = Flaky([exc])
    with pytest.raises(type(exc)):
        rel.call("aws", "x", f, sleep=lambda s: None)
    assert f.calls == 1 and rel.classify(exc)[0] == kind


def test_gives_up_after_attempts_and_counts_error():
    ctx, tok = rel.start_run("t")
    try:
        f = Flaky([HttpError(500, "boom")] * 10)
        with pytest.raises(HttpError):
            rel.call("gcp", "list", f, attempts=3, sleep=lambda s: None)
        assert f.calls == 3 and ctx.report()["api"]["gcp:list"]["errors_by_kind"] == {"server": 1}
    finally:
        rel.end_run(tok)


def test_circuit_breaker_per_provider():
    ctx, tok = rel.start_run("t")
    try:
        for _ in range(5):  # permission gaps on many scopes never take the provider down
            rel.scope_failed("azure", HttpError(403, "AuthorizationFailed"))
        assert rel.scope_gate("azure") is None
        for _ in range(4):
            rel.scope_failed("aws", HttpError(503, "ServiceUnavailable"))
        assert "unavailable" in rel.scope_gate("aws").lower() and rel.scope_gate("gcp") is None  # other clouds continue
        with pytest.raises(rel.CircuitOpen):
            rel.call("aws", "x", lambda: "never")
        rel.scope_failed("gcp", RuntimeError("invalid_grant: Token has been expired or revoked"))
        assert rel.scope_gate("gcp") and ctx.report()["providers"]["gcp"]["status"] == "Unavailable"
        rel.scope_ok("azure")
        assert ctx.report()["providers"]["azure"]["status"] == "Degraded"
    finally:
        rel.end_run(tok)
    assert rel.scope_gate("aws") is None  # state is per run


def test_success_resets_consecutive_failures():
    ctx, tok = rel.start_run("t")
    try:
        for _ in range(3):
            rel.scope_failed("aws", TimeoutError("timed out"))
        rel.scope_ok("aws")
        for _ in range(3):
            rel.scope_failed("aws", TimeoutError("timed out"))
        assert rel.scope_gate("aws") is None
    finally:
        rel.end_run(tok)


def test_rate_limiter_paces_calls():
    t = [0.0]
    slept = []
    lim = rel.RateLimiter(0.5, 1, clock=lambda: t[0], sleep=lambda s: (slept.append(s), t.__setitem__(0, t[0] + s)))
    lim.acquire()
    lim.acquire()
    lim.acquire()
    assert slept == [2.0, 2.0]


def test_masking_and_json_logs():
    assert mask("user alice.smith@latentview.com from 203.0.113.7 key AKIAABCDEFGHIJKLWXYZ") == \
        "user a***@latentview.com from 203.0.x.x key AKIA****WXYZ"
    rec = logging.LogRecord("x", logging.WARNING, __file__, 1, '{"event": "api_error", "provider": "azure", "who": "bob@corp.com"}', None, None)
    RedactingFilter().filter(rec)
    ctx, tok = rel.start_run("billing_refresh")
    try:
        out = json.loads(JsonFormatter().format(rec))
    finally:
        rel.end_run(tok)
    assert out["event"] == "api_error" and out["run_id"] == ctx.run_id and out["job"] == "billing_refresh" and out["who"] == "b***@corp.com"


def test_run_report_is_stored_on_execution_log(session_factory, db):
    def job(ctx: JobContext) -> JobResult:
        rel.call("azure", "list", lambda: 1)
        rel.scope_failed("aws", HttpError(503, "x"))
        return JobResult(JobStatus.SUCCESS, 1, 0)
    e = run_job(session_factory, "account_discovery", job)
    rep = db.get(AutomationExecutionLog, e.id).summary["run"]
    assert rep["run_id"] and rep["api"]["azure:list"]["calls"] == 1 and rep["providers"]["aws"]["scope_failures"] == 1


class _Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body or {}, headers or {}
        self.content = json.dumps(self._body).encode()
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


class _Http:
    def __init__(self, responses):
        self.responses, self.seen = list(responses), []

    def request(self, method, url, **kw):
        self.seen.append(url)
        return self.responses.pop(0)


class _Cred:
    def get_token(self, scope):
        return type("T", (), {"token": "t"})()


def test_azure_rest_throttle_then_large_pagination():
    pages = [_Resp(200, {"value": [{"i": i * 100 + j} for j in range(100)], "nextLink": f"https://management.azure.com/next{i}"}) for i in range(24)]
    pages.append(_Resp(200, {"value": [{"i": 9999}]}))
    http = _Http([_Resp(429, {"error": "throttled"}, {"Retry-After": "1"})] + pages)
    rest = AzureRest(type("S", (), {})(), credential=_Cred(), http=http, sleep=lambda s: None)
    items = list(rest.pages("https://management.azure.com/subscriptions/x/providers/Microsoft.Resources/resources"))
    assert len(items) == 2401 and len(http.seen) == 26


def test_azure_rest_permission_error_is_raised_not_empty():
    rest = AzureRest(type("S", (), {})(), credential=_Cred(), http=_Http([_Resp(403, {"error": {"code": "AuthorizationFailed"}})]), sleep=lambda s: None)
    with pytest.raises(HttpError) as e:
        list(rest.pages("https://management.azure.com/subscriptions/x/providers/Microsoft.Advisor/recommendations"))
    assert e.value.status == 403


class _CostRest:
    """Azure Cost Management stand-in: the tag query fails, everything else succeeds."""
    def request(self, method, url, **kw):
        body = kw.get("json") or {}
        grouping = (body.get("dataset") or {}).get("grouping") or []
        if any(g.get("type") == "TagKey" for g in grouping):
            raise HttpError(400, "BadRequest: tag key not found")
        d = int(date.today().strftime("%Y%m%d"))
        if "forecast" in url:
            return {"properties": {"columns": [{"name": "Cost"}, {"name": "Currency"}], "rows": [[5, "USD"]]}}
        cols = [{"name": n} for n in ("Cost", "UsageDate", "ResourceId", "ServiceName", "ResourceLocation", "MeterCategory", "MeterSubCategory", "Currency")]
        return {"properties": {"columns": cols, "rows": [[3, d, "/subscriptions/s/resourceGroups/rg/providers/x/y/z", "Storage", "eastus", "Storage", "Hot", "USD"]]}}

    def pages(self, url, params=None, method="GET", body=None):
        return iter([])


def test_cost_detail_one_breakdown_failing_keeps_the_others(db, settings):
    db.add(CloudSubscription(external_id="s", name="s", onboarding_status="Fully Onboarded", checks={"billing": {"status": "pass"}}))
    db.commit()
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "cost_detail_refresh"))
    s = settings.model_copy(update={"cost_tag_keys": ["environment"], "cost_include_amortized": False})
    res = run_cost_detail(JobContext(db=db, job=job, execution_id=1), s, {"azure": object()}, {"azure": AzureCostDetail(s, _CostRest())})
    got = {r.breakdown for r in db.scalars(select(CostDetailRecord))}
    assert got == {"resource", "service_region", "usage_type"}  # tag failed, the rest were stored
    assert res.status.value == "partial" and "tag:environment" in res.failures[0]["reason"] and "previous data kept" in res.failures[0]["reason"]


def test_entra_missing_permission_is_degraded_with_fix(db, settings):
    class Denied:
        def pages(self, url, params=None, method="GET", body=None):
            raise HttpError(403, "Authorization_RequestDenied")
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "entra_activity"))
    s = settings.model_copy(update={"azure_tenant_id": "t"})
    res = run_entra_activity(JobContext(db=db, job=job, execution_id=1), s, EntraActivityCollector(s, Denied()))
    # signed in with az login (no client secret): the fix is an Entra directory role, not an application permission
    assert res.status.value == "partial" and all("Global Reader" in f["reason"] and "az login" in f["reason"] for f in res.failures)
    app = s.model_copy(update={"azure_client_id": "app-id", "azure_client_secret": "x"})
    res = run_entra_activity(JobContext(db=db, job=job, execution_id=2), app, EntraActivityCollector(app, Denied()))
    assert all("AuditLog.Read.All" in f["reason"] and "admin consent" in f["reason"] for f in res.failures)
    assert datetime.now(UTC)  # job completed; nothing raised


def test_azure_429_is_throttle_and_honours_cost_management_retry_header():
    from app.services import reliability as rel

    class Resp:
        headers = {"x-ms-ratelimit-microsoft.costmanagement-qpu-retry-after": "7", "Content-Type": "application/json"}

    class HttpResponseError(Exception):
        status_code = 429
        response = Resp()

    exc = HttpResponseError("(429) Too many requests. Please retry.")
    assert rel.classify(exc)[0] == "throttle"
    waits, calls = [], []

    def fn():
        calls.append(1)
        if len(calls) < 3:
            raise exc
        return "ok"
    assert rel.call("azure", "cost_query", fn, rate_key="azure_cost", attempts=4, sleep=waits.append) == "ok"
    assert waits == [7.0, 7.0]
