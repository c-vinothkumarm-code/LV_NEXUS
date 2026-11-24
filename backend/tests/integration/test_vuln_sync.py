"""Native findings sync: status preservation, reappearance, authoritative absence, partial failure, no duplicates,
plus collector parsing for AWS Security Hub, Azure Advisor and Google SCC (provider APIs simulated)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from app.core.config import Settings
from app.models import CloudAccount, CloudSecurityFinding, CloudSubscription, FindingStatusHistory, NotificationLog, SyncCheckpoint, SyncRun
from app.scheduler.engine import JobContext
from app.services.vuln.collectors import AzureAdvisorCollector, SccCollector, SecurityHubCollector, normalize_advisor, normalize_scc, normalize_security_hub
from app.services.vuln.common import Coverage, HttpError, NormalizedFinding, Partition, classify, with_retry
from app.services.vuln.sync import run_security_sync

NOW = datetime.now(UTC)


def nf(nid, state="ACTIVE", sev="High", scope="111111111111", **kw):
    return NormalizedFinding(provider="aws", source="security_hub", native_id=nid, scope_external_id=scope, title=f"T {nid}", severity=sev,
                             native_state=state, region="us-east-1", resource_id=f"arn:aws:s3:::{nid}", last_observed_at=kw.pop("last", NOW),
                             first_observed_at=NOW - timedelta(days=1), native_updated_at=NOW, raw={"Id": nid}, **kw)


class FakeCollector:
    provider, source = "aws", "security_hub"

    def __init__(self, batches: dict, fail: dict | None = None, absence=False, facts=None):
        self.batches, self.fail, self.absence, self.facts = batches, fail or {}, absence, facts or []

    def plan(self, scopes):
        parts = []
        for (scope, region), items in self.batches.items():
            def fetch(since, items=items, key=(scope, region)):
                if key in self.fail:
                    raise self.fail[key]
                yield from items
            parts.append(Partition(scope, region, fetch, absence_resolves=self.absence))
        return parts, self.facts


@pytest.fixture()
def ctx(db):
    for acct in ("111111111111", "222222222222"):
        db.add(CloudAccount(external_id=acct, name=acct, onboarding_status="Fully Onboarded", monitoring_enabled=True))
    db.commit()
    return JobContext(db=db, execution_id=1, job=None)


def S(**kw):
    return Settings(_env_file=None, aws_enabled=True, **kw)


def count(db, model):
    return db.scalar(select(func.count()).select_from(model))


def test_insert_update_preserves_internal_workflow(db, ctx):
    col = FakeCollector({("111111111111", "us-east-1"): [nf("a"), nf("b", sev="Critical"), nf("c", state="RESOLVED")]})
    r = run_security_sync(ctx, S(), [col])
    assert r.status.value == "success"
    assert count(db, CloudSecurityFinding) == 2  # never-seen resolved finding is not imported
    a = db.scalar(select(CloudSecurityFinding).where(CloudSecurityFinding.title == "T a"))
    assert a.internal_status == "OPEN" and a.sla_due_at is not None
    # people work the finding
    a.internal_status, a.owner, a.analyst = "UNDER_REVIEW", "eng@example.com", "sec@example.com"
    db.commit()
    col.batches = {("111111111111", "us-east-1"): [nf("a", sev="Critical", description="changed"), nf("b", sev="Critical")]}
    run_security_sync(ctx, S(), [col])
    db.refresh(a)
    assert (a.internal_status, a.owner, a.analyst, a.severity, a.description) == ("UNDER_REVIEW", "eng@example.com", "sec@example.com", "Critical", "changed")
    assert count(db, CloudSecurityFinding) == 2  # idempotent: no duplicates
    run = db.scalar(select(SyncRun).order_by(SyncRun.id.desc()))
    assert run.status == "COMPLETED" and run.counts["new"] == 0 and run.counts["updated"] >= 1
    # new Critical notification queued once, de-duplicated across runs
    assert db.scalar(select(func.count()).select_from(NotificationLog).where(NotificationLog.category == "security_new_critical_finding")) == 2  # email + chat


def test_exception_status_survives_sync_and_reappearance_reopens_resolved(db, ctx):
    col = FakeCollector({("111111111111", "us-east-1"): [nf("x"), nf("y")]})
    run_security_sync(ctx, S(), [col])
    x, y = (db.scalar(select(CloudSecurityFinding).where(CloudSecurityFinding.title == t)) for t in ("T x", "T y"))
    x.internal_status = "EXCEPTION"
    y.internal_status, y.resolved_at = "RESOLVED", NOW - timedelta(days=3)
    db.commit()
    col.batches = {("111111111111", "us-east-1"): [nf("x", state="RESOLVED"), nf("y", state="RESOLVED")]}
    run_security_sync(ctx, S(), [col])
    db.refresh(x), db.refresh(y)
    assert x.internal_status == "EXCEPTION" and x.native_state == "RESOLVED"  # native and internal stay independent
    assert y.internal_status == "RESOLVED" and y.native_state == "RESOLVED"
    col.batches = {("111111111111", "us-east-1"): [nf("x", state="RESOLVED"), nf("y", state="ACTIVE")]}
    run_security_sync(ctx, S(), [col])
    db.refresh(y)
    assert y.internal_status == "REOPENED" and y.needs_reassessment and y.reopen_count == 1
    assert db.scalar(select(FindingStatusHistory).where(FindingStatusHistory.finding_id == y.id, FindingStatusHistory.new_value == "REOPENED")).actor == "sync"
    assert db.scalar(select(SyncRun).order_by(SyncRun.id.desc())).counts["reappeared"] == 1


def test_permission_error_is_not_zero_findings_and_run_continues(db, ctx):
    class Denied(Exception):
        response = {"Error": {"Code": "AccessDeniedException"}}
    col = FakeCollector({("111111111111", "us-east-1"): [nf("p")], ("222222222222", "us-east-1"): [nf("q", scope="222222222222")]},
                        fail={("222222222222", "us-east-1"): Denied("not authorized")})
    r = run_security_sync(ctx, S(), [col])
    run = db.scalar(select(SyncRun).order_by(SyncRun.id.desc()))
    assert r.status.value == "partial" and run.status == "PARTIALLY_COMPLETED" and run.counts["permission_errors"] == 1
    cp = db.scalar(select(SyncCheckpoint).where(SyncCheckpoint.scope_external_id == "222222222222"))
    assert cp.state == "ACCESS_DENIED" and cp.watermark is None and cp.consecutive_failures == 1
    assert count(db, CloudSecurityFinding) == 1
    # previously known finding of the failing account is not resolved or deleted because the call failed
    col.fail = {}
    run_security_sync(ctx, S(), [col])
    col.fail = {("222222222222", "us-east-1"): Denied("x")}
    col.batches[("222222222222", "us-east-1")] = []
    run_security_sync(ctx, S(), [col])
    q = db.scalar(select(CloudSecurityFinding).where(CloudSecurityFinding.title == "T q"))
    assert q.native_state == "ACTIVE"


def test_all_failed_is_failed_and_not_configured_is_failed(db, ctx):
    col = FakeCollector({("111111111111", "us-east-1"): []}, fail={("111111111111", "us-east-1"): HttpError(500, "boom")})
    assert run_security_sync(ctx, S(), [col]).status.value == "failed"
    assert run_security_sync(ctx, S(), []).status.value == "failed"
    assert db.scalar(select(SyncRun).order_by(SyncRun.id.desc())).errors[0]["kind"] == "not_configured"


def test_authoritative_absence_resolves_only_after_complete_listing(db, ctx):
    db.add(CloudSubscription(external_id="sub-1", name="s", onboarding_status="Fully Onboarded", monitoring_enabled=True))
    db.commit()

    def rec(i):
        return NormalizedFinding(provider="azure", source="azure_advisor", native_id=f"/subscriptions/sub-1/rec/{i}", scope_external_id="sub-1",
                                 title=f"R{i}", severity="High", native_state="ACTIVE", raw={})
    col = FakeCollector({("sub-1", "global"): [rec(1), rec(2)]}, absence=True)
    col.provider, col.source = "azure", "azure_advisor"
    run_security_sync(ctx, S(azure_enabled=True), [col])
    col.batches = {("sub-1", "global"): [rec(1)]}
    run_security_sync(ctx, S(azure_enabled=True), [col])
    r2 = db.scalar(select(CloudSecurityFinding).where(CloudSecurityFinding.title == "R2"))
    assert r2.native_state == "RESOLVED" and r2.internal_status == "OPEN"  # native resolution recorded; internal untouched


def test_abandoned_run_is_closed(db, ctx):
    db.add(SyncRun(trigger="schedule", mode="incremental", status="RUNNING"))
    db.commit()
    run_security_sync(ctx, S(), [FakeCollector({("111111111111", "us-east-1"): []})])
    assert db.scalar(select(SyncRun).order_by(SyncRun.id)).status == "FAILED"


def test_coverage_facts_recorded(db, ctx):
    col = FakeCollector({}, facts=[Coverage("222222222222", "aggregated", "PARTIALLY_CONFIGURED", "not a member")])
    run_security_sync(ctx, S(), [col])
    cp = db.scalar(select(SyncCheckpoint).where(SyncCheckpoint.scope_external_id == "222222222222"))
    assert cp.state == "PARTIALLY_CONFIGURED" and "member" in cp.last_error


# ---------------------------------------------------------------------------------------- provider parsing / clients
def test_security_hub_normalization():
    f = normalize_security_hub({"Id": "arn:aws:securityhub:us-east-1:111:finding/1", "AwsAccountId": "111", "Region": "us-east-1", "Title": "S3 public",
                                "Severity": {"Label": "CRITICAL"}, "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
                                "Resources": [{"Id": "arn:aws:s3:::b", "Type": "AwsS3Bucket"}], "Compliance": {"Status": "FAILED", "SecurityControlId": "S3.2",
                                "AssociatedStandards": [{"StandardsId": "standards/aws-foundational-security-best-practices/v/1.0.0"}]},
                                "Remediation": {"Recommendation": {"Text": "Block public access", "Url": "https://docs"}}, "RecordState": "ACTIVE",
                                "Workflow": {"Status": "NEW"}, "FirstObservedAt": "2026-11-01T00:00:00Z", "UpdatedAt": "2026-11-16T00:00:00.123Z"})
    assert (f.severity, f.control_id, f.native_state, f.resource_type, f.scope_external_id) == ("Critical", "S3.2", "ACTIVE", "AwsS3Bucket", "111")
    assert normalize_security_hub({"Id": "x", "RecordState": "ARCHIVED", "Severity": {"Label": "LOW"}}).native_state == "RESOLVED"
    assert normalize_security_hub({"Id": "x", "Compliance": {"Status": "PASSED"}}).native_state == "RESOLVED"


def test_security_hub_collector_paginates_and_flags_non_members():
    class Client:
        def __init__(self):
            self.calls = []

        def get_findings(self, **kw):
            self.calls.append(kw)
            if "NextToken" not in kw:
                return {"Findings": [{"Id": "1", "AwsAccountId": "111", "Severity": {"Label": "HIGH"}}], "NextToken": "t"}
            return {"Findings": [{"Id": "2", "AwsAccountId": "222", "Severity": {"Label": "LOW"}}]}

        def list_finding_aggregators(self):
            return {"FindingAggregators": [{"FindingAggregatorArn": "arn"}]}

        def get_finding_aggregator(self, **kw):
            return {"RegionLinkingMode": "ALL_REGIONS", "Regions": []}

        def get_paginator(self, name):
            class P:
                def paginate(self, **kw):
                    return [{"Members": [{"AccountId": "222", "MemberStatus": "Enabled"}]}]
            return P()
    client = Client()

    class Conn:
        def session_for(self, *a):
            return object()

        def client(self, *a):
            return client
    acct = lambda i, m=False: type("A", (), {"external_id": i, "is_management": m})()  # noqa: E731
    col = SecurityHubCollector(Settings(_env_file=None, aws_securityhub_aggregation_region="eu-west-1"), Conn())
    parts, cover = col.plan([acct("111", True), acct("222"), acct("333")])
    assert [c.state for c in cover if c.scope == "333"] == ["PARTIALLY_CONFIGURED"]
    got = list(parts[0].fetch(NOW - timedelta(days=1)))
    assert [g.native_id for g in got] == ["1", "2"] and "UpdatedAt" in client.calls[0]["Filters"]


def test_advisor_security_vs_non_security_and_paging():
    sec = {"id": "/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa/providers/Microsoft.Advisor/recommendations/r1",
           "properties": {"category": "Security", "impact": "High", "impactedField": "Microsoft.Storage/storageAccounts", "impactedValue": "sa",
                          "shortDescription": {"problem": "Storage allows public access", "solution": "Disable public access"}, "lastUpdated": "2026-11-15T10:00:00Z",
                          "resourceMetadata": {"resourceId": "/subscriptions/s1/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa"}}}
    cost = {"id": "/subscriptions/s1/providers/Microsoft.Advisor/recommendations/r2", "properties": {"category": "Cost", "impact": "Medium",
                                                                                                    "shortDescription": {"problem": "Right-size VM"}}}
    a, b = normalize_advisor(sec, "s1", "tenant", "mg-root"), normalize_advisor(cost, "s1", "tenant", None)
    assert a.is_security and not b.is_security and a.resource_group == "rg1" and a.parent_id == "mg-root" and a.severity == "High"

    class Resp:
        def __init__(self, code, body, headers=None):
            self.status_code, self._b, self.text, self.headers = code, body, str(body), headers or {}

        def json(self):
            return self._b
    calls = []

    class Http:
        def request(self, method, url, **kw):
            calls.append(url)
            if "ResourceGraph" in url:
                return Resp(403, {"error": "AuthorizationFailed"})
            if "page2" in url:
                return Resp(200, {"value": [cost]})
            if len([c for c in calls if "Advisor" in c]) == 1:
                return Resp(429, {}, {"Retry-After": "1"})
            return Resp(200, {"value": [sec], "nextLink": "https://management.azure.com/page2/Microsoft.Advisor"})

    class Cred:
        def get_token(self, scope):
            return type("T", (), {"token": "t"})()
    col = AzureAdvisorCollector(Settings(_env_file=None, azure_tenant_id="tenant"), credential=Cred(), http=Http(), sleep=lambda s: None)
    parts, cover = col.plan([type("Sub", (), {"external_id": "s1", "tenant_id": None})()])
    assert cover and cover[0].state == "PARTIALLY_CONFIGURED"  # Resource Graph denied: enrichment gap reported, not fatal
    got = list(parts[0].fetch(None))
    assert [g.is_security for g in got] == [True, False] and parts[0].absence_resolves


def test_scc_normalization_and_org_fallback():
    item = {"finding": {"name": "organizations/1/sources/2/findings/abc", "state": "ACTIVE", "category": "PUBLIC_BUCKET_ACL", "severity": "HIGH",
                        "findingClass": "MISCONFIGURATION", "eventTime": "2026-11-16T01:02:03.123456789Z", "mute": "UNMUTED", "nextSteps": "Remove allUsers",
                        "resourceName": "//storage.googleapis.com/b"},
            "resource": {"projectName": "//cloudresourcemanager.googleapis.com/projects/123", "type": "google.cloud.storage.Bucket",
                         "folders": [{"resourceFolder": "folders/9"}]}}
    f = normalize_scc(item, {"123": "proj-a"}, "1")
    assert (f.scope_external_id, f.severity, f.category, f.parent_id, f.native_state) == ("proj-a", "High", "MISCONFIGURATION", "folders/9", "ACTIVE")
    assert normalize_scc({**item, "finding": {**item["finding"], "state": "INACTIVE"}}, {}, "1").native_state == "RESOLVED"

    class Resp:
        def __init__(self, code, body):
            self.status_code, self._b, self.text = code, body, str(body)

        def json(self):
            return self._b

    class Sess:
        def get(self, url, params=None, timeout=None):
            return Resp(403, {}) if "organizations" in url else Resp(200, {"listFindingsResults": [item]})
    col = SccCollector(Settings(_env_file=None, gcp_organization_id="1"), session=Sess(), project_numbers={"123": "proj-a"})
    parts, cover = col.plan([type("P", (), {"external_id": "proj-a"})()])
    assert cover[0].state == "ACCESS_DENIED" and parts[0].scope == "proj-a" and len(list(parts[0].fetch(None))) == 1


def test_error_classification_and_backoff():
    assert classify(HttpError(403, "AuthorizationFailed"))[0] == "permission"
    assert classify(HttpError(429, "Too Many Requests"))[0] == "throttle"
    assert classify(type("E", (Exception,), {"response": {"Error": {"Code": "InvalidAccessException"}}})("x"))[0] == "not_enabled"
    n = {"i": 0}
    waits = []

    def flaky():
        n["i"] += 1
        if n["i"] < 3:
            raise HttpError(503, "busy")
        return "ok"
    assert with_retry(flaky, sleep=waits.append) == "ok" and len(waits) == 2 and waits[1] > waits[0]
    with pytest.raises(HttpError):
        with_retry(lambda: (_ for _ in ()).throw(HttpError(403, "denied")), sleep=waits.append)
