"""System health, pre-flight, run-problem alerts, Key Vault secrets and the dry-run demo check."""
from __future__ import annotations

import os

import pytest
from sqlalchemy import select

from app.core import secrets
from app.core.config import Settings
from app.models import AutomationExecutionLog, AutomationJob, CloudSubscription, JobStatus, NotificationLog
from app.scheduler.engine import JobResult, run_job
from app.services import preflight as pf
from tests.integration.test_identity_governance import login


class FakeConnector:
    provider = "azure"

    def __init__(self, fail=None, found=("sub-1",)):
        self.fail, self.found = fail, found

    def missing_configuration(self):
        return []

    def discover(self):
        if self.fail:
            raise self.fail
        return [type("S", (), {"external_id": x})() for x in self.found]


def _settings(**kw):
    return Settings(_env_file=None, azure_enabled=True, **kw)


def test_preflight_clouds_scopes_and_fixes(db):
    db.add(CloudSubscription(external_id="sub-1", name="prod", onboarding_status="Fully Onboarded",
                             checks={"authentication": {"status": "pass"}, "permissions": {"status": "pass"}}))
    db.add(CloudSubscription(external_id="sub-2", name="old", onboarding_status="Fully Onboarded", checks={"permissions": {"status": "fail"}}))
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "billing_refresh"))
    db.add(AutomationExecutionLog(job_id=job.id, job_name="billing_refresh", status="partial",
                                  failures=[{"provider": "azure", "scope": "sub-1", "reason": "AuthorizationFailed: 403 on Cost Management"}]))
    db.commit()
    rep = pf.run_preflight(db, _settings(), connectors=[FakeConnector()])
    by = {(c["scope"], c["check"]): c for c in rep["checks"]}
    assert rep["verdict"] == "FAIL"
    cost = by[("prod", "Cost Management")]
    assert cost["status"] == "FAIL" and cost["fix"] == pf.FIX_HINTS["permission"]
    assert any(c["check"] == "All known scopes visible" and c["status"] == "WARN" for c in rep["checks"])  # sub-2 not returned now: not deleted
    assert by[("old", "Azure Resource Manager resources")]["status"] == "FAIL"
    expired = pf.run_preflight(db, _settings(), connectors=[FakeConnector(fail=RuntimeError("AADSTS7000222: client secret expired (401)"))])
    cred = next(c for c in expired["checks"] if c["check"] == "Credentials and discovery")
    assert cred["status"] == "FAIL" and "expired" in cred["fix"]


def test_preflight_no_cloud_enabled_and_secrets_policy(db, monkeypatch):
    rep = pf.run_preflight(db, Settings(_env_file=None), connectors=[])
    assert any(c["check"] == "Cloud connections" and c["status"] == "FAIL" for c in rep["checks"])
    monkeypatch.setitem(secrets.SOURCES, "DATABASE_URL", "dotenv")
    prod = Settings(_env_file=None, app_env="production", auth_mode="entra", secret_key="k" * 40, frontend_url="https://x.example")
    checks = {c["check"]: c for c in pf._platform(db, prod)}
    assert checks["Secrets from Azure Key Vault"]["status"] == "FAIL" and checks["No secrets outside Key Vault"]["status"] == "FAIL"
    assert "DATABASE_URL" in checks["No secrets outside Key Vault"]["message"]


def test_failed_run_alerts_once_per_day_and_says_data_may_be_incomplete(session_factory, db):
    def boom(ctx):
        return JobResult(JobStatus.PARTIAL, 2, 1, {}, [{"provider": "aws", "scope": "111", "reason": "AccessDenied for ana@example.com from 8.8.4.4"}])
    run_job(session_factory, "billing_refresh", boom)
    run_job(session_factory, "billing_refresh", boom)
    msgs = [m for m in db.scalars(select(NotificationLog)) if "billing_refresh" in m.subject]
    assert msgs and len({m.channel for m in msgs}) == len(msgs)  # one per channel, second run deduplicated
    body = msgs[0].body
    assert "only PARTLY completed" in body and "ana@example.com" not in body and "8.8.4.4" not in body and "a***@example.com" in body


def test_system_health_api(client, db):
    login(client, db, "admin@latentview.com", "admin")
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "access_inventory"))
    db.add(AutomationExecutionLog(job_id=job.id, job_name="access_inventory", status="failed", error="Timeout talking to Graph"))
    db.commit()
    h = client.get("/api/v1/system/health").json()
    assert h["verdict"] == "FAIL"
    ai = next(j for j in h["jobs"] if j["name"] == "access_inventory")
    assert ai["problems"][0]["fix"] == pf.FIX_HINTS["timeout"] and ai["problem_streak"] == 1
    assert client.get("/api/v1/system/preflight").json()["verdict"] == "NOT_RUN"


def test_key_vault_loader(monkeypatch):
    class R:
        def __init__(self, code, value=None):
            self.status_code, self._v = code, value

        def json(self):
            return {"value": self._v}

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(self.status_code)

    class Http:
        def get(self, url, params, headers):
            assert headers["Authorization"] == "Bearer tok" and params == {"api-version": "7.4"}
            return R(200, "s3cr3t-value") if url.endswith("cloudnexus-session-secret") else R(404)

    class Cred:
        def get_token(self, scope):
            assert scope == "https://vault.azure.net/.default"
            return type("T", (), {"token": "tok"})()

    monkeypatch.delenv("SESSION_SECRET", raising=False)
    loaded = secrets.load_key_vault("https://kv.vault.azure.net", Cred(), Http())
    try:
        assert loaded == {"SESSION_SECRET": "cloudnexus-session-secret"} and secrets.SOURCES["SESSION_SECRET"] == "key_vault"
        assert os.environ["SESSION_SECRET"] == "s3cr3t-value" and secrets.STATUS["state"] == "ok"
    finally:
        os.environ.pop("SESSION_SECRET", None)

    class Denied(Http):
        def get(self, url, params, headers):
            return R(403)
    secrets.load_key_vault("https://kv.vault.azure.net", Cred(), Denied())
    assert secrets.STATUS["state"] == "error" and "Key Vault Secrets User" in secrets.STATUS["message"]


@pytest.mark.skipif(os.environ.get("TEST_DATABASE_URL", "").startswith("mysql"), reason="uses the in-memory test database as the source")
def test_dry_run_uses_throwaway_db_and_reports_partial(monkeypatch, session_factory, db):
    from app import demo_check
    from app.workers import jobs
    db.add(CloudSubscription(external_id="sub-1", name="prod", onboarding_status="Fully Onboarded"))
    db.commit()
    seen = {}

    def fake_ok(ctx, settings):
        seen["dry_run"], seen["sheets"] = settings.dry_run, settings.sheets_enabled
        seen["scopes"] = [s.external_id for s in ctx.db.scalars(select(CloudSubscription))]
        return JobResult(JobStatus.SUCCESS, 1, 0, {})

    def fake_partial(ctx, settings):
        return JobResult(JobStatus.PARTIAL, 2, 1, {}, [{"provider": "azure", "scope": "sub-1", "reason": "403"}])
    monkeypatch.setitem(jobs.JOB_FUNCTIONS, "billing_refresh", fake_ok)
    monkeypatch.setitem(jobs.JOB_FUNCTIONS, "access_inventory", fake_partial)
    monkeypatch.setattr("app.database.session.get_session_factory", lambda: session_factory)
    res = demo_check.dry_run(Settings(_env_file=None, azure_enabled=True, sheets_enabled=True), ["billing_refresh", "access_inventory"], out=lambda s: None)
    assert seen == {"dry_run": True, "sheets": False, "scopes": ["sub-1"]}
    assert [r["verdict"] for r in res] == ["PASS", "PARTIAL"]
    assert db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.triggered_by == "demo_check")) is None  # real DB untouched


def test_tenant_level_directory_failures_are_not_hidden(db):
    """Graph / management-group refusals belong to the tenant, not a subscription: pre-flight must FAIL them with the
    fix for the identity in use (user via az login vs app registration), and a missing P1/P2 licence is only a WARN."""
    for name, summary in (("access_inventory", {"directory": {"azure": [{"directory": "tenant-1", "coverage": [
            {"source": "entra_users", "state": "ACCESS_DENIED", "message": "Authorization_RequestDenied"},
            {"source": "azure_management_groups", "state": "ACCESS_DENIED", "message": "AuthorizationFailed on Microsoft.Management"},
            {"source": "entra_directory_roles", "state": "OK", "message": "12 roles"}]}]}}),
            ("entra_activity", {"sources": {"directory_audits": {"read": 40, "stored": 40},
                                            "sign_ins": {"unavailable": "licence", "note": "needs P1/P2"}}})):
        job = db.scalar(select(AutomationJob).where(AutomationJob.name == name))
        db.add(AutomationExecutionLog(job_id=job.id, job_name=name, status="partial", summary=summary))
    db.commit()
    user = {c["check"]: c for c in pf._directories(db, _settings())}
    assert user["Entra users"]["status"] == "FAIL" and "Global Reader" in user["Entra users"]["fix"] and "az login" in user["Entra users"]["fix"]
    assert "Tenant Root Group" in user["Management groups (inherited access)"]["fix"]
    assert user["Entra admin roles"]["status"] == "PASS" and user["Entra audit logs"]["status"] == "PASS"
    assert user["Entra sign-in logs"]["status"] == "WARN"
    app = {c["check"]: c for c in pf._directories(db, _settings(azure_client_id="app", azure_client_secret="x"))}
    assert "User.Read.All" in app["Entra users"]["fix"] and "Grant admin consent" in app["Entra users"]["fix"]
    rep = pf.run_preflight(db, _settings(), connectors=[FakeConnector()])
    assert rep["verdict"] == "FAIL"  # the directory gap is not hidden behind subscription-level PASS results


def test_entra_licence_error_is_not_a_failure():
    from app.services.azure.permissions import is_licence_error
    assert is_licence_error('{"error":{"code":"Authentication_RequestFromNonPremiumTenantOrB2CTenant"}}')
    assert not is_licence_error('{"error":{"code":"Authorization_RequestDenied"}}')
