import os

import pytest
from sqlalchemy import func, select

from app.models import AdminAuditLog, CloudAccount, ImmutableRecordError, OnboardingRecord, RemediationRecord, SecurityFinding, VMInventory
from app.scheduler.engine import run_job
from app.services.onboarding.engine import run_discovery
from tests.conftest import IS_POSTGRES

TRIGGERS = os.environ.get("TEST_DB_TRIGGERS") == "1"
from tests.fakes import FakeConnector, auth_failed

H = {"X-Requested-With": "mcp-dashboard"}


def seed_inventory(factory):
    conns = [FakeConnector("aws", {"1" * 12: {"name": "prod"}, "2" * 12: {"name": "locked", "checks": auth_failed()}}),
             FakeConnector("gcp", {"proj-a": {}, "proj-b": {}, "proj-c": {}}),
             FakeConnector("azure", {"sub-1": {}})]
    return run_job(factory, "account_discovery", lambda ctx: run_discovery(ctx, conns))


def test_health_and_readiness(client):
    assert client.get("/health").json()["status"] == "ok"
    ready = client.get("/health/ready")
    assert ready.status_code == 200 and ready.json()["database"] == "ok" and ready.json()["job_catalogue"] == 27  # + monthly_audit_reports


def test_empty_database_reports_not_collected_not_healthy(client):
    o = client.get("/api/v1/dashboard/overview").json()
    assert o["scopes"]["aws"]["total"] == 0 and o["vms"]["total"] == 0 and o["cost"]["total"] is None
    assert o["automation"]["success_rate_percent"] is None
    assert all(c["state"] == "not_collected" for c in o["collection"].values())


def test_overview_figures_match_database(client, session_factory, db):
    seed_inventory(session_factory)
    db.add_all([SecurityFinding(dedupe_key="k1", provider="aws", scope_external_id="1" * 12, rule_id="r", title="t", severity="Critical"),
                SecurityFinding(dedupe_key="k2", provider="gcp", scope_external_id="proj-a", rule_id="r", title="t", severity="High", review_status="Closed"),
                VMInventory(provider="aws", scope_external_id="1" * 12, instance_id="i-1", health_status="healthy"),
                VMInventory(provider="aws", scope_external_id="1" * 12, instance_id="i-2", health_status="unknown")])
    db.commit()
    o = client.get("/api/v1/dashboard/overview").json()
    assert {p: v["total"] for p, v in o["scopes"].items()} == {"aws": 2, "gcp": 3, "azure": 1}
    assert o["scopes"]["aws"]["fully_onboarded"] == db.scalar(select(func.count()).select_from(CloudAccount).where(CloudAccount.onboarding_status == "Fully Onboarded"))
    assert o["findings"] == {"critical": 1, "high": 0, "pending_investigations": 1}  # closed finding excluded
    assert o["vms"] == {"total": 2, "healthy": 1, "unhealthy": 0, "unknown": 1, "stopped": 0}  # unknown is not healthy
    assert o["automation"]["success_rate_percent"] == 0.0 and o["automation"]["counts"] == {"partial": 1}
    assert o["collection"]["inventory"]["last_status"] == "partial"


def test_inventory_filters_and_onboarding_summary(client, session_factory):
    seed_inventory(session_factory)
    assert client.get("/api/v1/inventory/scopes").json()["total"] == 6
    assert client.get("/api/v1/inventory/scopes", params={"provider": "gcp"}).json()["total"] == 3
    assert client.get("/api/v1/inventory/scopes", params={"status": "Access Failed"}).json()["items"][0]["name"] == "locked"
    assert client.get("/api/v1/inventory/scopes", params={"search": "PROJ-b"}).json()["total"] == 1
    s = client.get("/api/v1/onboarding/summary").json()
    assert s["by_status"]["Fully Onboarded"] == 5 and s["by_status"]["Access Failed"] == 1 and s["open_tasks"] == 1
    assert s["missing"]["authentication"][0]["external_id"] == "2" * 12


def test_task_decision_is_recorded_and_audited(client, session_factory, db):
    seed_inventory(session_factory)
    task_id = client.get("/api/v1/onboarding/tasks").json()["items"][0]["id"]
    assert client.post(f"/api/v1/onboarding/tasks/{task_id}/decision", json={"decision": "approved"}).status_code == 403  # CSRF
    r = client.post(f"/api/v1/onboarding/tasks/{task_id}/decision", json={"decision": "approved", "notes": "CR-1"}, headers=H)
    assert r.status_code == 200 and r.json()["status"] == "approved" and r.json()["decided_by"] == "dev-admin@localhost"
    assert client.post(f"/api/v1/onboarding/tasks/{task_id}/decision", json={"decision": "rejected"}, headers=H).status_code == 409
    assert db.scalar(select(AdminAuditLog).where(AdminAuditLog.action == "task.approved")) is not None
    assert db.get(RemediationRecord, task_id).status == "approved"


def test_manual_run_with_no_providers_is_reported_failed(client):
    assert client.post("/api/v1/jobs/account_discovery/run", headers=H).status_code == 202
    a = client.get("/api/v1/dashboard/automation").json()
    assert a["executions"][0]["status"] == "failed" and a["executions"][0]["trigger"] == "manual"
    assert "No cloud provider is enabled" in a["executions"][0]["failures"][0]["reason"]
    inv = client.get("/api/v1/dashboard/overview").json()["collection"]["inventory"]
    assert inv["state"] == "failed" and inv["last_status"] == "failed"  # a failed run is not "collected"
    assert [j["name"] for j in a["jobs"] if not j["implemented"]] == []
    assert client.post("/api/v1/jobs/not_a_job/run", headers=H).status_code == 404


def test_history_is_append_only(session_factory, db):
    seed_inventory(session_factory)
    rec = db.scalar(select(OnboardingRecord))
    rec.new_status = "tampered"
    with pytest.raises(ImmutableRecordError):
        db.commit()
    db.rollback()
    with pytest.raises(ImmutableRecordError):
        db.delete(db.scalar(select(OnboardingRecord)))
        db.commit()
    db.rollback()


@pytest.mark.skipif(not (IS_POSTGRES or TRIGGERS), reason="needs database triggers (PostgreSQL, or MySQL with trigger privilege)")
def test_database_trigger_blocks_raw_sql_tampering(session_factory, db):
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    seed_inventory(session_factory)
    for stmt in ("UPDATE onboarding_records SET new_status = 'x'", "DELETE FROM onboarding_records"):
        with pytest.raises(DBAPIError, match="append-only"):
            db.execute(text(stmt))
        db.rollback()
