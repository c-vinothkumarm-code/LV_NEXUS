"""The redesigned dashboards: every new figure comes from stored records, and missing data stays missing."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.config import Settings
from app.models import AutomationExecutionLog
from app.services.finops.engine import upsert_records
from app.services.soc.engine import run_security_events
from tests.helpers import ListCollector, ev, onboard, run
from tests.unit.test_finops import row

S = Settings(_env_file=None)


def test_overview_new_sections_on_empty_database(client):
    o = client.get("/api/v1/dashboard/overview").json()
    assert o["scheduler"]["state"] == "never_run" and o["cost_daily"] == [] and o["recent_events"] == []
    assert all(v["state"] == "not_connected" for v in o["provider_health"].values())
    assert o["vm_utilisation"]["cpu"]["average"] is None  # no data is None, not 0
    assert all(f["last_success_at"] is None for f in o["freshness"].values())
    assert {j["name"] for j in o["jobs"] if j["next_run_at"]} >= {"account_discovery", "security_events"}


def test_overview_reflects_collected_data(client, session_factory, db):
    onboard(session_factory, aws=["1" * 12])
    run(session_factory, "security_events", lambda ctx: run_security_events(ctx, S, [ListCollector("aws", {"1" * 12: [ev(event_id="e1", name="StopLogging")]})]))
    upsert_records(db, S, [row(day=datetime.now(UTC).date() - timedelta(days=2), cost="40")])
    db.commit()
    client.put("/api/v1/connections/aws", headers={"X-Requested-With": "mcp-dashboard"}, json={"enabled": True, "config": {"aws_member_role_name": "r"}})
    o = client.get("/api/v1/dashboard/overview").json()
    assert o["provider_health"]["aws"]["state"] == "healthy" and o["provider_health"]["aws"]["scopes_active"] == 1
    assert o["findings_open_by_severity"]["Critical"] == 1 and o["recent_events"][0]["event_name"] == "StopLogging"
    assert o["recent_events"][0]["source"] == "AWS CloudTrail"
    assert sum(d.get("aws", 0) for d in o["cost_daily"]) == 40.0
    assert any(a["area"] == "soc" for a in o["alerts"])
    assert o["freshness"]["security_events"]["last_success_at"] is not None
    scoped = client.get("/api/v1/dashboard/overview", params={"scope": "9" * 12}).json()
    assert scoped["findings_open_by_severity"]["Critical"] == 0 and scoped["recent_events"] == []


def test_scheduler_heartbeat(client, session_factory, db):
    onboard(session_factory, aws=["1" * 12])
    e = db.scalar(select(AutomationExecutionLog))
    e.trigger = "schedule"
    db.commit()
    assert client.get("/api/v1/dashboard/overview").json()["scheduler"]["state"] == "active"
    e.started_at = datetime.now(UTC) - timedelta(minutes=40)
    db.commit()
    o = client.get("/api/v1/dashboard/overview").json()
    assert o["scheduler"]["state"] == "stale" and any("Scheduler has not started" in a["text"] for a in o["alerts"])


def test_soc_finops_infra_new_fields(client, session_factory, db):
    onboard(session_factory, azure=["sub-1"])
    run(session_factory, "security_events", lambda ctx: run_security_events(ctx, S, [ListCollector("azure", {"sub-1": [
        ev(provider="azure", scope="sub-1", event_id="a1", name="Microsoft.Authorization/roleAssignments/write", resource_id="/subscriptions/sub-1/x")]})]))
    soc = client.get("/api/v1/dashboard/soc").json()
    assert soc["posture"]["azure"]["High"] == 1 and soc["posture"]["azure"]["open"] == 1 and soc["posture"]["azure"]["resolved"] == 0
    assert soc["recent_findings"][0]["source"] == "Azure Activity Log" and soc["recent_findings"][0]["resource_id"] == "/subscriptions/sub-1/x"
    assert soc["affected_resources"][0] == {"resource": "/subscriptions/sub-1/x", "findings": 1}
    upsert_records(db, S, [row(provider="azure", scope="sub-1", service="Storage", cost="12")])
    db.commit()
    fin = client.get("/api/v1/dashboard/finops").json()
    assert fin["metadata"]["reporting_currency"] == "USD" and fin["metadata"]["original_currencies"] == {"USD": 1}
    assert fin["metadata"]["periods"]["azure"].startswith("Each subscription") and fin["by_provider_range"]["azure"] == 12.0
    assert fin["monthly"][-1]["azure"] == 12.0 and fin["metadata"]["last_collected_at"]
    infra = client.get("/api/v1/dashboard/infrastructure").json()
    assert infra["by_region"] == {} and infra["utilisation"]["memory"]["average"] is None


def test_content_security_policy_on_app_pages_only(client):
    assert "content-security-policy" not in client.get("/api/v1/auth/me").headers
    assert "frame-ancestors 'none'" in client.get("/health").headers["content-security-policy"]
