"""Vulnerability management API: lifecycle, exceptions (separation of duties), evidence, RBAC, reports, sync endpoints."""
from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.security import create_session_token
from app.models import CloudSecurityFinding, FindingStatusHistory, Role, SyncRun, User
from tests.conftest import use_settings

H = {"X-Requested-With": "mcp-dashboard"}


def make_finding(db, **kw) -> CloudSecurityFinding:
    now = datetime.now(UTC)
    f = CloudSecurityFinding(provider=kw.pop("provider", "aws"), source="security_hub", native_id=kw.get("native_id", f"n{now.timestamp()}"),
                             native_id_hash=kw.pop("native_id_hash", str(now.timestamp())), scope_external_id="111", title=kw.pop("title", "Bucket public"),
                             severity=kw.pop("severity", "High"), native_state="ACTIVE", first_observed_at=now - timedelta(days=10),
                             first_synced_at=now - timedelta(days=10), last_synced_at=now, sla_due_at=now - timedelta(days=3),
                             resource_id="arn:aws:s3:::b", raw={}, **{k: v for k, v in kw.items() if k != "native_id"})
    db.add(f)
    db.commit()
    return f


def login(client, db, email, role, tmp_path=None, **settings):
    s = use_settings(client, auth_mode="entra", secret_key="k" * 40, **({"evidence_dir": str(tmp_path)} if tmp_path else {}), **settings)
    if not db.scalar(select(User).where(User.email == email)):
        db.add(User(email=email, roles=[db.scalar(select(Role).where(Role.name == role))]))
        db.commit()
    client.cookies.set("mcp_session", create_session_token(email, s, db))


def test_lifecycle_history_and_overdue(client, db):
    f = make_finding(db)
    login(client, db, "analyst@example.com", "security_analyst")
    page = client.get("/api/v1/security/findings?overdue=true").json()
    assert page["total"] == 1 and page["items"][0]["overdue"] is True
    r = client.post(f"/api/v1/security/findings/{f.id}/status", json={"status": "UNDER_REVIEW"}, headers=H)
    assert r.status_code == 200
    assert client.post(f"/api/v1/security/findings/{f.id}/status", json={"status": "RESOLVED"}, headers=H).status_code == 409  # reason required
    assert client.post(f"/api/v1/security/findings/{f.id}/status", json={"status": "EXCEPTION"}, headers=H).status_code == 409
    assert client.post(f"/api/v1/security/findings/{f.id}/status", json={"status": "FALSE_POSITIVE", "reason": "x"}, headers=H).status_code == 409  # needs approver
    assert client.post(f"/api/v1/security/findings/{f.id}/assign", json={"field": "owner", "value": "eng@example.com"}, headers=H).status_code == 200
    assert client.post(f"/api/v1/security/findings/{f.id}/comments", json={"kind": "investigation_note", "body": "checked"}, headers=H).status_code == 201
    r = client.post(f"/api/v1/security/findings/{f.id}/status", json={"status": "RESOLVED", "reason": "public access blocked"}, headers=H)
    assert r.status_code == 200 and r.json()["internal_status"] == "RESOLVED"
    d = client.get(f"/api/v1/security/findings/{f.id}").json()
    assert [h["to"] for h in d["history"] if h["field"] == "internal_status"] == ["UNDER_REVIEW", "RESOLVED"]
    assert d["comments"][0]["kind"] == "investigation_note" and d["finding"]["owner"] == "eng@example.com"
    assert client.post(f"/api/v1/security/findings/{f.id}/status", json={"status": "REOPENED", "reason": "still public"}, headers=H).json()["reopen_count"] == 1
    assert client.post(f"/api/v1/security/findings/{f.id}/status", json={"status": "UNDER_REVIEW"}).status_code == 403  # CSRF header required


def test_exception_workflow_separation_of_duties_and_expiry(client, db):
    f = make_finding(db, severity="Critical")
    login(client, db, "analyst@example.com", "security_analyst")
    bad = client.post(f"/api/v1/security/findings/{f.id}/exceptions", json={"business_justification": "short", "risk_acceptance": "x", "risk_owner": "o"}, headers=H)
    assert bad.status_code == 409
    body = {"business_justification": "Legacy integration needs public read until migration in Q1",
            "risk_acceptance": "Data is public marketing content", "risk_owner": "cio@example.com", "validity_days": 30}
    e = client.post(f"/api/v1/security/findings/{f.id}/exceptions", json=body, headers=H)
    assert e.status_code == 201 and e.json()["status"] == "PENDING_APPROVAL"
    assert client.post(f"/api/v1/security/findings/{f.id}/exceptions", json=body, headers=H).status_code == 409  # one at a time
    assert client.post(f"/api/v1/security/exceptions/{e.json()['id']}/decision", json={"approve": True}, headers=H).status_code == 403
    db.refresh(f)
    assert f.internal_status == "OPEN"  # not an exception until approved
    login(client, db, "approver@example.com", "exception_approver")
    assert client.post(f"/api/v1/security/exceptions/{e.json()['id']}/decision", json={"approve": False}, headers=H).status_code == 409  # reason for rejection
    ok = client.post(f"/api/v1/security/exceptions/{e.json()['id']}/decision", json={"approve": True, "notes": "accepted"}, headers=H)
    assert ok.status_code == 200 and ok.json()["status"] == "ACTIVE"
    db.refresh(f)
    assert f.internal_status == "EXCEPTION" and f.native_state == "ACTIVE" and f.sla_paused
    # expiry: the SLA job ends it and returns the finding for reassessment
    from app.models import FindingException
    from app.scheduler.engine import JobContext
    from app.services.vuln.sla_job import run_sla_check
    ex = db.get(FindingException, e.json()["id"])
    ex.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()
    from app.core.config import Settings
    run_sla_check(JobContext(db=db, execution_id=1, job=None), Settings(_env_file=None))
    db.refresh(f), db.refresh(ex)
    assert ex.status == "EXPIRED" and f.internal_status == "OPEN" and f.needs_reassessment and not f.sla_paused
    approvals = client.get(f"/api/v1/security/findings/{f.id}").json()["approvals"]
    assert [a["action"] for a in approvals] == ["requested", "approved", "expired"]


def test_requester_cannot_approve_own_exception(client, db):
    f = make_finding(db)
    login(client, db, "secadmin@example.com", "security_admin")
    e = client.post(f"/api/v1/security/findings/{f.id}/exceptions", headers=H, json={
        "business_justification": "Compensated by WAF and private endpoint rollout", "risk_acceptance": "Accepted for 30 days", "risk_owner": "o@example.com"}).json()
    r = client.post(f"/api/v1/security/exceptions/{e['id']}/decision", json={"approve": True, "notes": "self"}, headers=H)
    assert r.status_code == 409 and "requester" in r.json()["detail"]


def test_engineer_sees_only_assigned_and_cannot_triage(client, db, tmp_path):
    mine = make_finding(db, owner="eng@example.com", native_id_hash="h1")
    other = make_finding(db, native_id_hash="h2")
    login(client, db, "eng@example.com", "cloud_engineer", tmp_path)
    ids = [i["id"] for i in client.get("/api/v1/security/findings").json()["items"]]
    assert ids == [mine.id] and client.get(f"/api/v1/security/findings/{other.id}").status_code == 404
    assert client.post(f"/api/v1/security/findings/{mine.id}/status", json={"status": "UNDER_REVIEW"}, headers=H).status_code == 403
    assert client.post(f"/api/v1/security/findings/{mine.id}/comments", json={"kind": "verification_request", "body": "fixed, please verify"}, headers=H).status_code == 201
    up = client.post(f"/api/v1/security/findings/{mine.id}/evidence", headers=H, json={"kind": "file", "name": "screenshot.png",
                                                                                     "content_base64": base64.b64encode(b"proof").decode()})
    assert up.status_code == 201 and up.json()["sha256"]
    dl = client.get(f"/api/v1/security/evidence/{up.json()['id']}/download")
    assert dl.status_code == 200 and dl.content == b"proof" and "attachment" in dl.headers["content-disposition"]
    assert client.post(f"/api/v1/security/findings/{mine.id}/evidence", headers=H, json={"kind": "link", "name": "x", "reference": "javascript:alert(1)"}).status_code == 422


def test_auditor_read_only_and_reports(client, db):
    make_finding(db, severity="Critical")
    login(client, db, "aud@example.com", "auditor")
    assert client.get("/api/v1/security/overview").json()["kpis"]["critical"] == 1
    fid = client.get("/api/v1/security/findings").json()["items"][0]["id"]
    assert client.post(f"/api/v1/security/findings/{fid}/status", json={"status": "UNDER_REVIEW"}, headers=H).status_code == 403
    for fmt, magic in (("csv", b"\xef\xbb\xbf"), ("xlsx", b"PK"), ("pdf", b"%PDF")):
        r = client.get(f"/api/v1/security/reports/critical-high?format={fmt}")
        assert r.status_code == 200 and r.content.startswith(magic)
    assert client.get("/api/v1/security/reports/sync?format=csv").status_code == 200
    assert client.get("/api/v1/security/reports/nope").status_code == 404


def test_viewer_has_no_security_access(client, db):
    make_finding(db)
    login(client, db, "v@example.com", "viewer")
    assert client.get("/api/v1/security/findings").status_code == 403
    assert client.get("/api/v1/audit/events").status_code == 403
    assert client.get("/api/v1/sync/status").status_code == 403


def test_sync_endpoints_and_no_overlap(client, db):
    login(client, db, "cadmin@example.com", "cloud_admin")
    st = client.get("/api/v1/sync/status").json()
    assert st["schedule"]["cron"] == "0 2 * * *" and st["schedule"]["timezone"] == "UTC" and st["next_run_at"].endswith("02:00:00+00:00")
    assert {i["health"] for i in st["integrations"]} == {"NOT_CONFIGURED"}
    from app.models import AutomationJob
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "security_findings_sync"))
    job.lock_expires_at = datetime.now(UTC) + timedelta(hours=1)
    db.commit()
    assert client.post("/api/v1/sync/run", json={}, headers=H).status_code == 409
    job.lock_expires_at = None
    db.commit()
    assert client.post("/api/v1/sync/retry", headers=H).status_code == 409  # nothing failed
    assert client.post("/api/v1/sync/run", json={"full": True}, headers=H).status_code == 202
    run = db.scalar(select(SyncRun).order_by(SyncRun.id.desc()))
    assert run is not None and run.status == "FAILED" and run.trigger == "manual"  # no integration configured: never reported as success
    assert client.put("/api/v1/sync/schedule", json={"cron": "30 1 * * *"}, headers=H).status_code == 403  # cloud admin is not security admin
    assert client.get("/api/v1/sync/permissions").json()["items"][0]["required"]


def test_sla_policy_change_recalculates_and_is_recorded(client, db):
    f = make_finding(db, severity="High")
    login(client, db, "secadmin@example.com", "security_admin")
    r = client.put("/api/v1/security/sla-policies", json={"severity": "High", "target_hours": 48}, headers=H)
    assert r.status_code == 200 and r.json()["findings_recalculated"] == 1
    assert db.scalar(select(FindingStatusHistory).where(FindingStatusHistory.finding_id == f.id, FindingStatusHistory.field == "sla_due_at"))


@pytest.mark.parametrize("perm_role,code", [("security_admin", 200), ("security_analyst", 403)])
def test_notification_rules_admin_only(client, db, perm_role, code):
    login(client, db, f"{perm_role}@example.com", perm_role)
    assert client.put("/api/v1/security/notification-rules/new_high_finding", json={"enabled": False}, headers=H).status_code == code


def test_sources_report_coverage_not_zero(client, db):
    """A refused source is reported as access denied with its message, never as a clean '0 findings'."""
    from app.models import SyncCheckpoint
    login(client, db, "analyst@example.com", "security_analyst")
    make_finding(db, severity="Critical", native_id="c1", native_id_hash="c1")
    db.add_all([SyncCheckpoint(provider="aws", source="security_hub", scope_external_id="111", region="eu-west-1", state="OK",
                               last_success_at=datetime.now(UTC)),
                SyncCheckpoint(provider="aws", source="security_hub", scope_external_id="222", region="eu-west-1", state="ACCESS_DENIED",
                               last_error="AccessDeniedException: securityhub:GetFindings"),
                SyncCheckpoint(provider="gcp", source="scc", scope_external_id="org", region="global", state="ACCESS_DENIED", last_error="403")])
    db.commit()
    items = {(i["provider"], i["source"]): i for i in client.get("/api/v1/security/sources").json()["items"]}
    hub = items[("aws", "security_hub")]
    assert hub["critical"] == 1 and hub["status"] == "partial" and hub["access_denied"] == 1 and hub["problems"][0]["scope"] == "222"
    scc = items[("gcp", "scc")]
    assert scc["open"] == 0 and scc["status"] == "failed" and scc["label"] == "Google Security Command Center"
