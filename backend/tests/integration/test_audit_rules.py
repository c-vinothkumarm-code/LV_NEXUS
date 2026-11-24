"""Audit rule engine: classification, only flagged events investigated, thresholds, change windows, authorization rules,
correlation proposals, investigation workflow, rule history and dry-run testing."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app.core.config import Settings
from app.models import AuditEvent, AuditInvestigation, AuthorizationRule, DetectionRule, InvestigationCase, NotificationLog
from app.scheduler.engine import JobContext
from app.services.audit.engine import run_audit_evaluation
from app.services.audit.rules import EventView, categorize, evaluate, validate
from tests.integration.test_vuln_api import H, login

T0 = datetime(2026, 11, 17, 5, 0, tzinfo=UTC)  # Tuesday 10:30 IST: inside the default change window


def ev(db, i, op, actor="alice@example.com", provider="aws", ts=None, raw=None, ip="203.0.113.5", resource=None):
    e = AuditEvent(event_id=f"e{i}", provider=provider, scope_external_id="111", region="us-east-1", event_timestamp=ts or T0, event_name=op,
                   principal=actor, source_ip=ip, resource_id=resource, raw=raw or {"outcome": "success"})
    db.add(e)
    db.commit()
    return e


def evaluate_all(db):
    return run_audit_evaluation(JobContext(db=db, execution_id=1, job=None), Settings(_env_file=None))


def inv(db, e):
    return db.scalar(select(AuditInvestigation).where(AuditInvestigation.audit_event_id == e.id))


def test_condition_language_and_categories():
    e = AuditEvent(event_id="x", provider="aws", scope_external_id="1", event_timestamp=T0, event_name="StopLogging", principal="bob",
                   source_ip="10.1.2.3", raw={"outcome": "success", "requestParameters": {"name": "trail"}})
    v = EventView(e)
    assert evaluate({"all": [{"field": "operation", "op": "eq", "value": "stoplogging"}, {"not": {"field": "source_ip", "op": "cidr", "value": ["192.168.0.0/16"]}},
                             {"any": [{"field": "raw.requestParameters.name", "op": "eq", "value": "trail"}, {"field": "actor", "op": "eq", "value": "x"}]}]}, v)
    assert categorize("StopLogging") == "Security Policy Changes" and categorize("RunInstances") == "VM Creation"
    assert categorize("Microsoft.Authorization/roleAssignments/write") == "Role Assignments" and categorize("x", "denied") == "Unauthorized Access Attempts"
    for bad in ({"field": "nope", "op": "eq", "value": 1}, {"all": []}, {"field": "actor", "op": "regex", "value": "("},
                {"field": "source_ip", "op": "cidr", "value": ["not-a-cidr"]}):
        try:
            validate(bad)
            raise AssertionError(bad)
        except ValueError:
            pass


def test_normal_activity_is_retained_without_case_or_alert(db):
    e = ev(db, 1, "DescribeInstances")
    evaluate_all(db)
    i = inv(db, e)
    assert i.classification == "NORMAL" and i.status is None and i.case_id is None
    assert db.scalar(select(func.count()).select_from(InvestigationCase)) == 0
    assert db.scalar(select(func.count()).select_from(NotificationLog)) == 0
    assert db.get(AuditEvent, e.id) is not None  # never deleted


def test_violation_opens_one_case_per_actor_and_notifies_once(db):
    a = ev(db, 1, "StopLogging")
    b = ev(db, 2, "DeleteTrail", ts=T0 + timedelta(minutes=5))
    evaluate_all(db)
    ia, ib = inv(db, a), inv(db, b)
    assert ia.classification == "RULE_VIOLATION" and ia.status == "DETECTED" and ia.severity == "Critical"
    assert ia.case_id == ib.case_id  # grouped: same rule, same actor, within the window
    case = db.get(InvestigationCase, ia.case_id)
    assert set(case.event_ids) == {a.id, b.id} and case.rule_id is not None
    assert db.scalar(select(func.count()).select_from(NotificationLog).where(NotificationLog.category == "security_audit_rule_violation")) == 2  # email+chat once


def test_threshold_rule_needs_frequency(db):
    for i in range(4):
        ev(db, i, "GetObject", actor="mallory", raw={"outcome": "denied"}, ts=T0 + timedelta(minutes=i))
    evaluate_all(db)
    assert {i.classification for i in db.scalars(select(AuditInvestigation))} == {"NORMAL"}  # 4 < threshold 5
    e5 = ev(db, 9, "GetObject", actor="mallory", raw={"outcome": "denied"}, ts=T0 + timedelta(minutes=5))
    evaluate_all(db)
    assert inv(db, e5).classification == "SUSPICIOUS" and "threshold 5" in inv(db, e5).explanation


def test_change_window_review_required_only_outside_window(db):
    inside = ev(db, 1, "AuthorizeSecurityGroupIngress")  # 07:30 IST Tuesday
    outside = ev(db, 2, "AuthorizeSecurityGroupIngress", ts=T0 + timedelta(hours=18))  # 04:30 IST Wednesday
    evaluate_all(db)
    assert inv(db, inside).classification == "NORMAL"
    o = inv(db, outside)
    assert o.classification == "REVIEW_REQUIRED" and o.status == "DETECTED" and o.case_id is None  # review queue, no incident


def test_authorization_rule_is_scoped_and_explicit(db):
    db.add(AuthorizationRule(name="Approved trail rotation", actor="alice@example.com", operation="StopLogging", reason="Planned trail migration",
                             approval_reference="CHG-1001", approved_by="ciso@example.com", valid_from=T0 - timedelta(days=1), valid_until=T0 + timedelta(days=1)))
    db.commit()
    ok = ev(db, 1, "StopLogging")
    other_actor = ev(db, 2, "StopLogging", actor="bob@example.com")
    later = ev(db, 3, "StopLogging", ts=T0 + timedelta(days=3))
    evaluate_all(db)
    assert inv(db, ok).classification == "AUTHORIZED" and inv(db, ok).authorization_reference == "CHG-1001" and inv(db, ok).status is None
    assert inv(db, other_actor).classification == "RULE_VIOLATION"
    assert inv(db, later).classification == "RULE_VIOLATION"  # outside validity: not authorized automatically


def test_correlation_is_only_a_proposal(db):
    ev(db, 1, "StopLogging", actor="eve", ts=datetime.now(UTC) - timedelta(hours=1))
    ev(db, 2, "PutBucketAcl", actor="eve", raw={"outcome": "success", "requestParameters": {"grant": "AllUsers"}}, ts=datetime.now(UTC) - timedelta(minutes=30))
    evaluate_all(db)
    prop = db.scalar(select(InvestigationCase).where(InvestigationCase.origin == "correlation"))
    assert prop is not None and prop.status == "PROPOSED" and len(prop.event_ids) == 2


def test_investigation_workflow_api(client, db):
    e = ev(db, 1, "StopLogging")
    n = ev(db, 2, "DescribeInstances")
    evaluate_all(db)
    login(client, db, "soc@example.com", "soc_analyst")  # can investigate, cannot authorize
    url = f"/api/v1/audit/events/{e.id}/status"
    assert client.post(url, json={"status": "REVIEWING"}, headers=H).status_code == 200
    assert client.post(url, json={"status": "AUTHORIZED", "reason": "ok", "approval_reference": "CHG-1"}, headers=H).status_code == 409
    login(client, db, "analyst@example.com", "security_analyst")
    assert client.post(url, json={"status": "AUTHORIZED", "reason": "planned"}, headers=H).status_code == 409  # approval reference required
    assert client.post(url, json={"status": "ESCALATED", "escalated_to": "Someone"}, headers=H).status_code == 409
    assert client.post(url, json={"status": "ESCALATED", "escalated_to": "CISO"}, headers=H).status_code == 200
    assert client.post(f"/api/v1/audit/events/{e.id}/assign", json={"investigator": "analyst@example.com"}, headers=H).status_code == 200
    assert client.post(f"/api/v1/audit/events/{e.id}/notes", json={"body": "Trail stopped during maintenance?"}, headers=H).status_code == 201
    r = client.post(url, json={"status": "AUTHORIZED", "reason": "Planned migration", "approval_reference": "CHG-77", "change_ticket": "INC-5"}, headers=H)
    assert r.status_code == 200
    assert client.post(url, json={"status": "CLOSED"}, headers=H).status_code == 409  # closure reason
    assert client.post(url, json={"status": "CLOSED", "reason": "Verified with change board"}, headers=H).status_code == 200
    d = client.get(f"/api/v1/audit/events/{e.id}").json()
    assert [h["to"] for h in d["history"]] == ["DETECTED", "REVIEWING", "ESCALATED", "ESCALATED", "AUTHORIZED", "CLOSED"]
    assert d["event"]["investigation"]["authorization_reference"] == "CHG-77" and d["notes"]
    # a normal activity has no investigation unless someone flags it
    assert client.post(f"/api/v1/audit/events/{n.id}/status", json={"status": "REVIEWING"}, headers=H).status_code == 409
    assert client.post(f"/api/v1/audit/events/{n.id}/flag", json={"reason": "unexpected at this hour"}, headers=H).status_code == 200
    assert client.get("/api/v1/audit/events?view=queue").json()["total"] == 1
    assert client.get("/api/v1/audit/overview").json()["classification"]["RULE_VIOLATION"] == 1


def test_rules_admin_versioning_and_dry_run(client, db):
    ev(db, 1, "DeleteBucket", actor="ops")
    login(client, db, "secadmin@example.com", "security_admin")
    rule = {"rule_key": "AUD-100", "name": "Bucket deletion by ops", "conditions": {"all": [{"field": "operation", "op": "eq", "value": "DeleteBucket"},
                                                                                         {"field": "actor", "op": "eq", "value": "ops"}]},
            "action": "REVIEW_REQUIRED", "severity": "Medium"}
    test = client.post("/api/v1/audit/rules/test", json={"rule": rule, "days": 90}, headers=H).json()
    assert test["matches"] == 1 and db.scalar(select(func.count()).select_from(AuditInvestigation)) == 0  # dry run changes nothing
    assert client.post("/api/v1/audit/rules", json={**rule, "conditions": {"field": "x", "op": "eq", "value": 1}}, headers=H).status_code == 422
    created = client.post("/api/v1/audit/rules", json=rule, headers=H)
    assert created.status_code == 201
    rid = created.json()["id"]
    assert client.put(f"/api/v1/audit/rules/{rid}", json={**rule, "enabled": False}, headers=H).json()["version"] == 2
    hist = client.get(f"/api/v1/audit/rules/{rid}/history").json()["items"]
    assert [h["action"] for h in hist] == ["disabled", "created"] and hist[0]["actor"] == "secadmin@example.com"
    assert db.get(DetectionRule, rid).enabled is False
    login(client, db, "analyst@example.com", "security_analyst")
    assert client.post("/api/v1/audit/rules", json={**rule, "rule_key": "AUD-101"}, headers=H).status_code == 403
    wild = {"name": "x rule", "actor": "*", "operation": "StopLogging", "reason": "because we said so", "approval_reference": "CHG",
            "valid_until": (datetime.now(UTC) + timedelta(days=1)).isoformat()}
    login(client, db, "secadmin@example.com", "security_admin")
    assert client.post("/api/v1/audit/authorization-rules", json=wild, headers=H).status_code == 422
