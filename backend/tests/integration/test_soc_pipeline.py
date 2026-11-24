from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select

from app.core.config import Settings
from app.models import AuditEvent, AutomationJob, CloudAccount, NotificationLog, RemediationRecord, SecurityFinding, SecurityReview
from app.services.soc.engine import run_security_events
from tests.helpers import ListCollector, ev, onboard, run

A, B = "1" * 12, "2" * 12
S = Settings(_env_file=None)
H = {"X-Requested-With": "mcp-dashboard"}


def soc(factory, *collectors, settings=S):
    return run(factory, "security_events", lambda ctx: run_security_events(ctx, settings, list(collectors)))


def n(db, model, *where):
    return db.scalar(select(func.count()).select_from(model).where(*where))


def test_collects_detects_and_is_idempotent(session_factory, db):
    onboard(session_factory, aws=[A, B])
    events = {A: [ev(event_id="e1", raw={"cidr": "0.0.0.0/0"}), ev(event_id="e2", name="DescribeInstances", read_only=True)],
              B: [ev(scope=B, event_id="e3", name="StopLogging")]}
    c = ListCollector("aws", events)
    entry = soc(session_factory, c)
    assert entry.status == "success" and entry.scopes_total == 2 and entry.summary["events_stored"] == 3
    assert n(db, AuditEvent) == 3 and n(db, AuditEvent, AuditEvent.detection_status == "flagged") == 2
    findings = {f.rule_id: f for f in db.scalars(select(SecurityFinding))}
    assert findings["network_rule_change"].severity == "High" and findings["audit_logging_disabled"].severity == "Critical"
    assert all(f.review_status == "Pending Review" for f in findings.values())  # collected is not reviewed
    again = soc(session_factory, c)  # same events returned again: nothing is duplicated
    assert again.summary["events_stored"] == 0 and n(db, AuditEvent) == 3 and n(db, SecurityFinding) == len(findings)
    assert db.scalar(select(SecurityFinding).where(SecurityFinding.rule_id == "network_rule_change")).occurrence_count == 1


def test_checkpoint_advances_and_first_run_uses_lookback(session_factory, db):
    onboard(session_factory, aws=[A])
    c = ListCollector("aws")
    soc(session_factory, c)
    soc(session_factory, c)
    (_, since1, until1), (_, since2, _) = c.calls
    assert timedelta(hours=23) < until1 - since1 <= timedelta(hours=24, minutes=1) and since2 == until1 - timedelta(minutes=30)
    assert f"aws:{A}" in db.scalar(select(AutomationJob).where(AutomationJob.name == "security_events")).checkpoint


def test_duplicate_finding_counts_occurrences_and_keeps_review(session_factory, db, client):
    onboard(session_factory, aws=[A])
    soc(session_factory, ListCollector("aws", {A: [ev(event_id="e1")]}))
    f = db.scalar(select(SecurityFinding))
    bad = client.post(f"/api/v1/soc/findings/{f.id}/review", json={"status": "Confirmed Legitimate"}, headers=H)
    assert bad.status_code == 422  # a decision needs notes
    ok = client.post(f"/api/v1/soc/findings/{f.id}/review", json={"status": "Confirmed Legitimate", "notes": "Change CR-42"}, headers=H)
    assert ok.status_code == 200
    soc(session_factory, ListCollector("aws", {A: [ev(event_id="e9")]}))  # same rule, principal, resource, day
    db.expire_all()
    f = db.scalar(select(SecurityFinding))
    assert f.occurrence_count == 2 and f.review_status == "Confirmed Legitimate" and len(f.evidence["events"]) == 2
    reviews = db.scalars(select(SecurityReview)).all()
    assert [(r.previous_status, r.new_status, r.notes) for r in reviews] == [("Pending Review", "Confirmed Legitimate", "Change CR-42")]


def test_confirmed_suspicious_opens_incident_and_queues_alerts(session_factory, db, client):
    onboard(session_factory, aws=[A])
    soc(session_factory, ListCollector("aws", {A: [ev(event_id="e1", name="StopLogging")]}))
    f = db.scalar(select(SecurityFinding).where(SecurityFinding.rule_id == "audit_logging_disabled"))
    assert n(db, RemediationRecord, RemediationRecord.category == "incident") == 0
    r = client.post(f"/api/v1/soc/findings/{f.id}/review", json={"status": "Confirmed Suspicious", "notes": "Not an approved change"}, headers=H)
    assert r.status_code == 200
    assert n(db, RemediationRecord, RemediationRecord.category == "incident") == 1
    alerts = db.scalars(select(NotificationLog).where(NotificationLog.category == "soc_confirmed_incident")).all()
    assert {a.channel for a in alerts} == {"email", "google_chat"} and all(a.status == "queued" for a in alerts)
    detail = client.get(f"/api/v1/soc/findings/{f.id}").json()
    assert detail["review_status"] == "Confirmed Suspicious" and len(detail["reviews"]) == 1


def test_new_critical_finding_requests_verification_not_confirmation(session_factory, db):
    onboard(session_factory, aws=[A])
    soc(session_factory, ListCollector("aws", {A: [ev(event_id="e1", name="StopLogging")]}))
    note = db.scalar(select(NotificationLog).where(NotificationLog.category == "soc_verification_request"))
    assert note.status == "queued" and "Not confirmed" in note.body
    assert n(db, NotificationLog, NotificationLog.category == "soc_confirmed_incident") == 0


def test_threshold_rules_and_untrusted_network(session_factory, db):
    onboard(session_factory, aws=[A])
    fails = [ev(event_id=f"f{i}", name="ConsoleLogin", outcome="failure", resource_id=None) for i in range(5)]
    denied = [ev(event_id=f"d{i}", name="GetObject", outcome="denied", resource_id=None) for i in range(10)]
    change = [ev(event_id="c1", name="CreateUser", source_ip="198.51.100.77")]
    soc(session_factory, ListCollector("aws", {A: fails + denied + change}), settings=Settings(_env_file=None, soc_trusted_cidrs=["203.0.113.0/24"]))
    rules = {f.rule_id: f for f in db.scalars(select(SecurityFinding))}
    assert rules["repeated_failed_authentication"].severity == "High" and rules["repeated_failed_authentication"].evidence["window_count"] == 5
    assert "repeated_permission_denied" in rules and "unexpected_source_ip" in rules
    assert "iam_role_modification" in rules["unexpected_source_ip"].evidence["related_rules"]  # correlated by principal


def test_failing_and_unvalidated_scopes_are_reported_not_skipped(session_factory, db):
    onboard(session_factory, aws=[A, B], gcp=["proj-a"])
    row = db.scalar(select(CloudAccount).where(CloudAccount.external_id == B))
    row.checks = {**row.checks, "audit_logs": {"status": "fail", "detail": "CloudTrail is not configured"}}
    row.onboarding_status = "Partially Onboarded"
    db.commit()
    entry = soc(session_factory, ListCollector("aws", {A: [ev(event_id="e1")]}), ListCollector("gcp", error=RuntimeError("503 unavailable")))
    assert entry.status == "partial" and entry.scopes_total == 3 and entry.scopes_failed == 2
    reasons = {f["scope"]: f["reason"] for f in entry.failures}
    assert "Audit log access not validated" in reasons[B] and "503" in reasons["proj-a"]
    assert n(db, AuditEvent) == 1


def test_no_scopes_or_providers_is_failed(session_factory):
    assert soc(session_factory).status == "failed"
    assert soc(session_factory, ListCollector("aws")).status == "failed"  # nothing onboarded yet


def test_event_cap_keeps_checkpoint_at_last_event(session_factory, db):
    onboard(session_factory, aws=[A])
    t0 = datetime.now(UTC) - timedelta(hours=2)
    events = [ev(event_id=f"e{i}", name="DescribeInstances", read_only=True, ts=t0 + timedelta(minutes=i)) for i in range(5)]
    entry = soc(session_factory, ListCollector("aws", {A: events}), settings=Settings(_env_file=None, soc_max_events_per_scope=3))
    assert entry.status == "partial" and "cap" in entry.failures[0]["reason"] and n(db, AuditEvent) == 3
    ck = db.scalar(select(AutomationJob).where(AutomationJob.name == "security_events")).checkpoint[f"aws:{A}"]
    assert datetime.fromisoformat(ck) == events[2]["event_timestamp"]


def test_late_arriving_event_is_collected_once(session_factory, db):
    """An event delivered after the checkpoint passed its timestamp is still picked up by the overlap, exactly once."""
    onboard(session_factory, aws=[A])
    late_ts = datetime.now(UTC) - timedelta(minutes=10)
    c = ListCollector("aws")
    soc(session_factory, c)  # the event is not visible yet
    c.events = {A: [ev(event_id="late-1", name="StopLogging", ts=late_ts)]}
    c.collect = lambda scope, since, until: (e for e in c.events[A] if since <= e["event_timestamp"] <= until)
    soc(session_factory, c)
    soc(session_factory, c)
    assert n(db, AuditEvent, AuditEvent.event_id == "late-1") == 1
    assert db.scalar(select(SecurityFinding).where(SecurityFinding.rule_id == "audit_logging_disabled")).occurrence_count == 1
