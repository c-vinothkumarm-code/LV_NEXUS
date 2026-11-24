"""Live audit anomaly detection: each rule fires on the right pattern and stays quiet without a baseline; repeated runs
do not duplicate; alerts are masked; the watermark makes runs incremental; acknowledging records a note only."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.config import Settings
from app.models import AuditEvent, AutomationExecutionLog, AutomationJob, NotificationRule
from app.models.platform import AuditAnomaly
from app.scheduler.engine import JobContext
from app.services.audit.anomaly import is_delete, is_privilege, public_ip, run_anomaly_detection
from tests.integration.test_identity_governance import login

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)  # 17:30 in Asia/Kolkata
S = Settings(_env_file=None, anomaly_min_baseline_events=20, anomaly_failure_threshold=5, anomaly_mass_delete_threshold=5)
n = 0


def ev(db, principal, name="PutObject", ip="52.95.110.1", at=None, outcome="success", provider="aws", category="Management", region="eu-west-1",
       read_only=False):
    global n
    n += 1
    e = AuditEvent(event_id=f"e{n}", provider=provider, scope_external_id="111", region=region, event_timestamp=at or NOW, event_name=name,
                   principal=principal, source_ip=ip, event_category=category, raw={"outcome": outcome, "read_only": read_only})
    db.add(e)
    return e


def baseline(db, principal, ip="52.95.110.1", hour_utc=6, count=30, **kw):
    for i in range(count):
        ev(db, principal, ip=ip, at=(NOW - timedelta(days=1 + i % 20)).replace(hour=hour_utc, minute=i % 50), **kw)


def run(db, now=NOW):
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "anomaly_detection"))
    res = run_anomaly_detection(JobContext(db=db, execution_id=1, job=job), S, now)
    db.add(AutomationExecutionLog(job_id=job.id, job_name="anomaly_detection", status=res.status.value, summary=res.summary))
    db.commit()
    return res


def rules(db):
    return {a.rule: a for a in db.scalars(select(AuditAnomaly))}


def test_classifiers():
    assert public_ip("8.8.8.8") and not public_ip("10.0.0.1") and not public_ip("ec2.amazonaws.com") and not public_ip(None)
    mk = lambda p, nm: AuditEvent(provider=p, event_name=nm)  # noqa: E731
    assert is_privilege(mk("aws", "AttachRolePolicy")) and is_privilege(mk("gcp", "SetIamPolicy"))
    assert is_privilege(mk("azure", "Microsoft.Authorization/roleAssignments/write")) and is_privilege(mk("azure", "Add member to role"))
    assert not is_privilege(mk("aws", "GetObject"))
    assert is_delete(mk("aws", "TerminateInstances")) and is_delete(mk("gcp", "v1.compute.instances.delete"))
    assert is_delete(mk("azure", "Microsoft.Compute/virtualMachines/delete")) and not is_delete(mk("azure", "Microsoft.Compute/virtualMachines/write"))


def test_new_ip_and_unusual_hours_need_a_baseline(client, db):
    baseline(db, "arn:aws:iam::111:user/dev")  # 06:xx UTC = 11:30 IST every day
    ev(db, "arn:aws:iam::111:user/newbie", ip="34.120.0.10", at=NOW - timedelta(hours=1))  # no history: nothing but threshold rules
    db.commit()
    run(db, now=NOW - timedelta(minutes=50))  # first run: takes the last 24 h
    assert rules(db) == {}
    ev(db, "arn:aws:iam::111:user/dev", ip="34.120.0.10", at=NOW.replace(hour=21))  # 02:30 IST, new public IP
    ev(db, "arn:aws:iam::111:user/dev", ip="10.1.2.3", at=NOW.replace(hour=6))       # private IP never alerts
    db.commit()
    res = run(db, now=NOW.replace(hour=22))
    r = rules(db)
    assert set(r) == {"new_source_ip", "unusual_hours"} and r["new_source_ip"].detail["source_ips"] == ["34.120.0.10"]
    assert r["unusual_hours"].detail["local_hours"] == [2] and res.summary["new"] == 2
    assert run(db, now=NOW.replace(hour=23)).summary["events"] == 0  # watermark: nothing re-read


def test_threshold_rules_and_dedup(client, db):
    p = "arn:aws:iam::111:user/ops"
    for i in range(6):
        ev(db, p, name="DeleteBucket", at=NOW + timedelta(minutes=i))
    for i in range(5):
        ev(db, "arn:aws:iam::111:user/guess", name="ConsoleLogin", outcome="failure", at=NOW + timedelta(minutes=i))
    ev(db, p, name="AttachUserPolicy", at=NOW)
    ev(db, p, name="AttachUserPolicy", outcome="failure", at=NOW)  # refused change is not a privilege change
    db.add(NotificationRule(event_type="audit_anomaly", description="x", enabled=True, channels="email")) if not db.scalar(
        select(NotificationRule).where(NotificationRule.event_type == "audit_anomaly")) else None
    db.commit()
    run(db, now=NOW + timedelta(minutes=10))
    r = rules(db)
    assert r["mass_deletion"].severity == "Critical" and r["mass_deletion"].detail["max_in_window"] == 6
    assert r["failure_spike"].principal.endswith("user/guess")
    assert r["privilege_change"].event_count == 1
    for i in range(2):  # more deletions in the same window extend the same anomaly
        ev(db, p, name="DeleteBucket", at=NOW + timedelta(minutes=7 + i))
    db.commit()
    run(db, now=NOW + timedelta(minutes=12))
    assert db.query(AuditAnomaly).filter(AuditAnomaly.rule == "mass_deletion").count() == 1
    from app.models import NotificationLog
    bodies = " ".join(o.body for o in db.scalars(select(NotificationLog)))
    assert "Mass deletion" in bodies and "has not changed anything" in bodies


def test_new_country_from_entra_signins(client, db):
    for i in range(6):
        ev(db, "ana@example.com", name="Sign-in", provider="azure", category="EntraSignIn", region="IN", ip=None, at=NOW - timedelta(days=i + 1),
           read_only=True)
    ev(db, "ana@example.com", name="Sign-in", provider="azure", category="EntraSignIn", region="RO", ip=None, at=NOW, read_only=True)
    ev(db, "ana@example.com", name="Sign-in", provider="azure", category="EntraSignIn", region="BR", ip=None, at=NOW, outcome="failure", read_only=True)
    db.commit()
    run(db, now=NOW + timedelta(minutes=1))
    a = rules(db)["new_country"]
    assert a.detail["countries"] == ["RO"] and a.detail["known_countries"] == ["IN"]


def test_api_list_and_acknowledge(client, db):
    p = "arn:aws:iam::111:user/ops"
    ev(db, p, name="AttachRolePolicy", at=NOW)
    db.commit()
    run(db, now=NOW + timedelta(minutes=1))
    login(client, db, "admin@latentview.com", "admin")
    lst = client.get("/api/v1/activity/anomalies", params={"hours": 24 * 30}).json()
    assert lst["items"][0]["rule"] == "privilege_change" and lst["open_by_rule"] == {"privilege_change": 1}
    aid = lst["items"][0]["id"]
    assert client.post(f"/api/v1/activity/anomalies/{aid}/acknowledge", json={"note": "Approved change CHG-1"}, headers={"X-Requested-With": "mcp-dashboard"}).json()["status"] == "ACKNOWLEDGED"
    assert client.get("/api/v1/activity/anomalies", params={"hours": 24 * 30}).json()["items"] == []
