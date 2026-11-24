"""SOC rule library A-G: metadata on every rule, provider-native detections, provider-managed identities excluded,
incident confidence / summary / disposition, SOC alert e-mail with CSV raw-evidence attachment and a controlled recipient list."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select

from app.core.config import Settings
from app.models import AuditEvent, DetectionRule, InvestigationCase, NotificationLog
from app.scheduler.engine import JobContext
from app.services.audit.engine import run_audit_evaluation
from app.services.audit.soc_library import NEW_RULES, SOC_CATEGORIES, apply_soc_library
from app.services.notifications.channels import GmailChannel
from tests.integration.test_vuln_api import H, login

T0 = datetime(2026, 11, 17, 5, 0, tzinfo=UTC)
SG_OPEN_SSH = {"outcome": "success", "requestParameters": {"groupId": "sg-1", "ipPermissions": {"items": [
    {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}}


def _ev(db, i, op, actor="arn:aws:sts::111:assumed-role/Admin/ravi@latentview.com", raw=None, provider="aws", region="ap-south-1"):
    e = AuditEvent(event_id=f"s{i}", provider=provider, scope_external_id="111", region=region, event_timestamp=T0, event_name=op,
                   principal=actor, source_ip="203.0.113.7", resource_id="sg-1", raw=raw or {"outcome": "success"})
    db.add(e)
    db.commit()
    return e


def _run(db, **kw):
    s = Settings(_env_file=None, notify_email_to=["soc@latentview.com"], google_allowed_domain="latentview.com", **kw)
    return run_audit_evaluation(JobContext(db=db, execution_id=1, job=None), s)


def _enable_notifications(db):
    from app.models import NotificationRule
    for r in db.scalars(select(NotificationRule)):
        r.enabled, r.channels = True, "email,google_chat"
    db.commit()


def test_every_rule_has_library_metadata_and_all_categories_are_covered(db):
    rules = list(db.scalars(select(DetectionRule)))
    assert len(rules) >= 37 + len(NEW_RULES)
    for r in rules:
        assert r.soc_category in SOC_CATEGORIES, r.rule_key
        assert r.investigation_steps and r.remediation and r.exclusions, r.rule_key
    assert {r.soc_category for r in rules if r.enabled} == set(SOC_CATEGORIES)
    assert sum(1 for r in rules if r.mitre) >= len(rules) - 2
    # an administrator's change is never overwritten by the library
    r = db.scalar(select(DetectionRule).where(DetectionRule.rule_key == "AUD-001"))
    r.remediation = "our own runbook"
    db.commit()
    apply_soc_library(db)
    db.commit()
    assert db.get(DetectionRule, r.id).remediation == "our own runbook"
    assert apply_soc_library(db)["created"] == 0  # idempotent


def test_open_ssh_creates_incident_with_summary_and_soc_email_with_csv(db):
    _enable_notifications(db)
    _ev(db, 1, "AuthorizeSecurityGroupIngress", raw=SG_OPEN_SSH)
    _run(db, soc_alert_recipients=["soc-team@latentview.com"])
    rule = db.scalar(select(DetectionRule).where(DetectionRule.rule_key == "AUD-057"))
    assert rule.match_count == 1 and rule.last_triggered_at is not None
    case = db.scalar(select(InvestigationCase).where(InvestigationCase.rule_id == rule.id))
    assert case.confidence == "High" and case.disposition == "suspicious" and "not a confirmed incident" in case.summary
    assert case.notified_at is not None
    mail = db.scalar(select(NotificationLog).where(NotificationLog.channel == "email"))
    assert mail.subject.startswith("[LV NEXUS SOC ALERT] [CRITICAL]") and "AWS" in mail.subject
    assert mail.recipients == ["soc-team@latentview.com"]  # affected user NOT added (policy off by default)
    att = mail.attachments[0]
    assert att["filename"] == f"INC-{case.id:06d}-raw-events.csv" and "AuthorizeSecurityGroupIngress" in att["text"]
    assert "0.0.0.0/0" in att["text"] and "AUD-057" in att["text"]
    assert "Recommended investigation" in mail.body and "MITRE ATT&CK" in mail.body and mail.body_html
    chat = db.scalar(select(NotificationLog).where(NotificationLog.channel == "google_chat"))
    assert chat.attachments is None and "/audit/cases?case=" in chat.body
    # the same incident is never e-mailed twice
    _ev(db, 2, "AuthorizeSecurityGroupIngress", raw=SG_OPEN_SSH)
    _run(db, soc_alert_recipients=["soc-team@latentview.com"])
    assert len(db.scalars(select(NotificationLog).where(NotificationLog.channel == "email")).all()) == 1


def test_provider_managed_identity_is_not_a_detection(db):
    _ev(db, 3, "AuthorizeSecurityGroupIngress", raw=SG_OPEN_SSH,
        actor="arn:aws:sts::111:assumed-role/AWSServiceRoleForElasticLoadBalancing/elb")
    _ev(db, 4, "CreateServiceAccountKey", provider="gcp", region="global",
        actor="service-123@gcp-sa-cloudbuild.iam.gserviceaccount.com")
    _run(db)
    assert db.scalar(select(InvestigationCase)) is None


def test_gcp_owner_grant_and_aws_admin_port_variants(db):
    _ev(db, 5, "SetIamPolicy", provider="gcp", region="global", actor="dev@latentview.com",
        raw={"outcome": "success", "serviceData": {"policyDelta": {"bindingDeltas": [{"action": "ADD", "role": "roles/owner", "member": "user:x@latentview.com"}]}}})
    _ev(db, 6, "AuthorizeSecurityGroupIngress", raw={"outcome": "success", "requestParameters": {"ipPermissions": {"items": [
        {"fromPort": 443, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}})  # HTTPS to the world: not an admin-port violation
    _run(db)
    hits = {r.rule_key: r.match_count for r in db.scalars(select(DetectionRule))}
    # one case per event (first matching rule), but every matching rule is counted
    assert hits["AUD-045"] == 1 and hits["AUD-057"] == 0 and hits["AUD-058"] == 0


def test_affected_user_only_with_policy_and_corporate_domain(db):
    _enable_notifications(db)
    _ev(db, 7, "AuthorizeSecurityGroupIngress", raw=SG_OPEN_SSH)  # category D: not an identity-compromise rule
    _run(db, soc_notify_affected_user=True)
    mail = db.scalar(select(NotificationLog).where(NotificationLog.channel == "email"))
    assert mail.recipients == ["soc@latentview.com", "ravi@latentview.com"]


def test_api_rules_disposition_and_evidence_export(client, db):
    _ev(db, 8, "AuthorizeSecurityGroupIngress", raw=SG_OPEN_SSH)
    _run(db)
    case = db.scalar(select(InvestigationCase))
    login(client, db, "analyst@latentview.com", "security_analyst")
    body = client.get("/api/v1/audit/rules").json()
    assert set(body["categories"]) == set(SOC_CATEGORIES) and all(body["coverage"][k] >= 1 for k in SOC_CATEGORIES)
    r57 = next(r for r in body["items"] if r["rule_key"] == "AUD-057")
    assert r57["mitre"][0]["id"] == "T1133" and "AuthorizeSecurityGroupIngress" in r57["event_types"] and r57["data_status"] == "active"
    assert next(r for r in body["items"] if r["rule_key"] == "AUD-050")["data_status"] == "needs data source"
    r = client.post(f"/api/v1/audit/cases/{case.id}/disposition", json={"disposition": "approved_admin", "notes": "CHG-1042 approved window"}, headers=H)
    assert r.status_code == 200 and r.json()["disposition_label"] == "Approved administrative activity"
    assert client.post(f"/api/v1/audit/cases/{case.id}/disposition", json={"disposition": "made_up", "notes": "xxx"}, headers=H).status_code == 422
    csv = client.get(f"/api/v1/audit/cases/{case.id}/evidence.csv")
    assert csv.status_code == 200 and "attachment" in csv.headers["content-disposition"] and b"Original event payload" in csv.content
    login(client, db, "viewer@latentview.com", "viewer")
    assert client.post(f"/api/v1/audit/cases/{case.id}/disposition", json={"disposition": "false_positive", "notes": "xxx"}, headers=H).status_code == 403


def test_email_channel_attaches_files():
    sent = []

    class FakeSMTP:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, **kw):
            pass

        def login(self, *a):
            pass

        def send_message(self, msg):
            sent.append(msg)

    s = Settings(_env_file=None, notify_email_enabled=True, gmail_sender="cn@latentview.com", notify_email_to=["a@latentview.com"],
                 smtp_host="smtp", smtp_username="u", smtp_password="p")
    GmailChannel(s, smtp_factory=FakeSMTP).send("subj", "body", html="<b>x</b>", attachments=[{"filename": "e.csv", "content_type": "text/csv", "text": "a,b\n1,2\n"}])
    parts = [p for p in sent[0].iter_attachments()]
    assert parts and parts[0].get_filename() == "e.csv" and b"a,b" in parts[0].get_content().encode() if isinstance(parts[0].get_content(), str) else parts[0].get_content()
