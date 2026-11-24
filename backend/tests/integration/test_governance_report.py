"""Daily Governance Dashboard: covers every monitored area, uses names (not IDs), never says "all clear" on missing data,
appends one audit-register row per day, sends HTML over SMTP, expires stale queued messages, preview sends nothing."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.config import Settings
from app.models import NotificationLog
from app.models.access import AccessAssignment, CloudIdentity
from app.models.iam import IdentityChangeEvent
from app.scheduler.engine import JobContext
from app.services.google_sheets.backend import MemorySheetsBackend
from app.services.google_sheets.register import append_governance
from app.services.notifications import governance as gov
from app.services.notifications.channels import GmailChannel
from app.services.notifications.dispatcher import dispatch
from tests.integration.sample_estate import seed
from tests.integration.test_identity_governance import login

S = Settings(_env_file=None, dashboard_url="http://localhost:5173")


def test_snapshot_covers_every_area_with_names(db):
    seed(db)
    db.add(CloudIdentity(provider="azure", principal_id="u-1", principal_type="User", display_name="Asha Rao", sign_in_name="asha@example.com", enabled=False))
    db.add(AccessAssignment(provider="azure", source="rbac", source_id="a1", source_id_hash="h-a1", scope_external_id="sub-prod", scope_level="subscription",
                            scope_path="/subscriptions/sub-prod", principal_id="u-1", principal_type="User", role_name="Owner", access_type="role", privileged=True))
    db.add(IdentityChangeEvent(provider="azure", scope_external_id="sub-prod", principal_id="u-1", principal_name="Asha Rao", principal_type="User",
                               change_type="ROLE_ADDED", privileged=True, detected_at=datetime.now(UTC)))
    db.commit()
    s = gov.snapshot(db, S)
    page, text, chat = gov.html(s), gov.text(s), gov.chat(s)
    for section in ("Coverage", "Data freshness", "Security findings", "Audit &amp; anomalies", "Access (IAM)", "Cost", "Virtual machines", "Automation"):
        assert section in page
    assert "contoso-prod" in page and ">sub-prod<" not in page  # subscription shown by name
    assert s["access"]["privileged"] >= 1 and s["access"]["disabled_with_access"] >= 1
    assert any("disabled identity" in h for h in s["headline"]) and any("privileged access change" in h for h in s["headline"])
    assert s["status"] != "ALL CLEAR"  # core collectors never ran in this fixture
    assert "Asha Rao" in text and "Status:" in chat and len(chat) < 4000


def test_register_row_is_appended_once_per_day(db):
    seed(db)
    backend = MemorySheetsBackend()
    row = gov.register_row(gov.snapshot(db, S))
    assert append_governance(backend, row) is True
    assert append_governance(backend, row) is False
    tab = backend.tabs["Governance_Daily_Snapshot"]
    assert tab[0][:len(gov.REGISTER_HEAD)] == gov.REGISTER_HEAD and len(tab) == 2


def test_smtp_sends_html_and_text_and_reports_missing_settings():
    sent = {}

    class FakeSMTP:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            sent["tls"] = True

        def login(self, u, p):
            sent["login"] = u

        def send_message(self, msg):
            sent["msg"] = msg

    incomplete = Settings(_env_file=None, notify_email_enabled=True, gmail_sender="noc@example.com", notify_email_to=["ciso@example.com"])
    assert "SMTP_HOST" in GmailChannel(incomplete).missing() and not GmailChannel(incomplete).configured()
    full = incomplete.model_copy(update={"smtp_host": "smtp.example.com", "smtp_username": "noc@example.com", "smtp_password": "app-pass"})
    ch = GmailChannel(full, smtp_factory=FakeSMTP)
    assert ch.configured()
    ch.send("Daily", "plain text", html="<html><body>dash</body></html>")
    msg = sent["msg"]
    assert sent["tls"] and sent["login"] == "noc@example.com" and msg["To"] == "ciso@example.com"
    assert {p.get_content_type() for p in msg.iter_parts()} == {"text/plain", "text/html"}


def test_stale_queued_reports_are_expired_not_sent(db):
    old = NotificationLog(channel="google_chat", category="daily_report", subject="old", body="x", status="queued",
                          created_at=datetime.now(UTC) - timedelta(days=3))
    new = NotificationLog(channel="google_chat", category="daily_report", subject="new", body="y", status="queued")
    db.add_all([old, new])
    db.commit()
    delivered = []

    class Chat:
        name = "google_chat"

        def configured(self):
            return True

        def send(self, subject, body):
            delivered.append(subject)

    res = dispatch(JobContext(db=db, job=None, execution_id=None), S, channels={"google_chat": Chat()})
    db.refresh(old)
    assert delivered == ["new"] and old.status == "expired" and res.summary["expired"] == 1


def test_preview_renders_without_sending(client, db):
    seed(db)
    login(client, db, "ciso@latentview.com", "auditor")
    r = client.get("/api/v1/reports/governance/preview")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html") and "Daily Governance Dashboard" in r.text
    assert client.get("/api/v1/reports/governance/preview", params={"fmt": "json"}).json()["chat"].startswith("Status:")
    assert db.query(NotificationLog).count() == 0


def test_gcp_credentials_file_is_exported_for_google_clients(tmp_path, monkeypatch):
    import os

    from app.core.config import get_settings
    key = tmp_path / "gcp.json"
    key.write_text("{}")
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setenv("GCP_CREDENTIALS_FILE", str(key))
    get_settings.cache_clear()
    try:
        get_settings()
        assert os.environ["GOOGLE_APPLICATION_CREDENTIALS"] == str(key)
    finally:
        get_settings.cache_clear()
        monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
