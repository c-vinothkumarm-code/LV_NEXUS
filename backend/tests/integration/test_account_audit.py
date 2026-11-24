"""Account ownership (with history and budget-tracker budget) and the per-account monthly audit report / e-mail."""
from __future__ import annotations

import base64
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from sqlalchemy import select

from app.core.config import Settings
from app.models import AccountOwnershipHistory, BillingRecord, CloudAccount, CloudBudget, CloudSecurityFinding, NotificationLog
from app.services.notifications.channels import GmailChannel
from app.services.reports import audit_mail
from app.services.reports.audit_report import package, previous_month
from tests.integration.test_identity_governance import login

H = {"X-Requested-With": "mcp-dashboard"}
ACCT = "100000000777"  # fictional test account
MONTH = previous_month()


def _seed(db, spoc=True):
    db.add(CloudAccount(external_id=ACCT, name="demo-data-services", onboarding_status="Fully Onboarded", environment="Production"))
    db.add(CloudAccount(external_id="100000000778", name="demo-no-spoc", onboarding_status="Discovered"))
    for i in range(3):  # three months of cost, report month included
        m = (MONTH - timedelta(days=31 * i)).replace(day=10)
        db.add(BillingRecord(provider="aws", scope_external_id=ACCT, service="Amazon EC2", usage_date=m, cost_original=Decimal("400"), currency_original="USD",
                             cost_usd=Decimal("400"), collected_at=datetime.now(UTC)))
    db.add(CloudSecurityFinding(provider="aws", source="inspector", is_security=True, native_id="v1", native_id_hash="v1", scope_external_id=ACCT,
                                title="CVE-2026-0001 in openssl", severity="Critical", category="Software and Configuration Checks/Vulnerabilities/CVE",
                                native_state="ACTIVE", internal_status="OPEN", first_observed_at=datetime.now(UTC) - timedelta(days=10),
                                sla_due_at=datetime.now(UTC) - timedelta(days=5), last_synced_at=datetime.now(UTC)))
    db.add(CloudSecurityFinding(provider="aws", source="securityhub", is_security=True, native_id="c1", native_id_hash="c1", scope_external_id=ACCT,
                                title="S3 bucket allows public read", severity="High", category="Effects/Data Exposure",
                                native_state="ACTIVE", internal_status="OPEN", first_observed_at=datetime.now(UTC) - timedelta(days=3), last_synced_at=datetime.now(UTC)))
    db.add(CloudBudget(budget_key="BUD-7001", name="Data services", level="account", provider="aws", scope_external_id=ACCT, currency="USD",
                       original_monthly_amount=750, fx_rate_to_usd=1, original_monthly_usd=750, current_monthly_usd=750,
                       start_date=MONTH, end_date=MONTH + timedelta(days=400), status="ACTIVE", created_by="t"))
    db.commit()


OWN = {"spoc_name": "Spoc Person", "spoc_email": "Spoc.Person@latentview.com", "owner_email": "owner@latentview.com", "entity": "Data Services",
       "entity_lead": "Lead Person", "entity_lead_email": "lead@latentview.com", "cloud_admin_email": "cloudadmin@latentview.com",
       "finops_spoc_email": "finops@latentview.com", "cost_centre": "CC-100"}


def test_ownership_save_history_and_budget_from_tracker(client, db):
    _seed(db)
    r = client.put(f"/api/v1/accounts/ownership/aws/{ACCT}", headers=H, json={"fields": OWN})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["spoc_email"] == "spoc.person@latentview.com" and body["changed"] == len(OWN)
    assert body["approved_budget"]["monthly_usd"] == 750.0 and body["approved_budget"]["budgets"][0]["key"] == "BUD-7001"
    client.put(f"/api/v1/accounts/ownership/aws/{ACCT}", headers=H, json={"fields": {"cost_centre": "CC-200"}})
    hist = client.get(f"/api/v1/accounts/ownership/aws/{ACCT}").json()["history"]
    assert hist[0] == {**hist[0], "field": "cost_centre", "old": "CC-100", "new": "CC-200"}
    assert db.scalar(select(AccountOwnershipHistory).where(AccountOwnershipHistory.field == "spoc_email")).changed_by
    # validation and unknown fields
    assert client.put(f"/api/v1/accounts/ownership/aws/{ACCT}", headers=H, json={"fields": {"spoc_email": "not-an-email"}}).status_code == 422
    assert client.put(f"/api/v1/accounts/ownership/aws/{ACCT}", headers=H, json={"fields": {"password": "x"}}).status_code == 422
    assert client.put("/api/v1/accounts/ownership/aws/999999999999", headers=H, json={"fields": {}}).status_code == 422
    listing = client.get("/api/v1/accounts/ownership").json()
    assert {i["scope"] for i in listing["items"]} >= {ACCT, "100000000778"}


def test_viewer_cannot_edit_ownership_or_download_reports(client, db):
    _seed(db)
    login(client, db, "viewer@latentview.com", "viewer")
    assert client.put(f"/api/v1/accounts/ownership/aws/{ACCT}", headers=H, json={"fields": OWN}).status_code == 403
    assert client.get(f"/api/v1/reports/audit/aws/{ACCT}").status_code == 403


def test_report_package_content(client, db):
    _seed(db)
    client.put(f"/api/v1/accounts/ownership/aws/{ACCT}", headers=H, json={"fields": OWN})
    pkg = package(db, Settings(_env_file=None), "aws", ACCT, MONTH)
    d = pkg["data"]
    assert d["title"] == f"Cloud Security & Governance Audit Report – AWS demo-data-services ({ACCT}) – {MONTH:%B %Y}"
    assert pkg["pdf"][:5] == b"%PDF-" and len(pkg["pdf"]) > 3000
    assert [a["filename"].rsplit(".", 1)[1] for a in pkg["attachments"][:2]] == ["pdf", "docx"] and pkg["docx"][:2] == b"PK"
    assert [a["filename"][:2] for a in pkg["attachments"][2:]] == ["A_", "B_", "C_"]
    assert len(d["vulns"]["open"]) == 1 and len(d["findings"]["open"]) == 1 and len(d["overdue"]) == 1
    assert d["cost"]["month_cost"] == 400.0 and d["cost"]["budget"] == 750.0 and d["cost"]["status"] == "Within budget"
    assert sum(1 for m in d["cost"]["months"] if m["cost_usd"] is None) >= 9  # months without data are 'not collected', not $0
    assert all(x["status"] != "Reviewed" for x in d["domains"])  # automation never claims a human review
    vul_csv = next(a for a in pkg["attachments"] if a["filename"].startswith("C_Vulnerability"))["text"]
    assert "CVE-2026-0001" in vul_csv and "S3 bucket" in vul_csv and "vulnerability" in vul_csv
    assert pkg["subject"] == f"[LV NEXUS] Monthly Cloud Security & Governance Audit – demo-data-services – {MONTH:%B %Y}"
    r = client.get(f"/api/v1/reports/audit/aws/{ACCT}", params={"month": f"{MONTH:%Y-%m}"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf" and r.content[:5] == b"%PDF-"
    w = client.get(f"/api/v1/reports/audit/aws/{ACCT}", params={"month": f"{MONTH:%Y-%m}", "format": "docx"})
    assert w.status_code == 200 and w.content[:2] == b"PK" and w.headers["content-disposition"].endswith('.docx"')
    z = client.get(f"/api/v1/reports/audit/aws/{ACCT}", params={"format": "zip"})
    assert z.status_code == 200 and z.content[:2] == b"PK"
    assert client.get(f"/api/v1/reports/audit/aws/{ACCT}", params={"month": "2099-01"}).status_code == 422


def test_monthly_mail_recipients_dedup_and_missing_spoc(client, db):
    _seed(db)
    client.put(f"/api/v1/accounts/ownership/aws/{ACCT}", headers=H, json={"fields": OWN})
    s = Settings(_env_file=None)

    class Ctx:
        def __init__(self, db):
            self.db, self.execution_id = db, None
    res = audit_mail.run_monthly_audit_reports(Ctx(db), s)
    assert res.summary["queued"] == 1 and res.summary["not_sent"] == 1  # the scope without SPOC is reported, not skipped
    assert res.failures[0]["scope"] == "aws:100000000778" and "SPOC" in res.failures[0]["reason"]
    log = db.scalar(select(NotificationLog).where(NotificationLog.category == "security_monthly_audit_report"))
    assert log.channel == "email" and log.recipients[0] == "spoc.person@latentview.com"
    assert set(log.recipients[1:]) == {"cc:lead@latentview.com", "cc:owner@latentview.com", "cc:cloudadmin@latentview.com", "cc:finops@latentview.com"}
    assert base64.b64decode(log.attachments[0]["base64"])[:5] == b"%PDF-" and len(log.attachments) == 5
    # second run in the same month: nothing new is queued
    again = audit_mail.run_monthly_audit_reports(Ctx(db), s)
    assert again.summary["queued"] == 0 and again.summary["already_sent"] == 1
    assert db.scalar(select(NotificationLog).where(NotificationLog.category == "security_monthly_audit_report", NotificationLog.id != log.id)) is None
    # e-mail headers: SPOC in To, the others in Cc
    msg = GmailChannel(Settings(_env_file=None, gmail_sender="cloud@latentview.com"))._message(log.subject, log.body, log.recipients, None, log.attachments)
    assert msg["To"] == "spoc.person@latentview.com" and "lead@latentview.com" in msg["Cc"] and "spoc" not in msg["Cc"]
    assert any(p.get_filename() and p.get_filename().endswith(".pdf") for p in msg.iter_attachments())
    deliveries = client.get("/api/v1/reports/audit/deliveries").json()["items"]
    assert deliveries[0]["to"] == ["spoc.person@latentview.com"] and len(deliveries[0]["cc"]) == 4


def test_previous_month():
    assert previous_month(date(2026, 12, 1)) == date(2026, 11, 1)
    assert previous_month(date(2027, 1, 15)) == date(2026, 12, 1)
