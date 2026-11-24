"""Monthly audit report in the official LatentView Word layout: filled per scope from collected data only (fictional data)."""
from __future__ import annotations

import io
import re
import zipfile
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

import docx

from app.core.config import Settings
from app.models import BillingRecord, CloudAccount, CloudBudget, CloudResource, CloudSecurityFinding, CloudSubscription, IamCredential, VMInventory
from app.services.reports import audit_template as AT
from app.services.reports.audit_report import package

ACCT = "100000000901"  # fictional
MONTH = date(2026, 11, 1)


def _f(i, sev, region, observed, resolved=None, title="CVE-2026-1000 in libssl", state="ACTIVE", status="OPEN"):
    return CloudSecurityFinding(provider="aws", source="inspector", is_security=True, native_id=f"n{i}", native_id_hash=f"n{i}", scope_external_id=ACCT,
                                title=title, severity=sev, category="Software and Configuration Checks/Vulnerabilities/CVE", region=region,
                                native_state=state, internal_status=status, first_observed_at=observed, resolved_at=resolved,
                                sla_due_at=observed + timedelta(days=5), last_synced_at=datetime.now(UTC))


def _seed(db):
    db.add(CloudAccount(external_id=ACCT, name="demo-ledger", onboarding_status="Fully Onboarded"))
    for m, amt in ((date(2026, 10, 5), "700"), (date(2026, 11, 5), "900")):
        db.add(BillingRecord(provider="aws", scope_external_id=ACCT, service="Amazon EC2", usage_date=m, cost_original=Decimal(amt), currency_original="USD",
                             cost_usd=Decimal(amt), collected_at=datetime.now(UTC)))
    db.add(CloudBudget(budget_key="BUD-9001", name="Ledger", level="account", provider="aws", scope_external_id=ACCT, currency="USD",
                       original_monthly_amount=800, fx_rate_to_usd=1, original_monthly_usd=800, current_monthly_usd=800,
                       start_date=date(2026, 4, 1), end_date=date(2027, 3, 31), status="ACTIVE", created_by="t"))
    oct10, nov10 = datetime(2026, 10, 10, tzinfo=UTC), datetime(2026, 11, 10, tzinfo=UTC)
    db.add_all([_f(1, "Critical", "ap-south-1", oct10), _f(2, "High", "ap-south-1", oct10, title="Security group allows 0.0.0.0/0 on port 22"),
                _f(3, "Medium", "us-east-1", oct10, resolved=nov10, state="ARCHIVED", status="RESOLVED"),
                _f(4, "Low", "us-east-1", oct10, resolved=datetime(2026, 10, 20, tzinfo=UTC), state="ARCHIVED", status="RESOLVED")])
    old = datetime.now(UTC) - timedelta(days=120)
    db.add(IamCredential(provider="aws", scope_external_id=ACCT, principal_id="svc-batch", credential_id="AKIAFICTIONAL0001", kind="access_key",
                         status="Active", created_at_provider=old))
    db.add_all([VMInventory(provider="aws", scope_external_id=ACCT, instance_id="i-01", name="app-1", power_state="running", public_ip="203.0.113.5",
                            exposed_ports=[22, 443]),
                VMInventory(provider="aws", scope_external_id=ACCT, instance_id="i-02", name="batch-1", power_state="stopped", exposed_ports=[])])
    db.add(CloudResource(provider="aws", scope_external_id=ACCT, resource_id="arn:aws:s3:::demo-bucket", resource_type="s3:bucket", name="demo-bucket",
                         state="available", attributes={"tags": {"Owner": "team-ledger"}}))
    db.commit()


def _doc(pkg) -> docx.Document:
    return docx.Document(io.BytesIO(pkg["docx"]))


def test_fiscal_quarter_labels():
    assert AT.fiscal_quarter(date(2026, 11, 1))["label"] == "Q3 FY 2026-27 (October – December 2026)"
    assert AT.fiscal_quarter(date(2027, 2, 1))["label"] == "Q4 FY 2026-27 (January – March 2027)"
    assert AT.fiscal_quarter(date(2026, 4, 1))["label"] == "Q1 FY 2026-27 (April – June 2026)"


def test_template_filled_from_scope_data(db):
    _seed(db)
    pkg = package(db, Settings(_env_file=None, audit_report_reviewed_by="Reviewer Name"), "aws", ACCT, MONTH)
    d = _doc(pkg)
    P, T = [p.text for p in d.paragraphs], d.tables
    assert P[1] == "AWS Account" and P[3] == f"demo-ledger – {ACCT}" and P[4] == "Audit Month:  November 2026"
    assert d.sections[0].header.paragraphs[0].text.strip() == f"AWS Account  |  demo-ledger – {ACCT}  |  November 2026"
    cover = {r.cells[0].text: r.cells[1].text for r in T[0].rows}
    assert cover["Account ID"] == ACCT and cover["Reviewed By"] == "Reviewer Name" and cover["Prepared By"] == "Cloud Team" and cover["Audit Period"] == "01 – 30 November 2026"
    # 1. domains: never "Reviewed" by automation
    assert all(r.cells[1].text in (AT.REVIEW, AT.NC) for r in T[2].rows[1:])
    # 4. access: MFA is not collected and says so
    assert T[4].rows[1].cells[3].text == AT.NC
    # 5. fiscal quarter, budget status and the exceeded table
    assert "Q3 FY 2026-27 (October – December 2026)" in " ".join(P)
    q = [[c.text for c in r.cells] for r in T[5].rows]
    assert q[1] == ["October", "800.00", "700.00", "Within budget"] and q[2] == ["November", "800.00", "900.00", "Exceeds"] and q[3][1:] == ["", "", ""]
    assert q[4] == ["QUARTER TOTAL", "1,600.00", "1,600.00", "Near limit"]
    ex = [[c.text for c in r.cells] for r in T[6].rows]
    assert ex[1][1:] == ["NA"] * 5 and ex[2][1:4] == ["800.00", "900.00", "100.00"] and ex[2][5] == "Pending SPOC confirmation"
    # 6. mitigation tracker per month and the exceptions table (Critical/High open)
    mt = [[c.text for c in r.cells] for r in T[7].rows]
    assert mt[1][1:] == ["0", "0", "0", "1", "1", "3"] and mt[2][1:] == ["0", "0", "1", "0", "1", "2"] and mt[4][5:] == ["2", "2"]
    exc = [[c.text for c in r.cells] for r in T[8].rows[1:]]
    assert [r[2] for r in exc] == ["Critical", "High"] and all("SLA breached" in r[5] for r in exc)
    assert any("Total = Critical + High + Medium + Low = 1 + 1 + 0 + 0 = 2" in p for p in P)
    # 7. key older than 90 days is overdue; password rotation is not collected
    assert [c.text for c in T[9].rows[1].cells][1] == "1" and T[9].rows[1].cells[6].text == "Overdue"
    assert T[9].rows[2].cells[6].text.startswith("Not collected")
    # 9/10. network exposure and VM counts
    assert any("with SSH/RDP open to the internet: 1" in p for p in P)
    assert "Total VMs under management: 2" in P and "Active VMs: 1" in P and "Inactive / Orphaned VMs: 1" in P
    # 13. sign-off stays empty for the people who sign
    assert all(c.text == "" for r in T[10].rows[1:] for c in r.cells[1:])
    assert pkg["pdf"][:5] == b"%PDF-"
    b = next(a for a in pkg["attachments"] if a["filename"].startswith("B_"))["text"]
    assert "demo-bucket" in b and "team-ledger" in b and "Amazon EC2" in b


def test_azure_wording_and_not_collected(db):
    db.add(CloudSubscription(external_id="00000000-0000-0000-0000-00000000a001", name="demo-sub", onboarding_status="Discovered"))
    db.commit()
    pkg = package(db, Settings(_env_file=None), "azure", "00000000-0000-0000-0000-00000000a001", MONTH)
    d = _doc(pkg)
    P, T = [p.text for p in d.paragraphs], d.tables
    assert P[1] == "Azure Subscription" and T[0].rows[4].cells[0].text == "Subscription ID"
    text = " ".join(P) + " ".join(c.text for t in T for r in t.rows for c in r.cells)
    assert "Microsoft Defender for Cloud" in text and "Network Security Groups" in text
    assert "Security Hub" not in text and "EC2" not in text and "Elastic IP" not in text
    assert "Total VMs under management: Not collected" in P
    assert all(r.cells[2].text == "☐" for r in T[3].rows[1:])  # nothing collected → nothing ticked


def test_shipped_template_has_no_account_data():
    with zipfile.ZipFile(AT.TEMPLATE) as z:
        xml = " ".join(z.read(n).decode("utf-8", "ignore") for n in z.namelist() if n.endswith(".xml"))
    text = re.sub(r"<[^>]+>", " ", xml)
    assert not re.search(r"\b\d{12}\b", text), "AWS account ID in template"
    assert not re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", text), "e-mail address in template"
    assert "Account Name – Account ID" in text
