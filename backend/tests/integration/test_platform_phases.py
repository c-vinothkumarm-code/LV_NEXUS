"""Executive Command Center v2, Cost Intelligence, Governance & Compliance, AI Intelligence Center and Reports."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.security import create_session_token
from app.models import BillingRecord, CloudAccount, CloudSecurityFinding, NotificationLog, Role, User, VMInventory, VMMetric
from app.models.ai import AIRecommendation
from app.models.reporting import ReportArchive, ReportSchedule
from tests.conftest import use_settings

H = {"X-Requested-With": "mcp-dashboard"}
NOW = datetime.now(UTC)


def login(client, db, email, role, **kw):
    s = use_settings(client, auth_mode="google", google_oauth_client_id="c", google_oauth_client_secret="x",
                     google_allowed_domain="latentview.com", secret_key="k" * 40, **kw)
    if not db.scalar(select(User).where(User.email == email)):
        db.add(User(email=email, roles=[db.scalar(select(Role).where(Role.name == role))]))
        db.commit()
    client.cookies.set("mcp_session", create_session_token(email, s, db))


def finding(db, i, sev="Critical", standard="standards/cis-aws-foundations-benchmark/v/1.4.0", control="CIS.1.4", state="ACTIVE", status="OPEN",
            title="Ensure no root user access key exists"):
    db.add(CloudSecurityFinding(provider="aws", source="security_hub", native_id=f"n{i}", native_id_hash=f"h{i}", scope_external_id="111111111111",
                                title=title, severity=sev, native_state=state, internal_status=status, compliance_standard=standard, control_id=control,
                                first_synced_at=NOW, last_synced_at=NOW, sla_due_at=NOW - timedelta(days=1), raw={}))
    db.commit()


def estate(db):
    db.add(CloudAccount(external_id="111111111111", name="payments-prod", environment="Production", onboarding_status="Fully Onboarded"))
    db.commit()


def test_executive_summary_kpis_never_fake_zero(client, db):
    estate(db)
    login(client, db, "ciso@latentview.com", "executive")
    s = client.get("/api/v1/executive/summary").json()
    k = {x["key"]: x for x in s["kpis"]}
    assert k["aws_accounts"]["value"] == 1 and k["aws_accounts"]["link"].startswith("/inventory")
    assert k["mtd_spend"]["value"] is None and "not been collected" in k["mtd_spend"]["reason"]
    assert k["unapproved_access"]["value"] is None  # access inventory never collected
    assert len(k) >= 21 and all(x["link"] for x in s["kpis"])
    finding(db, 1)
    db.add(BillingRecord(provider="aws", scope_external_id="111111111111", service="EC2", usage_date=NOW.date(), cost_original=10,
                         currency_original="USD", cost_usd=10))
    db.commit()
    s = client.get("/api/v1/executive/summary").json()
    k = {x["key"]: x for x in s["kpis"]}
    assert k["critical"]["value"] == 1 and k["overdue"]["value"] == 1 and k["mtd_spend"]["value"] == 10
    assert s["risks"]["critical"][0]["environment"] == "Production" and s["risks"]["critical"][0]["status"] == "Overdue"
    assert any(d["type"] == "Overdue remediation" for d in s["decisions"])
    login(client, db, "eng@latentview.com", "cloud_engineer")  # no finops / access permission: values hidden with a reason
    k = {x["key"]: x for x in client.get("/api/v1/executive/summary").json()["kpis"]}
    assert k["mtd_spend"]["value"] is None and "finops:read" in k["mtd_spend"]["reason"]


def test_cost_explorer_periods_definitions_and_records(client, db):
    estate(db)
    login(client, db, "fin@latentview.com", "finops_analyst")
    e = client.get("/api/v1/cost/explorer").json()
    assert e["collected"] is False and e["total_usd"] is None and "UnblendedCost" in e["definitions"]["aws"]
    for d in range(3):
        db.add(BillingRecord(provider="aws", scope_external_id="111111111111", service="EC2", usage_date=NOW.date() - timedelta(days=d),
                             cost_original=10, currency_original="USD", cost_usd=10, is_final=d > 1))
    db.commit()
    e = client.get("/api/v1/cost/explorer", params={"period": "daily"}).json()
    assert e["total_usd"] == 30 and e["complete_days_usd"] == 20 and e["includes_today_partial"] and e["provisional_records"] == 2
    assert e["by_scope"][0]["name"] == "payments-prod" and e["by_environment"][0]["environment"] == "Production"
    assert client.get("/api/v1/cost/explorer", params={"period": "custom"}).status_code == 422
    assert client.get("/api/v1/cost/records", params={"period": "daily"}).json()["total"] == 3


def test_optimization_detects_idle_vm_without_inventing_savings(client, db):
    login(client, db, "fin@latentview.com", "finops_analyst")
    vm = VMInventory(provider="aws", scope_external_id="1", instance_id="i-idle", name="idle-1", power_state="running")
    db.add(vm)
    db.flush()
    for h in range(20):
        db.add(VMMetric(vm_id=vm.id, cpu_percent=1.0, collected_at=NOW - timedelta(hours=h)))
    db.commit()
    items = client.get("/api/v1/cost/optimization").json()["items"]
    idle = next(i for i in items if i["type"] == "idle_vm")
    assert idle["estimated_savings_usd"] is None and "not collected" in idle["savings_note"]


def test_governance_controls_from_findings_and_custom_framework(client, db):
    estate(db)
    finding(db, 1)  # failing CIS 1.4
    finding(db, 2, control="CIS.1.5", state="RESOLVED", status="RESOLVED", title="Ensure MFA is enabled")  # passing
    login(client, db, "gov@latentview.com", "governance_manager")
    fws = client.get("/api/v1/governance/frameworks").json()
    fw = fws["items"][0]
    assert fw["source"] == "native" and fw["passed"] == 1 and fw["failed"] == 1 and fw["pass_rate"] == 50.0 and "not" in fws["disclaimer"]
    csv = ("control_id,title,mapped_keywords,mapped_control_ids,owner,review_date\n"
           "A.1,Privileged accounts protected,root user,,ciso@latentview.com,2027-01-01\nA.2,Backups tested,,,ops@latentview.com,\n")
    r = client.post("/api/v1/governance/frameworks", headers=H, json={"key": "internal-baseline", "name": "Internal cloud standard", "csv_text": csv}).json()
    assert r["controls"] == 2
    d = client.get(f"/api/v1/governance/frameworks/{r['id']}").json()
    by = {c["control_id"]: c for c in d["control_list"]}
    assert by["A.1"]["status"] == "FAIL" and by["A.2"]["status"] == "NOT_ASSESSED"  # no evidence: never assumed passing
    client.post(f"/api/v1/governance/controls/{by['A.2']['id']}/evidence", headers=H, json={"kind": "link", "reference": "https://example.test/backup-test"})
    client.patch(f"/api/v1/governance/controls/{by['A.2']['id']}", headers=H, json={"manual_status": "PASS"})
    d = client.get(f"/api/v1/governance/frameworks/{r['id']}").json()
    assert {c["control_id"]: c["status"] for c in d["control_list"]}["A.2"] == "PASS"


def test_onboarding_workflow_blocks_production_with_open_critical(client, db):
    estate(db)
    finding(db, 1)
    login(client, db, "dev@latentview.com", "cloud_engineer")
    o = client.post("/api/v1/governance/onboarding", headers=H, json={"title": "Payments API", "business_purpose": "Public payments API",
                                                                       "provider": "aws", "environment": "Production", "internet_facing": True}).json()
    approvers = {"requirement": "governance_manager", "manager": "governance_manager", "cost": "finops_analyst", "finance": "finance_approver",
                 "governance": "governance_manager", "architecture": "security_admin", "setup": "cloud_admin", "deployment": "cloud_admin",
                 "vapt": "security_admin", "production": "governance_manager"}
    for st in o["stages"]:
        login(client, db, f"{st['key']}@latentview.com", approvers[st["key"]])
        body = {"decision": "APPROVED", "evidence": "https://example.test/evidence"}
        if st["key"] == "setup":
            body["scope_external_id"] = "111111111111"
        if st["key"] == "vapt":
            assert client.post(f"/api/v1/governance/onboarding/{o['id']}/stage", headers=H, json=body).status_code == 422  # internet checks
            body["checks"] = {c: True for c in st["checks"]}
        r = client.post(f"/api/v1/governance/onboarding/{o['id']}/stage", headers=H, json=body)
        if st["key"] == "production":
            assert r.status_code == 409 and "Critical / High" in r.json()["detail"]
        else:
            assert r.status_code == 200, (st["key"], r.text)


def test_ai_copilot_uses_permission_checked_facts(client, db):
    estate(db)
    finding(db, 1)
    login(client, db, "sa@latentview.com", "security_analyst")
    r = client.post("/api/v1/ai/ask", headers=H, json={"question": "What are our top five cloud security risks?"}).json()
    assert r["answer_source"] == "template" and "root user access key" in r["answer"] and r["results"][0]["source"].startswith("Native security")
    r = client.post("/api/v1/ai/ask", headers=H, json={"question": "Which AWS account has the highest monthly cost?"}).json()
    assert r["filters"]["provider"] == "aws" and "Highest-cost accounts this month" in r["denied"]  # FinOps data not visible to this role
    assert client.get("/api/v1/ai/conversations").json()["items"][0]["question"].startswith("Which AWS")


def test_agent_recommendation_needs_human_approval_execution_and_verification(client, db):
    estate(db)
    finding(db, 1)
    login(client, db, "sa@latentview.com", "security_analyst")
    run = client.post("/api/v1/ai/agents/security/run", headers=H).json()
    assert run["recommendations"] >= 1 and "Nothing has been changed" in run["summary"]
    assert client.post("/api/v1/ai/agents/security/run", headers=H).json()["recommendations"] == 0  # de-duplicated
    rec = client.get("/api/v1/ai/recommendations").json()["items"][0]
    assert rec["status"] == "PROPOSED" and rec["required_permission"] == "connections:manage"
    assert client.post(f"/api/v1/ai/recommendations/{rec['id']}/step", headers=H, json={"action": "accept"}).status_code == 409
    client.post(f"/api/v1/ai/recommendations/{rec['id']}/step", headers=H, json={"action": "request_approval"})
    assert client.post(f"/api/v1/ai/recommendations/{rec['id']}/step", headers=H, json={"action": "approve"}).status_code == 403
    login(client, db, "admin@latentview.com", "cloud_admin")
    assert client.post(f"/api/v1/ai/recommendations/{rec['id']}/step", headers=H, json={"action": "approve"}).json()["status"] == "APPROVED"
    assert client.post(f"/api/v1/ai/recommendations/{rec['id']}/step", headers=H, json={"action": "executed"}).status_code == 422
    client.post(f"/api/v1/ai/recommendations/{rec['id']}/step", headers=H, json={"action": "executed", "notes": "Root key deleted, CHG-1"})
    v = client.post(f"/api/v1/ai/recommendations/{rec['id']}/step", headers=H, json={"action": "verify"}).json()
    assert v["status"] == "NOT_VERIFIED"  # the finding is still active in the data: not claimed as fixed
    f = db.scalar(select(CloudSecurityFinding))
    f.native_state, f.internal_status = "RESOLVED", "RESOLVED"
    db.commit()
    r = db.get(AIRecommendation, rec["id"])
    r.status = "EXECUTED"
    db.commit()
    assert client.post(f"/api/v1/ai/recommendations/{rec['id']}/step", headers=H, json={"action": "verify"}).json()["status"] == "VERIFIED"


def test_all_reports_generate_and_respect_permissions(client, db):
    estate(db)
    finding(db, 1)
    login(client, db, "root@latentview.com", "admin")
    cat = client.get("/api/v1/reports/catalogue").json()["items"]
    assert len(cat) == 15 and all(c["available"] for c in cat)
    for c in cat:
        r = client.get(f"/api/v1/reports/run/{c['key']}", params={"format": "csv"})
        assert r.status_code == 200, (c["key"], r.text)
    assert client.get("/api/v1/reports/run/budget-utilization", params={"format": "xlsx"}).content[:2] == b"PK"
    assert client.get("/api/v1/reports/run/critical-high-vulnerabilities", params={"format": "pdf"}).content[:4] == b"%PDF"
    login(client, db, "fin@latentview.com", "finops_analyst")
    assert client.get("/api/v1/reports/run/privileged-access").status_code == 403


def test_scheduled_report_goes_to_archive_and_recipients(client, db):
    from app.api.routes.reports import run_due_schedules
    estate(db)
    login(client, db, "root@latentview.com", "admin")
    assert client.post("/api/v1/reports/schedules", headers=H, json={"report_key": "multi-cloud-inventory", "frequency": "weekly", "day": 0,
                                                                      "recipients": ["not-an-email"]}).status_code == 422
    s = client.post("/api/v1/reports/schedules", headers=H, json={"report_key": "multi-cloud-inventory", "frequency": "daily",
                                                                  "recipients": ["CIO@latentview.com"]}).json()
    row = db.get(ReportSchedule, s["id"])
    row.next_run_at = NOW - timedelta(minutes=1)
    db.commit()
    assert run_due_schedules(db, "https://cloudnexus.example.test") == {"generated": 1, "failed": 0}
    db.commit()
    a = db.scalar(select(ReportArchive))
    n = db.scalar(select(NotificationLog).where(NotificationLog.category == "scheduled_report"))
    assert a.size > 0 and n.recipients == ["cio@latentview.com"] and f"archive={a.id}" in n.body
    assert client.get(f"/api/v1/reports/archive/{a.id}").status_code == 200


@pytest.mark.parametrize("limit", [3])
def test_rate_limit(client, db, limit):
    import app.main as main
    from app.core.config import get_settings
    s = get_settings().model_copy(update={"rate_limit_per_minute": limit})
    main_get = main.get_settings
    main.get_settings = lambda: s
    try:
        from fastapi.testclient import TestClient
        app = main.create_app()
        app.dependency_overrides = client.app_ref.dependency_overrides
        with TestClient(app) as c:
            codes = [c.get("/api/v1/auth/providers").status_code for _ in range(limit + 1)]
        assert codes[-1] == 429 and codes[0] == 200
    finally:
        main.get_settings = main_get
