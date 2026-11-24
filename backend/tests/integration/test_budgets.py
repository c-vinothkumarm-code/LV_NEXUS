"""Cloud Budget Management: register, approval chains with segregation of duties, immutable originals and revisions,
actual vs forecast with missing data kept distinct from zero, no double counting, alerts at thresholds, settings, RBAC."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from sqlalchemy import select

from app.core.security import create_session_token
from app.models import BillingBudget, BillingRecord, CloudAccount, ImmutableRecordError, NotificationLog, Role, User
from app.models.budget import BudgetAlert, BudgetRevision, CloudBudget
from app.services.budget import engine as E
from tests.conftest import use_settings

H = {"X-Requested-With": "mcp-dashboard"}
TODAY = datetime.now(UTC).date()


def login(client, db, email, role):
    s = use_settings(client, auth_mode="google", google_oauth_client_id="c", google_oauth_client_secret="x",
                     google_allowed_domain="latentview.com", secret_key="k" * 40)
    if not db.scalar(select(User).where(User.email == email)):
        db.add(User(email=email, roles=[db.scalar(select(Role).where(Role.name == role))]))
        db.commit()
    client.cookies.set("mcp_session", create_session_token(email, s, db))


def bill(db, scope, amount, day, service="EC2", final=False):
    db.add(BillingRecord(provider="aws", scope_external_id=scope, service=service, usage_date=day, cost_original=amount,
                         currency_original="USD", cost_usd=amount, is_final=final))
    db.commit()


def budget_body(**kw):
    body = {"name": "Payments production", "level": "account", "environment": "Production", "provider": "aws",
            "scope_external_id": "111111111111", "project_application": "Payments", "monthly_amount": 1000, "currency": "USD",
            "start_date": TODAY.replace(day=1).isoformat(), "end_date": (TODAY + timedelta(days=365)).isoformat(),
            "email_subject": "RE: Payments cloud budget FY27", "native_alert_name": "payments-monthly", "owner": "payments-team@latentview.com"}
    body.update(kw)
    return body


def approve_new_budget(client, db, bid):
    """Project team (FinOps colleague) -> Finance -> Internal governance, each a different person."""
    req = client.get("/api/v1/budget-requests").json()["items"][0]
    for email, role in (("lead@latentview.com", "finops_analyst"), ("fin@latentview.com", "finance_approver"), ("gov@latentview.com", "governance_manager")):
        login(client, db, email, role)
        r = client.post(f"/api/v1/budget-requests/{req['id']}/decision", headers=H, json={"decision": "APPROVED", "email_reference": "msg-1"})
        assert r.status_code == 200, r.text
    return req


def setup_estate(db):
    db.add(CloudAccount(external_id="111111111111", name="payments-prod", environment="Production"))
    db.add(CloudAccount(external_id="222222222222", name="hr-prod", environment="Production"))
    db.commit()


def test_register_approval_chain_and_segregation(client, db):
    setup_estate(db)
    login(client, db, "owner@latentview.com", "finops_analyst")
    b = client.post("/api/v1/budgets", headers=H, json=budget_body()).json()
    assert b["status"] == "DRAFT" and b["budget_key"].startswith("BUD-") and b["approved_monthly_usd"] == 1000
    assert client.post("/api/v1/budgets", headers=H, json=budget_body(scope_external_id="999")).status_code == 422  # not discovered
    assert client.post("/api/v1/budgets", headers=H, json=budget_body(currency="INR")).status_code == 422  # rate required
    sub = client.post(f"/api/v1/budgets/{b['id']}/submit", headers=H).json()
    assert sub["status"] == "PENDING" and [s["key"] for s in sub["approvals"]["steps"]] == ["project_team", "finance", "internal"]
    req = client.get("/api/v1/budget-requests").json()["items"][0]
    # the requester cannot approve, Finance cannot approve the project-team step
    assert client.post(f"/api/v1/budget-requests/{req['id']}/decision", headers=H, json={"decision": "APPROVED"}).status_code == 403
    login(client, db, "fin@latentview.com", "finance_approver")
    assert client.post(f"/api/v1/budget-requests/{req['id']}/decision", headers=H, json={"decision": "APPROVED"}).status_code == 403
    login(client, db, "lead@latentview.com", "finops_analyst")
    assert client.post(f"/api/v1/budget-requests/{req['id']}/decision", headers=H, json={"decision": "APPROVED"}).status_code == 200
    assert client.post(f"/api/v1/budget-requests/{req['id']}/decision", headers=H, json={"decision": "APPROVED"}).status_code == 403  # Finance step now
    login(client, db, "fin@latentview.com", "finance_approver")
    assert client.post(f"/api/v1/budget-requests/{req['id']}/decision", headers=H, json={"decision": "REJECTED"}).status_code == 409  # notes needed
    client.post(f"/api/v1/budget-requests/{req['id']}/decision", headers=H, json={"decision": "APPROVED"})
    login(client, db, "gov@latentview.com", "governance_manager")
    client.post(f"/api/v1/budget-requests/{req['id']}/decision", headers=H, json={"decision": "APPROVED"})
    got = client.get(f"/api/v1/budgets/{b['id']}").json()
    assert got["status"] == "ACTIVE" and got["approvals"]["steps"][1] == {**got["approvals"]["steps"][1], "status": "APPROVED", "by": "fin@latentview.com"}
    # the register keeps the existing FinOps budget view in step
    legacy = db.scalar(select(BillingBudget).where(BillingBudget.approved_by == f"register:{b['budget_key']}"))
    assert legacy is not None and float(legacy.amount) == 1000
    login(client, db, "owner@latentview.com", "finops_analyst")
    assert client.put(f"/api/v1/budgets/{b['id']}", headers=H, json=budget_body(monthly_amount=5000)).status_code == 409  # approved: not editable


def test_actual_forecast_missing_data_and_alerts(client, db):
    setup_estate(db)
    login(client, db, "owner@latentview.com", "finops_analyst")
    b = client.post("/api/v1/budgets", headers=H, json=budget_body()).json()
    client.post(f"/api/v1/budgets/{b['id']}/submit", headers=H)
    approve_new_budget(client, db, b["id"])
    pos = client.get(f"/api/v1/budgets/{b['id']}").json()["position"]
    assert pos["actual_mtd_usd"] is None and pos["utilisation_percent"] is None  # no billing collected: unknown, not 0
    first = TODAY.replace(day=1)
    bill(db, "111111111111", Decimal("950"), first)
    bill(db, "222222222222", Decimal("5000"), first)  # another account: must not count
    pos = client.get(f"/api/v1/budgets/{b['id']}").json()["position"]
    assert pos["actual_mtd_usd"] == 950 and pos["utilisation_percent"] == 95 and pos["actual_is_provisional"] is True
    assert pos["level"] == "High warning" and pos["remaining_usd"] == 50
    summary = E.evaluate_alerts(db)
    db.commit()
    assert summary["alerts_raised"] == 3  # 50, 75, 90
    assert E.evaluate_alerts(db)["alerts_raised"] == 0  # once per threshold per month
    bill(db, "111111111111", Decimal("100"), first, service="S3")
    E.evaluate_alerts(db)
    db.commit()
    levels = {a.level for a in db.scalars(select(BudgetAlert))}
    assert {"Budget reached", "Budget exceeded"} <= levels
    assert db.scalar(select(NotificationLog).where(NotificationLog.category == "security_budget_alert")) is not None
    alerts = client.get("/api/v1/budget-alerts").json()["items"]
    assert all(a["source"] == "cloudnexus" and a["native_alert_name"] == "payments-monthly" for a in alerts)


def test_additional_budget_creates_revision_and_preserves_original(client, db):
    setup_estate(db)
    login(client, db, "owner@latentview.com", "finops_analyst")
    b = client.post("/api/v1/budgets", headers=H, json=budget_body()).json()
    client.post(f"/api/v1/budgets/{b['id']}/submit", headers=H)
    approve_new_budget(client, db, b["id"])
    login(client, db, "owner@latentview.com", "finops_analyst")
    assert client.post("/api/v1/budget-requests", headers=H, json={"request_type": "additional_budget", "budget_id": b["id"],
                                                                   "amount_monthly_usd": -10, "justification": "wrong sign test"}).status_code == 422
    r = client.post("/api/v1/budget-requests", headers=H, json={
        "request_type": "additional_budget", "budget_id": b["id"], "amount_monthly_usd": 250, "justification": "New fraud-detection workload",
        "requesting_team": "Payments", "email_subject": "Additional budget - Payments", "supporting_documents": ["https://example.test/estimate"]}).json()
    assert [s["key"] for s in r["steps"]] == ["project_team", "finance", "internal", "final"] and r["existing_monthly_usd"] == 1000
    assert r["proposed_monthly_usd"] == 1250
    approvers = (("lead@latentview.com", "finops_analyst"), ("fin@latentview.com", "finance_approver"),
                 ("gov@latentview.com", "governance_manager"), ("fin@latentview.com", "finance_approver"))
    for i, (email, role) in enumerate(approvers):
        login(client, db, email, role)
        res = client.post(f"/api/v1/budget-requests/{r['id']}/decision", headers=H, json={"decision": "APPROVED"})
        if i == 3:
            assert res.status_code == 403 and "different person" in res.json()["detail"]  # Finance approver cannot also give final approval
    login(client, db, "cfo@latentview.com", "finance_approver")
    assert client.post(f"/api/v1/budget-requests/{r['id']}/decision", headers=H, json={"decision": "APPROVED"}).json()["status"] == "APPROVED"
    got = client.get(f"/api/v1/budgets/{b['id']}").json()
    assert got["original_monthly_usd"] == 1000 and got["approved_monthly_usd"] == 1250
    assert got["revisions"][0]["previous_monthly_usd"] == 1000 and got["revisions"][0]["revised_monthly_usd"] == 1250
    assert len(got["revisions"][0]["approvers"]) == 4
    rev = db.scalar(select(BudgetRevision))
    rev.reason = "tampered"
    try:
        db.commit()
        raise AssertionError("revisions must be append-only")
    except ImmutableRecordError:
        db.rollback()


def test_consolidated_totals_do_not_double_count_allocations(client, db):
    setup_estate(db)
    login(client, db, "admin@latentview.com", "admin")
    org = CloudBudget(budget_key="BUD-9001", name="AWS total", level="provider", provider="aws", currency="USD", original_monthly_amount=5000,
                      fx_rate_to_usd=1, original_monthly_usd=5000, current_monthly_usd=5000, start_date=TODAY.replace(day=1),
                      end_date=TODAY + timedelta(days=30), status="ACTIVE", created_by="t")
    db.add(org)
    db.flush()
    db.add(CloudBudget(budget_key="BUD-9002", name="Payments share", level="account", parent_id=org.id, provider="aws",
                       scope_external_id="111111111111", currency="USD", original_monthly_amount=2000, fx_rate_to_usd=1,
                       original_monthly_usd=2000, current_monthly_usd=2000, start_date=TODAY.replace(day=1), end_date=TODAY + timedelta(days=30),
                       status="ACTIVE", created_by="t"))
    db.commit()
    s = client.get("/api/v1/budgets/summary").json()
    assert s["approved_monthly_usd"] == 5000 and s["root_budgets"] == 1 and s["actual_mtd_usd"] is None


def test_new_service_request_and_settings(client, db):
    setup_estate(db)
    login(client, db, "owner@latentview.com", "finops_analyst")
    bad = client.post("/api/v1/budget-requests", headers=H, json={"request_type": "new_service", "amount_monthly_usd": 300,
                                                                  "justification": "Need a managed database", "service_details": {"provider": "aws"}})
    assert bad.status_code == 422
    r = client.post("/api/v1/budget-requests", headers=H, json={
        "request_type": "new_service", "amount_monthly_usd": 300, "justification": "Managed PostgreSQL for the analytics team",
        "service_details": {"business_purpose": "Analytics", "provider": "aws", "service": "Amazon RDS", "estimated_monthly_cost_usd": 300}}).json()
    assert [s["key"] for s in r["steps"]] == ["project_team", "entity_lead", "finance", "internal"]
    # a FinOps analyst cannot change approval chains; a governance manager can, and a bigger chain applies above an amount
    assert client.put("/api/v1/budget-settings/thresholds", headers=H, json={"thresholds": [60, 80]}).status_code == 403
    login(client, db, "gov@latentview.com", "governance_manager")
    assert client.put("/api/v1/budget-settings/thresholds", headers=H, json={"thresholds": [60, 80, 95, 100]}).json()["thresholds"] == [60, 80, 95, 100]
    assert client.put("/api/v1/budget-settings/thresholds", headers=H, json={"thresholds": [150]}).status_code == 422
    w = client.put("/api/v1/budget-settings/workflows", headers=H, json={"request_type": "additional_budget", "min_amount_usd": 0,
                                                                         "steps": [{"key": "finance"}]}).json()
    assert [s["key"] for s in w["steps"]] == ["finance"]
    client.put("/api/v1/budget-settings/workflows", headers=H, json={"request_type": "additional_budget", "min_amount_usd": 10000,
                                                                     "steps": [{"key": "project_team"}, {"key": "finance"}, {"key": "final"}]})
    assert [s["key"] for s in E.chain_for(db, "additional_budget", Decimal(500))] == ["finance"]
    assert [s["key"] for s in E.chain_for(db, "additional_budget", Decimal(20000))] == ["project_team", "finance", "final"]
    assert client.put("/api/v1/budget-settings/workflows", headers=H, json={"request_type": "additional_budget", "steps": [{"key": "ceo"}]}).status_code == 422


def test_budget_permissions(client, db):
    login(client, db, "v@latentview.com", "viewer")
    assert client.get("/api/v1/budgets").status_code == 403
    login(client, db, "exec@latentview.com", "executive")
    assert client.get("/api/v1/budgets/summary").status_code == 200
    assert client.post("/api/v1/budgets", headers=H, json=budget_body()).status_code == 403
    login(client, db, "fin@latentview.com", "finance_approver")
    assert client.post("/api/v1/budgets", headers=H, json=budget_body()).status_code == 403  # approvers do not register budgets
    assert date.fromisoformat(TODAY.isoformat())
