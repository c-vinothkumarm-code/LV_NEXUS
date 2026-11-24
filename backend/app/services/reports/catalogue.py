"""The 15 platform reports. Each declares the permission it needs and builds (head, rows) from stored records,
honouring provider / scope / date filters. Reports never contain credentials or tokens."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import SCOPE_MODELS, AuditEvent, BillingRecord, CloudResource, CloudSecurityFinding, User
from app.models.access import AccessAssignment, AccessGrant, AccessRequest
from app.models.budget import BudgetApproval, BudgetRequest, CloudBudget

OPEN = ("OPEN", "UNDER_REVIEW", "REOPENED")


@dataclass
class Filters:
    provider: str | None = None
    scope: str | None = None
    date_from: date | None = None
    date_to: date | None = None

    def range(self, default_days: int = 30) -> tuple[date, date]:
        end = self.date_to or datetime.now(UTC).date()
        return self.date_from or end - timedelta(days=default_days), end


def _p(q, model, f: Filters):
    if f.provider:
        q = q.where(model.provider == f.provider)
    if f.scope and hasattr(model, "scope_external_id"):
        q = q.where(model.scope_external_id == f.scope)
    return q


def r_executive(db: Session, f: Filters, user: User):
    from app.api.routes.command_center import summary
    from app.core.config import get_settings
    s = summary(db=db, settings=get_settings(), user=user)
    rows = [[k["label"], k["value"] if k["value"] is not None else f"n/a ({k['reason']})", k["note"] or ""] for k in s["kpis"]]
    for group, items in s["risks"].items():
        rows += [[f"Risk ({group})", i["title"], f"{i['severity']} · owner {i['owner']} · {i['recommended_action']}"] for i in items]
    rows += [["Decision pending", d["title"], f"{d['type']} · {d['next_step']}"] for d in s["decisions"]]
    return ["Item", "Value", "Notes"], rows


def r_inventory(db, f, user):
    names = {(p, s.external_id): s.name for p, m in SCOPE_MODELS.items() for s in db.scalars(select(m))}
    rows = [[r.provider, r.scope_external_id, names.get((r.provider, r.scope_external_id)), r.name, r.resource_type, r.region,
             (r.attributes or {}).get("resource_group"), r.state, r.last_seen_at, r.resource_id]
            for r in db.scalars(_p(select(CloudResource), CloudResource, f).where(CloudResource.not_deleted()).order_by(CloudResource.provider))]
    return ["Cloud", "Scope ID", "Scope name", "Name", "Type", "Region", "Resource group", "State", "Last synchronized (UTC)", "Resource ID"], rows


def _findings(db, f, sev=None):
    q = _p(select(CloudSecurityFinding), CloudSecurityFinding, f).where(CloudSecurityFinding.is_security.is_(True))
    if sev:
        q = q.where(CloudSecurityFinding.severity.in_(sev), CloudSecurityFinding.native_state == "ACTIVE", CloudSecurityFinding.internal_status.in_(OPEN))
    rows = [[x.id, x.provider, x.scope_external_id, x.region, x.severity, x.title, x.category, x.source, x.resource_name or x.resource_id,
             x.internal_status, x.native_state, x.owner, x.sla_due_at, x.first_observed_at, x.last_observed_at]
            for x in db.scalars(q.order_by(CloudSecurityFinding.severity, CloudSecurityFinding.id))]
    return ["ID", "Cloud", "Scope", "Region", "Severity", "Title", "Category", "Source", "Resource", "Status", "Provider state", "Owner",
            "Target date (UTC)", "First detected", "Last observed"], rows


def r_cost(db, f, user):
    start, end = f.range()
    q = _p(select(BillingRecord), BillingRecord, f).where(BillingRecord.usage_date >= start, BillingRecord.usage_date <= end)
    rows = [[r.usage_date, r.provider, r.scope_external_id, r.service, r.cost_original, r.currency_original, r.cost_usd, r.conversion_rate,
             "final" if r.is_final else "provisional"] for r in db.scalars(q.order_by(BillingRecord.usage_date))]
    return ["Usage date", "Cloud", "Scope", "Service", "Cost (original)", "Currency", "Cost (USD)", "Rate to USD", "Status"], rows


def _budgets(db, only_exceeded=False):
    from app.services.budget.engine import position
    rows = []
    for b in db.scalars(select(CloudBudget).order_by(CloudBudget.budget_key)):
        p = position(db, b) if b.status in ("ACTIVE", "APPROVED", "EXPIRED") else None
        util = p["utilisation_percent"] if p else None
        if only_exceeded and not (util and util > 100):
            continue
        rows.append([b.budget_key, b.name, b.environment, b.provider, b.account_name, b.scope_external_id, b.project_application, b.status,
                     b.original_monthly_amount, b.currency, b.current_monthly_usd, p["actual_mtd_usd"] if p else None,
                     p["forecast_month_usd"] if p else None, util, b.owner, b.native_alert_name])
    return ["Budget", "Name", "ENV", "Cloud", "Account name", "Account ID", "Project / application", "Status", "Original monthly", "Currency",
            "Approved monthly (USD)", "Actual MTD (USD)", "Forecast (USD, estimate)", "Utilisation %", "Owner", "Native alert name"], rows


def r_budget_requests(db, f, user):
    rows = []
    for r in db.scalars(select(BudgetRequest).order_by(BudgetRequest.id)):
        approvals = "; ".join(f"{a.step_label}: {a.decision} by {a.actor}" for a in db.scalars(
            select(BudgetApproval).where(BudgetApproval.request_id == r.id).order_by(BudgetApproval.id)))
        rows.append([r.request_key, r.request_type, r.budget_id, r.amount_monthly_usd, r.proposed_monthly_usd, r.requester, r.status, approvals,
                     r.email_subject, r.created_at, r.decided_at])
    return ["Request", "Type", "Budget ID", "Amount / month (USD)", "Proposed / month", "Requester", "Status", "Approvals", "E-mail subject",
            "Created", "Decided"], rows


def _access(db, f, privileged=False):
    from app.services.access.engine import assignment_status
    st = assignment_status(db)
    rows = []
    for aid, v in st.items():
        a = db.get(AccessAssignment, aid)
        if (f.provider and a.provider != f.provider) or (f.scope and a.scope_external_id != f.scope) or (privileged and not a.privileged):
            continue
        i = v["identity"]
        rows.append([a.provider, a.scope_external_id, a.scope_level, a.resource_group, i.display_name if i else None, i.sign_in_name if i else a.principal_id,
                     a.principal_type, a.role_name, a.access_type, "yes" if a.privileged else "no", v["status"],
                     v["grant"].access_expiry_date if v["grant"] else None, a.last_seen_at])
    return ["Cloud", "Account / subscription / project", "Scope level", "Resource group", "DisplayName", "SignInName", "Identity type",
            "Access details", "Access type", "Privileged", "Approval status", "Approved expiry", "Last synced"], rows


def r_expired(db, f, user):
    rows = [[g.grant_key, g.provider, g.scope_external_id, g.sign_in_name, g.access_details, g.access_expiry_date, g.state, g.manager_approved_by,
             g.it_manager_approved_by] for g in db.scalars(select(AccessGrant).where(AccessGrant.state == "EXPIRED"))]
    head, live = _access(db, f)
    rows += [["(actual assignment)", r[0], r[1], r[5], r[7], r[11], "EXPIRED_STILL_ACTIVE", "", ""] for r in live if r[10] == "EXPIRED_STILL_ACTIVE"]
    return ["Approval", "Cloud", "Scope", "SignInName", "Access details", "Expiry", "State", "Manager approved by", "IT manager approved by"], rows


def r_access_requests(db, f, user):
    rows = [[r.request_key, r.request_type, r.provider, r.scope_external_id, r.sign_in_name, r.role_name, r.reason, r.requester, r.status,
             r.executed_by, r.executed_at, r.verified_at, r.verification_result, r.created_at]
            for r in db.scalars(_p(select(AccessRequest), AccessRequest, f).order_by(AccessRequest.id))]
    return ["Request", "Type", "Cloud", "Scope", "SignInName", "Role", "Revocation reason", "Requester", "Status", "Executed by", "Executed at",
            "Verified at", "Verification", "Created"], rows


def r_governance(db, f, user):
    from app.api.routes.governance import control_status, sync_native_frameworks
    from app.models.governance import ComplianceControl, ComplianceFramework
    sync_native_frameworks(db)
    rows = []
    for fw in db.scalars(select(ComplianceFramework)):
        for c in db.scalars(select(ComplianceControl).where(ComplianceControl.framework_id == fw.id)):
            s = control_status(db, fw, c)
            rows.append([fw.name, s["control_id"], s["title"], s["status"], s["failing_findings"], s["assessed_findings"], s["excepted"], s["evidence"],
                         s["owner"], s["review_date"]])
    return ["Framework", "Control", "Title", "Status (not a certification)", "Failing findings", "Assessed findings", "Excepted", "Evidence items",
            "Owner", "Review date"], rows


def r_activity(db, f, user):
    start, end = f.range(7)
    q = _p(select(AuditEvent), AuditEvent, f).where(AuditEvent.event_timestamp >= datetime.combine(start, datetime.min.time(), UTC),
                                                    AuditEvent.event_timestamp < datetime.combine(end + timedelta(days=1), datetime.min.time(), UTC))
    rows = [[e.event_timestamp, e.provider, e.scope_external_id, e.principal, e.event_name, e.resource_id, e.source_ip, e.event_category, e.severity, e.review_status]
            for e in db.scalars(q.order_by(AuditEvent.event_timestamp.desc()).limit(50000))]
    return ["Time (UTC)", "Cloud", "Scope", "Actor", "Action", "Resource", "Source IP", "Category", "Risk", "Review status"], rows


def r_optimization(db, f, user):
    from app.api.routes.cost import optimization
    from app.core.config import get_settings
    o = optimization(db=db, settings=get_settings(), _=user)
    return ["Type", "Title", "Cloud", "Scope", "Resource", "Evidence", "Confidence", "Estimated savings (USD)", "Recommended action"], [
        [i["type"], i["title"], i["provider"], i["scope"], i["resource"], i["evidence"], i["confidence"], i["estimated_savings_usd"] or i["savings_note"],
         i["recommended_action"]] for i in o["items"]]


@dataclass
class Report:
    key: str
    title: str
    permission: str
    build: Callable


REPORTS = {r.key: r for r in [
    Report("executive-cloud-health", "Executive Cloud Health Report", "inventory:read", r_executive),
    Report("multi-cloud-inventory", "Multi-Cloud Inventory Report", "inventory:read", r_inventory),
    Report("security-findings", "Security Findings Report", "vuln:read", lambda db, f, u: _findings(db, f)),
    Report("critical-high-vulnerabilities", "Critical and High Vulnerability Report", "vuln:read", lambda db, f, u: _findings(db, f, ("Critical", "High"))),
    Report("cloud-cost-billing", "Cloud Cost and Billing Report", "finops:read", r_cost),
    Report("budget-utilization", "Budget Utilization Report", "budget:read", lambda db, f, u: _budgets(db)),
    Report("budget-exceeded", "Budget Exceeded Report", "budget:read", lambda db, f, u: _budgets(db, True)),
    Report("additional-budget-approvals", "Additional Budget Approval Report", "budget:read", r_budget_requests),
    Report("cloud-access-inventory", "Cloud Access Inventory Report", "access:read", lambda db, f, u: _access(db, f)),
    Report("privileged-access", "Privileged Access Report", "access:read", lambda db, f, u: _access(db, f, True)),
    Report("expired-access", "Expired Access Report", "access:read", r_expired),
    Report("access-approvals-revocations", "Access Approval and Revocation Report", "access:read", r_access_requests),
    Report("governance-compliance", "Governance Compliance Report", "onboarding:read", r_governance),
    Report("cloud-activity-audit", "Cloud Activity Audit Report", "audit:read", r_activity),
    Report("cost-optimization", "Cost Optimization Report", "finops:read", r_optimization),
]}


def generate(db: Session, key: str, fmt: str, f: Filters, user: User) -> tuple[bytes, str, str]:
    from app.services.vuln.reports import render_table
    rep = REPORTS[key]
    head, rows = rep.build(db, f, user)
    sub = ", ".join(x for x in [f"cloud {f.provider}" if f.provider else "", f"scope {f.scope}" if f.scope else "",
                                f"{f.date_from} to {f.date_to}" if f.date_from or f.date_to else ""] if x)
    return render_table(key, rep.title, head, rows, fmt, sub)
