"""Executive Command Center: KPIs (each linked to its detail page), the organisation's highest-priority risks grouped by
type, the cloud expenditure overview and the executive decision tracker.

Every figure is computed from stored records. A KPI whose source is not collected or not visible to the caller's role is
returned with value None and a reason, never as zero. Business impact is stated only from data the platform holds."""
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.serializers import iso
from app.core.config import Settings, get_settings
from app.core.security import require
from app.database.session import get_db
from app.models import SCOPE_MODELS, BillingForecast, BillingRecord, CloudResource, CloudSecurityFinding, FindingException, OnboardingStatus, User, VMInventory
from app.models.access import AccessRequest
from app.models.budget import BudgetRequest, CloudBudget
from app.services.access import engine as AE
from app.services.budget import engine as BE

router = APIRouter(prefix="/api/v1/executive", tags=["executive command center"])
OPEN = ("OPEN", "UNDER_REVIEW", "REOPENED")
SEV = ("Critical", "High", "Medium", "Low")


def _kpi(key, label, value, link, note=None, fmt="int", reason=None):
    return {"key": key, "label": label, "value": value, "link": link, "note": note, "format": fmt, "reason": reason if value is None else None}


def _no(perm):
    return f"Requires the {perm} permission"


def _scopes(db):
    names, envs = {}, {}
    for p, m in SCOPE_MODELS.items():
        for s in db.scalars(select(m)):
            names[(p, s.external_id)] = s.name or s.external_id
            envs[(p, s.external_id)] = s.environment
    return names, envs


@router.get("/summary")
def summary(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(require("inventory:read"))):
    perms = user.permission_names
    today = datetime.now(UTC).date()
    month = today.replace(day=1)
    names, envs = _scopes(db)
    k = []
    # --- footprint
    counts = {p: db.scalar(select(func.count()).select_from(m).where(m.onboarding_status != OnboardingStatus.INACTIVE.value)) or 0 for p, m in SCOPE_MODELS.items()}
    connected = sum(1 for p, m in SCOPE_MODELS.items()
                    if db.scalar(select(func.count()).select_from(m).where(m.onboarding_status == OnboardingStatus.FULLY_ONBOARDED.value)))
    k += [_kpi("providers", "Cloud providers connected", connected, "/integrations", "with at least one fully onboarded scope"),
          _kpi("aws_accounts", "AWS accounts", counts["aws"], "/inventory?provider=aws"),
          _kpi("azure_subscriptions", "Azure subscriptions", counts["azure"], "/inventory?provider=azure"),
          _kpi("gcp_projects", "GCP projects", counts["gcp"], "/inventory?provider=gcp"),
          _kpi("resources", "Cloud resources", db.scalar(select(func.count()).select_from(CloudResource).where(CloudResource.not_deleted())) or 0,
               "/inventory/explorer", "Azure: all resource types; AWS / GCP: virtual machines"),
          _kpi("vms", "Virtual machines", db.scalar(select(func.count()).select_from(VMInventory).where(VMInventory.deleted_at.is_(None))) or 0, "/monitoring")]
    # --- cost and budgets
    if "finops:read" in perms:
        has_billing = bool(db.scalar(select(func.count()).select_from(BillingRecord)))
        reason = "Billing data has not been collected"
        prev_end = month - timedelta(days=1)
        prev = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date >= prev_end.replace(day=1), BillingRecord.usage_date <= prev_end))
        mtd = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date >= month))
        fc = db.scalar(select(func.sum(BillingForecast.forecast_amount)).where(BillingForecast.period_start == month))
        k += [_kpi("monthly_spend", "Last month's expenditure", float(prev) if has_billing and prev is not None else None, "/cost", "USD", "usd", reason),
              _kpi("mtd_spend", "Month-to-date expenditure", float(mtd) if has_billing and mtd is not None else None, "/cost", "USD, includes provisional billing", "usd", reason),
              _kpi("forecast", "Forecasted monthly expenditure", float(fc) if fc is not None else None, "/cost", "estimate", "usd", "No forecast collected")]
    else:
        k += [_kpi(x, label, None, "/cost", reason=_no("finops:read")) for x, label in
              (("monthly_spend", "Last month's expenditure"), ("mtd_spend", "Month-to-date expenditure"), ("forecast", "Forecasted monthly expenditure"))]
    budgets_over = []
    if "budget:read" in perms:
        active = [b for b in db.scalars(select(CloudBudget).where(CloudBudget.status == "ACTIVE"))]
        roots = [b for b in active if b.parent_id is None]
        pos = {b.id: BE.position(db, b) for b in active}
        approved = sum(float(b.current_monthly_usd) for b in roots)
        with_data = [b for b in roots if pos[b.id]["actual_mtd_usd"] is not None]
        util = round(100 * sum(pos[b.id]["actual_mtd_usd"] for b in with_data) / sum(float(b.current_monthly_usd) for b in with_data), 1) if with_data else None
        budgets_over = [b for b in active if (pos[b.id]["utilisation_percent"] or 0) > 100]
        pending_b = db.scalar(select(func.count()).select_from(BudgetRequest).where(BudgetRequest.status.in_(["PENDING", "MORE_INFO"]))) or 0
        k += [_kpi("approved_budgets", "Approved monthly budgets", approved if roots else None, "/budgets", "top-level active budgets", "usd", "No active budgets registered"),
              _kpi("budget_utilisation", "Budget utilisation", util, "/budgets", "month to date", "pct", "No billing data for budgeted scopes"),
              _kpi("over_budget", "Accounts over budget", len(budgets_over), "/budgets/alerts"),
              _kpi("pending_budget_approvals", "Pending budget approvals", pending_b, "/budgets#approvals")]
    else:
        k += [_kpi(x, label, None, "/budgets", reason=_no("budget:read")) for x, label in
              (("approved_budgets", "Approved monthly budgets"), ("budget_utilisation", "Budget utilisation"), ("over_budget", "Accounts over budget"),
               ("pending_budget_approvals", "Pending budget approvals"))]
    # --- security
    sec_rows = []
    if "vuln:read" in perms:
        base = (CloudSecurityFinding.is_security.is_(True), CloudSecurityFinding.native_state == "ACTIVE", CloudSecurityFinding.internal_status.in_(OPEN))
        sev = dict(db.execute(select(CloudSecurityFinding.severity, func.count()).where(*base).group_by(CloudSecurityFinding.severity)).all())
        overdue = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(*base, CloudSecurityFinding.sla_due_at < datetime.now(UTC))) or 0
        k += [_kpi("critical", "Critical security findings", sev.get("Critical", 0), "/vulnerabilities/findings?severity=Critical"),
              _kpi("high", "High security findings", sev.get("High", 0), "/vulnerabilities/findings?severity=High"),
              _kpi("medium", "Medium security findings", sev.get("Medium", 0), "/vulnerabilities/findings?severity=Medium"),
              _kpi("open_findings", "Open security findings", sum(sev.values()), "/vulnerabilities/findings"),
              _kpi("overdue", "Overdue remediation", overdue, "/vulnerabilities/remediation")]
        sec_rows = db.execute(select(CloudSecurityFinding.provider, CloudSecurityFinding.scope_external_id, CloudSecurityFinding.severity,
                                     func.min(CloudSecurityFinding.title), func.count(), func.min(CloudSecurityFinding.sla_due_at),
                                     func.min(CloudSecurityFinding.owner), func.min(CloudSecurityFinding.remediation))
                              .where(*base, CloudSecurityFinding.severity.in_(["Critical", "High"]))
                              .group_by(CloudSecurityFinding.provider, CloudSecurityFinding.scope_external_id, CloudSecurityFinding.severity)
                              .order_by(func.count().desc()).limit(40)).all()
    else:
        k += [_kpi(x, label, None, "/vulnerabilities", reason=_no("vuln:read")) for x, label in
              (("critical", "Critical security findings"), ("high", "High security findings"), ("medium", "Medium security findings"),
               ("open_findings", "Open security findings"), ("overdue", "Overdue remediation"))]
    # --- access
    acc = None
    priv_by_scope: dict = {}
    if "access:read" in perms and not settings.access_workflows_enabled:
        # Approval workflows are switched off (read-only Access page): report facts only, never "unapproved" against an unused register
        from app.models.access import AccessAssignment as AA
        live = (AA.removed_at.is_(None), ~AA.scope_external_id.contains(":"))
        holders = db.scalar(select(func.count(func.distinct(AA.principal_id))).where(*live)) or 0
        for p, sc, n in db.execute(select(AA.provider, AA.scope_external_id, func.count()).where(*live, AA.privileged.is_(True))
                                   .group_by(AA.provider, AA.scope_external_id)).all():
            priv_by_scope[(p, sc)] = n
        from app.api.routes.access_view import _coverage
        cov, _, ran = _coverage(db)
        gaps = sum(1 for v in cov.values() if any(c.get("state") != "OK" for c in v or []))
        k += [_kpi("identities_with_access", "Identities with access", holders if ran else None, "/access", reason="Access inventory not collected yet"),
              _kpi("privileged_access", "Privileged role assignments", sum(priv_by_scope.values()) if ran else None, "/access",
                   "Owner / administrator-level roles", reason="Access inventory not collected yet"),
              _kpi("access_gaps", "Scopes with unreadable access data", gaps if ran else None, "/system-health", "missing read permission",
                   reason="Access inventory not collected yet")]
    elif "access:read" in perms:
        st = AE.assignment_status(db)
        collected = bool(st)
        reqs = db.execute(select(AccessRequest.request_type, AccessRequest.status, func.count()).group_by(AccessRequest.request_type, AccessRequest.status)).all()
        pend = sum(n for t, s, n in reqs if s in ("PENDING", "MORE_INFO"))
        acc = st
        k += [_kpi("unapproved_access", "Unapproved access assignments", sum(1 for v in st.values() if v["status"] == "UNAPPROVED") if collected else None,
                   "/access/assignments?status=UNAPPROVED", reason="Access inventory not collected yet"),
              _kpi("expired_access", "Expired access still active", sum(1 for v in st.values() if v["status"] == "EXPIRED_STILL_ACTIVE") if collected else None,
                   "/access/assignments?status=EXPIRED_STILL_ACTIVE", reason="Access inventory not collected yet"),
              _kpi("pending_access", "Pending access requests", pend, "/access/requests")]
    else:
        k += [_kpi(x, label, None, "/access", reason=_no("access:read")) for x, label in
              (("unapproved_access", "Unapproved access assignments"), ("expired_access", "Expired access still active"), ("pending_access", "Pending access requests"))]

    # --- risks
    risks = {"critical": [], "high": [], "financial": [], "access": [], "compliance": []}
    for p, sc, sev, title, n, due, owner, remediation in sec_rows:
        overdue = bool(due and due < datetime.now(UTC))
        item = {"title": f"{n} {sev} finding{'s' if n > 1 else ''}: {title}" if n == 1 else f"{n} open {sev} findings (e.g. {title})",
                "provider": p, "scope": sc, "scope_name": names.get((p, sc), sc), "environment": envs.get((p, sc)), "severity": sev,
                "business_impact": f"Known {sev.lower()} weaknesses in {'a production' if (envs.get((p, sc)) or '').lower().startswith('prod') else 'an'} environment"
                                   + (" past their remediation date." if overdue else "."),
                "affected_resources": n, "owner": owner or "Unassigned", "status": "Overdue" if overdue else "Open", "target_date": iso(due),
                "recommended_action": (remediation or "Remediate, or raise a time-bound risk exception for approval.")[:300],
                "pending_decision": "Risk exception or remediation date" if overdue else None,
                "link": f"/vulnerabilities/findings?provider={p}&scope={sc}&severity={sev}"}
        (risks["critical"] if sev == "Critical" else risks["high"]).append(item)
    if "budget:read" in perms:
        for b in budgets_over:
            p = BE.position(db, b)
            risks["financial"].append({"title": f"Budget exceeded: {b.name}", "provider": b.provider, "scope": b.scope_external_id,
                                       "scope_name": b.account_name or b.scope_external_id, "environment": b.environment, "severity": "High",
                                       "business_impact": f"{p['actual_mtd_usd']:,.0f} USD spent against {float(b.current_monthly_usd):,.0f} USD approved this month",
                                       "affected_resources": None, "owner": b.owner or "Not set", "status": f"{p['utilisation_percent']}% used",
                                       "target_date": p["period_end"] if "period_end" in p else None,
                                       "recommended_action": "Review cost drivers; raise an additional budget request if the spend must continue.",
                                       "pending_decision": "Additional budget approval" if db.scalar(select(BudgetRequest.id).where(
                                           BudgetRequest.budget_id == b.id, BudgetRequest.status.in_(["PENDING", "MORE_INFO"]))) else None,
                                       "link": f"/budgets?budget={b.id}"})
    for (p, sc), n in sorted(priv_by_scope.items(), key=lambda kv: -kv[1])[:8]:
        risks["access"].append({"title": f"{n} privileged role assignment(s) (Owner / administrator level) - review that each is still needed",
                                "provider": p, "scope": sc, "scope_name": names.get((p, sc), sc), "environment": envs.get((p, sc)), "severity": "Medium",
                                "business_impact": "Broad rights on this account; a compromised or unneeded assignment has a large blast radius.",
                                "affected_resources": n, "owner": "Access administrator", "status": "Open", "target_date": None,
                                "recommended_action": "Review the privileged assignments on the Access page and remove any no longer needed "
                                                      "(in the cloud provider's console, under your change process).",
                                "pending_decision": None, "link": "/access"})
    if acc:
        names_a = {}
        for aid, v in acc.items():
            if v["status"] in ("UNAPPROVED", "EXPIRED_STILL_ACTIVE"):
                from app.models.access import AccessAssignment
                a = db.get(AccessAssignment, aid)
                if not a.privileged:
                    continue
                key = (a.provider, a.scope_external_id, v["status"])
                names_a.setdefault(key, []).append(a)
        for (p, sc, stt), items in names_a.items():
            risks["access"].append({"title": f"{len(items)} privileged assignment(s) {'without approval' if stt == 'UNAPPROVED' else 'past approved expiry'}",
                                    "provider": p, "scope": sc, "scope_name": names.get((p, sc), sc), "environment": envs.get((p, sc)), "severity": "High",
                                    "business_impact": "Privileged access that is not covered by a current approval.", "affected_resources": len(items),
                                    "owner": "Access administrator", "status": "Open", "target_date": None,
                                    "recommended_action": "Confirm the approval or request revocation (verified against the provider).",
                                    "pending_decision": "Access approval or revocation", "link": f"/access/assignments?status={stt}&provider={p}&scope={sc}"})
    if "onboarding:read" in perms:
        from app.api.routes.governance import framework_summary
        from app.models.governance import ComplianceFramework
        for fw in db.scalars(select(ComplianceFramework).where(ComplianceFramework.enabled.is_(True))):
            s = framework_summary(db, fw)
            if s["failed"]:
                risks["compliance"].append({"title": f"{s['failed']} failed control(s): {s['name']}", "provider": None, "scope": None, "scope_name": None,
                                            "environment": None, "severity": "Medium", "business_impact": f"Control pass rate {s['pass_rate']}% (not a certification).",
                                            "affected_resources": s["failed"], "owner": fw.owner or "Not set", "status": "Open", "target_date": None,
                                            "recommended_action": "Review failed controls and attach remediation evidence.", "pending_decision": None,
                                            "link": "/compliance"})
    # --- decisions
    decisions = []
    if "budget:read" in perms:
        for r in db.scalars(select(BudgetRequest).where(BudgetRequest.status.in_(["PENDING", "MORE_INFO"])).order_by(BudgetRequest.created_at)):
            step = r.steps[r.current_step]
            decisions.append({"type": "Finance approval" if step["permission"] == "budget:approve" else ("Budget increase" if r.request_type == "additional_budget" else "Budget approval"),
                              "title": f"{r.request_key} {r.request_type.replace('_', ' ')}: {float(r.amount_monthly_usd):,.0f} USD / month",
                              "owner": step["label"], "next_step": "Provide information" if r.status == "MORE_INFO" else f"Decision by {step['label']}",
                              "since": iso(r.created_at), "link": f"/budgets?request={r.id}#approvals"})
    if "access:read" in perms:
        for r in db.scalars(select(AccessRequest).where(AccessRequest.status.in_(["PENDING", "MORE_INFO", "APPROVED", "VERIFICATION_FAILED"]))
                            .order_by(AccessRequest.created_at)):
            nxt = {"APPROVED": "Execute in the provider (administrator)", "VERIFICATION_FAILED": "Investigate: change not observed in the provider",
                   "MORE_INFO": "Requester to provide information"}.get(r.status, f"Decision by {r.steps[r.current_step]['label']}" if r.current_step < len(r.steps) else "")
            decisions.append({"type": "Access decision", "title": f"{r.request_key} {r.request_type}: {r.sign_in_name} - {r.role_name}",
                              "owner": "Access administrator" if r.status in ("APPROVED", "VERIFICATION_FAILED") else r.steps[min(r.current_step, len(r.steps) - 1)]["label"],
                              "next_step": nxt, "since": iso(r.created_at), "link": f"/access/requests?request={r.id}"})
    if "vuln:read" in perms:
        for e in db.scalars(select(FindingException).where(FindingException.status == "PENDING_APPROVAL").order_by(FindingException.created_at)):
            decisions.append({"type": "Security exception", "title": f"Exception #{e.id} for finding #{e.finding_id}", "owner": "Exception approver",
                              "next_step": "Approve or reject the risk exception", "since": iso(e.created_at), "link": f"/vulnerabilities/exceptions?id={e.id}"})
        n = len([r for r in sec_rows if r[5] and r[5] < datetime.now(UTC)])
        if n:
            decisions.append({"type": "Overdue remediation", "title": f"{n} account(s) with Critical / High findings past their remediation date",
                              "owner": "Finding owners", "next_step": "Set a remediation date or request an exception", "since": None,
                              "link": "/vulnerabilities/remediation"})
    # --- expenditure overview
    spend = None
    if "finops:read" in perms:
        start = today - timedelta(days=30)
        daily = defaultdict(lambda: defaultdict(float))
        for d, p, c in db.execute(select(BillingRecord.usage_date, BillingRecord.provider, func.sum(BillingRecord.cost_usd)).where(
                BillingRecord.usage_date >= start).group_by(BillingRecord.usage_date, BillingRecord.provider)):
            daily[d.isoformat()][p] = float(c or 0)
        top_scopes = db.execute(select(BillingRecord.provider, BillingRecord.scope_external_id, func.sum(BillingRecord.cost_usd)).where(
            BillingRecord.usage_date >= month).group_by(BillingRecord.provider, BillingRecord.scope_external_id).order_by(func.sum(BillingRecord.cost_usd).desc()).limit(8)).all()
        top_ids = {(p, s) for p, s, _ in top_scopes[:5]}
        by_acct = defaultdict(lambda: defaultdict(float))
        for d, p, s, c in db.execute(select(BillingRecord.usage_date, BillingRecord.provider, BillingRecord.scope_external_id, func.sum(BillingRecord.cost_usd))
                                     .where(BillingRecord.usage_date >= start).group_by(BillingRecord.usage_date, BillingRecord.provider, BillingRecord.scope_external_id)):
            if (p, s) in top_ids:
                by_acct[d.isoformat()][names.get((p, s), s)] = float(c or 0)
        monthly = defaultdict(lambda: defaultdict(float))
        for d, p, c in db.execute(select(BillingRecord.usage_date, BillingRecord.provider, func.sum(BillingRecord.cost_usd)).where(
                BillingRecord.usage_date >= (month - timedelta(days=330)).replace(day=1)).group_by(BillingRecord.usage_date, BillingRecord.provider)):
            monthly[d.isoformat()[:7]][p] += float(c or 0)
        ytd = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date >= today.replace(month=1, day=1)))
        spend = {"daily_by_provider": [{"date": d, **v} for d, v in sorted(daily.items())],
                 "daily_by_account": [{"date": d, **v} for d, v in sorted(by_acct.items())], "accounts": [names.get(x, x[1]) for x in top_ids],
                 "monthly": [{"month": m, **v} for m, v in sorted(monthly.items())], "year_to_date_usd": float(ytd) if ytd is not None else None,
                 "top_accounts": [{"provider": p, "scope": s, "name": names.get((p, s), s), "cost_usd": float(c or 0)} for p, s, c in top_scopes],
                 "top_services": [{"service": sv, "cost_usd": float(c or 0)} for sv, c in db.execute(
                     select(BillingRecord.service, func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date >= month)
                     .group_by(BillingRecord.service).order_by(func.sum(BillingRecord.cost_usd).desc()).limit(8)).all()],
                 "today_partial": True}
    return {"kpis": k, "risks": {key: v[:8] for key, v in risks.items()}, "risk_counts": {key: len(v) for key, v in risks.items()},
            "decisions": decisions[:30], "decision_count": len(decisions), "spend": spend, "generated_at": datetime.now(UTC).isoformat(),
            "as_of_date": date.today().isoformat()}
