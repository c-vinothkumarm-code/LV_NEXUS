"""Budget register logic: actual spend, run-rate forecast, utilisation, status, approval chains, revisions and alerts.

Rules
- Actual spend comes from collected billing records (USD). If no billing record exists for the budget's scopes in the
  period, actual is None ("not collected"), never 0.
- Today's cost is partial: the forecast uses only complete days (run-rate) and is labelled an estimate.
- Consolidated totals count root budgets only; allocations (budgets with a parent) are part of their parent's amount.
- An approved budget's original amount never changes; approved changes are BudgetRevision rows.
- Budget alerts never stop, delete or change any cloud resource."""
from __future__ import annotations

import calendar
from datetime import UTC, date, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import BillingBudget, BillingRecord
from app.models.budget import ApprovalWorkflow, BudgetAlert, BudgetApproval, BudgetAuditEvent, BudgetRequest, BudgetRevision, BudgetSetting, CloudBudget
from app.models.inventory import SCOPE_MODELS

DEFAULT_THRESHOLDS = [50, 75, 90, 100]
EXCEEDED = 101  # stored threshold value for "above 100%"
LEVEL_LABEL = {50: "Informational", 75: "Warning", 90: "High warning", 100: "Budget reached", EXCEEDED: "Budget exceeded"}
STEP = {
    "project_team": ("Project team approval", "budget:manage"),
    "entity_lead": ("Entity lead approval", "budget:manage"),
    "finance": ("Finance approval", "budget:approve"),
    "internal": ("Internal governance approval", "governance:manage"),
    "final": ("Final approval", "budget:approve"),
}
DEFAULT_WORKFLOWS = {
    "new_budget": ["project_team", "finance", "internal"],
    "additional_budget": ["project_team", "finance", "internal", "final"],
    "budget_decrease": ["finance"],
    "new_service": ["project_team", "entity_lead", "finance", "internal"],
}
REQUEST_TYPES = tuple(DEFAULT_WORKFLOWS)
CENT = Decimal("0.01")


def q2(v) -> Decimal | None:
    return None if v is None else Decimal(str(v)).quantize(CENT, ROUND_HALF_UP)


def today() -> date:
    return datetime.now(UTC).date()


def audit(db: Session, actor: str, action: str, budget_id: int | None = None, request_id: int | None = None, **detail) -> None:
    db.add(BudgetAuditEvent(actor=actor, action=action, budget_id=budget_id, request_id=request_id, detail=_jsonable(detail)))


def _jsonable(v):
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, (date, datetime)):
        return v.isoformat()
    return v


# ------------------------------------------------------------------ settings and workflows
def seed_budget_defaults(db: Session) -> None:
    if db.scalar(select(BudgetSetting).where(BudgetSetting.key == "thresholds")) is None:
        db.add(BudgetSetting(key="thresholds", value=DEFAULT_THRESHOLDS, updated_by="system default"))
    existing = {w.request_type for w in db.scalars(select(ApprovalWorkflow))}
    for rtype, keys in DEFAULT_WORKFLOWS.items():
        if rtype not in existing:
            db.add(ApprovalWorkflow(request_type=rtype, min_amount_usd=Decimal(0), steps=[step(k) for k in keys], updated_by="system default"))
    from app.models import NotificationRule
    if db.scalar(select(NotificationRule).where(NotificationRule.event_type == "budget_alert")) is None:
        db.add(NotificationRule(event_type="budget_alert", description="Budget threshold reached or exceeded (LV NEXUS internal alert)",
                                enabled=True, channels="email,google_chat", updated_by="system default"))


def step(key: str, label: str | None = None, permission: str | None = None) -> dict:
    d_label, d_perm = STEP.get(key, (key.replace("_", " ").capitalize(), "budget:approve"))
    return {"key": key, "label": label or d_label, "permission": permission or d_perm}


def thresholds(db: Session, budget: CloudBudget | None = None) -> list[int]:
    if budget is not None and budget.thresholds:
        return sorted({int(t) for t in budget.thresholds})
    row = db.scalar(select(BudgetSetting).where(BudgetSetting.key == "thresholds"))
    return sorted({int(t) for t in (row.value if row else DEFAULT_THRESHOLDS)})


def chain_for(db: Session, request_type: str, amount_usd: Decimal) -> list[dict]:
    """The enabled workflow for this type with the highest minimum amount not above the request amount."""
    rows = [w for w in db.scalars(select(ApprovalWorkflow).where(ApprovalWorkflow.request_type == request_type, ApprovalWorkflow.enabled.is_(True)))
            if Decimal(w.min_amount_usd) <= abs(amount_usd)]
    if not rows:
        return [step(k) for k in DEFAULT_WORKFLOWS[request_type]]
    return max(rows, key=lambda w: Decimal(w.min_amount_usd)).steps


# ------------------------------------------------------------------ spend
def _month(d: date) -> tuple[date, date]:
    return d.replace(day=1), d.replace(day=calendar.monthrange(d.year, d.month)[1])


def budget_scopes(db: Session, b: CloudBudget) -> list[tuple[str, str]] | None:
    """Scopes whose spend counts towards the budget. None = every scope (of the provider, if set)."""
    pairs = []
    if b.scope_external_id and b.provider:
        pairs.append((b.provider, b.scope_external_id))
    pairs += [(s.get("provider"), s.get("scope")) for s in (b.scopes or []) if s.get("provider") and s.get("scope")]
    if pairs:
        return pairs
    if b.level == "environment" and b.environment:
        for prov, model in SCOPE_MODELS.items():
            if b.provider and prov != b.provider:
                continue
            pairs += [(prov, e) for (e,) in db.execute(select(model.external_id).where(model.environment == b.environment))]
        return pairs
    return None


def spend(db: Session, b: CloudBudget, start: date, end: date) -> tuple[Decimal | None, bool]:
    """(USD cost between start and end inclusive, provisional?). None when no billing record covers these scopes in the period."""
    from sqlalchemy import and_, or_

    where = [BillingRecord.usage_date >= start, BillingRecord.usage_date <= end, BillingRecord.cost_usd.is_not(None)]
    if b.provider:
        where.append(BillingRecord.provider == b.provider)
    if b.service:
        where.append(BillingRecord.service == b.service)
    pairs = budget_scopes(db, b)
    if pairs is not None:
        if not pairs:
            return None, False
        where.append(or_(*[and_(BillingRecord.provider == p, BillingRecord.scope_external_id == s) for p, s in pairs]))
    count, total = db.execute(select(func.count(), func.sum(BillingRecord.cost_usd)).where(*where)).one()
    if not count:
        return None, False
    provisional = db.scalar(select(func.count()).select_from(BillingRecord).where(*where, BillingRecord.is_final.is_(False))) or 0
    return q2(total or 0), provisional > 0


def position(db: Session, b: CloudBudget, on: date | None = None) -> dict:
    """Current-month actual, forecast and utilisation for one budget."""
    on = on or today()
    start, end = _month(on)
    actual, provisional = spend(db, b, start, min(on, end))
    complete_end = on - timedelta(days=1)
    forecast = None
    if actual is not None and complete_end >= start:
        complete, _ = spend(db, b, start, complete_end)
        days = (complete_end - start).days + 1
        forecast = q2((complete or Decimal(0)) / days * calendar.monthrange(on.year, on.month)[1]) if days else None
    approved = Decimal(b.current_monthly_usd)
    util = q2(actual / approved * 100) if actual is not None and approved > 0 else None
    return {"period_start": start.isoformat(), "period_end": end.isoformat(), "approved_monthly_usd": float(approved),
            "actual_mtd_usd": None if actual is None else float(actual), "actual_is_provisional": provisional,
            "forecast_month_usd": None if forecast is None else float(forecast), "forecast_method": "run-rate over complete days (estimate)",
            "remaining_usd": None if actual is None else float(approved - actual),
            "utilisation_percent": None if util is None else float(util),
            "level": level_for(util, thresholds(db, b)) if util is not None else None}


def level_for(util: Decimal | None, ths: list[int]) -> str | None:
    if util is None:
        return None
    if util > 100:
        return LEVEL_LABEL[EXCEEDED]
    crossed = [t for t in ths if util >= t]
    return LEVEL_LABEL.get(max(crossed), f"{max(crossed)}%") if crossed else "Within budget"


# ------------------------------------------------------------------ lifecycle
def refresh_status(b: CloudBudget, on: date | None = None) -> None:
    on = on or today()
    if b.status in ("APPROVED", "ACTIVE") and b.end_date < on:
        b.status = "EXPIRED"
    elif b.status == "APPROVED" and b.start_date <= on:
        b.status = "ACTIVE"


def sync_legacy_budget(db: Session, b: CloudBudget) -> None:
    """Keeps the existing FinOps budget view (billing_budgets) in step with the register for account- and provider-level
    budgets, for the current month. Rows are marked approved_by='register:<key>'."""
    marker = f"register:{b.budget_key}"
    start, end = _month(today())
    row = db.scalar(select(BillingBudget).where(BillingBudget.approved_by == marker, BillingBudget.period_start == start))
    eligible = b.status == "ACTIVE" and b.provider and b.level in ("account", "provider") and not b.scopes and b.start_date <= end and b.end_date >= start
    if not eligible:
        if row is not None:
            db.delete(row)
        return
    scope = b.scope_external_id if b.level == "account" and b.scope_external_id else "*"
    if row is None:
        clash = db.scalar(select(BillingBudget).where(BillingBudget.provider == b.provider, BillingBudget.scope_external_id == scope,
                                                      BillingBudget.service == (b.service or "*"), BillingBudget.period_start == start))
        if clash is not None:
            return  # a budget entered directly in FinOps already exists for this scope and month; it is left untouched
        row = BillingBudget(provider=b.provider, scope_external_id=scope, service=b.service or "*", period_start=start, approved_by=marker,
                            period_end=end, amount=Decimal(b.current_monthly_usd), currency="USD")
    with db.no_autoflush:
        ths = thresholds(db, b)
    if row not in db:
        db.add(row)
    row.period_end, row.amount, row.currency = end, Decimal(b.current_monthly_usd), "USD"
    row.threshold_info, row.threshold_warning = (ths[0] if ths else 50), (ths[1] if len(ths) > 1 else 75)
    row.threshold_high, row.threshold_exceeded = (ths[2] if len(ths) > 2 else 90), 100


def submit_request(db: Session, *, request_type: str, requester: str, amount_monthly_usd: Decimal, budget: CloudBudget | None,
                   justification: str, **fields) -> BudgetRequest:
    pos = position(db, budget) if budget is not None and budget.status in ("ACTIVE", "APPROVED") else None
    existing = Decimal(budget.current_monthly_usd) if budget is not None and request_type != "new_budget" else None
    req = BudgetRequest(request_key=next_key(db, BudgetRequest, BudgetRequest.request_key, "BRQ"), request_type=request_type,
                        budget_id=budget.id if budget else None, status="PENDING", steps=chain_for(db, request_type, amount_monthly_usd),
                        current_step=0, existing_monthly_usd=existing,
                        actual_mtd_usd=q2(pos["actual_mtd_usd"]) if pos and pos["actual_mtd_usd"] is not None else None,
                        forecast_month_usd=q2(pos["forecast_month_usd"]) if pos and pos["forecast_month_usd"] is not None else None,
                        amount_monthly_usd=q2(amount_monthly_usd),
                        proposed_monthly_usd=(existing + amount_monthly_usd) if existing is not None else q2(amount_monthly_usd),
                        justification=justification, requester=requester, **fields)
    db.add(req)
    db.flush()
    db.add(BudgetApproval(request_id=req.id, step_key="submitted", step_label="Submitted", decision="SUBMITTED", actor=requester,
                          notes=justification[:2000], email_reference=fields.get("email_reference")))
    audit(db, requester, f"request.submit.{request_type}", budget.id if budget else None, req.id, amount_monthly_usd=amount_monthly_usd)
    return req


def next_key(db: Session, model, column, prefix: str) -> str:
    n = (db.scalar(select(func.count()).select_from(model)) or 0) + 1
    while db.scalar(select(model.id).where(column == f"{prefix}-{n:04d}")):
        n += 1
    return f"{prefix}-{n:04d}"


class WorkflowError(ValueError):
    pass


def decide(db: Session, req: BudgetRequest, actor: str, perms: set[str], decision: str, notes: str | None, email_reference: str | None) -> None:
    if req.status not in ("PENDING",):
        raise WorkflowError(f"Request is {req.status.lower().replace('_', ' ')}")
    if actor == req.requester:
        raise WorkflowError("The requester cannot approve their own request (segregation of duties)")
    stepdef = req.steps[req.current_step]
    if stepdef["permission"] not in perms:
        raise WorkflowError(f"{stepdef['label']} requires the permission {stepdef['permission']}")
    prior = db.scalars(select(BudgetApproval).where(BudgetApproval.request_id == req.id, BudgetApproval.decision == "APPROVED")).all()
    if any(a.actor == actor for a in prior):
        raise WorkflowError("You have already approved another step of this request; a different person must approve this step")
    if decision not in ("APPROVED", "REJECTED", "MORE_INFO"):
        raise WorkflowError("decision must be APPROVED, REJECTED or MORE_INFO")
    if decision != "APPROVED" and not (notes or "").strip():
        raise WorkflowError("Notes are required to reject or to ask for more information")
    db.add(BudgetApproval(request_id=req.id, step_key=stepdef["key"], step_label=stepdef["label"], decision=decision, actor=actor,
                          notes=notes, email_reference=email_reference))
    audit(db, actor, f"request.{decision.lower()}", req.budget_id, req.id, step=stepdef["key"])
    if decision == "REJECTED":
        req.status, req.decided_at, req.outcome_note = "REJECTED", datetime.now(UTC), notes
        if req.request_type == "new_budget" and req.budget_id:
            db.get(CloudBudget, req.budget_id).status = "REJECTED"
        return
    if decision == "MORE_INFO":
        req.status = "MORE_INFO"
        return
    req.current_step += 1
    if req.current_step >= len(req.steps):
        _finalize(db, req, actor)


def respond(db: Session, req: BudgetRequest, actor: str, notes: str) -> None:
    if req.status != "MORE_INFO":
        raise WorkflowError("No information was requested")
    if actor != req.requester:
        raise WorkflowError("Only the requester can respond")
    db.add(BudgetApproval(request_id=req.id, step_key=req.steps[req.current_step]["key"], step_label="Information provided",
                          decision="INFO_PROVIDED", actor=actor, notes=notes))
    req.status = "PENDING"
    audit(db, actor, "request.respond", req.budget_id, req.id)


def _finalize(db: Session, req: BudgetRequest, actor: str) -> None:
    req.status, req.decided_at = "APPROVED", datetime.now(UTC)
    approvers = [{"step": a.step_label, "by": a.actor, "at": a.created_at.isoformat() if a.created_at else None}
                 for a in db.scalars(select(BudgetApproval).where(BudgetApproval.request_id == req.id, BudgetApproval.decision == "APPROVED"))]
    b = db.get(CloudBudget, req.budget_id) if req.budget_id else None
    if req.request_type == "new_budget" and b is not None:
        b.status, b.approved_at = "APPROVED", datetime.now(UTC)
        refresh_status(b)
        sync_legacy_budget(db, b)
        req.outcome_note = "Budget approved and recorded in the register."
    elif req.request_type in ("additional_budget", "budget_decrease") or (req.request_type == "new_service" and b is not None and req.amount_monthly_usd):
        if b is None:
            req.outcome_note = "Approved. No budget is linked, so no revision was recorded."
            return
        prev = Decimal(b.current_monthly_usd)
        change = Decimal(req.amount_monthly_usd)
        db.add(BudgetRevision(budget_id=b.id, request_id=req.id, change_monthly_usd=change, change_annual_usd=req.amount_annual_usd,
                              previous_monthly_usd=prev, revised_monthly_usd=prev + change, effective_date=req.effective_date or today(),
                              reason=req.justification, approvers=approvers, email_reference=req.email_reference,
                              evidence=req.supporting_documents or [], recorded_by=actor))
        b.current_monthly_usd = prev + change
        if b.current_annual_usd is not None and req.amount_annual_usd is not None:
            b.current_annual_usd = Decimal(b.current_annual_usd) + Decimal(req.amount_annual_usd)
        b.updated_by = actor
        sync_legacy_budget(db, b)
        audit(db, actor, "budget.revised", b.id, req.id, previous=prev, revised=prev + change)
        req.outcome_note = f"Budget revised from {prev:,.2f} to {prev + change:,.2f} USD per month."
    if req.request_type == "new_service":
        req.outcome_note = ((req.outcome_note or "") + " Approved for provisioning by an authorized administrator; "
                            "LV NEXUS does not provision cloud services.").strip()


# ------------------------------------------------------------------ alerts
def evaluate_alerts(db: Session, on: date | None = None) -> dict:
    """Raise an internal alert the first time a budget crosses each threshold in a month. Never touches cloud resources."""
    from app.services.vuln.notify import notify

    on = on or today()
    start, _ = _month(on)
    raised, checked, no_data = 0, 0, 0
    for b in db.scalars(select(CloudBudget).where(CloudBudget.status.in_(["APPROVED", "ACTIVE"]))):
        refresh_status(b, on)
        sync_legacy_budget(db, b)
        if b.status != "ACTIVE":
            continue
        checked += 1
        pos = position(db, b, on)
        util = pos["utilisation_percent"]
        if util is None:
            no_data += 1
            continue
        crossed = [t for t in thresholds(db, b) if util >= t] + ([EXCEEDED] if util > 100 else [])
        for t in crossed:
            if db.scalar(select(BudgetAlert.id).where(BudgetAlert.budget_id == b.id, BudgetAlert.period_start == start, BudgetAlert.threshold == t)):
                continue
            label = LEVEL_LABEL.get(t, f"{t}% threshold")
            action = ("Review cost drivers with the budget owner; raise an additional budget request if the spend is expected to continue."
                      if t >= 100 else "Review the forecast with the budget owner.")
            alert = BudgetAlert(budget_id=b.id, period_start=start, threshold=t, level=label, approved_usd=Decimal(b.current_monthly_usd),
                                actual_usd=Decimal(str(pos["actual_mtd_usd"])), forecast_usd=q2(pos["forecast_month_usd"]),
                                utilisation_percent=Decimal(str(util)), owner=b.owner, required_action=action, notified=[{"channel": "in_app", "at": datetime.now(UTC).isoformat()}])
            db.add(alert)
            raised += 1
            if t >= 90 and notify(db, "budget_alert", f"{b.budget_key}:{start}:{t}",
                                  f"[LV NEXUS budget] {label}: {b.name} at {util:.1f}%",
                                  f"Budget {b.budget_key} {b.name}: {pos['actual_mtd_usd']:,.2f} of {b.current_monthly_usd:,.2f} USD "
                                  f"({util:.1f}%) month to date. Forecast: {pos['forecast_month_usd'] or 'n/a'}. Owner: {b.owner or 'not set'}. "
                                  "This is a LV NEXUS alert, not a cloud provider alert. No cloud resource has been changed."):
                alert.notified = [*alert.notified, {"channel": "email,google_chat", "at": datetime.now(UTC).isoformat(), "queued": True}]
    return {"budgets_checked": checked, "alerts_raised": raised, "budgets_without_billing_data": no_data}
