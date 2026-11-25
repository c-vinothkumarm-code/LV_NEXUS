"""Cloud Budget Management API: register, revisions, requests with configurable approval chains, alerts and settings.

Nothing here changes a cloud resource. Approving a new-service request records the decision; provisioning is done
separately by an authorized administrator. Budget alerts never stop or modify workloads."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import log_action
from app.api.serializers import iso
from app.core.security import require
from app.database.session import get_db
from app.models import BillingRecord, User
from app.models.budget import (
    BUDGET_STATUSES,
    LEVELS,
    ApprovalWorkflow,
    BudgetAlert,
    BudgetApproval,
    BudgetAuditEvent,
    BudgetRequest,
    BudgetRevision,
    BudgetSetting,
    CloudBudget,
)
from app.models.inventory import SCOPE_MODELS
from app.services.budget import engine as E

router = APIRouter(prefix="/api/v1", tags=["budget management"])
ENVIRONMENTS = ["Production", "UAT", "Development", "POC", "Sandbox"]


def _f(v) -> float | None:
    return None if v is None else float(v)


# ------------------------------------------------------------------ serialisation
def _approval_summary(db: Session, b: CloudBudget) -> dict:
    """Project team / Finance / Internal approval columns of the register, from the budget's new_budget request."""
    req = db.scalar(select(BudgetRequest).where(BudgetRequest.budget_id == b.id, BudgetRequest.request_type == "new_budget")
                    .order_by(BudgetRequest.id.desc()).limit(1))
    if req is None:
        return {"request_id": None, "steps": []}
    decisions = {a.step_key: a for a in db.scalars(select(BudgetApproval).where(BudgetApproval.request_id == req.id).order_by(BudgetApproval.id))}
    steps = []
    for i, s in enumerate(req.steps):
        a = decisions.get(s["key"])
        state = a.decision if a else ("Waiting" if i == req.current_step and req.status == "PENDING" else "Not started")
        steps.append({"key": s["key"], "label": s["label"], "status": state, "by": a.actor if a else None, "at": iso(a.created_at) if a else None})
    return {"request_id": req.id, "request_key": req.request_key, "request_status": req.status, "steps": steps}


def _budget(db: Session, b: CloudBudget, with_position: bool = True) -> dict:
    E.refresh_status(b)
    d = {"id": b.id, "budget_key": b.budget_key, "name": b.name, "level": b.level, "parent_id": b.parent_id, "environment": b.environment,
         "provider": b.provider, "account_name": b.account_name, "scope_external_id": b.scope_external_id, "scopes": b.scopes or [],
         "project_application": b.project_application, "business_entity": b.business_entity, "service": b.service,
         "currency": b.currency, "original_monthly_amount": _f(b.original_monthly_amount), "original_annual_amount": _f(b.original_annual_amount),
         "fx_rate_to_usd": _f(b.fx_rate_to_usd), "fx_rate_date": iso(b.fx_rate_date),
         "original_monthly_usd": _f(b.original_monthly_usd), "original_annual_usd": _f(b.original_annual_usd),
         "approved_monthly_usd": _f(b.current_monthly_usd), "approved_annual_usd": _f(b.current_annual_usd),
         "start_date": iso(b.start_date), "end_date": iso(b.end_date), "email_subject": b.email_subject,
         "native_alert_name": b.native_alert_name, "owner": b.owner, "status": b.status, "thresholds": E.thresholds(db, b),
         "created_by": b.created_by, "created_at": iso(b.created_at), "updated_at": iso(b.updated_at), "approved_at": iso(b.approved_at),
         "approvals": _approval_summary(db, b)}
    if with_position and b.status in ("ACTIVE", "APPROVED", "EXPIRED"):
        d["position"] = E.position(db, b)
    else:
        d["position"] = None
    return d


def _request(r: BudgetRequest) -> dict:
    return {"id": r.id, "request_key": r.request_key, "request_type": r.request_type, "budget_id": r.budget_id, "status": r.status,
            "steps": r.steps, "current_step": r.current_step,
            "current_step_label": r.steps[r.current_step]["label"] if r.status in ("PENDING", "MORE_INFO") and r.current_step < len(r.steps) else None,
            "current_step_permission": r.steps[r.current_step]["permission"] if r.status == "PENDING" and r.current_step < len(r.steps) else None,
            "existing_monthly_usd": _f(r.existing_monthly_usd), "actual_mtd_usd": _f(r.actual_mtd_usd), "forecast_month_usd": _f(r.forecast_month_usd),
            "amount_monthly_usd": _f(r.amount_monthly_usd), "amount_annual_usd": _f(r.amount_annual_usd), "proposed_monthly_usd": _f(r.proposed_monthly_usd),
            "justification": r.justification, "project_service": r.project_service, "requesting_team": r.requesting_team, "requester": r.requester,
            "effective_date": iso(r.effective_date), "email_subject": r.email_subject, "email_reference": r.email_reference,
            "supporting_documents": r.supporting_documents, "service_details": r.service_details, "outcome_note": r.outcome_note,
            "decided_at": iso(r.decided_at), "created_at": iso(r.created_at)}


def _get_budget(db: Session, budget_id: int) -> CloudBudget:
    b = db.get(CloudBudget, budget_id)
    if b is None:
        raise HTTPException(404, "Budget not found")
    return b


# ------------------------------------------------------------------ register
class BudgetBody(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    level: str = "account"
    parent_id: int | None = None
    environment: str | None = None
    provider: str | None = None
    account_name: str | None = Field(default=None, max_length=255)
    scope_external_id: str | None = Field(default=None, max_length=128)
    scopes: list[dict] = []
    project_application: str | None = Field(default=None, max_length=255)
    business_entity: str | None = Field(default=None, max_length=255)
    service: str | None = Field(default=None, max_length=255)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    monthly_amount: Decimal = Field(gt=0)
    annual_amount: Decimal | None = Field(default=None, gt=0)
    fx_rate_to_usd: Decimal | None = Field(default=None, gt=0)
    fx_rate_date: date | None = None
    start_date: date
    end_date: date
    email_subject: str | None = Field(default=None, max_length=512)
    native_alert_name: str | None = Field(default=None, max_length=255)
    owner: str | None = Field(default=None, max_length=255)
    thresholds: list[int] | None = None

    @field_validator("currency")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()


def _apply(db: Session, b: CloudBudget, body: BudgetBody) -> None:
    if body.level not in LEVELS:
        raise HTTPException(422, f"level must be one of {', '.join(LEVELS)}")
    if body.end_date < body.start_date:
        raise HTTPException(422, "The end date must be after the start date")
    if body.environment and body.environment not in ENVIRONMENTS:
        raise HTTPException(422, f"environment must be one of {', '.join(ENVIRONMENTS)}")
    if body.provider and body.provider not in SCOPE_MODELS:
        raise HTTPException(422, "provider must be aws, azure or gcp")
    if body.level == "account":
        model = SCOPE_MODELS.get(body.provider or "")
        if model is None or not body.scope_external_id or not db.scalar(select(model.id).where(model.external_id == body.scope_external_id)):
            raise HTTPException(422, "An account-level budget needs a provider and an account / subscription / project from the discovered inventory")
    if body.currency != "USD" and not body.fx_rate_to_usd:
        raise HTTPException(422, "A non-USD budget needs the exchange rate to USD used for the approval (and its date)")
    if body.parent_id is not None:
        parent = db.get(CloudBudget, body.parent_id)
        if parent is None or parent.id == b.id:
            raise HTTPException(422, "Unknown parent budget")
    rate = Decimal(1) if body.currency == "USD" else Decimal(body.fx_rate_to_usd)
    for k in ("name", "level", "parent_id", "environment", "provider", "account_name", "scope_external_id", "scopes", "project_application",
              "business_entity", "service", "currency", "email_subject", "native_alert_name", "owner", "thresholds", "start_date", "end_date", "fx_rate_date"):
        setattr(b, k, getattr(body, k))
    b.original_monthly_amount, b.original_annual_amount = body.monthly_amount, body.annual_amount
    b.fx_rate_to_usd = rate
    b.original_monthly_usd = E.q2(body.monthly_amount * rate)
    b.original_annual_usd = E.q2(body.annual_amount * rate) if body.annual_amount else E.q2(body.monthly_amount * rate * 12)
    b.current_monthly_usd, b.current_annual_usd = b.original_monthly_usd, b.original_annual_usd
    if b.scope_external_id and not b.account_name:
        s = db.scalar(select(SCOPE_MODELS[b.provider]).where(SCOPE_MODELS[b.provider].external_id == b.scope_external_id))
        b.account_name = s.name if s else None


@router.get("/budgets")
def list_budgets(status: str | None = None, provider: str | None = None, environment: str | None = None, level: str | None = None,
                 q: str | None = None, db: Session = Depends(get_db), _: User = Depends(require("budget:read"))):
    stmt = select(CloudBudget)
    for col, val in ((CloudBudget.status, status), (CloudBudget.provider, provider), (CloudBudget.environment, environment), (CloudBudget.level, level)):
        if val:
            stmt = stmt.where(col == val)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(CloudBudget.name.ilike(like), CloudBudget.budget_key.ilike(like), CloudBudget.scope_external_id.ilike(like),
                              CloudBudget.project_application.ilike(like), CloudBudget.account_name.ilike(like)))
    rows = list(db.scalars(stmt.order_by(CloudBudget.budget_key)))
    out = [_budget(db, b) for b in rows]
    db.commit()  # status refresh (APPROVED -> ACTIVE -> EXPIRED)
    return {"items": out, "statuses": list(BUDGET_STATUSES), "levels": list(LEVELS), "environments": ENVIRONMENTS}


@router.get("/budgets/summary")
def budget_summary(db: Session = Depends(get_db), _: User = Depends(require("budget:read"))):
    """Consolidated figures count root budgets only, so an allocation is never added on top of its parent."""
    all_b = list(db.scalars(select(CloudBudget)))
    for b in all_b:
        E.refresh_status(b)
    active = [b for b in all_b if b.status == "ACTIVE"]
    roots = [b for b in active if b.parent_id is None]
    positions = {b.id: E.position(db, b) for b in active}
    with_data = [b for b in roots if positions[b.id]["actual_mtd_usd"] is not None]
    actual = sum(Decimal(str(positions[b.id]["actual_mtd_usd"])) for b in with_data) if with_data else None
    forecast_known = [b for b in roots if positions[b.id]["forecast_month_usd"] is not None]
    approved = sum(Decimal(b.current_monthly_usd) for b in roots)
    over = [b for b in active if (positions[b.id]["utilisation_percent"] or 0) > 100]
    near = [b for b in active if 75 <= (positions[b.id]["utilisation_percent"] or 0) <= 100]
    pending = list(db.scalars(select(BudgetRequest).where(BudgetRequest.status.in_(["PENDING", "MORE_INFO"]))))
    db.commit()
    return {"approved_monthly_usd": float(approved), "approved_annual_usd": float(sum(Decimal(b.current_annual_usd or 0) for b in roots)),
            "actual_mtd_usd": _f(actual), "actual_covers_budgets": len(with_data), "root_budgets": len(roots),
            "remaining_usd": _f(approved - actual) if actual is not None else None,
            "utilisation_percent": _f(E.q2(actual / approved * 100)) if actual is not None and approved else None,
            "forecast_month_usd": _f(sum(Decimal(str(positions[b.id]["forecast_month_usd"])) for b in forecast_known)) if forecast_known else None,
            "forecast_covers_budgets": len(forecast_known),
            "over_budget": [{"id": b.id, "budget_key": b.budget_key, "name": b.name, "utilisation_percent": positions[b.id]["utilisation_percent"]} for b in over],
            "approaching": [{"id": b.id, "budget_key": b.budget_key, "name": b.name, "utilisation_percent": positions[b.id]["utilisation_percent"]} for b in near],
            "pending_requests": len(pending),
            "awaiting_finance": sum(1 for r in pending if r.status == "PENDING" and r.steps[r.current_step]["permission"] == "budget:approve"),
            "expired": sum(1 for b in all_b if b.status == "EXPIRED"), "draft": sum(1 for b in all_b if b.status == "DRAFT"),
            "by_status": {s: sum(1 for b in all_b if b.status == s) for s in BUDGET_STATUSES},
            "open_alerts": db.scalar(select(func.count()).select_from(BudgetAlert).where(BudgetAlert.acknowledged_at.is_(None))) or 0,
            "billing_last_collected": iso(db.scalar(select(func.max(BillingRecord.collected_at)))),
            "note": "Consolidated totals count top-level budgets only; allocations are part of their parent budget. Actual is month to date "
                    "and includes provisional (not yet final) billing; forecast is a run-rate estimate."}


@router.post("/budgets", status_code=201)
def create_budget(body: BudgetBody, db: Session = Depends(get_db), user: User = Depends(require("budget:manage"))):
    b = CloudBudget(budget_key=E.next_key(db, CloudBudget, CloudBudget.budget_key, "BUD"), status="DRAFT", created_by=user.email, updated_by=user.email,
                    name=body.name, level=body.level, start_date=body.start_date, end_date=body.end_date)
    _apply(db, b, body)
    db.add(b)
    db.flush()
    E.audit(db, user.email, "budget.create", b.id, original_monthly_usd=b.original_monthly_usd)
    log_action(db, user.email, "budget.create", b.budget_key)
    db.commit()
    return _budget(db, b)


@router.put("/budgets/{budget_id}")
def update_budget(budget_id: int, body: BudgetBody, db: Session = Depends(get_db), user: User = Depends(require("budget:manage"))):
    b = _get_budget(db, budget_id)
    if b.status not in ("DRAFT", "REJECTED"):
        raise HTTPException(409, "An approved budget cannot be edited. Raise an additional budget or decrease request to change the amount.")
    _apply(db, b, body)
    b.status, b.updated_by = "DRAFT", user.email
    E.audit(db, user.email, "budget.update", b.id)
    db.commit()
    return _budget(db, b)


@router.post("/budgets/{budget_id}/submit")
def submit_budget(budget_id: int, db: Session = Depends(get_db), user: User = Depends(require("budget:manage"))):
    b = _get_budget(db, budget_id)
    if b.status not in ("DRAFT", "REJECTED"):
        raise HTTPException(409, f"Budget is {b.status.lower()}")
    E.submit_request(db, request_type="new_budget", requester=user.email, amount_monthly_usd=Decimal(b.original_monthly_usd), budget=b,
                     justification=f"Approval of budget {b.budget_key} {b.name}", email_subject=b.email_subject,
                     amount_annual_usd=b.original_annual_usd, effective_date=b.start_date)
    b.status = "PENDING"
    db.commit()
    return _budget(db, b)


@router.get("/budgets/{budget_id}")
def get_budget(budget_id: int, db: Session = Depends(get_db), _: User = Depends(require("budget:read"))):
    b = _get_budget(db, budget_id)
    revs = db.scalars(select(BudgetRevision).where(BudgetRevision.budget_id == b.id).order_by(BudgetRevision.id))
    reqs = db.scalars(select(BudgetRequest).where(BudgetRequest.budget_id == b.id).order_by(BudgetRequest.id.desc()))
    alerts = db.scalars(select(BudgetAlert).where(BudgetAlert.budget_id == b.id).order_by(BudgetAlert.id.desc()).limit(100))
    events = db.scalars(select(BudgetAuditEvent).where(BudgetAuditEvent.budget_id == b.id).order_by(BudgetAuditEvent.id.desc()).limit(200))
    children = db.scalars(select(CloudBudget).where(CloudBudget.parent_id == b.id))
    today = E.today()
    months = []
    m = today.replace(day=1)
    for _ in range(6):
        end = (m.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        actual, prov = E.spend(db, b, m, min(end, today))
        months.append({"month": m.isoformat()[:7], "actual_usd": _f(actual), "provisional": prov})
        m = (m - timedelta(days=1)).replace(day=1)
    out = {**_budget(db, b),
           "revisions": [{"id": r.id, "change_monthly_usd": _f(r.change_monthly_usd), "previous_monthly_usd": _f(r.previous_monthly_usd),
                          "revised_monthly_usd": _f(r.revised_monthly_usd), "effective_date": iso(r.effective_date), "reason": r.reason,
                          "approvers": r.approvers, "email_reference": r.email_reference, "recorded_by": r.recorded_by,
                          "request_id": r.request_id, "created_at": iso(r.created_at)} for r in revs],
           "requests": [_request(r) for r in reqs], "alerts": [_alert(a, b) for a in alerts],
           "allocations": [{"id": c.id, "budget_key": c.budget_key, "name": c.name, "approved_monthly_usd": _f(c.current_monthly_usd), "status": c.status}
                           for c in children],
           "history": [{"action": e.action, "actor": e.actor, "detail": e.detail, "at": iso(e.created_at)} for e in events],
           "monthly_actuals": list(reversed(months))}
    db.commit()
    return out


# ------------------------------------------------------------------ requests and approvals
class RequestBody(BaseModel):
    request_type: str
    budget_id: int | None = None
    amount_monthly_usd: Decimal
    amount_annual_usd: Decimal | None = None
    justification: str = Field(min_length=10)
    project_service: str | None = Field(default=None, max_length=255)
    requesting_team: str | None = Field(default=None, max_length=255)
    effective_date: date | None = None
    email_subject: str | None = Field(default=None, max_length=512)
    email_reference: str | None = Field(default=None, max_length=512)
    supporting_documents: list[str] = []
    service_details: dict | None = None


class DecisionBody(BaseModel):
    decision: str
    notes: str | None = Field(default=None, max_length=4000)
    email_reference: str | None = Field(default=None, max_length=512)


@router.post("/budget-requests", status_code=201)
def create_request(body: RequestBody, db: Session = Depends(get_db), user: User = Depends(require("budget:manage"))):
    if body.request_type not in ("additional_budget", "budget_decrease", "new_service"):
        raise HTTPException(422, "request_type must be additional_budget, budget_decrease or new_service (new budgets are submitted from the register)")
    b = _get_budget(db, body.budget_id) if body.budget_id else None
    if body.request_type in ("additional_budget", "budget_decrease"):
        if b is None or b.status not in ("ACTIVE", "APPROVED"):
            raise HTTPException(422, "Additional budget and decreases apply to an approved, active budget")
        if (body.request_type == "additional_budget") != (body.amount_monthly_usd > 0):
            raise HTTPException(422, "An additional budget is a positive amount; a decrease is a negative amount")
        if body.request_type == "budget_decrease" and Decimal(b.current_monthly_usd) + body.amount_monthly_usd < 0:
            raise HTTPException(422, "A decrease cannot take the budget below zero")
    if body.request_type == "new_service":
        need = {"business_purpose", "provider", "service", "estimated_monthly_cost_usd"}
        missing = need - set((body.service_details or {}).keys())
        if missing:
            raise HTTPException(422, f"service_details needs: {', '.join(sorted(missing))}")
        if body.amount_monthly_usd < 0:
            raise HTTPException(422, "The additional budget for a new service cannot be negative")
    fields = body.model_dump(exclude={"request_type", "budget_id", "amount_monthly_usd", "justification"})
    req = E.submit_request(db, request_type=body.request_type, requester=user.email, amount_monthly_usd=body.amount_monthly_usd, budget=b,
                           justification=body.justification, **fields)
    log_action(db, user.email, f"budget_request.{body.request_type}", req.request_key)
    db.commit()
    return _request(req)


@router.get("/budget-requests")
def list_requests(status: str | None = None, request_type: str | None = None, awaiting_me: bool = False,
                  db: Session = Depends(get_db), user: User = Depends(require("budget:read"))):
    stmt = select(BudgetRequest)
    if status:
        stmt = stmt.where(BudgetRequest.status == status)
    if request_type:
        stmt = stmt.where(BudgetRequest.request_type == request_type)
    rows = list(db.scalars(stmt.order_by(BudgetRequest.id.desc()).limit(500)))
    if awaiting_me:
        done = {r for (r,) in db.execute(select(BudgetApproval.request_id).where(BudgetApproval.actor == user.email, BudgetApproval.decision == "APPROVED"))}
        rows = [r for r in rows if r.status == "PENDING" and r.requester != user.email and r.id not in done
                and r.steps[r.current_step]["permission"] in user.permission_names]
    names = {b.id: (b.budget_key, b.name) for b in db.scalars(select(CloudBudget))}
    return {"items": [{**_request(r), "budget": names.get(r.budget_id)} for r in rows]}


@router.get("/budget-requests/{request_id}")
def get_request(request_id: int, db: Session = Depends(get_db), _: User = Depends(require("budget:read"))):
    r = db.get(BudgetRequest, request_id)
    if r is None:
        raise HTTPException(404, "Request not found")
    hist = db.scalars(select(BudgetApproval).where(BudgetApproval.request_id == r.id).order_by(BudgetApproval.id))
    b = db.get(CloudBudget, r.budget_id) if r.budget_id else None
    return {**_request(r), "budget": None if b is None else {"id": b.id, "budget_key": b.budget_key, "name": b.name},
            "history": [{"step": h.step_label, "decision": h.decision, "actor": h.actor, "notes": h.notes, "email_reference": h.email_reference,
                         "at": iso(h.created_at)} for h in hist]}


def _get_request(db: Session, request_id: int) -> BudgetRequest:
    r = db.get(BudgetRequest, request_id)
    if r is None:
        raise HTTPException(404, "Request not found")
    return r


@router.post("/budget-requests/{request_id}/decision")
def decide(request_id: int, body: DecisionBody, db: Session = Depends(get_db), user: User = Depends(require("budget:read"))):
    """The step's own permission is checked inside (project team, Finance, internal governance or final approver)."""
    r = _get_request(db, request_id)
    try:
        E.decide(db, r, user.email, user.permission_names, body.decision, body.notes, body.email_reference)
    except E.WorkflowError as exc:
        raise HTTPException(403 if "permission" in str(exc) or "segregation" in str(exc) or "different person" in str(exc) else 409, str(exc)) from exc
    log_action(db, user.email, f"budget_request.{body.decision.lower()}", r.request_key)
    db.commit()
    return _request(r)


@router.post("/budget-requests/{request_id}/respond")
def respond(request_id: int, body: DecisionBody, db: Session = Depends(get_db), user: User = Depends(require("budget:manage"))):
    r = _get_request(db, request_id)
    if not (body.notes or "").strip():
        raise HTTPException(422, "Provide the requested information")
    try:
        E.respond(db, r, user.email, body.notes)
    except E.WorkflowError as exc:
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    return _request(r)


@router.post("/budget-requests/{request_id}/withdraw")
def withdraw(request_id: int, db: Session = Depends(get_db), user: User = Depends(require("budget:manage"))):
    r = _get_request(db, request_id)
    if r.requester != user.email:
        raise HTTPException(403, "Only the requester can withdraw a request")
    if r.status not in ("PENDING", "MORE_INFO"):
        raise HTTPException(409, f"Request is {r.status.lower()}")
    r.status, r.decided_at = "WITHDRAWN", datetime.now(UTC)
    db.add(BudgetApproval(request_id=r.id, step_key="withdrawn", step_label="Withdrawn", decision="WITHDRAWN", actor=user.email))
    if r.request_type == "new_budget" and r.budget_id:
        db.get(CloudBudget, r.budget_id).status = "DRAFT"
    E.audit(db, user.email, "request.withdraw", r.budget_id, r.id)
    db.commit()
    return _request(r)


# ------------------------------------------------------------------ alerts
def _alert(a: BudgetAlert, b: CloudBudget | None) -> dict:
    return {"id": a.id, "budget_id": a.budget_id, "budget_key": b.budget_key if b else None, "budget_name": b.name if b else None,
            "scope": (f"{b.provider or 'all'}:{b.scope_external_id}" if b and b.scope_external_id else (b.level if b else None)),
            "period_start": iso(a.period_start), "threshold": a.threshold, "level": a.level, "approved_usd": _f(a.approved_usd),
            "actual_usd": _f(a.actual_usd), "forecast_usd": _f(a.forecast_usd), "remaining_usd": _f(Decimal(a.approved_usd) - Decimal(a.actual_usd)),
            "utilisation_percent": _f(a.utilisation_percent), "owner": a.owner, "required_action": a.required_action, "source": a.source,
            "native_alert_name": b.native_alert_name if b else None, "notified": a.notified, "acknowledged_by": a.acknowledged_by,
            "acknowledged_at": iso(a.acknowledged_at), "created_at": iso(a.created_at)}


@router.get("/budget-alerts")
def list_alerts(open_only: bool = False, db: Session = Depends(get_db), _: User = Depends(require("budget:read"))):
    stmt = select(BudgetAlert)
    if open_only:
        stmt = stmt.where(BudgetAlert.acknowledged_at.is_(None))
    budgets = {b.id: b for b in db.scalars(select(CloudBudget))}
    return {"items": [_alert(a, budgets.get(a.budget_id)) for a in db.scalars(stmt.order_by(BudgetAlert.id.desc()).limit(500))]}


@router.post("/budget-alerts/{alert_id}/acknowledge")
def acknowledge(alert_id: int, db: Session = Depends(get_db), user: User = Depends(require("budget:manage"))):
    a = db.get(BudgetAlert, alert_id)
    if a is None:
        raise HTTPException(404, "Alert not found")
    if a.acknowledged_at is None:
        a.acknowledged_by, a.acknowledged_at = user.email, datetime.now(UTC)
        E.audit(db, user.email, "alert.acknowledge", a.budget_id, threshold=a.threshold)
        db.commit()
    return _alert(a, db.get(CloudBudget, a.budget_id))


@router.post("/budget-alerts/evaluate")
def evaluate_now(db: Session = Depends(get_db), user: User = Depends(require("budget:configure"))):
    summary = E.evaluate_alerts(db)
    log_action(db, user.email, "budget.alerts_evaluated", None, summary)
    db.commit()
    return summary


# ------------------------------------------------------------------ settings
class ThresholdBody(BaseModel):
    thresholds: list[int] = Field(min_length=1, max_length=8)


class WorkflowBody(BaseModel):
    request_type: str
    min_amount_usd: Decimal = Field(default=Decimal(0), ge=0)
    steps: list[dict] = Field(min_length=1, max_length=8)
    enabled: bool = True


@router.get("/budget-settings")
def get_settings_(db: Session = Depends(get_db), _: User = Depends(require("budget:read"))):
    return {"thresholds": E.thresholds(db), "workflows": [
        {"id": w.id, "request_type": w.request_type, "min_amount_usd": _f(w.min_amount_usd), "steps": w.steps, "enabled": w.enabled,
         "updated_by": w.updated_by, "updated_at": iso(w.updated_at)}
        for w in db.scalars(select(ApprovalWorkflow).order_by(ApprovalWorkflow.request_type, ApprovalWorkflow.min_amount_usd))],
        "step_catalogue": [{"key": k, "label": v[0], "permission": v[1]} for k, v in E.STEP.items()], "request_types": list(E.REQUEST_TYPES)}


@router.put("/budget-settings/thresholds")
def set_thresholds(body: ThresholdBody, db: Session = Depends(get_db), user: User = Depends(require("budget:configure"))):
    ths = sorted(set(body.thresholds))
    if any(t < 1 or t > 100 for t in ths):
        raise HTTPException(422, "Thresholds are percentages from 1 to 100 (above 100% is always 'Budget exceeded')")
    row = db.scalar(select(BudgetSetting).where(BudgetSetting.key == "thresholds"))
    old = row.value if row else None
    if row is None:
        row = BudgetSetting(key="thresholds", value=ths)
        db.add(row)
    row.value, row.updated_by = ths, user.email
    E.audit(db, user.email, "settings.thresholds", previous=old, new=ths)
    db.commit()
    return {"thresholds": ths}


@router.put("/budget-settings/workflows")
def set_workflow(body: WorkflowBody, db: Session = Depends(get_db), user: User = Depends(require("budget:configure"))):
    if body.request_type not in E.REQUEST_TYPES:
        raise HTTPException(422, f"request_type must be one of {', '.join(E.REQUEST_TYPES)}")
    steps = []
    for s in body.steps:
        key = str(s.get("key", "")).strip()
        if key not in E.STEP:
            raise HTTPException(422, f"Unknown step {key!r}; use one of {', '.join(E.STEP)}")
        steps.append(E.step(key, s.get("label")))
    if len({s['key'] for s in steps}) != len(steps):
        raise HTTPException(422, "A step can appear only once in a chain")
    w = db.scalar(select(ApprovalWorkflow).where(ApprovalWorkflow.request_type == body.request_type, ApprovalWorkflow.min_amount_usd == body.min_amount_usd))
    old = w.steps if w else None
    if w is None:
        w = ApprovalWorkflow(request_type=body.request_type, min_amount_usd=body.min_amount_usd, steps=steps)
        db.add(w)
    w.steps, w.enabled, w.updated_by = steps, body.enabled, user.email
    E.audit(db, user.email, "settings.workflow", request_type=body.request_type, min_amount_usd=body.min_amount_usd, previous=old, new=steps)
    db.commit()
    return {"request_type": w.request_type, "min_amount_usd": _f(w.min_amount_usd), "steps": w.steps, "enabled": w.enabled}

