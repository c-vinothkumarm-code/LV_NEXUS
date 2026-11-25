"""Cloud connection registry, identity governance (lifecycle, effective access, privileged access, change trail,
exceptions, revocation plans), cost analysis, structured AI analysis, central audit trail and management decisions."""
from __future__ import annotations

import calendar
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import access_workflows, log_action, require_any
from app.core.config import Settings, get_settings
from app.core.security import require
from app.database.session import get_db
from app.models import SCOPE_MODELS, BillingForecast, BillingRecord, CloudBudget, User
from app.models.access import AccessAssignment, CloudIdentity
from app.models.iam import (
    AccessRevocationItem,
    AccessRevocationPlan,
    IamCredential,
    IamEffectiveAccess,
    IamException,
    IdentityChangeEvent,
    IdentityGroupMember,
)
from app.models.platform import AIAnalysisResult, AuditTrail, CostDetailRecord, ManagementDecision, ProviderBudget
from app.services import trail
from app.services.access import lifecycle as lc

router = APIRouter(prefix="/api/v1", tags=["platform"])


def _aware(dt):
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _f(v):
    return float(v) if isinstance(v, Decimal) else v


# ================================================================== connections
@router.get("/connections/registry")
def connection_registry(provider: str | None = None, db: Session = Depends(get_db),
                        _: User = Depends(require_any("sync:read", "onboarding:read", "inventory:read"))):
    from app.services.connections_health import registry
    return registry(db, provider)


# ================================================================== identities
def _ident(i: CloudIdentity, counts: dict | None = None) -> dict:
    c = (counts or {}).get((i.provider, i.principal_id), {})
    return {"id": i.id, "provider": i.provider, "principal_id": i.principal_id, "type": i.principal_type, "name": i.display_name,
            "sign_in_name": i.sign_in_name, "user_type": i.user_type, "enabled": i.enabled, "lifecycle": i.lifecycle_status,
            "is_new": lc.is_new(i), "first_seen_at": i.first_seen_at, "provider_created_at": i.provider_created_at,
            "last_sign_in_at": i.last_sign_in_at, "missing_since": i.missing_since, "status_changed_at": i.status_changed_at,
            "directory": i.directory_scope, "shared": i.shared, "last_seen_at": i.last_seen_at,
            "assignments": c.get("n", 0), "privileged": c.get("p", 0), "scopes": sorted(c.get("s", set()))[:20],
            "attributes": {k: v for k, v in (i.attributes or {}).items() if k != "baseline"}}


def _counts(db: Session) -> dict:
    out: dict = defaultdict(lambda: {"n": 0, "p": 0, "s": set()})
    for e in db.scalars(select(IamEffectiveAccess)):
        c = out[(e.provider, e.principal_id)]
        c["n"] += 1
        c["p"] += int(e.privileged)
        c["s"].add(e.scope_external_id)
    return out


@router.get("/iam/identities")
def identities(provider: str | None = None, lifecycle: str | None = None, type: str | None = None, new: bool = False,
               privileged: bool = False, q: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(100, ge=1, le=500),
               db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    stmt = select(CloudIdentity)
    if provider:
        stmt = stmt.where(CloudIdentity.provider == provider)
    if lifecycle:
        stmt = stmt.where(CloudIdentity.lifecycle_status.in_(lifecycle.split(",")))
    if type:
        stmt = stmt.where(CloudIdentity.principal_type.in_(type.split(",")))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(CloudIdentity.display_name.ilike(like), CloudIdentity.sign_in_name.ilike(like), CloudIdentity.principal_id.ilike(like)))
    counts = _counts(db)
    rows = [_ident(i, counts) for i in db.scalars(stmt.order_by(CloudIdentity.first_seen_at.desc(), CloudIdentity.id.desc()))]
    if new:
        rows = [r for r in rows if r["is_new"]]
    if privileged:
        rows = [r for r in rows if r["privileged"]]
    summary = defaultdict(int)
    for r in rows:
        summary[r["lifecycle"]] += 1
    return {"total": len(rows), "summary": dict(summary), "items": rows[(page - 1) * page_size: page * page_size]}


@router.get("/iam/identities/{iid}")
def identity_detail(iid: int, db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    i = db.get(CloudIdentity, iid)
    if i is None:
        raise HTTPException(404, "Identity not found")
    eff = lc.effective_for(db, i.provider, i.principal_id)
    groups = list(db.scalars(select(IdentityGroupMember).where(IdentityGroupMember.provider == i.provider, IdentityGroupMember.member_id == i.principal_id)))
    creds = list(db.scalars(select(IamCredential).where(IamCredential.provider == i.provider, IamCredential.principal_id == i.principal_id)))
    changes = list(db.scalars(select(IdentityChangeEvent).where(IdentityChangeEvent.provider == i.provider, IdentityChangeEvent.principal_id == i.principal_id)
                              .order_by(IdentityChangeEvent.id.desc()).limit(100)))
    plans = list(db.scalars(select(AccessRevocationPlan).where(AccessRevocationPlan.provider == i.provider, AccessRevocationPlan.principal_id == i.principal_id)
                            .order_by(AccessRevocationPlan.id.desc())))
    return {"identity": _ident(i, _counts(db)), "effective_access": [_eff(e) for e in eff],
            "groups": [{"group": g.group_name or g.group_id, "since": g.first_seen_at, "removed_at": g.removed_at} for g in groups],
            "credentials": [_cred(c) for c in creds], "changes": [_chg(c) for c in changes], "revocation_plans": [_plan(p) for p in plans]}


def _eff(e: IamEffectiveAccess) -> dict:
    return {"assignment_id": e.assignment_id, "scope": e.scope_external_id, "scope_level": e.scope_level, "scope_path": e.scope_path,
            "role": e.role_name, "privileged": e.privileged, "via": e.via, "via_group": e.via_group, "inherited_from": e.inherited_from}


def _cred(c: IamCredential) -> dict:
    age = (datetime.now(UTC) - _aware(c.created_at_provider)).days if c.created_at_provider else None
    return {"id": c.id, "credential_id": c.credential_id, "kind": c.kind, "status": c.status, "created": c.created_at_provider, "expires": c.expires_at,
            "last_used": c.last_used_at, "age_days": age, "removed_at": c.removed_at, "scope": c.scope_external_id}


def _chg(c: IdentityChangeEvent) -> dict:
    return {"id": c.id, "provider": c.provider, "scope": c.scope_external_id, "principal_id": c.principal_id, "principal": c.principal_name,
            "type": c.principal_type, "change": c.change_type, "privileged": c.privileged, "previous": c.previous_state, "new": c.new_state,
            "approval_reference": c.approval_reference, "source_event_id": c.source_event_id, "initiated_by": c.initiated_by, "at": c.detected_at}


@router.get("/iam/effective")
def effective(provider: str | None = None, principal: str | None = None, scope: str | None = None, privileged: bool = False,
              via: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(200, ge=1, le=1000),
              db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    stmt = select(IamEffectiveAccess)
    if provider:
        stmt = stmt.where(IamEffectiveAccess.provider == provider)
    if principal:
        stmt = stmt.where(IamEffectiveAccess.principal_id == principal)
    if scope:
        stmt = stmt.where(IamEffectiveAccess.scope_external_id == scope)
    if privileged:
        stmt = stmt.where(IamEffectiveAccess.privileged.is_(True))
    if via:
        stmt = stmt.where(IamEffectiveAccess.via == via)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = list(db.scalars(stmt.order_by(IamEffectiveAccess.id).offset((page - 1) * page_size).limit(page_size)))
    idents = {(i.provider, i.principal_id): i for i in db.scalars(select(CloudIdentity).where(
        CloudIdentity.principal_id.in_([r.principal_id for r in rows] or ["-"])))}
    return {"total": total, "items": [{**_eff(r), "provider": r.provider, "principal_id": r.principal_id, "principal_type": r.principal_type,
                                       "principal": (lambda i: (i.sign_in_name or i.display_name) if i else None)(idents.get((r.provider, r.principal_id))),
                                       "lifecycle": (lambda i: i.lifecycle_status if i else None)(idents.get((r.provider, r.principal_id)))} for r in rows]}


@router.get("/iam/privileged")
def privileged_access(provider: str | None = None, db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    from app.services.access.engine import assignment_status
    st = assignment_status(db)
    stmt = select(IamEffectiveAccess).where(IamEffectiveAccess.privileged.is_(True))
    if provider:
        stmt = stmt.where(IamEffectiveAccess.provider == provider)
    idents = {(i.provider, i.principal_id): i for i in db.scalars(select(CloudIdentity))}
    out = []
    for e in db.scalars(stmt):
        i = idents.get((e.provider, e.principal_id))
        s = st.get(e.assignment_id, {})
        out.append({**_eff(e), "provider": e.provider, "principal_id": e.principal_id, "principal_type": e.principal_type,
                    "principal": (i.sign_in_name or i.display_name) if i else None, "lifecycle": i.lifecycle_status if i else None,
                    "last_sign_in_at": i.last_sign_in_at if i else None, "approval": s.get("status"),
                    "grant": s["grant"].grant_key if s.get("grant") else None,
                    "pim": (db.get(AccessAssignment, e.assignment_id).pim_state if db.get(AccessAssignment, e.assignment_id) else None)})
    by = defaultdict(int)
    for r in out:
        by[r["approval"] or "unknown"] += 1
    return {"total": len(out), "by_approval": dict(by), "items": out}


@router.get("/iam/changes")
def changes(provider: str | None = None, change: str | None = None, privileged: bool = False, days: int = Query(30, ge=1, le=365),
            principal: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(200, ge=1, le=1000),
            db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    stmt = select(IdentityChangeEvent).where(IdentityChangeEvent.detected_at >= datetime.now(UTC) - timedelta(days=days))
    if provider:
        stmt = stmt.where(IdentityChangeEvent.provider == provider)
    if change:
        stmt = stmt.where(IdentityChangeEvent.change_type.in_(change.split(",")))
    if privileged:
        stmt = stmt.where(IdentityChangeEvent.privileged.is_(True))
    if principal:
        stmt = stmt.where(or_(IdentityChangeEvent.principal_id.ilike(f"%{principal}%"), IdentityChangeEvent.principal_name.ilike(f"%{principal}%")))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    counts = dict(db.execute(select(IdentityChangeEvent.change_type, func.count()).where(
        IdentityChangeEvent.detected_at >= datetime.now(UTC) - timedelta(days=days)).group_by(IdentityChangeEvent.change_type)).all())
    rows = db.scalars(stmt.order_by(IdentityChangeEvent.id.desc()).offset((page - 1) * page_size).limit(page_size))
    return {"total": total, "by_type": counts, "items": [_chg(c) for c in rows]}


@router.post("/iam/identities/{iid}/shared", dependencies=[Depends(access_workflows)])
def mark_shared(iid: int, shared: bool = True, db: Session = Depends(get_db), user: User = Depends(require("access:manage"))):
    i = db.get(CloudIdentity, iid)
    if i is None:
        raise HTTPException(404, "Identity not found")
    prev = i.shared
    i.shared = shared
    log_action(db, user.email, "access.identity_shared", i.principal_id, {"previous": prev, "shared": shared})
    db.commit()
    return {"shared": i.shared}


# ------------------------------------------------------------------ exceptions
def _exc(e: IamException) -> dict:
    return {"id": e.id, "key": e.exception_key, "category": e.category, "provider": e.provider, "principal_id": e.principal_id,
            "principal": e.principal_name, "scope": e.scope_path, "expected": e.expected, "actual": e.actual, "risk": e.risk, "owner": e.owner,
            "status": e.status, "evidence": e.evidence, "notes": e.resolution_notes, "resolved_by": e.resolved_by,
            "last_detected_at": e.last_detected_at, "cleared_at": e.cleared_at, "created_at": e.created_at}


@router.get("/iam/exceptions")
def exceptions(category: str | None = None, status: str | None = "OPEN,IN_PROGRESS", provider: str | None = None,
               db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    stmt = select(IamException)
    if category:
        stmt = stmt.where(IamException.category.in_(category.split(",")))
    if status:
        stmt = stmt.where(IamException.status.in_(status.split(",")))
    if provider:
        stmt = stmt.where(IamException.provider == provider)
    rows = list(db.scalars(stmt.order_by(IamException.id.desc()).limit(2000)))
    by = dict(db.execute(select(IamException.category, func.count()).where(IamException.status.in_(["OPEN", "IN_PROGRESS"]))
                         .group_by(IamException.category)).all())
    return {"total": len(rows), "by_category": by, "items": [_exc(e) for e in rows]}


class ExceptionUpdate(BaseModel):
    owner: str | None = Field(default=None, max_length=255)
    status: str | None = None
    notes: str | None = Field(default=None, max_length=4000)


@router.patch("/iam/exceptions/{eid}")
def update_exception(eid: int, body: ExceptionUpdate, db: Session = Depends(get_db), user: User = Depends(require("access:manage"))):
    e = db.get(IamException, eid)
    if e is None:
        raise HTTPException(404, "Exception not found")
    prev = {"owner": e.owner, "status": e.status}
    if body.status:
        if body.status not in ("OPEN", "IN_PROGRESS", "RESOLVED", "ACCEPTED"):
            raise HTTPException(422, "status must be OPEN, IN_PROGRESS, RESOLVED or ACCEPTED")
        if body.status in ("RESOLVED", "ACCEPTED") and not (body.notes or "").strip():
            raise HTTPException(422, "A resolution note is required")
        if body.status == "RESOLVED" and e.cleared_at is None:
            raise HTTPException(409, "The condition is still present in the latest inventory: fix it in the provider (or accept the risk) first")
        e.status, e.resolved_by = body.status, user.email if body.status in ("RESOLVED", "ACCEPTED") else e.resolved_by
    if body.owner is not None:
        e.owner = body.owner or None
    if body.notes:
        e.resolution_notes = body.notes
    log_action(db, user.email, "access.exception_update", e.exception_key, {"previous": prev, "status": e.status, "owner": e.owner})
    db.commit()
    return _exc(e)


# ------------------------------------------------------------------ revocation plans
def _plan(p: AccessRevocationPlan, items: list | None = None) -> dict:
    d = {"id": p.id, "key": p.plan_key, "provider": p.provider, "principal_id": p.principal_id, "principal": p.principal_name, "reason": p.reason,
         "status": p.status, "created_by": p.created_by, "created_at": p.created_at, "approved_by": p.approved_by, "approved_at": p.approved_at,
         "executed_by": p.executed_by, "executed_at": p.executed_at, "verified_at": p.verified_at, "notes": p.notes,
         "before": p.before_snapshot, "after": p.after_snapshot}
    if items is not None:
        d["items"] = [{"id": i.id, "kind": i.kind, "description": i.description, "scope": i.scope_path, "action": i.action, "auto_allowed": i.auto_allowed,
                       "status": i.status, "verified_at": i.verified_at} for i in items]
    return d


class PlanBody(BaseModel):
    reason: str = Field(pattern="^(deleted|disabled|offboarding|security_incident)$")


@router.post("/iam/identities/{iid}/revocation-plan", status_code=201, dependencies=[Depends(access_workflows)])
def create_plan(iid: int, body: PlanBody, db: Session = Depends(get_db), user: User = Depends(require("access:manage"))):
    i = db.get(CloudIdentity, iid)
    if i is None:
        raise HTTPException(404, "Identity not found")
    if db.scalar(select(AccessRevocationPlan).where(AccessRevocationPlan.provider == i.provider, AccessRevocationPlan.principal_id == i.principal_id,
                                                    AccessRevocationPlan.status.in_(["DRAFT", "APPROVAL_REQUESTED", "APPROVED", "EXECUTING"]))):
        raise HTTPException(409, "An open revocation plan already exists for this identity")
    p = lc.build_plan(db, i, body.reason, user.email)
    trail.record(db, category="revocation", actor=user.email, action="revocation.plan_created", provider=i.provider, target=i.principal_id,
                 new_state={"plan": p.plan_key, "items": len(p.before_snapshot)})
    lc.refresh_status(db)
    db.commit()
    return _plan(p, list(db.scalars(select(AccessRevocationItem).where(AccessRevocationItem.plan_id == p.id))))


@router.get("/iam/revocations")
def revocations(status: str | None = None, db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    stmt = select(AccessRevocationPlan)
    if status:
        stmt = stmt.where(AccessRevocationPlan.status.in_(status.split(",")))
    return {"items": [_plan(p) for p in db.scalars(stmt.order_by(AccessRevocationPlan.id.desc()).limit(500))]}


@router.get("/iam/revocations/{pid}")
def revocation(pid: int, db: Session = Depends(get_db), _: User = Depends(require("access:read"))):
    p = db.get(AccessRevocationPlan, pid)
    if p is None:
        raise HTTPException(404, "Plan not found")
    return _plan(p, list(db.scalars(select(AccessRevocationItem).where(AccessRevocationItem.plan_id == p.id).order_by(AccessRevocationItem.id))))


class PlanStep(BaseModel):
    action: str
    notes: str | None = Field(default=None, max_length=4000)
    item_id: int | None = None


PLAN_STEPS = {"request_approval": ("DRAFT", "APPROVAL_REQUESTED", "access:manage"), "approve": ("APPROVAL_REQUESTED", "APPROVED", "access:approve"),
              "reject": ("APPROVAL_REQUESTED", "REJECTED", "access:approve"), "executed": ("APPROVED", "EXECUTING", "access:manage"),
              "cancel": (None, "CANCELLED", "access:manage"), "skip_item": (None, None, "access:manage"), "verify": (None, None, "access:manage")}


@router.post("/iam/revocations/{pid}/step", dependencies=[Depends(access_workflows)])
def plan_step(pid: int, body: PlanStep, db: Session = Depends(get_db), user: User = Depends(require_any("access:manage", "access:approve"))):
    """Human steps only. 'executed' records that an administrator removed the access in the provider; the plan becomes
    VERIFIED only when the next complete inventory no longer shows it."""
    p = db.get(AccessRevocationPlan, pid)
    if p is None:
        raise HTTPException(404, "Plan not found")
    if body.action not in PLAN_STEPS:
        raise HTTPException(422, f"action must be one of {', '.join(PLAN_STEPS)}")
    frm, to, perm = PLAN_STEPS[body.action]
    if perm not in user.permission_names:
        raise HTTPException(403, f"This step needs {perm}")
    prev = p.status
    if body.action == "skip_item":
        it = db.get(AccessRevocationItem, body.item_id or 0)
        if it is None or it.plan_id != p.id or not (body.notes or "").strip():
            raise HTTPException(422, "item_id of this plan and a reason are required")
        it.status = "SKIPPED"
    elif body.action == "verify":
        if p.status not in ("EXECUTING", "PARTIALLY_VERIFIED", "VERIFICATION_FAILED"):
            raise HTTPException(409, "Only executed plans can be verified")
        if p.status == "VERIFICATION_FAILED":
            p.status = "EXECUTING"
        lc.verify_plans(db)
    else:
        if frm and p.status != frm:
            raise HTTPException(409, f"Plan is {p.status.lower()}")
        if body.action == "cancel" and p.status in ("VERIFIED", "CANCELLED", "REJECTED"):
            raise HTTPException(409, f"Plan is {p.status.lower()}")
        if body.action in ("reject", "cancel", "executed") and not (body.notes or "").strip():
            raise HTTPException(422, "Notes are required (reason, or the change reference for execution)")
        if body.action == "approve" and user.email.lower() == p.created_by.lower():
            raise HTTPException(409, "Segregation of duties: the creator of a plan cannot approve it")
        p.status = to
        if body.action == "approve":
            p.approved_by, p.approved_at = user.email, datetime.now(UTC)
        if body.action == "executed":
            p.executed_by, p.executed_at = user.email, datetime.now(UTC)
        if body.notes:
            p.notes = ((p.notes + "\n") if p.notes else "") + f"{user.email}: {body.notes}"
    trail.record(db, category="revocation", actor=user.email, action=f"revocation.{body.action}", provider=p.provider, target=p.principal_id,
                 previous_state={"status": prev}, new_state={"status": p.status, "item": body.item_id}, approval_reference=p.plan_key,
                 execution_result="RECORDED_BY_ADMIN" if body.action == "executed" else None,
                 verification_result=p.status if body.action == "verify" else None, evidence_reference=(body.notes or "")[:1024] or None)
    lc.refresh_status(db)
    db.commit()
    return revocation(pid, db)


# ================================================================== cost analysis
PERIODS = ("current_billing_period", "last_7_days", "last_30_days", "this_month", "previous_month", "last_invoice", "last_3_invoices",
           "last_12_invoices", "year_to_date", "financial_year", "custom_financial_period", "custom")
GROUPS = {"provider": None, "scope": None, "service": None, "resource_group": "resource", "resource": "resource", "resource_type": "resource",
          "region": "service_region", "sku": "sku", "usage_type": "usage_type", "environment": "tag", "cost_center": "tag",
          "business_entity": "tag"}
TAG_KEY = {"environment": 0, "cost_center": 1, "business_entity": 2}


def cost_period(period: str, start: date | None, end: date | None, fy: int | None, settings: Settings, today: date | None = None) -> tuple[date, date, str]:
    today = today or datetime.now(UTC).date()
    m0 = today.replace(day=1)

    def months_back(n: int) -> date:
        y, m = m0.year, m0.month - n
        while m <= 0:
            y, m = y - 1, m + 12
        return date(y, m, 1)
    fsm = settings.financial_year_start_month
    if period in ("current_billing_period", "this_month"):
        return m0, today, "Calendar month to date (Azure subscriptions may bill on a different cycle)"
    if period == "last_7_days":
        return today - timedelta(days=6), today, "Last 7 days including today (partial)"
    if period == "last_30_days":
        return today - timedelta(days=29), today, "Last 30 days including today (partial)"
    if period in ("previous_month", "last_invoice"):
        s = months_back(1)
        return s, m0 - timedelta(days=1), "Previous billing month" + (" (invoice documents are not collected; billing month used)" if period == "last_invoice" else "")
    if period in ("last_3_invoices", "last_12_invoices"):
        n = 3 if period == "last_3_invoices" else 12
        return months_back(n), m0 - timedelta(days=1), f"Last {n} complete billing months (invoice documents are not collected)"
    if period == "year_to_date":
        return today.replace(month=1, day=1), today, "Calendar year to date"
    if period in ("financial_year", "custom_financial_period"):
        y = fy or (today.year if today.month >= fsm else today.year - 1)
        s = date(y, fsm, 1)
        e = date(y + 1, fsm, 1) - timedelta(days=1)
        return s, min(e, today), f"Financial year starting {calendar.month_name[fsm]} {y}"
    if period == "custom":
        if not start or not end or end < start:
            raise HTTPException(422, "A custom period needs a start and an end date")
        return start, end, "Custom range"
    raise HTTPException(422, f"period must be one of {', '.join(PERIODS)}")


@router.get("/cost/billing-periods")
def billing_periods(scope: str | None = None, db: Session = Depends(get_db), _: User = Depends(require("finops:read"))):
    """Every Azure subscription with its own billing periods (current + recent closed ones) and their totals.
    A subscription without periods says why (not onboarded, billing access missing, not collected yet) instead of showing 0."""
    from app.models import BillingPeriod
    from app.services.onboarding.status import AUTOMATION_ELIGIBLE
    from app.services.scopes import check_passed
    today = datetime.now(UTC).date()
    model = SCOPE_MODELS["azure"]
    q = select(model).order_by(model.name)
    if scope:
        q = q.where(model.external_id == scope)
    subs = list(db.scalars(q))
    rows = defaultdict(list)
    pq = select(BillingPeriod).where(BillingPeriod.provider == "azure").order_by(BillingPeriod.period_start.desc())
    for p in db.scalars(pq.where(BillingPeriod.scope_external_id == scope) if scope else pq):
        rows[p.scope_external_id].append(p)
    out = []
    for sub in subs:
        periods = rows.get(sub.external_id, [])
        gap = None
        if not periods:
            if sub.onboarding_status not in AUTOMATION_ELIGIBLE or not sub.monitoring_enabled:
                perm = (sub.checks or {}).get("permissions") or {}
                gap = f"Not collected: subscription is '{sub.onboarding_status}'" + (f" – {perm.get('detail')}" if perm.get("detail") else "")
            elif not check_passed(sub, "billing"):
                gap = "Not collected: billing access not validated – " + (((sub.checks or {}).get("billing") or {}).get("detail") or "assign Cost Management Reader")
            else:
                gap = "Not collected yet: appears after the next billing_refresh run (hourly)"
        items = []
        for p in periods:
            current = p.period_start <= today <= p.period_end
            elapsed = (min(today, p.period_end) - p.period_start).days + 1
            items.append({"name": p.name, "start": p.period_start.isoformat(), "end": p.period_end.isoformat(),
                          "status": "current" if current else "closed", "days_elapsed": elapsed, "days_total": (p.period_end - p.period_start).days + 1,
                          "cost_original": _f(p.total_original), "currency": p.currency, "cost_usd": _f(p.total_usd), "cost_inr": _f(p.total_inr),
                          "total_source": p.total_source, "is_final": p.is_final, "invoice_ids": p.invoice_ids or [],
                          "collected_at": p.total_collected_at.isoformat() if p.total_collected_at else None})
        out.append({"scope": sub.external_id, "name": sub.name, "onboarding_status": sub.onboarding_status,
                    "source": periods[0].source if periods else None, "note": periods and periods[0].source == "calendar_month" and
                    "Azure does not publish billing periods for this agreement; calendar months are shown." or None,
                    "periods": items, "gap": gap})
    return {"as_of": datetime.now(UTC).isoformat(), "today": today.isoformat(), "subscriptions": out,
            "definitions": {"current": "Current period: summed from the daily cost records collected so far (provisional; Azure publishes usage 8-24 h late).",
                            "closed": "Closed periods: total read from Azure Cost Management for exactly the period dates; final once Azure closes the period.",
                            "dates": "Dates are the subscription's own billing cycle from Azure (Microsoft.Billing billing periods), not calendar months, unless stated."}}


@router.get("/cost/analysis")
def cost_analysis(period: str = "this_month", start: date | None = None, end: date | None = None, fy: int | None = None,
                  provider: str | None = None, scope: str | None = None, service: str | None = None, region: str | None = None,
                  resource_group: str | None = None, group_by: str = "service", cost_type: str = "actual",
                  db: Session = Depends(get_db), settings: Settings = Depends(get_settings), _: User = Depends(require("finops:read"))):
    if group_by not in GROUPS:
        raise HTTPException(422, f"group_by must be one of {', '.join(GROUPS)}")
    if cost_type not in ("actual", "amortized"):
        raise HTTPException(422, "cost_type must be actual or amortized")
    s, e, label = cost_period(period, start, end, fy, settings)
    if period == "current_billing_period" and scope:
        from app.services.finops.periods import current_period
        cp = current_period(db, scope)
        if cp is not None:  # the subscription's own billing cycle instead of the calendar month
            s, e = cp.period_start, min(cp.period_end, datetime.now(UTC).date())
            label = f"Current billing period {cp.period_start:%d %b} – {cp.period_end:%d %b %Y}" + (" (calendar month)" if cp.source == "calendar_month" else "")
    today = datetime.now(UTC).date()
    names ={sc.external_id: sc.name for m in SCOPE_MODELS.values() for sc in db.scalars(select(m))}

    def br(extra=()):
        w = [BillingRecord.usage_date.between(s, e), BillingRecord.cost_usd.is_not(None), *extra]
        if provider:
            w.append(BillingRecord.provider == provider)
        if scope:
            w.append(BillingRecord.scope_external_id == scope)
        if service:
            w.append(BillingRecord.service == service)
        return w
    use_detail = GROUPS[group_by] is not None or region or resource_group or cost_type == "amortized"
    total = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(*br()))
    daily = defaultdict(dict)
    for p, d, v in db.execute(select(BillingRecord.provider, BillingRecord.usage_date, func.sum(BillingRecord.cost_usd)).where(*br())
                              .group_by(BillingRecord.provider, BillingRecord.usage_date)).all():
        daily[d.isoformat()][p] = _f(v)
    # previous period of the same length, for variance
    span = (e - s).days + 1
    ps, pe = s - timedelta(days=span), s - timedelta(days=1)
    w_prev = [BillingRecord.usage_date.between(ps, pe), BillingRecord.cost_usd.is_not(None)] + \
             ([BillingRecord.provider == provider] if provider else []) + ([BillingRecord.scope_external_id == scope] if scope else []) + \
             ([BillingRecord.service == service] if service else [])
    prev_total = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(*w_prev))
    # grouping
    groups, coverage = [], {}
    if not use_detail:
        col = {"provider": BillingRecord.provider, "scope": BillingRecord.scope_external_id, "service": BillingRecord.service}[group_by]
        for k, v in db.execute(select(col, func.sum(BillingRecord.cost_usd)).where(*br()).group_by(col).order_by(func.sum(BillingRecord.cost_usd).desc())).all():
            groups.append({"key": k, "label": names.get(k, k) if group_by == "scope" else k, "cost_usd": _f(v)})
        coverage = {p: "collected" for p in ("aws", "azure", "gcp")}
    else:
        bd = GROUPS[group_by] or ("resource" if resource_group else "service_region")
        tag_key = settings.cost_tag_keys[TAG_KEY[group_by]] if bd == "tag" and len(settings.cost_tag_keys) > TAG_KEY[group_by] else None
        w = [CostDetailRecord.usage_date.between(s, e), CostDetailRecord.amount_usd.is_not(None), CostDetailRecord.cost_type == cost_type]
        for col, val in ((CostDetailRecord.provider, provider), (CostDetailRecord.scope_external_id, scope), (CostDetailRecord.service, service),
                         (CostDetailRecord.region, region), (CostDetailRecord.resource_group, resource_group)):
            if val:
                w.append(col == val)
        breakdowns = {"aws": [], "azure": [], "gcp": []}
        if bd == "tag":
            breakdowns = {"aws": [f"tag:{tag_key}"[:24]], "azure": [f"tag:{tag_key}"[:24]], "gcp": ["sku"]}
        elif bd == "resource":
            breakdowns = {"aws": ["resource"], "azure": ["resource"], "gcp": ["resource"]}
        elif bd == "service_region":
            breakdowns = {"aws": ["service_region"], "azure": ["service_region"], "gcp": ["sku"]}
        elif bd == "sku":
            breakdowns = {"aws": [], "azure": [], "gcp": ["sku"]}
        elif bd == "usage_type":
            breakdowns = {"aws": ["usage_type"], "azure": ["usage_type"], "gcp": ["sku"]}
        agg: dict = defaultdict(lambda: {"cost_usd": 0.0, "providers": set()})
        for p, bds in breakdowns.items():
            if provider and p != provider:
                continue
            if not bds:
                coverage[p] = "not available from this provider"
                continue
            rows = list(db.scalars(select(CostDetailRecord).where(*w, CostDetailRecord.provider == p, CostDetailRecord.breakdown.in_(bds))))
            coverage[p] = "collected" if rows else ("not collected (enable resource-level cost)" if bd == "resource" else "not collected yet")
            for r in rows:
                key = {"region": r.region, "resource_group": r.resource_group, "resource": r.resource_id, "resource_type": r.resource_type,
                       "sku": r.sku, "usage_type": r.usage_type or r.sku}.get(group_by) if bd != "tag" else (r.tags or {}).get(tag_key, "(untagged)")
                if group_by in ("provider", "scope", "service"):
                    key = {"provider": r.provider, "scope": r.scope_external_id, "service": r.service}[group_by]
                g = agg[key or "(not reported)"]
                g["cost_usd"] += float(r.amount_usd or 0)
                g["providers"].add(p)
                g.setdefault("name", r.resource_name if group_by == "resource" else None)
        groups = sorted(({"key": k, "label": v.get("name") or k, "cost_usd": round(v["cost_usd"], 6), "providers": sorted(v["providers"])}
                         for k, v in agg.items()), key=lambda x: -x["cost_usd"])
    # forecast (current month only)
    m0, mend = today.replace(day=1), date(today.year, today.month, calendar.monthrange(today.year, today.month)[1])
    fc_rows = list(db.scalars(select(BillingForecast).where(BillingForecast.period_start == m0)))
    fc_by = defaultdict(dict)
    for f in fc_rows:
        if (provider and f.provider != provider) or (scope and f.scope_external_id != scope):
            continue
        fc_by[(f.provider, f.scope_external_id)][f.method] = f
    mtd = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date.between(m0, today), BillingRecord.cost_usd.is_not(None),
                                                                   *([BillingRecord.provider == provider] if provider else []),
                                                                   *([BillingRecord.scope_external_id == scope] if scope else [])))
    mtd_by = {(p, sc): v for p, sc, v in db.execute(select(BillingRecord.provider, BillingRecord.scope_external_id, func.sum(BillingRecord.cost_usd))
                                                     .where(BillingRecord.usage_date.between(m0, today), BillingRecord.cost_usd.is_not(None))
                                                     .group_by(BillingRecord.provider, BillingRecord.scope_external_id)).all()}
    methods: set[str] = set()
    forecast_total = None
    for key, methods_map in fc_by.items():
        prov = next((v for k, v in methods_map.items() if k.startswith("provider:")), None)
        if prov is not None and prov.currency == "USD":  # provider forecast covers the rest of the month: add month-to-date actual
            forecast_total = (forecast_total or 0.0) + float(mtd_by.get(key) or 0) + float(prov.forecast_amount)
            methods.add("provider forecast")
        elif "run_rate" in methods_map:
            forecast_total = (forecast_total or 0.0) + float(methods_map["run_rate"].forecast_amount)
            methods.add("run-rate estimate")
    actual_vs_forecast = []
    if forecast_total is not None and mtd is not None:
        remaining_days = (mend - today).days
        per_day = max(0.0, (forecast_total - float(mtd)) / remaining_days) if remaining_days > 0 else 0.0
        cum = 0.0
        for i in range(mend.day):
            d = m0 + timedelta(days=i)
            if d <= today:
                cum += float(db.scalar(select(func.sum(BillingRecord.cost_usd)).where(
                    BillingRecord.usage_date == d, BillingRecord.cost_usd.is_not(None), *([BillingRecord.provider == provider] if provider else []),
                    *([BillingRecord.scope_external_id == scope] if scope else []))) or 0)
                actual_vs_forecast.append({"date": d.isoformat(), "actual": round(cum, 2), "forecast": None})
            else:
                cum += per_day
                actual_vs_forecast.append({"date": d.isoformat(), "actual": None, "forecast": round(cum, 2)})
    # budgets: approved register (business) and provider budgets (alert configuration) are reported separately
    budgets = list(db.scalars(select(CloudBudget).where(CloudBudget.status == "ACTIVE", CloudBudget.start_date <= e, CloudBudget.end_date >= s,
                                                        CloudBudget.level.in_(["account", "provider"]))))
    if provider:
        budgets = [b for b in budgets if b.provider == provider]
    if scope:
        budgets = [b for b in budgets if b.scope_external_id == scope]
    approved = sum((b.current_monthly_usd for b in budgets), Decimal(0)) if budgets else None
    pbs = [b for b in db.scalars(select(ProviderBudget).where(ProviderBudget.removed_at.is_(None))) if (not provider or b.provider == provider)
           and (not scope or b.scope_external_id == scope)]
    # month over month (12 months)
    mom = defaultdict(dict)
    y0 = date(today.year - 1, today.month, 1)
    for p, ym, v in db.execute(select(BillingRecord.provider, BillingRecord.usage_date, BillingRecord.cost_usd).where(
                                   BillingRecord.usage_date >= y0, BillingRecord.cost_usd.is_not(None),
                                   *([BillingRecord.provider == provider] if provider else []),
                                   *([BillingRecord.scope_external_id == scope] if scope else []))).all():
        key = ym.strftime("%Y-%m") if isinstance(ym, date) else str(ym)
        mom[key][p] = mom[key].get(p, 0.0) + float(v or 0)
    # top increasing services: this month to date vs same days last month
    pm0 = (m0 - timedelta(days=1)).replace(day=1)
    pm_end = min(pm0 + timedelta(days=today.day - 1), m0 - timedelta(days=1))
    cur_s = dict(db.execute(select(BillingRecord.service, func.sum(BillingRecord.cost_usd)).where(
        BillingRecord.usage_date.between(m0, today), BillingRecord.cost_usd.is_not(None), *([BillingRecord.provider == provider] if provider else []),
        *([BillingRecord.scope_external_id == scope] if scope else [])).group_by(BillingRecord.service)).all())
    prev_s = dict(db.execute(select(BillingRecord.service, func.sum(BillingRecord.cost_usd)).where(
        BillingRecord.usage_date.between(pm0, pm_end), BillingRecord.cost_usd.is_not(None), *([BillingRecord.provider == provider] if provider else []),
        *([BillingRecord.scope_external_id == scope] if scope else [])).group_by(BillingRecord.service)).all())
    increases = sorted(({"service": k, "current": _f(v), "previous": _f(prev_s.get(k) or 0), "increase": _f(v - (prev_s.get(k) or 0))}
                        for k, v in cur_s.items() if v is not None and v > (prev_s.get(k) or 0)), key=lambda x: -x["increase"])[:10]
    # donuts and top resources from the detail table (actual)
    det_w = [CostDetailRecord.usage_date.between(s, e), CostDetailRecord.amount_usd.is_not(None), CostDetailRecord.cost_type == "actual"] + \
            ([CostDetailRecord.provider == provider] if provider else []) + ([CostDetailRecord.scope_external_id == scope] if scope else [])
    by_region = defaultdict(float)
    for _p, r, v in db.execute(select(CostDetailRecord.provider, CostDetailRecord.region, func.sum(CostDetailRecord.amount_usd)).where(
            *det_w, or_(CostDetailRecord.breakdown == "service_region", (CostDetailRecord.provider == "gcp") & (CostDetailRecord.breakdown == "sku")))
            .group_by(CostDetailRecord.provider, CostDetailRecord.region)).all():
        by_region[r or "global / not reported"] += float(v or 0)
    top_res = [{"resource_id": rid, "name": n, "provider": p, "scope": sc, "cost_usd": float(v or 0)} for rid, n, p, sc, v in db.execute(
        select(CostDetailRecord.resource_id, func.max(CostDetailRecord.resource_name), CostDetailRecord.provider, CostDetailRecord.scope_external_id,
               func.sum(CostDetailRecord.amount_usd)).where(*det_w, CostDetailRecord.breakdown == "resource", CostDetailRecord.resource_id.is_not(None))
        .group_by(CostDetailRecord.resource_id, CostDetailRecord.provider, CostDetailRecord.scope_external_id)
        .order_by(func.sum(CostDetailRecord.amount_usd).desc()).limit(10)).all()]
    by_rg = [{"resource_group": rg, "scope": sc, "cost_usd": float(v or 0)} for rg, sc, v in db.execute(
        select(CostDetailRecord.resource_group, CostDetailRecord.scope_external_id, func.sum(CostDetailRecord.amount_usd)).where(
            *det_w, CostDetailRecord.breakdown == "resource", CostDetailRecord.resource_group.is_not(None))
        .group_by(CostDetailRecord.resource_group, CostDetailRecord.scope_external_id).order_by(func.sum(CostDetailRecord.amount_usd).desc()).limit(25)).all()]
    by_scope = [{"provider": p, "scope": sc, "name": names.get(sc, sc), "cost_usd": _f(v)} for p, sc, v in db.execute(
        select(BillingRecord.provider, BillingRecord.scope_external_id, func.sum(BillingRecord.cost_usd)).where(*br())
        .group_by(BillingRecord.provider, BillingRecord.scope_external_id).order_by(func.sum(BillingRecord.cost_usd).desc())).all()]
    by_service = [{"service": k, "cost_usd": _f(v)} for k, v in db.execute(select(BillingRecord.service, func.sum(BillingRecord.cost_usd)).where(*br())
                                                                           .group_by(BillingRecord.service).order_by(func.sum(BillingRecord.cost_usd).desc())).all()]
    freshness = {p: {"last_usage_date": d, "last_collected_at": c} for p, d, c in db.execute(
        select(BillingRecord.provider, func.max(BillingRecord.usage_date), func.max(BillingRecord.collected_at)).group_by(BillingRecord.provider)).all()}
    for p, t in db.execute(select(CostDetailRecord.provider, func.max(CostDetailRecord.provider_refreshed_at)).group_by(CostDetailRecord.provider)).all():
        freshness.setdefault(p, {})["detail_refreshed_at"] = t
    tot = _f(total)
    return {
        "period": {"key": period, "start": s, "end": e, "label": label, "includes_today": e >= today},
        "collected": total is not None, "cost_type": cost_type,
        "summary": {"actual_usd": tot, "previous_period_usd": _f(prev_total), "variance_usd": (tot - _f(prev_total)) if tot is not None and prev_total is not None else None,
                    "variance_pct": round((tot - _f(prev_total)) / _f(prev_total) * 100, 1) if tot is not None and prev_total else None,
                    "month_to_date_usd": _f(mtd), "forecast_month_usd": round(forecast_total, 2) if forecast_total is not None else None,
                    "forecast_method": " + ".join(sorted(methods)) or None,
                    "approved_budget_usd": _f(approved), "remaining_budget_usd": (_f(approved) - (_f(mtd) or 0)) if approved is not None else None,
                    "budget_utilisation_pct": round((_f(mtd) or 0) / _f(approved) * 100, 1) if approved else None,
                    "daily_average_usd": round(tot / max(1, (min(e, today) - s).days + 1), 2) if tot is not None else None},
        "group_by": group_by, "groups": groups[:200], "group_coverage": coverage,
        "daily": [{"date": d, **v} for d, v in sorted(daily.items())], "actual_vs_forecast": actual_vs_forecast,
        "by_service": by_service[:25], "by_region": sorted(({"region": k, "cost_usd": round(v, 2)} for k, v in by_region.items()), key=lambda x: -x["cost_usd"])[:15],
        "by_scope": by_scope, "by_resource_group": by_rg, "top_resources": top_res, "top_increasing_services": increases,
        "month_over_month": [{"month": k, **{p: round(x, 2) for p, x in v.items()}} for k, v in sorted(mom.items())],
        "provider_budgets": [{"provider": b.provider, "scope": b.scope_external_id, "name": b.name, "amount": _f(b.amount), "currency": b.currency,
                              "current_spend": _f(b.current_spend), "forecast_spend": _f(b.forecast_spend), "time_grain": b.time_grain} for b in pbs],
        "freshness": freshness,
        "notes": ["Forecast is shown separately from actual cost and is never added to it.",
                  "Billing data is delayed by the provider (typically 8-24 hours); today is partial.",
                  "Approved budgets come from the LV NEXUS budget register; provider budgets are alert configurations only.",
                  "Region, resource group, resource, SKU and tag groupings come from cost_detail_refresh; providers without that data show 'not collected'."],
    }


# ================================================================== structured AI
class AnalyzeBody(BaseModel):
    subject_type: str
    subject_id: str = Field(max_length=64)


@router.post("/ai/analyze", status_code=201)
def ai_analyze(body: AnalyzeBody, db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(require("ai:use"))):
    from app.services.intelligence.structured import analyze, as_dict
    perm = {"activity_event": "audit:read", "identity_change": "access:read", "finding": "vuln:read"}.get(body.subject_type)
    if perm and perm not in user.permission_names:
        raise HTTPException(403, f"Analysing this subject needs {perm}")
    r = analyze(db, settings, user.email, body.subject_type, body.subject_id)
    log_action(db, user.email, "ai.analyze", f"{body.subject_type}:{body.subject_id}", {"risk": r.risk, "by": r.generated_by})
    db.commit()
    return as_dict(r)


@router.get("/ai/analyses")
def ai_analyses(subject_type: str | None = None, subject_id: str | None = None, db: Session = Depends(get_db), _: User = Depends(require("ai:use"))):
    from app.services.intelligence.structured import as_dict
    stmt = select(AIAnalysisResult)
    if subject_type:
        stmt = stmt.where(AIAnalysisResult.subject_type == subject_type)
    if subject_id:
        stmt = stmt.where(AIAnalysisResult.subject_id == subject_id)
    return {"items": [as_dict(r) for r in db.scalars(stmt.order_by(AIAnalysisResult.id.desc()).limit(100))]}


# ================================================================== audit trail
@router.get("/audit-trail")
def audit_trail(category: str | None = None, actor: str | None = None, action: str | None = None, provider: str | None = None,
                q: str | None = None, start: date | None = None, end: date | None = None, page: int = Query(1, ge=1),
                page_size: int = Query(100, ge=1, le=500), db: Session = Depends(get_db), _: User = Depends(require_any("audit:read", "admin:users"))):
    stmt = select(AuditTrail)
    for col, val in ((AuditTrail.category, category), (AuditTrail.provider, provider)):
        if val:
            stmt = stmt.where(col.in_(val.split(",")))
    if actor:
        stmt = stmt.where(AuditTrail.actor.ilike(f"%{actor}%"))
    if action:
        stmt = stmt.where(AuditTrail.action.ilike(f"%{action}%"))
    if q:
        stmt = stmt.where(or_(AuditTrail.target.ilike(f"%{q}%"), AuditTrail.scope.ilike(f"%{q}%"), AuditTrail.audit_id == q))
    if start:
        stmt = stmt.where(AuditTrail.created_at >= datetime.combine(start, datetime.min.time(), UTC))
    if end:
        stmt = stmt.where(AuditTrail.created_at < datetime.combine(end + timedelta(days=1), datetime.min.time(), UTC))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(AuditTrail.id.desc()).offset((page - 1) * page_size).limit(page_size))
    cats = dict(db.execute(select(AuditTrail.category, func.count()).group_by(AuditTrail.category)).all())
    return {"total": total, "by_category": cats, "items": [{
        "audit_id": r.audit_id, "category": r.category, "provider": r.provider, "scope": r.scope, "actor": r.actor, "action": r.action,
        "target": r.target, "previous_state": r.previous_state, "new_state": r.new_state, "approval_reference": r.approval_reference,
        "execution_result": r.execution_result, "verification_result": r.verification_result, "evidence_reference": r.evidence_reference,
        "at": r.created_at, "hash": r.row_hash[:16]} for r in rows]}


@router.get("/audit-trail/verify")
def audit_trail_verify(db: Session = Depends(get_db), _: User = Depends(require_any("audit:read", "admin:users"))):
    return trail.verify(db)


# ================================================================== executive decisions + identity / operations health
class DecisionBody(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    source: str = Field(max_length=64)
    risk_summary: str = Field(min_length=3, max_length=4000)
    business_impact: str = Field(min_length=3, max_length=4000)
    recommended_action: str = Field(min_length=3, max_length=4000)
    priority: str = Field(pattern="^(Critical|High|Medium|Low)$")
    owner: str = Field(min_length=3, max_length=255)
    due_date: date | None = None


def _dec(d: ManagementDecision) -> dict:
    overdue = d.status == "OPEN" and d.due_date is not None and d.due_date < datetime.now(UTC).date()
    return {"id": d.id, "key": d.decision_key, "title": d.title, "source": d.source, "risk_summary": d.risk_summary, "business_impact": d.business_impact,
            "recommended_action": d.recommended_action, "priority": d.priority, "owner": d.owner, "due_date": d.due_date, "status": d.status,
            "overdue": overdue, "decision": d.decision, "decided_by": d.decided_by, "decided_at": d.decided_at, "created_by": d.created_by,
            "created_at": d.created_at}


@router.get("/executive/decisions")
def decisions(status: str | None = None, db: Session = Depends(get_db), _: User = Depends(require("inventory:read"))):
    stmt = select(ManagementDecision)
    if status:
        stmt = stmt.where(ManagementDecision.status.in_(status.split(",")))
    return {"items": [_dec(d) for d in db.scalars(stmt.order_by(ManagementDecision.id.desc()).limit(500))]}


@router.post("/executive/decisions", status_code=201)
def create_decision(body: DecisionBody, db: Session = Depends(get_db), user: User = Depends(require_any("governance:manage", "security:admin", "admin:users"))):
    from app.services.access.engine import next_key
    d = ManagementDecision(decision_key=next_key(db, ManagementDecision, ManagementDecision.decision_key, "DEC"), created_by=user.email, **body.model_dump())
    db.add(d)
    log_action(db, user.email, "governance.decision_created", d.decision_key, {"title": body.title, "owner": body.owner, "priority": body.priority})
    db.commit()
    return _dec(d)


class DecisionUpdate(BaseModel):
    status: str = Field(pattern="^(OPEN|DECIDED|DEFERRED|CLOSED)$")
    decision: str | None = Field(default=None, max_length=4000)
    owner: str | None = Field(default=None, max_length=255)
    due_date: date | None = None


@router.patch("/executive/decisions/{did}")
def update_decision(did: int, body: DecisionUpdate, db: Session = Depends(get_db),
                    user: User = Depends(require_any("governance:manage", "security:admin", "admin:users", "budget:approve"))):
    d = db.get(ManagementDecision, did)
    if d is None:
        raise HTTPException(404, "Decision not found")
    if body.status in ("DECIDED", "CLOSED", "DEFERRED") and not (body.decision or d.decision):
        raise HTTPException(422, "Record the decision or reason")
    prev = {"status": d.status, "owner": d.owner}
    d.status = body.status
    if body.decision:
        d.decision, d.decided_by, d.decided_at = body.decision, user.email, datetime.now(UTC)
    if body.owner:
        d.owner = body.owner
    if body.due_date:
        d.due_date = body.due_date
    log_action(db, user.email, "governance.decision_update", d.decision_key, {"previous": prev, "status": d.status})
    db.commit()
    return _dec(d)


@router.get("/executive/operations-health")
def operations_health(db: Session = Depends(get_db), _: User = Depends(require("inventory:read"))):
    """Per-cloud health and identity / operations KPIs for the executive view. Unknown values stay null with a reason."""
    from app.models import AuditEvent
    from app.services.connections_health import registry
    reg = registry(db)
    by = defaultdict(lambda: {"scopes": 0, "healthy": 0, "degraded": 0, "not_connected": 0})
    for it in reg["items"]:
        b = by[it["provider"]]
        b["scopes"] += 1
        b[{"Healthy": "healthy", "Degraded": "degraded"}.get(it["health"], "not_connected")] += 1
    clouds = {p: {**v, "health_pct": round(v["healthy"] / v["scopes"] * 100) if v["scopes"] else None} for p, v in by.items()}
    week, day = datetime.now(UTC) - timedelta(days=7), datetime.now(UTC) - timedelta(hours=24)
    has_dir = db.scalar(select(func.count()).select_from(CloudIdentity).where(CloudIdentity.directory_scope.is_not(None))) or 0
    idents = list(db.scalars(select(CloudIdentity)))
    new_ids = sum(1 for i in idents if lc.is_new(i)) if has_dir else None
    deleted_recon = sum(1 for i in idents if i.lifecycle_status in ("Reconciliation Required", "Access Revocation Pending")) if has_dir else None
    priv_changes = db.scalar(select(func.count()).select_from(IdentityChangeEvent).where(IdentityChangeEvent.privileged.is_(True),
                                                                                         IdentityChangeEvent.detected_at >= week))
    failed_ops = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.event_timestamp >= day,
                                                                              AuditEvent.raw["outcome"].as_string().in_(["failure", "denied"])))
    events_any = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.collected_at >= day))
    open_exc = dict(db.execute(select(IamException.risk, func.count()).where(IamException.status.in_(["OPEN", "IN_PROGRESS"])).group_by(IamException.risk)).all())
    open_dec = [_dec(d) for d in db.scalars(select(ManagementDecision).where(ManagementDecision.status == "OPEN").order_by(ManagementDecision.due_date))]
    return {"clouds": clouds,
            "kpis": [
                {"key": "new_identities", "label": "New identities (30 days)", "value": new_ids, "link": "/access/identities?new=true",
                 "reason": None if has_dir else "Directory (Entra ID / IAM / service accounts) not collected yet"},
                {"key": "deleted_reconcile", "label": "Deleted / disabled identities needing reconciliation", "value": deleted_recon,
                 "link": "/access/lifecycle", "reason": None if has_dir else "Directory not collected yet"},
                {"key": "privileged_changes", "label": "Privileged access changes (7 days)", "value": priv_changes, "link": "/access/changes?privileged=true"},
                {"key": "failed_operations", "label": "Failed cloud operations (24 h)", "value": failed_ops if events_any else None,
                 "link": "/activity?result=failure", "reason": None if events_any else "No activity collected in the last 24 hours"},
                {"key": "iam_exceptions", "label": "Open access exceptions", "value": sum(open_exc.values()), "link": "/access/exceptions"},
            ],
            "iam_exceptions_by_risk": open_exc, "decisions": open_dec}
