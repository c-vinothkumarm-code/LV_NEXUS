from __future__ import annotations

from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.api.deps import require_any
from app.api.serializers import iso, query_scopes, scope_dict, task_dict
from app.core.config import Settings, get_settings
from app.core.security import assigned_scopes, audit, require, scope_condition
from app.database.session import get_db
from app.models import (
    SCOPE_LABEL,
    SCOPE_MODELS,
    CloudResource,
    CloudSecurityFinding,
    OnboardingRecord,
    OnboardingStatus,
    RemediationRecord,
    User,
    VMInventory,
    utcnow,
)
from app.schemas.common import ScopeUpdate, TaskDecision
from app.services.registry import prerequisites

router = APIRouter(prefix="/api/v1", tags=["inventory"])


@router.get("/inventory/scopes")
def list_scopes(provider: str | None = None, status: str | None = None, search: str | None = None,
                environment: str | None = None, db: Session = Depends(get_db),
                user: User = Depends(require_any("inventory:read", "inventory:read_assigned"))):
    rows = query_scopes(db, provider, status, search, environment)
    if "inventory:read" not in user.permission_names:  # Project Owner: only assigned scopes
        allowed = assigned_scopes(user)
        rows = [r for r in rows if (r.provider, r.external_id) in allowed]
    return {"total": len(rows), "items": [scope_dict(r) for r in rows]}


@router.patch("/inventory/scopes/{provider}/{external_id}")
def update_scope(provider: str, external_id: str, body: ScopeUpdate, db: Session = Depends(get_db),
                 user: User = Depends(require("admin:users"))):
    """Application-side settings only (monitoring toggle, environment label). No cloud change is made."""
    model = SCOPE_MODELS.get(provider)
    row = db.scalar(select(model).where(model.external_id == external_id)) if model else None
    if row is None:
        raise HTTPException(404, "Scope not found")
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(row, k, v)
    audit(db, user.email, "scope.update", f"{provider}:{external_id}", **changes)
    db.commit()
    return scope_dict(row)


@router.get("/onboarding/summary")
def onboarding_summary(db: Session = Depends(get_db), _: User = Depends(require("onboarding:read"))):
    rows = query_scopes(db)
    by_status = {s.value: 0 for s in OnboardingStatus}
    by_provider: dict[str, dict[str, int]] = {p: {s.value: 0 for s in OnboardingStatus} for p in SCOPE_MODELS}
    missing = {"permissions": [], "audit_logs": [], "billing": [], "monitoring": [], "authentication": [], "configuration": []}
    for r in rows:
        by_status[r.onboarding_status] += 1
        by_provider[r.provider][r.onboarding_status] += 1
        if r.onboarding_status == OnboardingStatus.INACTIVE.value:
            continue
        for check, bucket in missing.items():
            c = (r.checks or {}).get(check)
            if c and c.get("status") != "pass" and c.get("status") != "not_applicable":
                bucket.append({"provider": r.provider, "external_id": r.external_id, "name": r.name,
                               "status": c.get("status"), "detail": c.get("detail")})
    recent = sorted(rows, key=lambda r: r.first_discovered_at, reverse=True)[:10]
    open_tasks = db.scalars(select(RemediationRecord).where(
        RemediationRecord.category == "onboarding", RemediationRecord.status == "pending_approval")).all()
    return {"total": len(rows), "by_status": by_status, "by_provider": by_provider, "missing": missing,
            "recently_discovered": [scope_dict(r) for r in recent], "open_tasks": len(open_tasks)}


@router.get("/onboarding/records")
def onboarding_records(provider: str | None = None, external_id: str | None = None, limit: int = 100,
                       db: Session = Depends(get_db), _: User = Depends(require("onboarding:read"))):
    stmt = select(OnboardingRecord).order_by(OnboardingRecord.created_at.desc(), OnboardingRecord.id.desc())
    if provider:
        stmt = stmt.where(OnboardingRecord.provider == provider)
    if external_id:
        stmt = stmt.where(OnboardingRecord.scope_external_id == external_id)
    items = db.scalars(stmt.limit(min(limit, 500))).all()
    return {"items": [{"id": r.id, "provider": r.provider, "scope_external_id": r.scope_external_id,
                       "scope_name": r.scope_name, "event_type": r.event_type, "previous_status": r.previous_status,
                       "new_status": r.new_status, "detail": r.detail, "execution_id": r.execution_id,
                       "created_at": iso(r.created_at)} for r in items]}


@router.get("/onboarding/tasks")
def onboarding_tasks(status: str | None = None, provider: str | None = None, db: Session = Depends(get_db),
                     _: User = Depends(require("onboarding:read"))):
    stmt = select(RemediationRecord).where(RemediationRecord.category == "onboarding").order_by(RemediationRecord.created_at.desc())
    if status:
        stmt = stmt.where(RemediationRecord.status == status)
    if provider:
        stmt = stmt.where(RemediationRecord.provider == provider)
    return {"items": [task_dict(t) for t in db.scalars(stmt.limit(500))]}


@router.post("/onboarding/tasks/{task_id}/decision")
def decide_task(task_id: int, body: TaskDecision, db: Session = Depends(get_db),
                user: User = Depends(require("onboarding:approve"))):
    """Records a human decision. Approval authorises a person to do the work; the platform does not do it."""
    task = db.get(RemediationRecord, task_id)
    if task is None:
        raise HTTPException(404, "Task not found")
    if task.status != "pending_approval":
        raise HTTPException(409, f"Task is already {task.status}")
    task.status, task.decided_by, task.decided_at, task.decision_notes = body.decision, user.email, utcnow(), body.notes
    audit(db, user.email, f"task.{body.decision}", f"remediation:{task.id}", notes=body.notes)
    db.commit()
    return task_dict(task)


@router.get("/prerequisites")
def get_prerequisites(db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                      _: User = Depends(require("onboarding:read"))):
    from app.services.connections import effective_settings

    return {"providers": prerequisites(effective_settings(db, settings))}


@router.get("/search")
def global_search(q: str = Query(min_length=2, max_length=100), db: Session = Depends(get_db),
                  user: User = Depends(require_any("inventory:read", "inventory:read_assigned"))):
    """Search across accounts / subscriptions / projects, resources, virtual machines and security findings.
    Results respect the caller's permissions and, for scoped roles, their assigned scopes."""
    perms = user.permission_names
    like = f"%{q.strip()}%"
    out: list[dict] = []
    allowed = None if "inventory:read" in perms else assigned_scopes(user)
    for r in query_scopes(db, search=q.strip()):
        if allowed is None or (r.provider, r.external_id) in allowed:
            out.append({"type": "scope", "provider": r.provider, "title": r.name or r.external_id,
                        "subtitle": f"{SCOPE_LABEL[r.provider]} {r.external_id} · {r.onboarding_status}",
                        "link": f"/inventory?search={quote(r.external_id)}"})
    limit = scope_condition(CloudResource, user)
    stmt = select(CloudResource).where(or_(CloudResource.name.ilike(like), CloudResource.resource_id.ilike(like)))
    for r in db.scalars((stmt if limit is None else stmt.where(limit)).limit(15)):
        out.append({"type": "resource", "provider": r.provider, "title": r.name or r.resource_id.rsplit("/", 1)[-1],
                    "subtitle": f"{r.resource_type} · {r.scope_external_id} · {r.region or 'global'}", "link": "/monitoring"})
    if {"infra:read", "inventory:read_assigned"} & perms:
        limit = scope_condition(VMInventory, user) if "infra:read" not in perms else None
        stmt = select(VMInventory).where(VMInventory.deleted_at.is_(None),
                                         or_(VMInventory.name.ilike(like), VMInventory.instance_id.ilike(like),
                                             VMInventory.private_ip.ilike(like), VMInventory.public_ip.ilike(like)))
        for v in db.scalars((stmt if limit is None else stmt.where(limit)).limit(15)):
            out.append({"type": "vm", "provider": v.provider, "title": v.name or v.instance_id,
                        "subtitle": f"VM · {v.power_state or 'unknown'} · {v.scope_external_id}", "link": "/monitoring"})
    if {"vuln:read", "vuln:read_assigned"} & perms:
        stmt = select(CloudSecurityFinding).where(or_(CloudSecurityFinding.title.ilike(like), CloudSecurityFinding.resource_name.ilike(like),
                                                      CloudSecurityFinding.control_id.ilike(like)))
        if "vuln:read" not in perms:
            pairs = assigned_scopes(user)
            stmt = stmt.where(or_(CloudSecurityFinding.owner == user.email,
                                  *[and_(CloudSecurityFinding.provider == p, CloudSecurityFinding.scope_external_id == s) for p, s in pairs]))
        for f in db.scalars(stmt.order_by(CloudSecurityFinding.id.desc()).limit(15)):
            out.append({"type": "finding", "provider": f.provider, "title": f.title,
                        "subtitle": f"{f.severity} · {f.internal_status} · {f.scope_external_id}",
                        "link": f"/vulnerabilities/findings?id={f.id}"})
    return {"query": q, "items": out[:50]}
