"""Access registry (admin-controlled provisioning) and RBAC. Every change is written to the append-only admin audit log,
and suspension, revocation or a role change ends the person's open sessions immediately."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.serializers import iso
from app.core.config import Settings, get_settings
from app.core.security import ROLE_LABELS, ROLES, audit, require, revoke_sessions
from app.database.session import get_db
from app.models import SCOPE_MODELS, AccessAuditLog, AdminAuditLog, Role, User, UserScopeAssignment, UserSession

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])
_STATUSES = ("ACTIVE", "SUSPENDED", "REVOKED")


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None
    access_status: str | None = None
    access_expires_at: datetime | None = None
    clear_expiry: bool = False
    display_name: str | None = Field(default=None, max_length=255)


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)
    role: str
    access_expires_at: datetime | None = None


def _user(u: User, sessions: int = 0) -> dict:
    return {"id": u.id, "email": u.email, "display_name": u.display_name, "roles": [r.name for r in u.roles],
            "is_active": u.is_active, "access_status": u.access_status, "google_sub_bound": bool(u.google_sub),
            "authorized_at": iso(u.authorized_at), "access_expires_at": iso(u.access_expires_at), "role_source": u.role_source,
            "created_by": u.created_by, "modified_by": u.modified_by, "last_login_at": iso(u.last_login_at),
            "created_at": iso(u.created_at), "open_sessions": sessions, "role_labels": [ROLE_LABELS.get(r.name, r.name) for r in u.roles],
            "scopes": [{"provider": a.provider, "scope_external_id": a.scope_external_id} for a in u.scope_assignments]}


def _open_sessions(db: Session) -> dict[int, int]:
    now = datetime.now(UTC)
    rows = db.execute(select(UserSession.user_id, func.count()).where(UserSession.revoked_at.is_(None), UserSession.expires_at > now)
                      .group_by(UserSession.user_id))
    return dict(rows.all())


def _role(db: Session, name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == name))
    if role is None:
        raise HTTPException(422, "Unknown role")
    return role


@router.get("/users")
def list_users(db: Session = Depends(get_db), _: User = Depends(require("admin:users"))):
    open_ = _open_sessions(db)
    return {"items": [_user(u, open_.get(u.id, 0)) for u in db.scalars(select(User).order_by(User.email))],
            "roles": [{"name": n, "label": ROLE_LABELS.get(n, n), "description": d} for n, (d, _p) in ROLES.items()]}


@router.post("/users", status_code=201)
def provision_user(body: UserCreate, db: Session = Depends(get_db), actor: User = Depends(require("admin:users")),
                   settings: Settings = Depends(get_settings)):
    """Grant application access to a corporate account. The person still has to pass every Google Workspace check."""
    email = body.email.strip().lower()
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    if settings.auth_mode != "dev" and domain not in settings.corporate_domains | {d.lower() for d in settings.allowed_email_domains}:
        raise HTTPException(422, "Only corporate accounts of the allowed domain can be provisioned")
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "This account is already in the access registry")
    if body.access_expires_at and body.access_expires_at.replace(tzinfo=body.access_expires_at.tzinfo or UTC) <= datetime.now(UTC):
        raise HTTPException(422, "Access expiry must be in the future")
    u = User(email=email, display_name=body.display_name, roles=[_role(db, body.role)], authorized_at=datetime.now(UTC),
             access_expires_at=body.access_expires_at, created_by=actor.email, modified_by=actor.email, role_source="allowlist")
    db.add(u)
    audit(db, actor.email, "user.provision", email, role=body.role, access_expires_at=iso(body.access_expires_at))
    db.commit()
    return _user(u)


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserUpdate, db: Session = Depends(get_db), actor: User = Depends(require("admin:users"))):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    removing_access = body.is_active is False or (body.access_status in ("SUSPENDED", "REVOKED"))
    if target.id == actor.id and (removing_access or (body.role and body.role != "admin")):
        raise HTTPException(409, "You cannot remove your own administrator access")
    if body.access_status is not None and body.access_status not in _STATUSES:
        raise HTTPException(422, "access_status must be ACTIVE, SUSPENDED or REVOKED")
    ended = 0
    if body.role is not None and [r.name for r in target.roles] != [body.role]:
        target.roles = [_role(db, body.role)]
        target.role_source = "allowlist"  # an explicit administrator decision overrides group mapping
        ended += revoke_sessions(db, target.id, "role_changed")
    if body.is_active is not None:
        target.is_active = body.is_active
        if body.is_active and target.access_status != "ACTIVE" and body.access_status is None:
            target.access_status = "ACTIVE"
    if body.access_status is not None:
        target.access_status = body.access_status
        target.is_active = body.access_status == "ACTIVE"
    if removing_access:
        ended += revoke_sessions(db, target.id, (body.access_status or "deactivated").lower())
    if body.clear_expiry:
        target.access_expires_at = None
    elif body.access_expires_at is not None:
        target.access_expires_at = body.access_expires_at
    if body.display_name is not None:
        target.display_name = body.display_name
    if body.access_status == "ACTIVE" or body.is_active:
        target.authorized_at = datetime.now(UTC)
    target.modified_by = actor.email
    audit(db, actor.email, "user.update", target.email, sessions_ended=ended,
          **{k: (iso(v) if isinstance(v, datetime) else v) for k, v in body.model_dump(exclude_none=True).items()})
    db.commit()
    return _user(target)


class ScopeRef(BaseModel):
    provider: str
    scope_external_id: str = Field(min_length=1, max_length=128)


class ScopeAssignment(BaseModel):
    scopes: list[ScopeRef]


@router.put("/users/{user_id}/scopes")
def set_user_scopes(user_id: int, body: ScopeAssignment, db: Session = Depends(get_db), actor: User = Depends(require("admin:users"))):
    """Accounts / subscriptions / projects a scoped role (Project Owner) may see. Only discovered scopes can be assigned."""
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    wanted = {(s.provider, s.scope_external_id) for s in body.scopes}
    for p, sc in wanted:
        model = SCOPE_MODELS.get(p)
        if model is None or not db.scalar(select(model.id).where(model.external_id == sc)):
            raise HTTPException(422, f"{p}:{sc} is not in the discovered inventory")
    before = {(a.provider, a.scope_external_id) for a in target.scope_assignments}
    target.scope_assignments = [a for a in target.scope_assignments if (a.provider, a.scope_external_id) in wanted]
    for p, sc in sorted(wanted - before):
        target.scope_assignments.append(UserScopeAssignment(provider=p, scope_external_id=sc, assigned_by=actor.email))
    target.modified_by = actor.email
    audit(db, actor.email, "user.scopes", target.email, added=sorted(f"{p}:{s}" for p, s in wanted - before),
          removed=sorted(f"{p}:{s}" for p, s in before - wanted))
    db.commit()
    db.refresh(target)
    return _user(target)


@router.post("/users/{user_id}/revoke-sessions")
def revoke_user_sessions(user_id: int, db: Session = Depends(get_db), actor: User = Depends(require("admin:users"))):
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found")
    n = revoke_sessions(db, target.id, "admin_revoked")
    audit(db, actor.email, "user.sessions_revoked", target.email, sessions_ended=n)
    db.commit()
    return {"sessions_ended": n}


@router.get("/audit")
def audit_log(limit: int = 200, db: Session = Depends(get_db), _: User = Depends(require("admin:users"))):
    rows = db.scalars(select(AdminAuditLog).order_by(AdminAuditLog.id.desc()).limit(min(limit, 1000)))
    return {"items": [{"id": r.id, "actor": r.actor, "action": r.action, "target": r.target, "detail": r.detail,
                       "created_at": iso(r.created_at)} for r in rows]}


@router.get("/access-log")
def access_log(limit: int = 200, event: str | None = None, db: Session = Depends(get_db), _: User = Depends(require("admin:users"))):
    """Sign-in history: successes, denials (with reason), logouts and throttling, plus a 24-hour failure summary."""
    q = select(AccessAuditLog).order_by(AccessAuditLog.id.desc()).limit(min(limit, 1000))
    if event:
        q = q.where(AccessAuditLog.event == event)
    since = datetime.now(UTC) - timedelta(hours=24)
    by_reason = dict(db.execute(select(AccessAuditLog.reason, func.count()).where(
        AccessAuditLog.event == "login_denied", AccessAuditLog.created_at >= since).group_by(AccessAuditLog.reason)).all())
    return {"items": [{"id": r.id, "event": r.event, "reason": r.reason, "email": r.email, "ip_address": r.ip_address,
                       "created_at": iso(r.created_at)} for r in db.scalars(q)],
            "failures_24h": {"total": sum(by_reason.values()), "by_reason": by_reason}}
