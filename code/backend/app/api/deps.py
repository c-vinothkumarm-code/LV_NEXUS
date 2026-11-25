"""Shared API dependencies for the security modules."""
from __future__ import annotations

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.security import CSRF_HEADER, CSRF_VALUE, audit, current_user
from app.models import User


def require_any(*perms: str):
    """Like require(), for endpoints open to several roles; also enforces the CSRF header on state-changing requests."""
    def dep(request: Request, user: User = Depends(current_user)) -> User:
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            raise HTTPException(403, "Missing CSRF header")
        if not set(perms) & user.permission_names:
            raise HTTPException(403, f"Missing permission: one of {', '.join(perms)}")
        return user
    return dep


def log_action(db: Session, actor: str, action: str, target: str | None = None, detail: dict | None = None) -> None:
    """Admin audit log entry (append-only)."""
    audit(db, actor, action, (target or "")[:255] or None, **(detail or {}))


def access_workflows(settings: Settings = Depends(get_settings)) -> None:
    """Legacy access-management workflows (register, requests, approvals, reviews, revocation plans) are switched off:
    the Access page is read-only. The tables and history are kept; set ACCESS_WORKFLOWS_ENABLED=true to re-enable the API."""
    if not settings.access_workflows_enabled:
        raise HTTPException(404, "Access workflows are disabled: the Access page is read-only (ACCESS_WORKFLOWS_ENABLED=false).")
