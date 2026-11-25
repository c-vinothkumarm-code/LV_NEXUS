"""Sessions and RBAC. Sessions are signed, HttpOnly cookies; permissions come from the database."""
from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.database.session import get_db
from app.models import AdminAuditLog, Role, User

SESSION_COOKIE = "mcp_session"
SIGNED_OUT_COOKIE = "mcp_signed_out"  # dev mode only: lets "Sign out" work without a real identity provider
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "mcp-dashboard"
_ALG = "HS256"

PERMISSIONS: dict[str, str] = {
    "inventory:read": "View cloud inventory",
    "onboarding:read": "View onboarding status and history",
    "onboarding:approve": "Approve or reject onboarding tasks",
    "soc:read": "View audit events and security findings",
    "soc:review": "Record security review decisions",
    "finops:read": "View billing and budgets",
    "finops:manage": "Manage budgets",
    "infra:read": "View VM inventory and health",
    "automation:read": "View automation status",
    "automation:run": "Trigger automation jobs manually",
    "admin:users": "Manage users and roles",
    "connections:manage": "Configure cloud connections",
    "vuln:read": "View all native cloud security findings",
    "vuln:read_assigned": "View findings assigned to me",
    "vuln:triage": "Change finding workflow status, assign owners and analysts",
    "vuln:remediate": "Comment, upload evidence and request resolution verification",
    "exception:request": "Request a risk exception",
    "exception:approve": "Approve or reject risk exceptions",
    "audit:read": "View audit activities and investigations",
    "audit:investigate": "Work flagged audit activities and investigation cases",
    "audit:authorize": "Mark a flagged activity as authorized",
    "audit:rules": "Create, change and test audit detection and authorization rules",
    "sync:read": "View integration coverage and synchronization history",
    "sync:run": "Start or retry a security synchronization",
    "security:admin": "Configure SLA policies and notification rules",
    "reports:export": "Export security reports",
    "inventory:read_assigned": "View the accounts, subscriptions and projects assigned to me, and their resources",
    "exec:read": "View the Executive Command Center",
    "budget:read": "View approved budgets, budget requests and alerts",
    "budget:manage": "Register budgets and raise additional budget requests",
    "budget:approve": "Approve or reject budget requests (Finance)",
    "budget:configure": "Configure budget thresholds and approval chains",
    "access:read": "View cloud identities, access assignments and access requests",
    "access:manage": "Manage access requests, extensions, revocations and reviews",
    "access:approve": "Approve access requests and extensions (business manager)",
    "access:request": "Request cloud access, extensions and revocations",
    "ai:use": "Use the AI Copilot and agents (answers are limited to the data the role can see)",
    "governance:manage": "Manage governance policies, controls and exceptions",
    "assets:read": "View Cloud Services & Asset Management (inventory, activity, business metadata)",
    "assets:edit": "Edit business metadata of assets (SPOC, manager, department, classification, Commvault status)",
    "assets:import": "Bulk import asset business metadata from CSV / Excel",
    "assets:configure": "Configure activity thresholds and inactivity notifications",
}
# Role names are stored in the database and kept stable; ROLE_LABELS gives the business names used in the UI.
ROLES: dict[str, tuple[str, list[str]]] = {
    "admin": ("Full platform administration", []),  # filled with every permission below
    "cloud_admin": ("Cloud integrations, inventory, discovery, findings and synchronization",
                    ["assets:read", "assets:edit", "assets:import", "assets:configure", "ai:use", "access:request", "inventory:read", "onboarding:read", "onboarding:approve", "infra:read", "automation:read", "automation:run",
                     "connections:manage", "vuln:read", "vuln:triage", "exception:request", "audit:read", "sync:read", "sync:run",
                     "reports:export"]),
    "security_admin": ("Security administration: rules, SLA, notifications, exceptions",
                       ["assets:read", "ai:use", "access:request", "inventory:read", "onboarding:read", "automation:read", "soc:read", "soc:review", "vuln:read", "vuln:triage",
                        "vuln:remediate", "exception:request", "exception:approve", "audit:read", "audit:investigate", "audit:authorize",
                        "audit:rules", "sync:read", "sync:run", "security:admin", "reports:export"]),
    "security_analyst": ("Security findings, investigations and remediation",
                         ["assets:read", "ai:use", "access:request", "inventory:read", "onboarding:read", "soc:read", "soc:review", "vuln:read", "vuln:triage", "vuln:remediate",
                          "exception:request", "audit:read", "audit:investigate", "audit:authorize", "sync:read", "reports:export"]),
    "soc_analyst": ("SOC review", ["access:request", "inventory:read", "onboarding:read", "soc:read", "soc:review", "automation:read", "audit:read", "audit:investigate"]),
    "finops_analyst": ("Cost, budgets, forecasts and optimization",
                       ["assets:read", "ai:use", "access:request", "inventory:read", "finops:read", "finops:manage", "automation:read", "budget:read", "budget:manage", "reports:export"]),
    "access_admin": ("Access requests, reviews, extensions and revocations",
                     ["assets:read", "ai:use", "access:request", "inventory:read", "onboarding:read", "access:read", "access:manage", "reports:export"]),
    "governance_manager": ("Policies, approvals and compliance",
                           ["assets:read", "assets:configure", "ai:use", "access:request", "inventory:read", "onboarding:read", "automation:read", "vuln:read", "exception:request", "audit:read",
                            "sync:read", "governance:manage", "access:read", "access:approve", "budget:read", "budget:configure", "reports:export"]),
    "finance_approver": ("Financial approvals and budget revisions",
                         ["ai:use", "access:request", "inventory:read", "finops:read", "budget:read", "budget:approve", "reports:export"]),
    "exception_approver": ("Approve or reject risk exceptions", ["access:request", "inventory:read", "vuln:read", "exception:approve", "sync:read", "reports:export"]),
    "executive": ("Executive dashboards and reports (CISO, CTO, senior management)",
                  ["assets:read", "ai:use", "exec:read", "inventory:read", "onboarding:read", "automation:read", "finops:read", "infra:read", "vuln:read",
                   "audit:read", "sync:read", "budget:read", "access:read", "reports:export"]),
    "project_owner": ("Assigned accounts, subscriptions and projects only",
                      ["access:request", "inventory:read_assigned", "assets:read", "assets:edit", "vuln:read_assigned", "vuln:remediate", "exception:request"]),
    "cloud_engineer": ("Remediate assigned findings", ["assets:read", "access:request", "inventory:read", "vuln:read_assigned", "vuln:remediate", "exception:request"]),
    "infra_operator": ("Infrastructure monitoring", ["assets:read", "assets:edit", "access:request", "inventory:read", "onboarding:read", "infra:read", "automation:read", "automation:run"]),
    "auditor": ("Read-only security, audit and governance records, exports",
                ["assets:read", "ai:use", "inventory:read", "onboarding:read", "automation:read", "soc:read", "vuln:read", "audit:read", "sync:read",
                 "budget:read", "access:read", "reports:export"]),
    "viewer": ("Read-only dashboards", ["assets:read", "access:request", "inventory:read", "onboarding:read", "automation:read"]),
}
ROLES["admin"] = (ROLES["admin"][0], list(PERMISSIONS))
ROLE_LABELS = {"admin": "Super Admin", "cloud_admin": "Cloud Admin", "security_admin": "Security Admin", "security_analyst": "Security Analyst",
               "soc_analyst": "SOC Analyst", "finops_analyst": "FinOps Analyst", "access_admin": "Access Administrator",
               "governance_manager": "Governance Manager", "finance_approver": "Finance Approver", "exception_approver": "Exception Approver",
               "executive": "Executive / CISO", "project_owner": "Project Owner", "cloud_engineer": "Cloud Engineer",
               "infra_operator": "Infrastructure Operator", "auditor": "Auditor", "viewer": "Viewer"}


def assigned_scopes(user: User) -> set[tuple[str, str]]:
    """(provider, scope) pairs a scoped user (e.g. Project Owner) may see."""
    return {(a.provider, a.scope_external_id) for a in getattr(user, "scope_assignments", [])}


def scope_condition(model, user: User):
    """SQL condition limiting `model` (provider + scope_external_id columns) to the user's assigned scopes.
    Returns None when the user may see every scope. A scoped user with no assignment sees nothing."""
    from sqlalchemy import and_, false, or_

    if "inventory:read" in user.permission_names:
        return None
    pairs = assigned_scopes(user)
    if not pairs:
        return false()
    return or_(*[and_(model.provider == p, model.scope_external_id == s) for p, s in sorted(pairs)])


def _client(request: Request | None) -> tuple[str | None, str | None]:
    if request is None:
        return None, None
    ip = request.client.host if request.client else None
    return ip, (request.headers.get("user-agent") or "")[:255] or None


def create_session_token(email: str, settings: Settings, db: Session | None = None, *, request: Request | None = None,
                         method: str | None = None, auth_time: datetime | None = None) -> str:
    """Opens a server-side session and returns the signed cookie value that refers to it.

    The cookie carries only a random session ID (plus the e-mail for diagnostics); every request is checked against the
    session row, so logout, administrator revocation and expiry take effect immediately."""
    now = datetime.now(UTC)
    sid = secrets.token_urlsafe(32)
    expires = now + timedelta(minutes=settings.session_ttl_minutes)
    auth_time = auth_time or now
    hard_limit = auth_time + timedelta(minutes=settings.session_absolute_max_minutes)
    expires = min(expires, hard_limit)
    if db is not None:
        from app.models import UserSession

        user = db.scalar(select(User).where(User.email == email.lower()))
        if user is not None:
            ip, ua = _client(request)
            db.add(UserSession(session_id=sid, user_id=user.id, created_at=now, auth_time=auth_time, expires_at=expires, last_seen_at=now,
                               ip_address=ip, user_agent=ua, auth_method=method or settings.auth_mode))
            db.commit()
    payload = {"sub": email.lower(), "sid": sid, "iat": now, "exp": expires, "typ": "session"}
    return jwt.encode(payload, settings.secret_key, algorithm=_ALG)


def decode_token(token: str, settings: Settings, typ: str = "session") -> dict:
    data = jwt.decode(token, settings.secret_key, algorithms=[_ALG])
    if data.get("typ") != typ:
        raise jwt.InvalidTokenError("wrong token type")
    return data


def revoke_sessions(db: Session, user_id: int, reason: str, except_sid: str | None = None) -> int:
    """Ends every open session for a user (suspension, revocation, role change). Returns how many were ended."""
    from app.models import UserSession

    now = datetime.now(UTC)
    rows = db.scalars(select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None)))
    n = 0
    for r in rows:
        if r.session_id != except_sid:
            r.revoked_at, r.revoked_reason = now, reason
            n += 1
    return n


def access_problem(user: User, now: datetime | None = None) -> str | None:
    """Why a registered person may not use the application right now (None = allowed)."""
    now = now or datetime.now(UTC)
    if not user.is_active or user.access_status in ("SUSPENDED", "REVOKED"):
        return "disabled"
    if user.access_expires_at is not None and user.access_expires_at <= now:
        return "access_expired"
    return None


def upsert_user(db: Session, email: str, display_name: str | None, settings: Settings) -> User:
    email = email.lower()
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        is_admin = email in {e.lower() for e in settings.bootstrap_admin_emails} or (
            settings.auth_mode == "dev" and email == settings.dev_user_email.lower())
        role = db.scalar(select(Role).where(Role.name == ("admin" if is_admin else "viewer")))
        user = User(email=email, display_name=display_name, roles=[role] if role else [], authorized_at=datetime.now(UTC),
                    role_source="bootstrap" if is_admin else "allowlist", created_by="system:first-sign-in")
        db.add(user)
    elif display_name and not user.display_name:
        user.display_name = display_name
    user.last_login_at = datetime.now(UTC)
    db.commit()
    return user


def _session_user(db: Session, data: dict, settings: Settings) -> User | None:
    from app.models import UserSession

    sid = data.get("sid")
    if not sid:
        return None
    row = db.scalar(select(UserSession).where(UserSession.session_id == sid))
    now = datetime.now(UTC)
    if row is None or row.revoked_at is not None or row.expires_at <= now:
        return None
    if row.last_seen_at and row.last_seen_at + timedelta(minutes=settings.session_idle_minutes) <= now:
        row.revoked_at, row.revoked_reason = now, "idle_timeout"
        db.commit()
        return None
    user = db.get(User, row.user_id)
    if user is None or user.email != str(data.get("sub", "")).lower():
        return None
    if row.last_seen_at is None or (now - row.last_seen_at).total_seconds() > 60:  # limit writes to one a minute
        row.last_seen_at = now
        db.commit()
    return user


def current_user(request: Request, db: Session = Depends(get_db),
                 settings: Settings = Depends(get_settings)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        try:
            data = decode_token(token, settings)
        except jwt.PyJWTError:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired session") from None
        user = _session_user(db, data, settings)
        if user is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session has ended. Sign in again.")
    elif settings.auth_mode == "dev" and not request.cookies.get(SIGNED_OUT_COOKIE):
        user = upsert_user(db, settings.dev_user_email, "Local developer", settings)
    else:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    if user is None or access_problem(user):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User is not active")
    return user


def require(permission: str):
    """Dependency enforcing an RBAC permission, plus a CSRF header on state-changing requests."""

    def _dep(request: Request, user: User = Depends(current_user)) -> User:
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CSRF_HEADER) != CSRF_VALUE:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing CSRF header")
        if permission not in user.permission_names:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Missing permission: {permission}")
        return user

    return _dep


def audit(db: Session, actor: str, action: str, target: str | None = None, **detail) -> None:
    db.add(AdminAuditLog(actor=actor, action=action, target=target, detail=detail))
    from app.services.trail import record  # central tamper-evident trail (lazy import: avoids a model import cycle)
    category = action.split(".", 1)[0] if "." in action else "platform"
    record(db, category=category[:32], actor=actor, action=action, target=target, new_state=detail or None,
           approval_reference=str(detail.get("approval_reference") or detail.get("request_key") or "")[:64] or None)
