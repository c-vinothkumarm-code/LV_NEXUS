"""Sign-in: Google Workspace (OpenID Connect, Authorization Code + PKCE), Microsoft Entra ID, or a local developer
session (AUTH_MODE=dev, never in production).

Every identity check happens here, on the server, against a signature-verified ID token: issuer, audience, expiry,
nonce, state, PKCE, `email_verified`, the Workspace `hd` claim and the e-mail domain. A verified corporate identity
grants nothing by itself: the person must be provisioned in the access registry (or be a member of a mapped Google
group, read server-side). Sessions are server-side rows referenced by an HttpOnly, SameSite cookie; the browser never
receives an identity-provider token or client secret, and Google access/refresh tokens are not kept."""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.security import (
    CSRF_HEADER,
    CSRF_VALUE,
    ROLE_LABELS,
    SESSION_COOKIE,
    SIGNED_OUT_COOKIE,
    _client,
    access_problem,
    audit,
    create_session_token,
    current_user,
    decode_token,
    revoke_sessions,
    upsert_user,
)
from app.database.session import get_db
from app.models import AccessAuditLog, Role, User, UserSession

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
_STATE_COOKIE = "mcp_oauth_state"
_GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"  # noqa: S105 - endpoint URL, not a secret
_GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs"
_GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
_ENTRA = "https://login.microsoftonline.com/{tenant}"

EXTERNAL = "Access denied. This application is restricted to authorized LatentView corporate accounts."
NOT_PROVISIONED = ("Your LatentView Google Workspace account has been successfully authenticated, but application access has not "
                   "been provisioned. Please contact the platform administrator.")
MESSAGES = {
    "external_account": EXTERNAL,
    "unverified_email": EXTERNAL,
    "not_provisioned": NOT_PROVISIONED,
    "disabled": "Your access to this application has been suspended or revoked. Please contact the platform administrator.",
    "access_expired": "Your access to this application has expired. Please contact the platform administrator.",
    "identity_mismatch": "This sign-in does not match the Google identity registered for this account. Please contact the platform administrator.",
    "invalid_token": "Your sign-in could not be verified. Please start again from the sign-in page.",
    "state_invalid": "Your sign-in session expired or could not be verified. Please start again from the sign-in page.",
    "idp_error": "Sign-in was cancelled or failed at Google. Please try again.",
    "throttled": "Too many unsuccessful sign-in attempts from this network. Please wait a few minutes and try again.",
    "session_expired": "Your session has ended. Please sign in again.",
}


class AuthDenied(Exception):
    def __init__(self, code: str, email: str | None = None, sub: str | None = None):
        super().__init__(code)
        self.code, self.email, self.sub = code, email, sub


@dataclass
class Identity:
    email: str
    name: str | None
    sub: str | None


def _callback_url(settings: Settings) -> str:
    """Where the identity provider returns the browser. GOOGLE_REDIRECT_URI when set (validated at start-up), otherwise
    FRONTEND_URL — never the incoming request's host, which a proxy or attacker can change."""
    if settings.auth_mode == "google" and settings.google_redirect_uri:
        return settings.google_redirect_uri.rstrip("/")
    return f"{settings.frontend_url.rstrip('/')}/api/v1/auth/callback"


def _secure(settings: Settings) -> bool:
    return settings.app_env == "production"


def _login_page(settings: Settings, code: str) -> RedirectResponse:
    return RedirectResponse(f"{settings.frontend_url.rstrip('/')}/login?{urlencode({'error': code})}", status_code=303)


def _set_session(resp, token: str, settings: Settings) -> None:
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax", secure=_secure(settings),
                    max_age=settings.session_ttl_minutes * 60, path="/")
    resp.delete_cookie(SIGNED_OUT_COOKIE, path="/")


def _record(db: Session, request: Request | None, event: str, reason: str | None = None, email: str | None = None,
            sub: str | None = None) -> None:
    ip, ua = _client(request)
    db.add(AccessAuditLog(event=event, reason=reason, email=email, google_sub=sub, ip_address=ip, user_agent=ua))
    db.commit()


def _throttled(db: Session, request: Request, settings: Settings) -> bool:
    ip, _ = _client(request)
    if not ip:
        return False
    since = datetime.now(UTC) - timedelta(minutes=settings.auth_throttle_window_minutes)
    n = db.scalar(select(func.count()).select_from(AccessAuditLog).where(
        AccessAuditLog.ip_address == ip, AccessAuditLog.event == "login_denied", AccessAuditLog.created_at >= since))
    return (n or 0) >= settings.auth_throttle_failures


def provider_ready(settings: Settings) -> bool:
    if settings.auth_mode == "google":
        return bool(settings.google_oauth_client_id and settings.google_oauth_client_secret and settings.corporate_domains)
    if settings.auth_mode == "entra":
        return bool(settings.entra_tenant_id and settings.entra_client_id and settings.entra_client_secret and settings.allowed_email_domains)
    return settings.auth_mode == "dev"


@router.get("/providers")
def providers(settings: Settings = Depends(get_settings)):
    """What the login page may offer. Only working, configured flows are listed (no decorative buttons)."""
    labels = {"dev": "Continue as local developer", "google": "Sign in with Google Workspace", "entra": "Sign in with Microsoft"}
    ready = provider_ready(settings)
    return {"mode": settings.auth_mode, "environment": settings.app_env, "app_name": settings.app_name,
            "session_minutes": settings.session_ttl_minutes, "messages": MESSAGES,
            "providers": [{"id": settings.auth_mode, "label": labels[settings.auth_mode], "url": "/api/v1/auth/login"}] if ready else [],
            "problem": None if ready else f"Sign-in is not fully configured for AUTH_MODE={settings.auth_mode}. "
                                          "Set the client ID, client secret and the allowed corporate domain."}


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)  # 86 characters, within RFC 7636's 43-128
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@router.get("/login")
def login(request: Request, settings: Settings = Depends(get_settings), db: Session = Depends(get_db)):
    if settings.auth_mode == "dev":
        user = upsert_user(db, settings.dev_user_email, "Local developer", settings)
        resp = RedirectResponse(settings.frontend_url)
        _set_session(resp, create_session_token(user.email, settings, db, request=request, method="dev"), settings)
        return resp
    if not provider_ready(settings):
        name = "Microsoft Entra ID" if settings.auth_mode == "entra" else "Google Workspace sign-in"
        raise HTTPException(503, f"{name} is not configured")
    if _throttled(db, request, settings):
        _record(db, request, "throttled", "too_many_failures")
        return _login_page(settings, "throttled")
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = _pkce()
    cookie = jwt.encode({"s": state, "n": nonce, "v": verifier, "p": settings.auth_mode, "typ": "oauth_state",
                         "exp": datetime.now(UTC) + timedelta(minutes=10)}, settings.secret_key, algorithm="HS256")
    common = {"redirect_uri": _callback_url(settings), "response_type": "code", "scope": "openid email profile",
              "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account"}
    if settings.auth_mode == "entra":
        url = f"{_ENTRA.format(tenant=settings.entra_tenant_id)}/oauth2/v2.0/authorize?" + urlencode(
            {"client_id": settings.entra_client_id, "response_mode": "query", **common})
    else:
        # `hd` only pre-selects the Workspace account in Google's chooser; it is NOT trusted. The `hd` claim in the
        # verified ID token is checked in the callback. access_type=online: no refresh token is ever issued.
        url = f"{_GOOGLE_AUTH}?" + urlencode({"client_id": settings.google_oauth_client_id, "access_type": "online",
                                              "hd": sorted(settings.corporate_domains)[0], **common})
    resp = RedirectResponse(url)
    resp.set_cookie(_STATE_COOKIE, cookie, httponly=True, samesite="lax", secure=_secure(settings), max_age=600, path="/api/v1/auth")
    return resp


@lru_cache(maxsize=4)
def _entra_jwks(tenant: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(f"{_ENTRA.format(tenant=tenant)}/discovery/v2.0/keys", cache_keys=True, lifespan=3600)


@lru_cache(maxsize=1)
def _google_jwks() -> jwt.PyJWKClient:
    return jwt.PyJWKClient(_GOOGLE_JWKS, cache_keys=True, lifespan=3600)


def verify_entra_id_token(token: str, settings: Settings, nonce: str, jwks: jwt.PyJWKClient | None = None) -> dict:
    """Signature (tenant JWKS), audience, issuer, tenant, expiry and nonce are all checked."""
    tenant = settings.entra_tenant_id
    key = (jwks or _entra_jwks(tenant)).get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], audience=settings.entra_client_id,
                        issuer=f"{_ENTRA.format(tenant=tenant)}/v2.0", options={"require": ["exp", "iat", "aud", "iss"]})
    if claims.get("tid") != tenant:
        raise jwt.InvalidTokenError("token is from a different tenant")
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
        raise jwt.InvalidTokenError("nonce mismatch")
    return claims


def verify_google_id_token(token: str, settings: Settings, nonce: str, jwks: jwt.PyJWKClient | None = None) -> dict:
    """Signature against Google's published keys, audience (our client ID), issuer, expiry, issued-at, subject and
    nonce. Domain and verification checks follow in _identity."""
    key = (jwks or _google_jwks()).get_signing_key_from_jwt(token).key
    claims = jwt.decode(token, key, algorithms=["RS256"], audience=settings.google_oauth_client_id,
                        options={"require": ["exp", "iat", "aud", "iss", "sub"]}, leeway=30)
    if claims.get("iss") not in _GOOGLE_ISSUERS:
        raise jwt.InvalidIssuerError("unexpected issuer")
    if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):  # mandatory: a missing nonce fails
        raise jwt.InvalidTokenError("nonce mismatch")
    return claims


def _exchange(settings: Settings, code: str, verifier: str) -> str:
    if settings.auth_mode == "entra":
        url = f"{_ENTRA.format(tenant=settings.entra_tenant_id)}/oauth2/v2.0/token"
        data = {"client_id": settings.entra_client_id, "client_secret": settings.entra_client_secret, "scope": "openid email profile"}
    else:
        url = _GOOGLE_TOKEN
        data = {"client_id": settings.google_oauth_client_id, "client_secret": settings.google_oauth_client_secret}
    try:
        resp = httpx.post(url, timeout=15, data={**data, "code": code, "code_verifier": verifier, "redirect_uri": _callback_url(settings),
                                                 "grant_type": "authorization_code"})
        body = resp.json()
    except (httpx.HTTPError, ValueError):
        raise AuthDenied("idp_error") from None
    if resp.status_code != 200 or "id_token" not in body:
        raise AuthDenied("idp_error")
    return body["id_token"]  # the access token in `body` is discarded, never stored


def _identity(settings: Settings, id_token: str, nonce: str, jwks: jwt.PyJWKClient | None = None) -> Identity:
    try:
        if settings.auth_mode == "entra":
            claims = verify_entra_id_token(id_token, settings, nonce, jwks)
            email = claims.get("email") or claims.get("preferred_username") or claims.get("upn") or ""
            verified, hd_ok, sub = True, True, claims.get("oid") or claims.get("sub")  # tenant check restricts to the directory
        else:
            claims = verify_google_id_token(id_token, settings, nonce, jwks)
            email, sub = claims.get("email") or "", claims.get("sub")
            verified = claims.get("email_verified") is True or claims.get("email_verified") == "true"
            hd_ok = str(claims.get("hd", "")).lower() in settings.corporate_domains  # Workspace account of our domain
    except jwt.PyJWTError:
        raise AuthDenied("invalid_token") from None
    email = email.strip().lower()
    domain_ok = "@" in email and email.rsplit("@", 1)[-1] in {d.lower() for d in (settings.corporate_domains if settings.auth_mode == "google"
                                                                                   else settings.allowed_email_domains)}
    if not domain_ok or not hd_ok:
        raise AuthDenied("external_account", email, sub)
    if not verified:
        raise AuthDenied("unverified_email", email, sub)
    return Identity(email, claims.get("name"), sub)


def _authorize(db: Session, settings: Settings, ident: Identity, group_lookup=None) -> User:
    """Access registry decision. Raises AuthDenied; returns the user (with roles) when access is granted."""
    from app.services.identity.google_groups import lookup_groups, roles_for

    user = db.scalar(select(User).where(User.email == ident.email))
    bootstrap = ident.email in {e.lower() for e in settings.bootstrap_admin_emails}
    group_roles, group, lookup_error = ([], None, None)
    if settings.auth_mode == "google" and (user is None or user.role_source.startswith("google_group")):
        group_roles, group, lookup_error = roles_for(ident.email, settings, group_lookup or lookup_groups)
    now = datetime.now(UTC)
    if user is None:
        if not (bootstrap or group_roles or settings.auth_auto_provision):
            raise AuthDenied("not_provisioned", ident.email, ident.sub)
        names = ["admin"] if bootstrap else (group_roles or ["viewer"])
        user = User(email=ident.email, display_name=ident.name, authorized_at=now,
                    roles=list(db.scalars(select(Role).where(Role.name.in_(names)))),
                    role_source="bootstrap" if bootstrap else (f"google_group:{group}" if group_roles else "allowlist"),
                    created_by="system:bootstrap" if bootstrap else ("system:google-group" if group_roles else "system:auto-provision"))
        db.add(user)
        db.flush()
        audit(db, user.created_by, "user.provisioned", user.email, roles=names, source=user.role_source)
    elif user.role_source.startswith("google_group"):
        if lookup_error or not group_roles:  # fail closed: group roles are only granted on a successful, matching lookup
            raise AuthDenied("not_provisioned", ident.email, ident.sub)
        if sorted(r.name for r in user.roles) != group_roles:
            audit(db, "system:google-group", "user.roles_synced", user.email, roles=group_roles, group=group)
            user.roles = list(db.scalars(select(Role).where(Role.name.in_(group_roles))))
            user.role_source = f"google_group:{group}"
    problem = access_problem(user, now)
    if problem:
        raise AuthDenied(problem, ident.email, ident.sub)
    if ident.sub:
        if user.google_sub is None:
            user.google_sub = ident.sub  # bound at first sign-in; a recycled or re-created account will not match
        elif user.google_sub != ident.sub:
            raise AuthDenied("identity_mismatch", ident.email, ident.sub)
    if not user.roles:
        raise AuthDenied("not_provisioned", ident.email, ident.sub)
    if ident.name and not user.display_name:
        user.display_name = ident.name
    user.last_login_at = now
    return user


@router.get("/callback", name="oauth_callback")
def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None,
             settings: Settings = Depends(get_settings), db: Session = Depends(get_db)):
    try:
        if _throttled(db, request, settings):
            _record(db, request, "throttled", "too_many_failures")
            return _login_page(settings, "throttled")
        try:
            saved = decode_token(request.cookies.get(_STATE_COOKIE, ""), settings, typ="oauth_state")
        except jwt.PyJWTError:
            raise AuthDenied("state_invalid") from None
        if saved.get("p") != settings.auth_mode or not state or not secrets.compare_digest(str(saved.get("s", "")), state):
            raise AuthDenied("state_invalid")
        if error or not code:
            raise AuthDenied("idp_error")
        ident = _identity(settings, _exchange(settings, code, saved["v"]), saved["n"])
        user = _authorize(db, settings, ident)
        db.commit()
    except AuthDenied as denied:
        db.rollback()
        _record(db, request, "login_denied", denied.code, denied.email, denied.sub)
        resp = _login_page(settings, denied.code)
        resp.delete_cookie(_STATE_COOKIE, path="/api/v1/auth")
        return resp
    # session fixation protection: any session presented with this browser is ended and a fresh ID is issued
    old = request.cookies.get(SESSION_COOKIE)
    if old:
        try:
            sid = decode_token(old, settings).get("sid")
            row = db.scalar(select(UserSession).where(UserSession.session_id == sid)) if sid else None
            if row and row.revoked_at is None:
                row.revoked_at, row.revoked_reason = datetime.now(UTC), "replaced_at_sign_in"
        except jwt.PyJWTError:
            pass
    audit(db, user.email, "login", via=settings.auth_mode)
    db.commit()
    _record(db, request, "login_success", None, user.email, ident.sub)
    resp = RedirectResponse(settings.frontend_url, status_code=303)
    _set_session(resp, create_session_token(user.email, settings, db, request=request, method=settings.auth_mode), settings)
    resp.delete_cookie(_STATE_COOKIE, path="/api/v1/auth")
    return resp


def _session_row(request: Request, settings: Settings, db: Session) -> UserSession | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    try:
        sid = decode_token(token, settings).get("sid")
    except jwt.PyJWTError:
        return None
    return db.scalar(select(UserSession).where(UserSession.session_id == sid)) if sid else None


@router.post("/logout")
def logout(request: Request, settings: Settings = Depends(get_settings), db: Session = Depends(get_db)):
    """Ends the session server-side (the row is revoked, so a copied cookie stops working) and removes the cookie."""
    row = _session_row(request, settings, db)
    if row and row.revoked_at is None:
        row.revoked_at, row.revoked_reason = datetime.now(UTC), "logout"
        user = db.get(User, row.user_id)
        audit(db, user.email if user else "unknown", "logout")
        db.commit()
        _record(db, request, "logout", None, user.email if user else None)
    resp = JSONResponse({"status": "signed_out"})
    resp.delete_cookie(SESSION_COOKIE, path="/", secure=_secure(settings), httponly=True, samesite="lax")
    if settings.auth_mode == "dev":
        resp.set_cookie(SIGNED_OUT_COOKIE, "1", httponly=True, samesite="lax", secure=_secure(settings), max_age=7 * 24 * 3600, path="/")
    return resp


@router.post("/renew")
def renew(request: Request, user: User = Depends(current_user), settings: Settings = Depends(get_settings), db: Session = Depends(get_db)):
    """Session renewal with rotation: a new session ID replaces the old one, never beyond the absolute sign-in limit."""
    if request.headers.get(CSRF_HEADER) != CSRF_VALUE:
        raise HTTPException(403, "Missing CSRF header")
    row = _session_row(request, settings, db)
    if row is None:  # dev auto-session without a cookie
        resp = JSONResponse({"status": "renewed"})
        _set_session(resp, create_session_token(user.email, settings, db, request=request), settings)
        return resp
    if row.auth_time + timedelta(minutes=settings.session_absolute_max_minutes) <= datetime.now(UTC) + timedelta(minutes=1):
        raise HTTPException(401, "The maximum session length has been reached. Sign in again.")
    row.revoked_at, row.revoked_reason = datetime.now(UTC), "rotated"
    db.commit()
    token = create_session_token(user.email, settings, db, request=request, method=row.auth_method, auth_time=row.auth_time)
    resp = JSONResponse({"status": "renewed", "session_expires_at": datetime.fromtimestamp(decode_token(token, settings)["exp"], UTC).isoformat()})
    _set_session(resp, token, settings)
    return resp


@router.get("/me")
def me(request: Request, user: User = Depends(current_user), settings: Settings = Depends(get_settings), db: Session = Depends(get_db)):
    row = _session_row(request, settings, db)
    return {"email": user.email, "display_name": user.display_name, "roles": [r.name for r in user.roles],
            "permissions": sorted(user.permission_names), "auth_mode": settings.auth_mode, "app_name": settings.app_name,
            "role_labels": [ROLE_LABELS.get(r.name, r.name) for r in user.roles], "session_minutes": settings.session_ttl_minutes,
            "session_idle_minutes": settings.session_idle_minutes,
            "session_expires_at": row.expires_at.isoformat() if row else None,
            "access_expires_at": user.access_expires_at.isoformat() if user.access_expires_at else None}


__all__ = ["router", "MESSAGES", "AuthDenied", "Identity", "provider_ready", "revoke_sessions"]
