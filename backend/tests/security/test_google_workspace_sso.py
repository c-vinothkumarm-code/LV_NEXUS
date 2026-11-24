"""Google Workspace SSO acceptance tests: corporate-only access, provisioning registry, PKCE/state/nonce, server-side
sessions (logout, revocation, rotation, idle timeout, fixation), throttling, group role mapping and experiences."""
import base64
import hashlib
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

import app.api.routes.auth as auth
from app.api.routes.auth import EXTERNAL, NOT_PROVISIONED
from app.models import AccessAuditLog, Role, User, UserSession
from app.services.identity.google_groups import GroupLookupError, roles_for
from tests.conftest import use_settings

H = {"X-Requested-With": "mcp-dashboard"}
CID = "client-123.apps.googleusercontent.com"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJWKS:
    def get_signing_key_from_jwt(self, token):
        return type("K", (), {"key": KEY.public_key()})()


def gsettings(client, **kw):
    base = dict(auth_mode="google", google_oauth_client_id=CID, google_oauth_client_secret="not-a-real-secret",
                google_allowed_domain="latentview.com", secret_key="s" * 40, frontend_url="http://localhost:5173")
    base.update(kw)
    return use_settings(client, **base)


def id_token(nonce, key=KEY, **over):
    now = int(time.time())
    claims = {"iss": "https://accounts.google.com", "aud": CID, "sub": "1001", "iat": now, "exp": now + 600, "nonce": nonce,
              "email": "priya@latentview.com", "email_verified": True, "hd": "latentview.com", "name": "Priya"}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256")


@pytest.fixture()
def google(monkeypatch):
    """Replaces only the network: Google's token endpoint and published keys. All verification logic is real."""
    seen = {}
    monkeypatch.setattr(auth, "_google_jwks", lambda: FakeJWKS())

    def exchange(settings, code, verifier):
        seen["verifier"] = verifier
        return seen["make"](seen["nonce"])

    monkeypatch.setattr(auth, "_exchange", exchange)
    return seen


def sign_in(client, google, key=KEY, state_override=None, **claims):
    r = client.get("/api/v1/auth/login", follow_redirects=False)
    assert r.status_code == 307, r.text
    q = parse_qs(urlparse(r.headers["location"]).query)
    google["nonce"], google["challenge"] = q["nonce"][0], q["code_challenge"][0]
    drop_nonce = claims.pop("nonce", "keep") is None
    google["make"] = lambda nonce: id_token(None if drop_nonce else nonce, key=key, **claims)
    return client.get("/api/v1/auth/callback", params={"code": "auth-code", "state": state_override or q["state"][0],
                                                       "email": "attacker-chosen@latentview.com"}, follow_redirects=False)


def error_of(r):
    loc = r.headers.get("location", "")
    return parse_qs(urlparse(loc).query).get("error", [None])[0] if "/login?" in loc else None


def provision(db, email="priya@latentview.com", role="security_analyst", **kw):
    u = User(email=email, roles=[db.scalar(select(Role).where(Role.name == role))], created_by="admin@latentview.com", **kw)
    db.add(u)
    db.commit()
    return u


def test_login_request_uses_pkce_state_nonce_and_minimal_scopes(client):
    gsettings(client)
    r = client.get("/api/v1/auth/login", follow_redirects=False)
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["scope"] == ["openid email profile"] and q["code_challenge_method"] == ["S256"] and q["access_type"] == ["online"]
    assert len(q["state"][0]) >= 32 and len(q["nonce"][0]) >= 32 and q["hd"] == ["latentview.com"]
    assert "not-a-real-secret" not in r.headers["location"]
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    p = client.get("/api/v1/auth/providers").json()
    assert p["providers"][0]["label"] == "Sign in with Google Workspace" and p["messages"]["external_account"] == EXTERNAL


def test_provisioned_corporate_account_signs_in_with_pkce(client, db, google):
    gsettings(client)
    provision(db)
    r = sign_in(client, google)
    assert r.status_code == 303 and error_of(r) is None
    # the verifier sent to Google matches the challenge sent in the authorization request
    challenge = base64.urlsafe_b64encode(hashlib.sha256(google["verifier"].encode()).digest()).rstrip(b"=").decode()
    assert challenge == google["challenge"]
    me = client.get("/api/v1/auth/me").json()
    assert me["email"] == "priya@latentview.com" and me["roles"] == ["security_analyst"]
    u = db.scalar(select(User).where(User.email == "priya@latentview.com"))
    db.refresh(u)
    assert u.google_sub == "1001" and u.last_login_at is not None
    assert db.scalar(select(AccessAuditLog).where(AccessAuditLog.event == "login_success")) is not None


@pytest.mark.parametrize("claims,code", [
    ({"email": "someone@gmail.com", "hd": None}, "external_account"),
    ({"email": "priya@latentview.com", "hd": None}, "external_account"),         # corporate-looking e-mail, not a Workspace account
    ({"email": "priya@latentview.com", "hd": "latentview.co"}, "external_account"),
    ({"email": "priya@latentview.com.evil.io", "hd": "latentview.com"}, "external_account"),
    ({"email_verified": False}, "unverified_email"),
    ({"aud": "someone-elses-client"}, "invalid_token"),
    ({"iss": "https://evil.example.com"}, "invalid_token"),
    ({"exp": int(time.time()) - 600}, "invalid_token"),
    ({"nonce": None}, "invalid_token"),                                          # nonce is mandatory
])
def test_rejected_identities(client, db, google, claims, code):
    gsettings(client)
    provision(db)
    r = sign_in(client, google, **dict(claims))
    assert error_of(r) == code
    assert client.get("/api/v1/auth/me").status_code == 401
    assert db.scalar(select(AccessAuditLog).where(AccessAuditLog.event == "login_denied", AccessAuditLog.reason == code)) is not None


def test_forged_signature_and_state_mismatch(client, db, google):
    gsettings(client)
    provision(db)
    assert error_of(sign_in(client, google, key=OTHER_KEY)) == "invalid_token"
    assert error_of(sign_in(client, google, state_override="forged-state")) == "state_invalid"


def test_unprovisioned_corporate_account_gets_exact_message(client, db, google):
    gsettings(client)
    r = sign_in(client, google)
    assert error_of(r) == "not_provisioned"
    assert client.get("/api/v1/auth/providers").json()["messages"]["not_provisioned"] == NOT_PROVISIONED
    assert db.scalar(select(User).where(User.email == "priya@latentview.com")) is None  # a valid login grants nothing


def test_suspended_expired_and_rebound_accounts_are_denied(client, db, google):
    gsettings(client)
    u = provision(db, access_status="SUSPENDED", is_active=False)
    assert error_of(sign_in(client, google)) == "disabled"
    u.access_status, u.is_active, u.access_expires_at = "ACTIVE", True, datetime.now(UTC) - timedelta(days=1)
    db.commit()
    assert error_of(sign_in(client, google)) == "access_expired"
    u.access_expires_at, u.google_sub = None, "999-original-identity"
    db.commit()
    assert error_of(sign_in(client, google)) == "identity_mismatch"


def test_logout_revokes_server_session(client, db, google):
    gsettings(client)
    provision(db)
    sign_in(client, google)
    copied = client.cookies.get("mcp_session")
    assert client.post("/api/v1/auth/logout").status_code == 200
    client.cookies.set("mcp_session", copied)  # replaying the old cookie does not work
    assert client.get("/api/v1/auth/me").status_code == 401
    assert db.scalar(select(UserSession).where(UserSession.revoked_reason == "logout")) is not None


def test_admin_suspension_ends_open_sessions(client, db, google):
    gsettings(client)
    analyst = provision(db)
    provision(db, email="admin@latentview.com", role="admin")
    sign_in(client, google)
    analyst_cookie = client.cookies.get("mcp_session")
    sign_in(client, google, email="admin@latentview.com", sub="2002")
    r = client.patch(f"/api/v1/admin/users/{analyst.id}", json={"access_status": "SUSPENDED"}, headers=H)
    assert r.status_code == 200 and r.json()["access_status"] == "SUSPENDED"
    client.cookies.set("mcp_session", analyst_cookie)
    assert client.get("/api/v1/auth/me").status_code == 401


def test_session_fixation_rotation_and_idle_timeout(client, db, google):
    s = gsettings(client)
    provision(db)
    sign_in(client, google)
    first = client.cookies.get("mcp_session")
    sign_in(client, google)  # signing in again with an existing cookie issues a new session and ends the old one
    second = client.cookies.get("mcp_session")
    assert first != second
    assert db.scalar(select(UserSession).where(UserSession.revoked_reason == "replaced_at_sign_in")) is not None
    r = client.post("/api/v1/auth/renew", headers=H)
    assert r.status_code == 200 and client.cookies.get("mcp_session") != second
    client.cookies.set("mcp_session", second)
    assert client.get("/api/v1/auth/me").status_code == 401  # the pre-rotation ID no longer works
    assert client.post("/api/v1/auth/renew").status_code in (401, 403)  # CSRF header required
    # idle timeout
    sign_in(client, google)
    row = db.scalars(select(UserSession).where(UserSession.revoked_at.is_(None))).all()[-1]
    row.last_seen_at = datetime.now(UTC) - timedelta(minutes=s.session_idle_minutes + 1)
    db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_throttling_after_repeated_failures(client, db, google):
    gsettings(client, auth_throttle_failures=3)
    for _ in range(3):
        assert error_of(sign_in(client, google, email="x@gmail.com", hd=None)) == "external_account"
    r = client.get("/api/v1/auth/login", follow_redirects=False)
    assert error_of(r) == "throttled"


def test_group_role_mapping_is_server_side_and_fails_closed(client, db, google, monkeypatch):
    import app.services.identity.google_groups as gg

    s = gsettings(client, google_group_lookup_enabled=True, google_group_role_map=["cxo@latentview.com=executive"],
                  google_workspace_admin_groups=["platform-admins@latentview.com"])
    assert roles_for("a@latentview.com", s, lambda e: {"cxo@latentview.com", "all@latentview.com"})[0] == ["executive"]
    assert roles_for("a@latentview.com", s, lambda e: {"platform-admins@latentview.com"})[0] == ["admin"]
    monkeypatch.setattr(gg, "lookup_groups", lambda email: {"cxo@latentview.com"})
    assert error_of(sign_in(client, google)) is None
    u = db.scalar(select(User).where(User.email == "priya@latentview.com"))
    assert [r.name for r in u.roles] == ["executive"] and u.role_source == "google_group:cxo@latentview.com"
    me = client.get("/api/v1/auth/me").json()
    assert me["role_labels"] == ["Executive / CISO"]
    assert client.get("/api/v1/admin/users").status_code == 403

    def broken(email):
        raise GroupLookupError("403")

    monkeypatch.setattr(gg, "lookup_groups", broken)
    assert error_of(sign_in(client, google)) == "not_provisioned"  # lookup failure never grants or keeps group roles


def test_admin_provisioning_registry(client, db):
    gsettings(client)
    admin = provision(db, email="admin@latentview.com", role="admin")
    from app.core.security import create_session_token
    client.cookies.set("mcp_session", create_session_token(admin.email, use_settings(client, **gsettings(client).model_dump()), db))
    r = client.post("/api/v1/admin/users", json={"email": "New.Person@LatentView.com", "role": "finops_analyst",
                                                 "access_expires_at": (datetime.now(UTC) + timedelta(days=90)).isoformat()}, headers=H)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["email"] == "new.person@latentview.com" and body["created_by"] == "admin@latentview.com" and body["access_expires_at"]
    assert client.post("/api/v1/admin/users", json={"email": "x@gmail.com", "role": "viewer"}, headers=H).status_code == 422
    assert client.post("/api/v1/admin/users", json={"email": "new.person@latentview.com", "role": "viewer"}, headers=H).status_code == 409
    log = client.get("/api/v1/admin/access-log").json()
    assert "failures_24h" in log
