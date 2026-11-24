"""Sign-in, sign-out, session expiry, Entra ID token checks and user access management."""
import time
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from app.api.routes.auth import AuthDenied, Identity, _identity, verify_entra_id_token
from app.core.config import Settings
from app.core.security import create_session_token
from app.models import AdminAuditLog, Role, User
from tests.conftest import use_settings

H = {"X-Requested-With": "mcp-dashboard"}
TENANT, CLIENT = "11111111-2222-3333-4444-555555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJWKS:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, token):
        return type("K", (), {"key": self.key})()


def entra_settings(**kw):
    return Settings(_env_file=None, auth_mode="entra", entra_tenant_id=TENANT, entra_client_id=CLIENT, entra_client_secret="s",
                    allowed_email_domains=["latentview.com"], **kw)


def token(**over):
    now = int(time.time())
    claims = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "aud": CLIENT, "tid": TENANT, "iat": now, "exp": now + 600,
              "nonce": "n1", "preferred_username": "Analyst@LatentView.com", "name": "Analyst"}
    claims.update(over)
    return jwt.encode(claims, KEY, algorithm="RS256")


def test_entra_token_checks():
    s, jwks = entra_settings(), FakeJWKS(KEY.public_key())
    assert verify_entra_id_token(token(), s, "n1", jwks)["tid"] == TENANT
    bad = [token(aud="someone-else"), token(iss="https://login.microsoftonline.com/other/v2.0"), token(tid="other-tenant"),
           token(nonce="replayed"), token(exp=int(time.time()) - 10)]
    for t in bad:
        with pytest.raises(jwt.PyJWTError):
            verify_entra_id_token(t, s, "n1", jwks)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(jwt.PyJWTError):  # signed by someone else
        verify_entra_id_token(jwt.encode(jwt.decode(token(), options={"verify_signature": False}), other_key, algorithm="RS256"), s, "n1", jwks)


def test_entra_identity_enforces_domain(monkeypatch):
    import app.api.routes.auth as auth

    s = entra_settings()
    monkeypatch.setattr(auth, "_entra_jwks", lambda tenant: FakeJWKS(KEY.public_key()))
    assert _identity(s, token(), "n1") == Identity("analyst@latentview.com", "Analyst", None)
    with pytest.raises(AuthDenied) as e:
        _identity(s, token(preferred_username="outsider@gmail.com"), "n1")
    assert e.value.code == "external_account"
    with pytest.raises(AuthDenied) as e:
        _identity(s, token(nonce="x"), "n1")
    assert e.value.code == "invalid_token"


def test_entra_login_redirect_and_providers(client):
    use_settings(client, **entra_settings(frontend_url="http://localhost:5173").model_dump())
    p = client.get("/api/v1/auth/providers").json()
    assert p["providers"] == [{"id": "entra", "label": "Sign in with Microsoft", "url": "/api/v1/auth/login"}] and p["problem"] is None
    r = client.get("/api/v1/auth/login", follow_redirects=False)
    loc = r.headers["location"]
    assert loc.startswith(f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize?") and f"client_id={CLIENT}" in loc
    assert "nonce=" in loc and "code_challenge_method=S256" in loc and "redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fapi%2Fv1%2Fauth%2Fcallback" in loc and "client_secret" not in loc
    assert "httponly" in r.headers["set-cookie"].lower()


def test_unconfigured_provider_offers_no_button(client):
    use_settings(client, auth_mode="entra")
    p = client.get("/api/v1/auth/providers").json()
    assert p["providers"] == [] and "not fully configured" in p["problem"]
    assert client.get("/api/v1/auth/login", follow_redirects=False).status_code == 503


def test_callback_rejects_forged_or_expired_state(client):
    use_settings(client, **entra_settings().model_dump())
    r = client.get("/api/v1/auth/callback", params={"code": "c", "state": "s"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("/login?error=state_invalid")
    s = entra_settings()
    old = jwt.encode({"s": "s", "n": "n", "v": "v", "p": "entra", "typ": "oauth_state", "exp": datetime.now(UTC) - timedelta(minutes=1)},
                     s.secret_key, algorithm="HS256")
    client.cookies.set("mcp_oauth_state", old)
    r = client.get("/api/v1/auth/callback", params={"code": "c", "state": "s"}, follow_redirects=False)
    assert r.headers["location"].endswith("/login?error=state_invalid")


def test_dev_logout_really_signs_out(client, db):
    assert client.get("/api/v1/auth/me").status_code == 200
    r = client.post("/api/v1/auth/logout")
    assert r.status_code == 200 and "mcp_signed_out" in r.headers["set-cookie"]
    assert client.get("/api/v1/auth/me").status_code == 401  # no silent re-login after sign-out
    assert client.get("/api/v1/auth/login", follow_redirects=False).status_code == 307
    assert client.get("/api/v1/auth/me").status_code == 200  # signing in again works


def test_expired_session_is_rejected(client):
    s = use_settings(client, auth_mode="entra", session_ttl_minutes=-1)
    client.cookies.set("mcp_session", create_session_token("dev-admin@localhost", s))
    assert client.get("/api/v1/auth/me").status_code == 401


def test_admin_can_manage_access_and_is_audited(client, db):
    viewer = User(email="new@example.com", roles=[db.scalar(select(Role).where(Role.name == "viewer"))])
    db.add(viewer)
    db.commit()
    users = client.get("/api/v1/admin/users").json()
    assert {u["email"] for u in users["items"]} >= {"new@example.com", "dev-admin@localhost"} and len(users["roles"]) == 16
    r = client.patch(f"/api/v1/admin/users/{viewer.id}", json={"role": "soc_analyst"}, headers=H)
    assert r.status_code == 200 and r.json()["roles"] == ["soc_analyst"]
    assert client.patch(f"/api/v1/admin/users/{viewer.id}", json={"role": "superuser"}, headers=H).status_code == 422
    me = db.scalar(select(User).where(User.email == "dev-admin@localhost"))
    assert client.patch(f"/api/v1/admin/users/{me.id}", json={"is_active": False}, headers=H).status_code == 409
    assert client.patch(f"/api/v1/admin/users/{viewer.id}", json={"is_active": False}, headers=H).json()["is_active"] is False
    assert db.scalar(select(AdminAuditLog).where(AdminAuditLog.action == "user.update")) is not None
    assert len(client.get("/api/v1/admin/audit").json()["items"]) >= 2


def test_viewer_cannot_manage_users(client, db):
    s = use_settings(client, auth_mode="entra")
    db.add(User(email="v@example.com", roles=[db.scalar(select(Role).where(Role.name == "viewer"))]))
    db.commit()
    client.cookies.set("mcp_session", create_session_token("v@example.com", s, db))
    assert client.get("/api/v1/admin/users").status_code == 403
    assert client.patch("/api/v1/admin/users/1", json={"role": "admin"}, headers=H).status_code == 403


def test_invalid_auth_mode_is_rejected():
    with pytest.raises(ValueError):
        Settings(_env_file=None, auth_mode="saml")
