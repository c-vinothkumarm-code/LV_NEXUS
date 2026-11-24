import ast
import pathlib
import re

from app.core.security import create_session_token
from app.models import Role, User
from tests.conftest import use_settings

H = {"X-Requested-With": "mcp-dashboard"}
APP = pathlib.Path(__file__).resolve().parents[2] / "app"
READ_ONLY_PREFIXES = ("describe_", "list_", "get_", "lookup_", "assume_role", "test_iam_permissions", "batch_get_",
                      "search_", "usage", "paginate", "refresh", "fetch_id_token", "credential", "credentials")
MUTATING = re.compile(r"^(create|delete|put|update|modify|attach|detach|terminate|stop|start|reboot|revoke|authorize|"
                      r"set_iam_policy|set|remove|add|enable|disable|begin_|patch|insert|undelete|move)_?")


def test_unauthenticated_requests_are_rejected(client):
    use_settings(client, auth_mode="google")
    for path in ("/api/v1/dashboard/overview", "/api/v1/inventory/scopes", "/api/v1/onboarding/tasks", "/api/v1/auth/me"):
        assert client.get(path).status_code == 401
    assert client.post("/api/v1/jobs/account_discovery/run", headers=H).status_code == 401
    assert client.get("/health").status_code == 200


def test_forged_session_cookie_is_rejected(client):
    s = use_settings(client, auth_mode="google")
    forged = create_session_token("attacker@example.com", s.model_copy(update={"secret_key": "another-key"}))
    client.cookies.set("mcp_session", forged)
    assert client.get("/api/v1/auth/me").status_code == 401


def test_viewer_cannot_approve_run_jobs_or_see_soc_and_finops(client, db):
    s = use_settings(client, auth_mode="google")
    db.add(User(email="viewer@example.com", roles=[db.query(Role).filter_by(name="viewer").one()]))
    db.commit()
    client.cookies.set("mcp_session", create_session_token("viewer@example.com", s, db))
    assert client.get("/api/v1/inventory/scopes").status_code == 200
    assert client.get("/api/v1/dashboard/soc").status_code == 403
    assert client.get("/api/v1/dashboard/finops").status_code == 403
    assert client.post("/api/v1/jobs/account_discovery/run", headers=H).status_code == 403
    assert client.post("/api/v1/onboarding/tasks/1/decision", json={"decision": "approved"}, headers=H).status_code == 403
    assert client.patch("/api/v1/inventory/scopes/aws/1", json={"monitoring_enabled": False}, headers=H).status_code == 403


def test_deactivated_user_loses_access(client, db):
    s = use_settings(client, auth_mode="google")
    db.add(User(email="gone@example.com", is_active=False))
    db.commit()
    client.cookies.set("mcp_session", create_session_token("gone@example.com", s, db))
    assert client.get("/api/v1/auth/me").status_code == 401


def test_prerequisites_never_expose_secret_values(client):
    use_settings(client, azure_client_secret="very-secret-value", aws_external_id="ext-secret", azure_enabled=True)
    body = client.get("/api/v1/prerequisites").text
    assert "very-secret-value" not in body and "ext-secret" not in body


def test_pubsub_endpoint_requires_configuration_and_token(client):
    assert client.post("/api/v1/events/pubsub").status_code == 503
    use_settings(client, pubsub_push_audience="https://example.test/push")
    assert client.post("/api/v1/events/pubsub").status_code == 401
    assert client.post("/api/v1/events/pubsub", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


def test_security_headers(client):
    r = client.get("/api/v1/auth/me")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["cache-control"] == "no-store"


def _cloud_calls(path: pathlib.Path) -> set[str]:
    """Method names invoked on cloud SDK objects in a connector module."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def test_connectors_make_only_read_only_cloud_calls():
    """Guards the READ-ONLY operating mode: connector code must not call any mutating SDK method."""
    paths = list((APP / "services").rglob("connector.py")) + list((APP / "services").rglob("collectors.py"))
    assert len(paths) >= 6
    for path in paths:
        offenders = {n for n in _cloud_calls(path) if MUTATING.match(n) and not n.startswith(READ_ONLY_PREFIXES)}
        offenders -= {"add", "update", "setdefault", "startswith", "set_cookie"}  # python builtins, not SDK calls
        assert not offenders, f"{path.name}: possible mutating cloud calls {offenders}"


def test_no_hardcoded_cloud_ids_or_static_keys_in_source():
    root = APP.parent.parent
    patterns = {"aws access key": re.compile(r"AKIA[0-9A-Z]{16}"), "12-digit id": re.compile(r"(?<![\d.])\d{12,13}(?![\d.])"),
                "private key": re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
                "static aws key setting": re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"]")}
    for path in list(APP.rglob("*.py")) + [root / ".env.example", root / "docker-compose.yml"]:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for label, pat in patterns.items():
            assert not pat.search(text), f"{label} found in {path}"


def test_google_login_uses_frontend_url_for_the_callback(client):
    """Behind the dev proxy the request host is the API's; the redirect URI must still be the public address."""
    use_settings(client, auth_mode="google", google_oauth_client_id="cid", google_oauth_client_secret="sec",
                 frontend_url="http://localhost:5173", allowed_email_domains=["example.com"])
    r = client.get("/api/v1/auth/login", headers={"host": "127.0.0.1:8000"}, follow_redirects=False)
    assert r.status_code == 307 and r.headers["location"].startswith("https://accounts.google.com/")
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fapi%2Fv1%2Fauth%2Fcallback" in r.headers["location"]
    assert "sec" not in r.headers["location"].split("client_id")[0]


def test_security_headers_on_every_response(client):
    r = client.get("/health")
    h = {k.lower(): v for k, v in r.headers.items()}
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
    csp = h["content-security-policy"]
    assert "default-src 'self'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-eval" not in csp
    assert "camera=()" in h["permissions-policy"]


def test_spa_fallback_never_answers_file_probes(tmp_path, monkeypatch):
    """Unknown file-like paths (/.env, /openapi.json) are 404; client-side routes get the app shell; no traversal."""
    from fastapi.testclient import TestClient

    from app.core.config import get_settings
    from app.main import create_app
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><title>LV NEXUS</title>")
    (dist / "logo.svg").write_text("<svg/>")
    (tmp_path / "secret.txt").write_text("nope")
    monkeypatch.setenv("FRONTEND_DIST", str(dist))
    get_settings.cache_clear()
    try:
        c = TestClient(create_app())
        assert c.get("/compliance/policies").text.startswith("<!doctype html>")
        assert c.get("/logo.svg").status_code == 200
        for probe in ("/.env", "/config.json", "/backup.sql", "/wp-login.php"):  # /openapi.json is off only in production
            assert c.get(probe).status_code == 404, probe
        assert "nope" not in c.get("/../secret.txt").text and "nope" not in c.get("/%2e%2e/secret.txt").text
    finally:
        get_settings.cache_clear()
