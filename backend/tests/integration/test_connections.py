from sqlalchemy import select

import app.services.registry as registry
from app.core.config import Settings
from app.core.security import create_session_token
from app.models import AdminAuditLog, CloudAccount, CloudConnection, Role, User
from app.services.connections import effective_settings
from tests.conftest import use_settings
from tests.fakes import FakeConnector

H = {"X-Requested-With": "mcp-dashboard"}


def test_connection_saved_in_dashboard_overrides_environment(client, db):
    r = client.put("/api/v1/connections/aws", headers=H, json={"enabled": True, "config": {
        "aws_member_role_name": "mcp-readonly", "aws_external_id": "ext-secret-1", "aws_regions": "ap-south-1, us-east-1", "aws_profile": "mgmt"}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] and body["missing"] == [] and body["managed_in_dashboard"]
    fields = {f["key"]: f for f in body["fields"]}
    assert fields["aws_member_role_name"]["value"] == "mcp-readonly" and fields["aws_regions"]["value"] == "ap-south-1, us-east-1"
    assert fields["aws_external_id"]["value"] == "" and fields["aws_external_id"]["is_set"] and "ext-secret-1" not in r.text  # never echoed back
    eff = effective_settings(db, Settings(_env_file=None))
    assert eff.aws_enabled and eff.aws_member_role_name == "mcp-readonly" and eff.aws_regions == ["ap-south-1", "us-east-1"]
    assert eff.aws_external_id == "ext-secret-1" and eff.aws_profile == "mgmt" and not eff.gcp_enabled
    # saving again with the sensitive field left blank keeps the stored value
    client.put("/api/v1/connections/aws", headers=H, json={"enabled": True, "config": {"aws_member_role_name": "mcp-readonly"}})
    db.expire_all()
    assert db.scalar(select(CloudConnection)).config["aws_external_id"] == "ext-secret-1"
    assert db.scalar(select(AdminAuditLog).where(AdminAuditLog.action == "connection.save")) is not None


def test_invalid_or_incomplete_connections_are_rejected(client):
    put = lambda p, enabled, cfg: client.put(f"/api/v1/connections/{p}", headers=H, json={"enabled": enabled, "config": cfg})  # noqa: E731
    assert put("gcp", True, {}).status_code == 422  # cannot enable without the organisation ID
    assert put("gcp", False, {"gcp_organization_id": "not-a-number"}).status_code == 422
    assert put("azure", False, {"azure_tenant_id": "abc"}).status_code == 422
    assert put("aws", False, {"aws_member_role_name": "role name; drop"}).status_code == 422
    assert put("aws", False, {"aws_regions": "mumbai"}).status_code == 422
    assert put("aws", False, {"aws_secret_access_key": "x"}).status_code == 422  # credentials are not accepted at all
    assert put("gcp", False, {"gcp_billing_export_table": "p.d.t; DROP"}).status_code == 422
    assert put("oracle", False, {}).status_code == 404
    assert client.put("/api/v1/connections/aws", json={"enabled": False, "config": {}}).status_code == 403  # CSRF header required
    assert put("gcp", False, {"gcp_organization_id": "123456789012"}).status_code == 200  # saved but not enabled


def test_test_connection_and_discovery_use_dashboard_settings(client, db, monkeypatch):
    seen = {}

    def fake_build(provider, settings):
        seen[provider] = settings
        if provider == "azure":
            return FakeConnector("azure", discover_error=RuntimeError("AADSTS700016 client_secret=abc"))
        return FakeConnector(provider, {"1" * 12: {"name": "prod"}, "2" * 12: {"name": "dev"}})

    monkeypatch.setattr(registry, "build_connector", fake_build)
    assert client.post("/api/v1/connections/aws/test", headers=H).json()["ok"] is True  # FakeConnector needs no settings
    client.put("/api/v1/connections/aws", headers=H, json={"enabled": True, "config": {"aws_member_role_name": "mcp-readonly"}})
    t = client.post("/api/v1/connections/aws/test", headers=H).json()
    assert t == {"provider": "aws", "ok": True, "detail": "Connected. 2 accounts visible.", "scopes_visible": 2}
    assert seen["aws"].aws_member_role_name == "mcp-readonly" and db.scalar(select(CloudAccount)) is None  # a test stores no inventory
    bad = client.post("/api/v1/connections/azure/test", headers=H).json()
    assert bad["ok"] is False and "AADSTS700016" in bad["detail"] and "abc" not in bad["detail"]
    assert client.get("/api/v1/connections").json()["providers"][0]["last_test"]["ok"] is True
    # the discovery job picks the dashboard settings up without a restart
    assert client.post("/api/v1/jobs/account_discovery/run", headers=H).status_code == 202
    db.expire_all()
    assert {a.name for a in db.scalars(select(CloudAccount))} == {"prod", "dev"}
    ex = client.get("/api/v1/dashboard/automation").json()["executions"][0]
    assert ex["status"] == "success" and ex["scopes_total"] == 2


def test_only_admins_can_change_connections(client, db):
    s = use_settings(client, auth_mode="google")
    db.add(User(email="viewer@example.com", roles=[db.query(Role).filter_by(name="viewer").one()]))
    db.commit()
    client.cookies.set("mcp_session", create_session_token("viewer@example.com", s, db))
    assert client.get("/api/v1/connections").status_code == 200
    assert client.put("/api/v1/connections/aws", headers=H, json={"enabled": False, "config": {}}).status_code == 403
    assert client.post("/api/v1/connections/aws/test", headers=H).status_code == 403
