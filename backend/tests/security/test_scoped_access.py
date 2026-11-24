"""Project Owner scope assignments, the new business roles, and permission-aware global search."""
from datetime import UTC, datetime

from sqlalchemy import select

from app.core.security import ROLE_LABELS, ROLES, create_session_token
from app.models import CloudAccount, CloudSecurityFinding, CloudSubscription, Role, User, VMInventory
from tests.conftest import use_settings

H = {"X-Requested-With": "mcp-dashboard"}


def login(client, db, email, role):
    s = use_settings(client, auth_mode="google", google_oauth_client_id="c", google_oauth_client_secret="x",
                     google_allowed_domain="latentview.com", secret_key="k" * 40)
    if not db.scalar(select(User).where(User.email == email)):
        db.add(User(email=email, roles=[db.scalar(select(Role).where(Role.name == role))]))
        db.commit()
    client.cookies.set("mcp_session", create_session_token(email, s, db))


def estate(db):
    now = datetime.now(UTC)
    db.add_all([CloudAccount(external_id="111111111111", name="payments-prod"), CloudAccount(external_id="222222222222", name="hr-prod"),
                CloudSubscription(external_id="sub-a", name="analytics")])
    for i, scope in enumerate(["111111111111", "222222222222"]):
        db.add(CloudSecurityFinding(provider="aws", source="security_hub", native_id=f"n{i}", native_id_hash=f"h{i}", scope_external_id=scope,
                                    title=f"Public bucket in {scope}", severity="High", native_state="ACTIVE", first_synced_at=now,
                                    last_synced_at=now, raw={}))
        db.add(VMInventory(provider="aws", scope_external_id=scope, instance_id=f"i-{i}", name=f"vm-{scope}", power_state="running"))
    db.commit()


def test_spec_roles_exist_with_business_labels():
    for role in ("admin", "cloud_admin", "security_analyst", "finops_analyst", "access_admin", "governance_manager", "finance_approver",
                 "executive", "project_owner", "auditor", "viewer"):
        assert role in ROLES and ROLE_LABELS[role]
    assert ROLE_LABELS["admin"] == "Super Admin" and ROLE_LABELS["executive"] == "Executive / CISO"
    assert "admin:users" not in ROLES["executive"][1] and "budget:approve" in ROLES["finance_approver"][1]
    assert "budget:approve" not in ROLES["finops_analyst"][1]  # requesters do not approve their own budgets


def test_project_owner_sees_only_assigned_scopes(client, db):
    estate(db)
    login(client, db, "admin@latentview.com", "admin")
    owner = User(email="owner@latentview.com", roles=[db.scalar(select(Role).where(Role.name == "project_owner"))])
    db.add(owner)
    db.commit()
    assert client.put(f"/api/v1/admin/users/{owner.id}/scopes", headers=H,
                      json={"scopes": [{"provider": "aws", "scope_external_id": "999"}]}).status_code == 422  # not discovered
    r = client.put(f"/api/v1/admin/users/{owner.id}/scopes", headers=H, json={"scopes": [{"provider": "aws", "scope_external_id": "111111111111"}]})
    assert r.status_code == 200 and r.json()["scopes"] == [{"provider": "aws", "scope_external_id": "111111111111"}]

    login(client, db, "owner@latentview.com", "project_owner")
    assert [s["external_id"] for s in client.get("/api/v1/inventory/scopes").json()["items"]] == ["111111111111"]
    findings = client.get("/api/v1/security/findings").json()["items"]
    assert {f["scope"] for f in findings} == {"111111111111"}
    other = db.scalar(select(CloudSecurityFinding).where(CloudSecurityFinding.scope_external_id == "222222222222"))
    assert client.get(f"/api/v1/security/findings/{other.id}").status_code == 404
    infra = client.get("/api/v1/dashboard/infrastructure").json()
    assert [v["name"] for v in infra["vms"]] == ["vm-111111111111"]
    for path in ("/api/v1/dashboard/overview", "/api/v1/dashboard/finops", "/api/v1/dashboard/soc", "/api/v1/admin/users"):
        assert client.get(path).status_code == 403
    hits = client.get("/api/v1/search", params={"q": "prod"}).json()["items"]
    assert {h["title"] for h in hits if h["type"] == "scope"} == {"payments-prod"}
    assert all("222222222222" not in h["subtitle"] for h in hits)


def test_project_owner_without_assignment_sees_nothing(client, db):
    estate(db)
    login(client, db, "new.owner@latentview.com", "project_owner")
    assert client.get("/api/v1/inventory/scopes").json()["items"] == []
    assert client.get("/api/v1/security/findings").json()["items"] == []
    assert client.get("/api/v1/dashboard/infrastructure").json()["vms"] == []


def test_search_respects_permissions(client, db):
    estate(db)
    login(client, db, "viewer@latentview.com", "viewer")
    types = {h["type"] for h in client.get("/api/v1/search", params={"q": "1111"}).json()["items"]}
    assert "scope" in types and "finding" not in types and "vm" not in types  # viewer has no finding / VM permission
    login(client, db, "analyst@latentview.com", "security_analyst")
    types = {h["type"] for h in client.get("/api/v1/search", params={"q": "bucket"}).json()["items"]}
    assert types == {"finding"}
    assert client.get("/api/v1/search", params={"q": "x"}).status_code == 422
