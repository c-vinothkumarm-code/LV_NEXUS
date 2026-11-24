"""Unified Cloud Inventory: categories, hierarchy, resource list filters, resource detail, and Project Owner scoping."""
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.api.routes.explorer import category
from app.core.security import create_session_token
from app.models import CloudAccount, CloudProject, CloudResource, CloudSecurityFinding, CloudSubscription, Role, User, UserScopeAssignment, VMInventory, VMMetric
from tests.conftest import use_settings


def login(client, db, email, role):
    s = use_settings(client, auth_mode="google", google_oauth_client_id="c", google_oauth_client_secret="x",
                     google_allowed_domain="latentview.com", secret_key="k" * 40)
    if not db.scalar(select(User).where(User.email == email)):
        db.add(User(email=email, roles=[db.scalar(select(Role).where(Role.name == role))]))
        db.commit()
    client.cookies.set("mcp_session", create_session_token(email, s, db))


def estate(db):
    now = datetime.now(UTC)
    db.add_all([CloudAccount(external_id="111111111111", name="payments", parent="ou-payments", environment="Production"),
                CloudSubscription(external_id="sub-a", name="analytics", tenant_id="tenant-1", environment="Development"),
                CloudProject(external_id="proj-x", name="ml", parent="folders/42")])
    rg = "/subscriptions/sub-a/resourceGroups/rg-data/providers/"
    db.add_all([
        CloudResource(provider="azure", scope_external_id="sub-a", resource_id=rg + "Microsoft.Storage/storageAccounts/stdata", name="stdata",
                      resource_type="Microsoft.Storage/storageAccounts", region="centralindia", state="present", last_seen_at=now,
                      attributes={"resource_group": "rg-data", "tags": {"Owner": "data-team"}}),
        CloudResource(provider="azure", scope_external_id="sub-a", resource_id=rg + "Microsoft.Sql/servers/sqlx", name="sqlx",
                      resource_type="Microsoft.Sql/servers", region="centralindia", state="present", last_seen_at=now,
                      attributes={"resource_group": "rg-data"}),
        CloudResource(provider="aws", scope_external_id="111111111111", resource_id="i-0abc", name="web-1", resource_type="virtual_machine",
                      region="us-east-1", state="present", last_seen_at=now - timedelta(days=5)),
        CloudResource(provider="azure", scope_external_id="sub-a", resource_id=rg + "Microsoft.Network/publicIPAddresses/old", name="old",
                      resource_type="Microsoft.Network/publicIPAddresses", region="centralindia", state="deleted", last_seen_at=now),
    ])
    vm = VMInventory(provider="aws", scope_external_id="111111111111", instance_id="i-0abc", name="web-1", power_state="running", public_ip="1.2.3.4")
    db.add(vm)
    db.flush()
    db.add(VMMetric(vm_id=vm.id, cpu_percent=12.0, collected_at=now))
    db.add(CloudSecurityFinding(provider="azure", source="azure_advisor", native_id="n1", native_id_hash="h1", scope_external_id="sub-a",
                                resource_id=rg + "Microsoft.Storage/storageAccounts/stdata", title="Storage open", severity="High",
                                native_state="ACTIVE", first_synced_at=now, last_synced_at=now, raw={}))
    db.commit()


def test_category_rule():
    assert category("Microsoft.Storage/storageAccounts") == "Storage" and category("Microsoft.Sql/servers") == "Databases"
    assert category("virtual_machine") == "Virtual machines" and category("Microsoft.ContainerService/managedClusters") == "Kubernetes"
    assert category("Something/Unknown") == "Other"


def test_summary_tree_list_and_detail(client, db):
    estate(db)
    login(client, db, "admin@latentview.com", "security_analyst")
    s = client.get("/api/v1/inventory/summary").json()
    assert s["total_resources"] == 3 and s["by_category"] == {"Storage": 1, "Databases": 1, "Virtual machines": 1}  # deleted excluded
    assert s["by_environment"] == {"Development": 2, "Production": 1} and s["vms_with_public_ip"] == 1
    t = client.get("/api/v1/inventory/tree").json()["providers"]
    az = next(p for p in t if p["provider"] == "azure")
    sub = az["groups"][0]["scopes"][0]
    assert az["groups"][0]["parent"] == "Tenant tenant-1" and sub["resource_groups"] == [{"name": "rg-data", "resources": 2}]  # deleted resource excluded
    assert sub["open_findings"] == 1
    aws = next(p for p in t if p["provider"] == "aws")
    assert aws["groups"][0]["parent"] == "ou-payments"
    lst = client.get("/api/v1/inventory/resources", params={"provider": "azure", "resource_group": "rg-data"}).json()
    assert {r["name"] for r in lst["items"]} == {"stdata", "sqlx"}
    assert client.get("/api/v1/inventory/resources", params={"category": "Databases"}).json()["total"] == 1
    assert client.get("/api/v1/inventory/resources", params={"environment": "Production"}).json()["total"] == 1
    st = next(r for r in lst["items"] if r["name"] == "stdata")
    assert st["owner"] == "data-team" and st["open_findings"] == 1
    d = client.get(f"/api/v1/inventory/resources/{st['id']}").json()
    assert d["findings"][0]["title"] == "Storage open" and d["cost"]["available"] is False and d["vm"] is None
    web = client.get("/api/v1/inventory/resources", params={"q": "web"}).json()["items"][0]
    assert web["stale"] is True
    dv = client.get(f"/api/v1/inventory/resources/{web['id']}").json()
    assert dv["vm"]["monitoring"] == "Reporting" and "operating system" in dv["vm"]["not_collected"]


def test_project_owner_inventory_is_scoped(client, db):
    estate(db)
    login(client, db, "po@latentview.com", "project_owner")
    po = db.scalar(select(User).where(User.email == "po@latentview.com"))
    db.add(UserScopeAssignment(user_id=po.id, provider="aws", scope_external_id="111111111111", assigned_by="admin"))
    db.commit()
    assert client.get("/api/v1/inventory/summary").json()["total_resources"] == 1
    items = client.get("/api/v1/inventory/resources").json()["items"]
    assert [i["name"] for i in items] == ["web-1"]
    other = db.scalar(select(CloudResource).where(CloudResource.name == "stdata"))
    assert client.get(f"/api/v1/inventory/resources/{other.id}").status_code == 404
    assert [p["provider"] for p in client.get("/api/v1/inventory/tree").json()["providers"]] == ["aws"]
