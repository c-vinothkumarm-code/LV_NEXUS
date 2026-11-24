"""Cloud accounts tree: one tree per cloud; counts, health and cost roll up from resource group / region to the root;
cost below account level is null (not collected) rather than zero; assigned-scope users only see their scopes."""
from __future__ import annotations

from datetime import date
from decimal import Decimal

from app.models import BillingRecord, CloudAccount, CloudProject, CloudResource, CloudSecurityFinding, CloudSubscription, VMInventory
from app.models.platform import CostDetailRecord
from tests.integration.test_identity_governance import login

AZ_RG = "/subscriptions/sub-1/resourceGroups/rg-app"


def _finding(provider, scope, rid, sev, n, rg=None, region=None):
    return CloudSecurityFinding(provider=provider, source="test", native_id=f"f{n}", native_id_hash=f"h{n}", scope_external_id=scope, resource_id=rid,
                                resource_group=rg, region=region, title=f"finding {n}", severity=sev)


def _seed(db):
    db.add_all([CloudSubscription(external_id="sub-1", name="prod-sub", onboarding_status="Fully Onboarded", tenant_id="t-1"),
                CloudAccount(external_id="111", name="aws-prod", onboarding_status="Fully Onboarded", parent="ou-core"),
                CloudProject(external_id="proj-a", name="analytics", onboarding_status="Discovered", parent="folders/42")])
    db.add_all([CloudResource(provider="azure", scope_external_id="sub-1", resource_id=f"{AZ_RG}/providers/Microsoft.Storage/storageAccounts/st1",
                              resource_type="storageaccount", name="st1", region="eastus", attributes={}),
                CloudResource(provider="aws", scope_external_id="111", resource_id="arn:aws:s3:::b1", resource_type="s3", name="b1", region="us-east-1", attributes={}),
                CloudResource(provider="gcp", scope_external_id="proj-a", resource_id="//storage/b2", resource_type="bucket", name="b2", region="europe-west1", attributes={})])
    db.add(VMInventory(provider="azure", scope_external_id="sub-1", instance_id=f"{AZ_RG}/providers/Microsoft.Compute/virtualMachines/vm1", name="vm1",
                       region="eastus", health_status="critical", exposed_ports=[]))
    db.add_all([_finding("azure", "sub-1", f"{AZ_RG}/providers/Microsoft.Storage/storageAccounts/st1", "Critical", 1, rg="rg-app"),
                _finding("aws", "111", "arn:aws:s3:::b1", "High", 2, region="us-east-1")])
    db.add(BillingRecord(provider="azure", scope_external_id="sub-1", service="VM", usage_date=date.today(), cost_original=Decimal(30),
                         currency_original="USD", cost_usd=Decimal(30)))
    db.add(CostDetailRecord(row_hash="x1", provider="azure", breakdown="resource", scope_external_id="sub-1", usage_date=date.today(), currency="USD",
                            amount=Decimal(20), amount_usd=Decimal(20), resource_group="rg-app",
                            resource_id=f"{AZ_RG}/providers/Microsoft.Storage/storageAccounts/st1"))
    db.commit()


def test_tree_rolls_up_per_cloud(client, db):
    _seed(db)
    login(client, db, "exec@latentview.com", "executive")
    t = client.get("/api/v1/accounts/tree").json()
    clouds = {c["provider"]: c for c in t["clouds"]}
    az = clouds["azure"]
    assert az["scopes"] == 1 and az["resources"] == 1 and az["vms"] == 1 and az["vms_unhealthy"] == 1 and az["critical"] == 1
    sub = az["children"][0]["children"][0]
    assert sub["kind"] == "Subscription" and sub["cost_mtd"] == 30 and sub["health"] == "Healthy"
    rg = next(c for c in sub["children"] if c["child"] == "rg-app")
    assert rg["kind"] == "Resource group" and rg["cost_mtd"] == 20 and rg["findings"] == 1
    aws = clouds["aws"]
    assert aws["children"][0]["name"] == "ou-core" and aws["high"] == 1
    region = aws["children"][0]["children"][0]["children"][0]
    assert region["child"] == "us-east-1" and region["cost_mtd"] is None  # not collected, never zero
    gcp = clouds["gcp"]
    assert gcp["children"][0]["children"][0]["health"] == "Attention" and gcp["children"][0]["children"][0]["cost_mtd"] is None

    node = client.get("/api/v1/accounts/node", params={"provider": "azure", "scope": "sub-1", "child": "rg-app"}).json()
    assert node["total"] == 1 and node["items"][0]["findings"] == 1 and node["items"][0]["cost_mtd"] == 20
    assert node["vms"][0]["health"] == "critical" and node["findings"][0]["severity"] == "Critical"
    assert client.get("/api/v1/accounts/tree", params={"provider": "gcp"}).json()["clouds"][0]["provider"] == "gcp"


def test_assigned_scope_user_sees_only_assigned(client, db):
    _seed(db)
    login(client, db, "owner@latentview.com", "project_owner")
    t = client.get("/api/v1/accounts/tree").json()
    assert all(c["scopes"] == 0 for c in t["clouds"])
    assert client.get("/api/v1/accounts/node", params={"provider": "azure", "scope": "sub-1"}).json()["total"] == 0
