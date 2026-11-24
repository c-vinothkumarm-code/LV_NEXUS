"""Read-only Access view: tree per cloud, who-has-access at subscription / resource group / resource level with inheritance,
group expansion, people search, per-node "missing permission" messages, and the legacy workflow API switched off."""
from __future__ import annotations

from sqlalchemy import select

from app.models import AutomationExecutionLog, AutomationJob, CloudAccount, CloudProject, CloudSubscription
from app.models.access import AccessAssignment, CloudIdentity
from app.models.iam import IdentityGroupMember
from app.services.access.collectors import h
from tests.conftest import use_settings
from tests.integration.test_identity_governance import login

SUB = "/subscriptions/sub-1"
RG = f"{SUB}/resourceGroups/rg-app"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm1"


def _a(provider, scope, sid, level, path, pid, ptype, role, access="Direct", rg=None, res=None, inherited=None, privileged=False, source="t"):
    return AccessAssignment(provider=provider, source=source, source_id=sid, source_id_hash=h(source, sid), scope_external_id=scope, scope_level=level,
                            scope_path=path, resource_group=rg, resource_name=res, principal_id=pid, principal_type=ptype, role_name=role,
                            access_type=access, inherited_from=inherited, privileged=privileged)


def _seed(db):
    db.add_all([CloudSubscription(external_id="sub-1", name="prod-sub", onboarding_status="Fully Onboarded"),
                CloudSubscription(external_id="sub-2", name="locked-sub", onboarding_status="Fully Onboarded"),
                CloudAccount(external_id="111", name="aws-prod", onboarding_status="Fully Onboarded"),
                CloudProject(external_id="proj-a", name="analytics", onboarding_status="Fully Onboarded")])
    db.add_all([
        _a("azure", "sub-1", "1", "subscription", SUB, "u-alice", "User", "Owner", privileged=True),
        _a("azure", "sub-1", "2|via:sub-1", "management_group", "/providers/Microsoft.Management/managementGroups/root", "u-carol", "User", "Reader",
           access="Inherited", inherited="/providers/Microsoft.Management/managementGroups/root"),
        _a("azure", "sub-1", "3", "resource_group", RG, "g-ops", "Group", "Contributor", access="Group", rg="rg-app", privileged=True),
        _a("azure", "sub-1", "4", "resource", VM, "u-bob", "User", "Virtual Machine Contributor", rg="rg-app", res="vm1"),
        _a("aws", "111", "5", "account", "arn:aws:iam::111", "arn:aws:iam::111:user/dev", "User", "ReadOnlyAccess"),
        _a("aws", "111", "6", "resource", "arn:aws:s3:::data", "arn:aws:iam::222:role/partner", "Role", "s3:GetObject", res="data",
           inherited="cross-account", source="aws_resource_policy"),
        _a("gcp", "proj-a", "7", "project", "projects/proj-a", "user:ana@example.com", "User", "roles/viewer"),
        _a("gcp", "proj-a", "8", "resource", "//storage.googleapis.com/projects/_/buckets/raw", "group:eng@example.com", "Group",
           "roles/storage.objectViewer", access="Group", res="raw", source="gcp_resource_iam"),
    ])
    db.add_all([CloudIdentity(provider="azure", principal_id="u-alice", principal_type="User", display_name="Alice Admin", sign_in_name="alice@example.com"),
                CloudIdentity(provider="azure", principal_id="u-dave", principal_type="User", display_name="Dave Ops", sign_in_name="dave@example.com"),
                IdentityGroupMember(provider="azure", group_id="g-ops", group_name="ops", member_id="u-dave", member_type="User")])
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == "access_inventory"))
    db.add(AutomationExecutionLog(job_id=job.id, job_name="access_inventory", status="partial", summary={"coverage": {
        "azure:sub-1": [{"source": "azure_rbac", "state": "OK", "message": "ok"}],
        "azure:sub-2": [{"source": "azure_rbac", "state": "ACCESS_DENIED", "message": "AuthorizationFailed"}],
        "aws:111": [{"source": "aws_iam", "state": "OK", "message": "ok"},
                    {"source": "aws_resource_policy:kms", "state": "ACCESS_DENIED", "message": "AccessDenied"}],
        "gcp:proj-a": [{"source": "gcp_iam", "state": "OK", "message": "ok"}]}}))
    db.commit()


def test_tree_levels_and_missing_permission(client, db):
    _seed(db)
    login(client, db, "admin@latentview.com", "admin")
    t = client.get("/api/v1/access/tree").json()
    assert t["collected"] and t["last_refreshed"]
    az = next(c for c in t["clouds"] if c["provider"] == "azure")
    subs = {s["scope"]: s for g in az["children"] for s in g["children"]}
    assert subs["sub-1"]["principals"] == 2 and subs["sub-1"]["inherited"] == 1 and subs["sub-1"]["privileged"] == 1
    assert subs["sub-1"]["children"][0]["name"] == "rg-app" and subs["sub-1"]["children"][0]["resources"] == 1
    assert subs["sub-2"]["unavailable"] == ["Access data unavailable – missing permission: Microsoft.Authorization/roleAssignments/read (Reader on the subscription)"]
    aws = next(c for c in t["clouds"] if c["provider"] == "aws")
    acct = aws["children"][0]["children"][0]
    names = {c["name"]: c for c in acct["children"]}
    assert "S3 buckets" in names and acct["unavailable"] == []  # account-level reads worked
    assert names["Resource-level access"]["unavailable"][0].endswith("kms:ListKeys, kms:DescribeKey, kms:GetKeyPolicy")
    gcp = next(c for c in t["clouds"] if c["provider"] == "gcp")
    assert gcp["children"][0]["children"][0]["children"][0]["name"] == "storage"


def test_who_inherits_down_and_expands_groups(client, db):
    _seed(db)
    login(client, db, "admin@latentview.com", "admin")
    sub = client.get("/api/v1/access/who", params={"provider": "azure", "scope": "sub-1"}).json()
    assert {i["display_name"] for i in sub["items"]} == {"Alice Admin", "u-carol"}
    carol = next(i for i in sub["items"] if i["principal_id"] == "u-carol")
    assert carol["inherited_via"].endswith("managementGroups/root")
    rg = client.get("/api/v1/access/who", params={"provider": "azure", "scope": "sub-1", "child": "rg-app"}).json()
    ops = next(i for i in rg["items"] if i["principal_id"] == "g-ops")
    assert ops["inherited_via"] is None and ops["members"][0]["display_name"] == "Dave Ops"
    assert next(i for i in rg["items"] if i["principal_id"] == "u-alice")["inherited_via"] == "subscription"
    assert rg["resources"] == [{"resource": VM, "name": "vm1"}] and all(i["principal_id"] != "u-bob" for i in rg["items"])
    vm = client.get("/api/v1/access/who", params={"provider": "azure", "scope": "sub-1", "child": "rg-app", "resource": VM}).json()
    assert {i["principal_id"] for i in vm["items"]} == {"u-bob", "g-ops", "u-alice", "u-carol"}
    assert next(i for i in vm["items"] if i["principal_id"] == "g-ops")["inherited_via"] == "resource group"
    s3 = client.get("/api/v1/access/who", params={"provider": "aws", "scope": "111", "child": "S3 buckets", "resource": "arn:aws:s3:::data"}).json()
    assert next(i for i in s3["items"] if i["type"] == "Role")["cross_account"] is True
    assert client.get("/api/v1/access/who", params={"provider": "azure", "scope": "sub-1", "q": "alice"}).json()["total"] == 1


def test_search_person_includes_group_access(client, db):
    _seed(db)
    login(client, db, "admin@latentview.com", "admin")
    r = client.get("/api/v1/access/search", params={"q": "dave"}).json()["items"][0]
    assert r["display_name"] == "Dave Ops" and r["access"][0]["through_group"] == "ops" and r["access"][0]["where"] == "rg-app"


def test_legacy_workflows_switched_off(client, db):
    login(client, db, "admin@latentview.com", "admin")
    use_settings(client, access_workflows_enabled=False)
    for path in ("/api/v1/access/register", "/api/v1/access/requests", "/api/v1/access/reviews", "/api/v1/access/history"):
        assert client.get(path).status_code == 404
    assert client.post("/api/v1/access/requests", json={}).status_code == 404
    assert client.post("/api/v1/iam/identities/1/revocation-plan", json={}).status_code == 404
