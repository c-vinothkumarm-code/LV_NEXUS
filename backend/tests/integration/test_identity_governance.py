"""Identity governance: directory collection (Graph / ARM simulated), baseline vs change detection, lifecycle (new, disabled,
deleted only from a complete listing), effective access through groups, inherited assignments across subscriptions,
reconciliation exceptions, revocation plans (segregation of duties, verification against the next inventory), and the
tamper-evident audit trail."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.security import create_session_token
from app.models import ImmutableRecordError, Role, User
from app.models.access import AccessAssignment, AccessGrant, CloudIdentity
from app.models.iam import AccessRevocationItem, IamEffectiveAccess, IamException, IdentityChangeEvent
from app.models.platform import AuditTrail
from app.services import trail
from app.services.access import engine as A
from app.services.access import lifecycle as L
from app.services.access.collectors import Found, Result
from app.services.access.directory import AzureDirectory, Directory, DirIdentity, DirMember
from app.services.vuln.common import HttpError
from tests.conftest import use_settings

H = {"X-Requested-With": "mcp-dashboard"}
SUB = "22222222-aaaa-bbbb-cccc-000000000001"
SUB2 = "22222222-aaaa-bbbb-cccc-000000000002"
TENANT = "tenant-1"


class FakeRest:
    """Stands in for AzureRest: routes are URL substrings -> list of items (pages) / dict (request) / exception."""
    def __init__(self, routes: dict):
        self.routes = routes

    def _find(self, url):
        for k, v in self.routes.items():
            if k in url:
                if isinstance(v, Exception):
                    raise v
                return v
        raise HttpError(404, f"no route {url}")

    def pages(self, url, params=None, method="GET", body=None):
        yield from self._find(url)

    def request(self, method, url, **kw):
        return self._find(url)


def login(client, db, email, role):
    s = use_settings(client, auth_mode="google", google_oauth_client_id="c", google_oauth_client_secret="x",
                     google_allowed_domain="latentview.com", secret_key="k" * 40)
    if not db.scalar(select(User).where(User.email == email)):
        db.add(User(email=email, roles=[db.scalar(select(Role).where(Role.name == role))]))
        db.commit()
    client.cookies.set("mcp_session", create_session_token(email, s, db))


def rbac(principal, role, scope=f"/subscriptions/{SUB}", ptype="User", i=None):
    return Found("azure_rbac", f"{scope}/providers/Microsoft.Authorization/roleAssignments/{i or principal + role}", "subscription", scope,
                 principal, ptype, role, None, "Group" if ptype == "Group" else "Direct")


def directory(users, members=(), complete=True):
    d = Directory("azure", TENANT, identities=[DirIdentity(pid, "User", name, upn, enabled, "Member", None) for pid, name, upn, enabled in users],
                  members=[DirMember(g, gname, m, "User") for g, gname, m in members])
    d.identities_complete = d.members_complete = d.credentials_complete = complete
    return d


def inventory(db, assignments, users, members=(), complete=True):
    before = L.snapshot(db, "azure")
    res = Result(assignments=list(assignments))
    A.store(db, "azure", SUB, res)
    L.apply_directory(db, directory(users, members, complete))
    L.diff_assignments(db, "azure", before, {SUB})
    L.rebuild_effective(db)
    A.reconcile(db)
    L.verify_plans(db)
    L.refresh_status(db)
    L.compute_exceptions(db)
    db.commit()


ALICE = ("u-alice", "Alice", "alice@latentview.com", True)
BOB = ("u-bob", "Bob", "bob@latentview.com", True)


def test_azure_directory_collects_graph_mg_and_pim():
    rest = FakeRest({
        "/users": [{"id": "u1", "displayName": "A", "userPrincipalName": "a@latentview.com", "accountEnabled": True, "userType": "Member",
                    "createdDateTime": "2026-11-10T00:00:00Z"},
                   {"id": "u2", "displayName": "Guest", "userPrincipalName": "g_ext#EXT#@x", "accountEnabled": False, "userType": "Guest"}],
        "/servicePrincipals": [{"id": "sp1", "appId": "app-1", "displayName": "ci", "servicePrincipalType": "Application", "accountEnabled": True},
                               {"id": "mi1", "appId": "app-2", "displayName": "vm-id", "servicePrincipalType": "ManagedIdentity"}],
        "/transitiveMembers": [{"id": "u1", "@odata.type": "#microsoft.graph.user"}],
        "/applications": [{"appId": "app-1", "passwordCredentials": [{"keyId": "k1", "endDateTime": "2027-01-01T00:00:00Z"}], "keyCredentials": []}],
        "roleAssignments?": [],
        "/roleManagement/directory/roleAssignments": [{"id": "dra1", "principalId": "u1", "roleDefinitionId": "62e9", "directoryScopeId": "/",
                                                        "roleDefinition": {"displayName": "Global Administrator"}}],
        "/roleManagement/directory/roleEligibilitySchedules": [{"id": "e1", "principalId": "u2", "roleDefinitionId": "x",
                                                                 "roleDefinition": {"displayName": "User Administrator"},
                                                                 "scheduleInfo": {"expiration": {"endDateTime": "2026-12-31T00:00:00Z"}}}],
        "managementGroups/root/providers/Microsoft.Authorization/roleDefinitions": [{"id": "/providers/x/roleDefinitions/own", "properties": {"roleName": "Owner"}}],
        "managementGroups/root/providers/Microsoft.Authorization/roleAssignments": [
            {"id": "mga1", "properties": {"scope": "/providers/Microsoft.Management/managementGroups/root", "principalId": "u1",
                                          "principalType": "User", "roleDefinitionId": "/providers/x/roleDefinitions/own"}}],
        "/providers/Microsoft.Management/managementGroups": [{"id": "/providers/Microsoft.Management/managementGroups/root", "name": "root"}],
        "roleEligibilityScheduleInstances": [{"id": "pe1", "properties": {"principalId": "u1", "principalType": "User", "scope": f"/subscriptions/{SUB}/resourceGroups/rg1",
                                                                          "roleDefinitionId": "c", "endDateTime": "2026-12-01T00:00:00Z",
                                                                          "expandedProperties": {"roleDefinition": {"displayName": "Contributor"}}}}],
    })
    d = AzureDirectory(type("S", (), {"azure_tenant_id": TENANT})(), rest).collect([SUB], {"g1"})
    kinds = {i.principal_id: i.principal_type for i in d.identities}
    assert kinds == {"u1": "User", "u2": "User", "sp1": "ServicePrincipal", "mi1": "ManagedIdentity"} and d.identities_complete
    assert [c.kind for c in d.credentials] == ["client_secret"] and d.members[0].group_id == "g1"
    tenant = d.assignments[f"tenant:{TENANT}"].assignments
    assert {(f.role_name, f.pim_state) for f in tenant} == {("Global Administrator", "active"), ("User Administrator", "eligible")}
    mg = d.assignments["mg:root"].assignments
    assert len(mg) == 1 and mg[0].role_name == "Owner" and mg[0].scope_level == "management_group"
    pim = d.assignments[SUB].assignments[0]
    assert (pim.scope_level, pim.resource_group, pim.pim_state, pim.role_name) == ("resource_group", "rg1", "eligible", "Contributor")
    # a denied source is coverage, not "nothing found"
    denied = AzureDirectory(type("S", (), {"azure_tenant_id": TENANT})(), FakeRest({"/users": HttpError(403, "Authorization_RequestDenied"),
                                                                                    "/servicePrincipals": []})).collect([], set())
    assert not denied.identities_complete and any(c["state"] == "ACCESS_DENIED" for c in denied.coverage)


def test_inherited_assignment_is_stored_once_per_subscription(db):
    from types import SimpleNamespace as NS

    from app.services.access.collectors import AzureRbacCollector
    mg = "/providers/Microsoft.Management/managementGroups/root"
    a = NS(id=f"{mg}/providers/Microsoft.Authorization/roleAssignments/1", scope=mg, principal_id="u1", principal_type="User",
           role_definition_id="r", condition=None)
    fake = NS(clients=NS(authorization=lambda s: NS(role_definitions=NS(list=lambda scope: [NS(id="r", role_name="Reader")]),
                                                    role_assignments=NS(list_for_subscription=lambda: [a]))))
    for sub in (SUB, SUB2):
        A.store(db, "azure", sub, AzureRbacCollector(fake).collect(sub))
    db.commit()  # previously: unique-constraint violation when the same group assignment appeared under two subscriptions
    rows = list(db.scalars(select(AccessAssignment)))
    assert len(rows) == 2 and all(r.inherited_from == mg and r.access_type == "Inherited" for r in rows)


def test_baseline_then_changes_lifecycle_and_effective_access(db):
    inventory(db, [rbac("u-alice", "Reader"), rbac("g-admins", "Owner", ptype="Group")], [ALICE], [("g-admins", "Admins", "u-alice")])
    assert db.scalar(select(IdentityChangeEvent)) is None  # first inventory is a baseline
    alice = db.scalar(select(CloudIdentity).where(CloudIdentity.principal_id == "u-alice"))
    assert alice.lifecycle_status == "Active" and not L.is_new(alice)
    eff = {(e.principal_id, e.role_name, e.via) for e in db.scalars(select(IamEffectiveAccess))}
    assert ("u-alice", "Owner", "Group") in eff and ("u-alice", "Reader", "Direct") in eff  # group access expanded to the member
    # second run: Bob is new and gets Contributor (privileged, no approval); Alice's Reader becomes Contributor (role change)
    inventory(db, [rbac("u-alice", "Contributor"), rbac("g-admins", "Owner", ptype="Group"), rbac("u-bob", "Contributor")], [ALICE, BOB],
              [("g-admins", "Admins", "u-alice")])
    changes = {(c.principal_id, c.change_type) for c in db.scalars(select(IdentityChangeEvent))}
    assert ("u-bob", "NEW_IDENTITY") in changes and ("u-bob", "PERMISSION_ADDED") in changes and ("u-alice", "ROLE_CHANGED") in changes
    bob = db.scalar(select(CloudIdentity).where(CloudIdentity.principal_id == "u-bob"))
    assert bob.lifecycle_status == "New" and L.is_new(bob)
    cats = {(e.principal_id, e.category) for e in db.scalars(select(IamException))}
    assert ("u-bob", "UNAUTHORIZED_PRIVILEGE_CHANGE") in cats and ("u-bob", "PROVISIONED_WITHOUT_APPROVAL") in cats
    with pytest.raises(ImmutableRecordError):
        ev = db.scalar(select(IdentityChangeEvent))
        ev.change_type = "X"
        db.flush()
    db.rollback()


def test_deleted_only_from_complete_listing_and_revocation_plan(client, db):
    inventory(db, [rbac("u-alice", "Owner"), rbac("u-bob", "Reader")], [ALICE, BOB])
    inventory(db, [rbac("u-alice", "Owner"), rbac("u-bob", "Reader")], [BOB], complete=False)  # Graph listing failed half-way
    alice = db.scalar(select(CloudIdentity).where(CloudIdentity.principal_id == "u-alice"))
    assert alice.missing_since is None and alice.lifecycle_status == "Active"
    inventory(db, [rbac("u-alice", "Owner"), rbac("u-bob", "Reader")], [BOB])  # complete listing without Alice
    db.refresh(alice)
    assert alice.missing_since is not None and alice.lifecycle_status == "Reconciliation Required"
    assert db.scalar(select(IdentityChangeEvent).where(IdentityChangeEvent.change_type == "IDENTITY_DELETED")).principal_id == "u-alice"
    assert db.scalar(select(IamException).where(IamException.category == "DELETED_IDENTITY_WITH_ACCESS")).principal_id == "u-alice"

    login(client, db, "admin1@latentview.com", "admin")
    r = client.post(f"/api/v1/iam/identities/{alice.id}/revocation-plan", headers=H, json={"reason": "deleted"})
    assert r.status_code == 201, r.text
    plan = r.json()
    assert plan["status"] == "DRAFT" and len(plan["items"]) == 1 and plan["items"][0]["action"] == "remove"
    step = lambda body: client.post(f"/api/v1/iam/revocations/{plan['id']}/step", headers=H, json=body)  # noqa: E731
    assert step({"action": "request_approval"}).json()["status"] == "APPROVAL_REQUESTED"
    assert step({"action": "approve"}).status_code == 409  # the creator cannot approve
    login(client, db, "mgr@latentview.com", "governance_manager")
    assert step({"action": "approve"}).json()["status"] == "APPROVED"
    login(client, db, "admin1@latentview.com", "admin")
    assert step({"action": "executed"}).status_code == 422  # change reference required
    assert step({"action": "executed", "notes": "CHG-1234 removed in portal"}).json()["status"] == "EXECUTING"
    inventory(db, [rbac("u-alice", "Owner"), rbac("u-bob", "Reader")], [BOB])  # still present: not verified
    assert client.get(f"/api/v1/iam/revocations/{plan['id']}").json()["status"] == "EXECUTING"
    inventory(db, [rbac("u-bob", "Reader")], [BOB])  # removed by the administrator
    got = client.get(f"/api/v1/iam/revocations/{plan['id']}").json()
    assert got["status"] == "VERIFIED" and got["items"][0]["status"] == "VERIFIED"
    db.refresh(alice)
    assert alice.lifecycle_status == "Access Revoked"
    assert trail.verify(db)["valid"] and db.scalar(select(AuditTrail).where(AuditTrail.action == "revocation.executed")).approval_reference == plan["key"]


def test_shared_identity_is_never_automatic_and_scope_mismatch(client, db):
    inventory(db, [rbac("u-bob", "Owner")], [BOB])
    bob = db.scalar(select(CloudIdentity).where(CloudIdentity.principal_id == "u-bob"))
    bob.shared = True
    db.add(AccessGrant(grant_key="AG-1", provider="azure", scope_external_id="other-sub", sign_in_name="bob@latentview.com",
                       access_details="Owner", state="ACTIVE", created_by="t"))
    db.commit()
    inventory(db, [rbac("u-bob", "Owner")], [BOB])
    assert db.scalar(select(IamException).where(IamException.principal_id == "u-bob", IamException.status == "OPEN")).category == "SCOPE_MISMATCH"
    plan = L.build_plan(db, bob, "offboarding", "x@latentview.com")
    db.commit()
    items = list(db.scalars(select(AccessRevocationItem).where(AccessRevocationItem.plan_id == plan.id)))
    assert items and all(i.action == "review_shared" and not i.auto_allowed for i in items)


def test_identity_api_views(client, db):
    inventory(db, [rbac("u-alice", "Reader")], [ALICE])
    inventory(db, [rbac("u-alice", "Reader"), rbac("u-bob", "Owner")], [ALICE, BOB])
    login(client, db, "acc@latentview.com", "access_admin")
    ids = client.get("/api/v1/iam/identities", params={"new": "true"}).json()
    assert [i["principal_id"] for i in ids["items"]] == ["u-bob"] and ids["items"][0]["privileged"] == 1
    detail = client.get(f"/api/v1/iam/identities/{ids['items'][0]['id']}").json()
    assert detail["effective_access"][0]["role"] == "Owner" and {c["change"] for c in detail["changes"]} >= {"NEW_IDENTITY", "PERMISSION_ADDED"}
    assert client.get("/api/v1/iam/privileged").json()["total"] == 1
    assert client.get("/api/v1/iam/changes", params={"privileged": "true"}).json()["total"] >= 1
    exc = client.get("/api/v1/iam/exceptions").json()
    eid = next(e["id"] for e in exc["items"] if e["category"] == "PROVISIONED_WITHOUT_APPROVAL")
    assert client.patch(f"/api/v1/iam/exceptions/{eid}", headers=H, json={"status": "RESOLVED", "notes": "done"}).status_code == 409  # still present
    assert client.patch(f"/api/v1/iam/exceptions/{eid}", headers=H, json={"status": "ACCEPTED", "notes": "break-glass account"}).json()["status"] == "ACCEPTED"
    login(client, db, "viewer@latentview.com", "viewer")
    assert client.get("/api/v1/iam/identities").status_code == 403


def test_audit_trail_hash_chain_detects_tampering(db):
    for i in range(3):
        trail.record(db, category="platform", actor="a@latentview.com", action=f"test.{i}", new_state={"i": i})
    db.commit()
    assert trail.verify(db) == {"valid": True, "checked": 3, "broken_at": None}
    forged = AuditTrail(audit_id="forged", category="platform", actor="x", action="test.forged", created_at=datetime.now(UTC) - timedelta(days=1),
                        prev_hash="0" * 64, row_hash="f" * 64)
    db.add(forged)
    db.commit()
    v = trail.verify(db)
    assert not v["valid"] and v["broken_at"] == "forged"
