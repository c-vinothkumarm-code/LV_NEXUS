"""Cloud Access Management: provider inventory (Azure RBAC simulated, GCP IAM simulated), approvals kept separate from
actual assignments, request -> approval -> execution -> verification, extensions, revocations, reviews, import, RBAC."""
from __future__ import annotations

from datetime import date, timedelta
from types import SimpleNamespace as NS

from sqlalchemy import select

from app.core.security import create_session_token
from app.models import CloudProject, CloudSubscription, ImmutableRecordError, Role, User
from app.models.access import AccessApproval, AccessAssignment, AccessGrant
from app.services.access import engine as A
from app.services.access.collectors import AzureRbacCollector, GcpIamCollector, is_privileged
from tests.conftest import use_settings

H = {"X-Requested-With": "mcp-dashboard"}
SUB = "11111111-aaaa-bbbb-cccc-000000000001"
OWNER = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/8e3af657"
READER = f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions/acdd72a7"


class FakeAzure:
    """Stands in for the Azure SDK client: same method names and object shapes."""
    def __init__(self, assignments):
        self.assignments = assignments
        auth = NS(role_definitions=NS(list=lambda scope: [NS(id=OWNER, role_name="Owner"), NS(id=READER, role_name="Reader")]),
                  role_assignments=NS(list_for_subscription=lambda: list(self.assignments)))
        self.clients = NS(authorization=lambda sub: auth)


def ra(i, principal, role=READER, scope=None, ptype="User"):
    return NS(id=f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments/{i}", scope=scope or f"/subscriptions/{SUB}",
              principal_id=principal, principal_type=ptype, role_definition_id=role, condition=None)


def login(client, db, email, role):
    s = use_settings(client, auth_mode="google", google_oauth_client_id="c", google_oauth_client_secret="x",
                     google_allowed_domain="latentview.com", secret_key="k" * 40)
    if not db.scalar(select(User).where(User.email == email)):
        db.add(User(email=email, roles=[db.scalar(select(Role).where(Role.name == role))]))
        db.commit()
    client.cookies.set("mcp_session", create_session_token(email, s, db))


def collect(db, fake):
    res = AzureRbacCollector(fake).collect(SUB)
    A.store(db, "azure", SUB, res)
    A.reconcile(db)
    db.commit()
    return res


def setup(db):
    db.add(CloudSubscription(external_id=SUB, name="analytics-prod", environment="Production"))
    db.commit()


def test_collectors_scope_levels_and_privilege():
    fake = FakeAzure([ra(1, "u1"), ra(2, "u2", OWNER), ra(3, "g1", READER, f"/subscriptions/{SUB}/resourceGroups/rg-data", "Group"),
                      ra(4, "u3", READER, "/providers/Microsoft.Management/managementGroups/root")])
    res = AzureRbacCollector(fake).collect(SUB)
    by = {f.principal_id: f for f in res.assignments}
    assert by["u2"].role_name == "Owner" and is_privileged("Owner") and not is_privileged("Reader")
    assert (by["g1"].scope_level, by["g1"].resource_group, by["g1"].access_type) == ("resource_group", "rg-data", "Group")
    assert (by["u3"].scope_level, by["u3"].access_type) == ("management_group", "Inherited")
    gcp = NS(clients=NS(projects=NS(get_iam_policy=lambda request, timeout=None: NS(bindings=[
        NS(role="roles/owner", members=["user:alice@latentview.com", "serviceAccount:ci@p.iam.gserviceaccount.com"], condition=None)]))))
    g = GcpIamCollector(gcp).collect("proj-x")
    assert {(f.principal_type, f.sign_in_name) for f in g.assignments} == {("User", "alice@latentview.com"), ("ServiceAccount", "ci@p.iam.gserviceaccount.com")}
    assert all(is_privileged(f.role_name) for f in g.assignments)
    denied = AzureRbacCollector(NS(clients=NS(authorization=lambda s: (_ for _ in ()).throw(PermissionError("403 AuthorizationFailed"))))).collect(SUB)
    assert not denied.complete and denied.assignments == []  # a failure is never "no access"


def test_incomplete_collection_never_removes_assignments(db):
    setup(db)
    fake = FakeAzure([ra(1, "u1")])
    collect(db, fake)
    broken = AzureRbacCollector(NS(clients=NS(authorization=lambda s: (_ for _ in ()).throw(RuntimeError("boom"))))).collect(SUB)
    A.store(db, "azure", SUB, broken)
    db.commit()
    assert db.scalar(select(AccessAssignment)).removed_at is None
    fake.assignments = []
    collect(db, fake)
    assert db.scalar(select(AccessAssignment)).removed_at is not None


def test_grant_request_approval_execution_verification(client, db):
    setup(db)
    fake = FakeAzure([ra(1, "existing-user")])
    collect(db, fake)
    login(client, db, "dev@latentview.com", "cloud_engineer")
    r = client.post("/api/v1/access/requests", headers=H, json={
        "request_type": "grant", "provider": "azure", "scope_external_id": SUB, "sign_in_name": "dev@latentview.com", "role_name": "Owner",
        "justification": "Deploy the analytics platform", "requested_expiry": (date.today() + timedelta(days=30)).isoformat()}).json()
    assert r["privileged"] is True and [s["key"] for s in r["steps"]] == ["manager", "it_manager", "privileged"]
    assert client.post(f"/api/v1/access/requests/{r['id']}/decision", headers=H, json={"decision": "APPROVED"}).status_code == 403
    login(client, db, "gov@latentview.com", "governance_manager")       # manager step (access:approve)
    assert client.post(f"/api/v1/access/requests/{r['id']}/decision", headers=H, json={"decision": "APPROVED", "evidence": "msg-1"}).status_code == 200
    assert client.post(f"/api/v1/access/requests/{r['id']}/decision", headers=H, json={"decision": "APPROVED"}).status_code == 403  # IT step
    login(client, db, "itm@latentview.com", "access_admin")             # IT manager step (access:manage)
    client.post(f"/api/v1/access/requests/{r['id']}/decision", headers=H, json={"decision": "APPROVED"})
    login(client, db, "gov2@latentview.com", "governance_manager")      # privileged step (governance:manage), a different person
    assert client.post(f"/api/v1/access/requests/{r['id']}/decision", headers=H, json={"decision": "APPROVED"}).json()["status"] == "APPROVED"
    g = db.scalar(select(AccessGrant))
    db.refresh(g)
    assert g.state == "APPROVED" and g.manager_approved_by == "gov@latentview.com" and g.it_manager_approved_by == "itm@latentview.com"
    # executing is recorded, but the access is not ACTIVE until the provider shows it
    login(client, db, "itm@latentview.com", "access_admin")
    assert client.post(f"/api/v1/access/requests/{r['id']}/execute", headers=H, json={"decision": "x"}).status_code == 422
    ex = client.post(f"/api/v1/access/requests/{r['id']}/execute", headers=H, json={"decision": "x", "notes": "Assigned Owner in the Azure portal"}).json()
    assert ex["status"] == "EXECUTED"
    reg = client.get("/api/v1/access/register").json()["items"][0]
    assert reg["access_status"] == "Pending" and reg["observed_in_provider"] is False
    assert client.get("/api/v1/access/reconciliation").json()["approved_not_provisioned"][0]["sign_in_name"] == "dev@latentview.com"
    fake.assignments.append(ra(2, "dev@latentview.com", OWNER))  # principal id equals the sign-in name in this simulation
    collect(db, fake)
    assert client.get(f"/api/v1/access/requests/{r['id']}").json()["status"] == "VERIFIED"
    reg = client.get("/api/v1/access/register").json()["items"][0]
    assert reg["access_status"] == "Active" and reg["observed_in_provider"] is True
    statuses = {a["principal_id"]: a["approval_status"] for a in client.get("/api/v1/access/assignments").json()["items"]}
    assert statuses == {"existing-user": "UNAPPROVED", "dev@latentview.com": "APPROVED"}
    s = client.get("/api/v1/access/summary").json()
    assert s["unapproved"] == 1 and s["privileged"] == 1 and s["inactive_identities"] is None  # sign-ins not collected: unknown, not 0
    hist = client.get(f"/api/v1/access/requests/{r['id']}").json()["history"]
    assert [h["decision"] for h in hist] == ["SUBMITTED", "APPROVED", "APPROVED", "APPROVED", "EXECUTED"]
    row = db.scalar(select(AccessApproval))
    row.notes = "tampered"
    try:
        db.commit()
        raise AssertionError("access approvals are append-only")
    except ImmutableRecordError:
        db.rollback()


def test_revocation_is_verified_only_when_the_provider_no_longer_returns_it(client, db):
    setup(db)
    fake = FakeAzure([ra(1, "contractor@latentview.com", OWNER)])
    collect(db, fake)
    login(client, db, "itm@latentview.com", "access_admin")
    a = client.get("/api/v1/access/assignments").json()["items"][0]
    assert a["approval_status"] == "UNAPPROVED"
    assert client.post("/api/v1/access/requests", headers=H, json={"request_type": "revocation", "assignment_id": a["id"], "reason": "whatever",
                                                                    "justification": "No approval on record"}).status_code == 422
    r = client.post("/api/v1/access/requests", headers=H, json={"request_type": "revocation", "assignment_id": a["id"], "reason": "unapproved",
                                                                "justification": "No approval on record for Owner"}).json()
    login(client, db, "itm2@latentview.com", "access_admin")
    client.post(f"/api/v1/access/requests/{r['id']}/decision", headers=H, json={"decision": "APPROVED"})
    client.post(f"/api/v1/access/requests/{r['id']}/execute", headers=H, json={"decision": "x", "notes": "Removed the role assignment"})
    collect(db, fake)  # still present at the provider
    assert client.get(f"/api/v1/access/requests/{r['id']}").json()["status"] == "EXECUTED"
    fake.assignments = []
    collect(db, fake)
    got = client.get(f"/api/v1/access/requests/{r['id']}").json()
    assert got["status"] == "VERIFIED" and "no longer returned" in got["verification_result"]


def test_import_business_register_extension_and_expiry(client, db):
    setup(db)
    fake = FakeAzure([ra(1, "ana@latentview.com")])
    collect(db, fake)
    login(client, db, "itm@latentview.com", "access_admin")
    past = (date.today() - timedelta(days=3)).strftime("%d/%m/%Y")
    csv = ("Cloud Provider,Environment,Account Name,Account ID,Resource Group,DisplayName,Access Details,SignInName,Manager Approved By,"
           "IT Manager Approved By,Access Given Date,Access Extended Date,Access Expiry Date,Access Revocation Date,Email Subject\n"
           f"Azure,Production,analytics-prod,{SUB},,Ana,Reader,ana@latentview.com,Mgr One,IT One,01/01/2026,,{past},,RE: Access for Ana\n"
           f"Azure,Production,analytics-prod,{SUB},,Bad,Reader,,Mgr,IT,01/01/2026,,,,\n")
    res = client.post("/api/v1/access/register/import", headers=H, json={"csv_text": csv}).json()
    assert res["imported"] == 1 and res["errors"][0]["row"] == 3
    reg = client.get("/api/v1/access/register").json()["items"][0]
    assert reg["manager_approved_by"] == "Mgr One" and reg["email_subject"] == "RE: Access for Ana" and reg["source"] == "import"
    assert reg["access_status"] == "Expired"  # verified present, then past expiry
    st = client.get("/api/v1/access/assignments").json()["items"][0]["approval_status"]
    assert st == "EXPIRED_STILL_ACTIVE"
    login(client, db, "ana@latentview.com", "cloud_engineer")
    r = client.post("/api/v1/access/requests", headers=H, json={"request_type": "extension", "grant_id": reg["id"], "justification": "Project extended to Q2",
                                                                "requested_expiry": (date.today() + timedelta(days=60)).isoformat()}).json()
    for email, role in (("gov@latentview.com", "governance_manager"), ("itm@latentview.com", "access_admin")):
        login(client, db, email, role)
        client.post(f"/api/v1/access/requests/{r['id']}/decision", headers=H, json={"decision": "APPROVED"})
    reg = client.get("/api/v1/access/register").json()["items"][0]
    assert reg["access_status"] == "Active" and reg["access_extended_date"] == date.today().isoformat()


def test_access_review_creates_revocation_requests(client, db):
    setup(db)
    collect(db, FakeAzure([ra(1, "u1", OWNER), ra(2, "u2")]))
    login(client, db, "itm@latentview.com", "access_admin")
    rv = client.post("/api/v1/access/reviews", headers=H, json={"name": "Q4 privileged review", "privileged_only": True, "reviewer": "gov@latentview.com",
                                                                "due_date": (date.today() + timedelta(days=14)).isoformat()}).json()
    assert rv["items"] == 1
    login(client, db, "gov@latentview.com", "governance_manager")
    item = client.get(f"/api/v1/access/reviews/{rv['id']}").json()["items"][0]
    assert client.post(f"/api/v1/access/reviews/{rv['id']}/items/{item['id']}", headers=H, json={"decision": "REMOVE"}).status_code == 422
    d = client.post(f"/api/v1/access/reviews/{rv['id']}/items/{item['id']}", headers=H, json={"decision": "REMOVE", "comment": "Left the project"}).json()
    assert d["follow_up_request_id"]
    assert client.post(f"/api/v1/access/reviews/{rv['id']}/complete", headers=H).json()["status"] == "COMPLETED"
    assert client.get(f"/api/v1/access/requests/{d['follow_up_request_id']}").json()["request_type"] == "revocation"


def test_access_permissions(client, db):
    setup(db)
    login(client, db, "v@latentview.com", "viewer")
    assert client.get("/api/v1/access/assignments").status_code == 403
    assert client.get("/api/v1/access/requests").status_code == 200  # own requests only
    assert client.post("/api/v1/access/register/import", headers=H, json={"csv_text": "a,b,c\n1,2,3"}).status_code == 403
    login(client, db, "aud@latentview.com", "auditor")
    assert client.get("/api/v1/access/summary").status_code == 200
    assert client.post("/api/v1/access/reconcile", headers=H).status_code == 403
    db.add(CloudProject(external_id="p1", name="p1"))
    db.commit()
