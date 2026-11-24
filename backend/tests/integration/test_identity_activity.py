"""User Access monthly activity: users added / deleted come only from successful user-creation events in the collected
audit logs; role assignments, service accounts and failed calls are never counted as new users; duplicates are counted once."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.models import AuditEvent
from app.services.access import identity_activity as IA
from tests.integration.test_identity_governance import login

NOW = datetime.now(UTC)


def _ev(db, eid, provider, scope, name, raw, minutes=10, principal="admin@latentview.com"):
    db.add(AuditEvent(event_id=eid, provider=provider, scope_external_id=scope, event_timestamp=NOW - timedelta(minutes=minutes),
                      event_name=name, principal=principal, raw={"outcome": "success", **raw}))


def _seed(db):
    # AWS: a new IAM user (counted), the same user via a second source on the same day (counted once), a policy attach (access granted)
    _ev(db, "a1", "aws", "111", "CreateUser", {"requestParameters": {"userName": "asha"}})
    _ev(db, "a2", "aws", "111", "CreateUser", {"requestParameters": {"userName": "ASHA"}}, minutes=9)
    _ev(db, "a3", "aws", "111", "AttachUserPolicy", {"requestParameters": {"userName": "asha", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}})
    _ev(db, "a4", "aws", "111", "DeleteUser", {"requestParameters": {"userName": "old.user"}})
    _ev(db, "a5", "aws", "111", "CreateUser", {"requestParameters": {"userName": "blocked"}, "outcome": "denied"})  # failed: not counted
    _ev(db, "a6", "aws", "111", "DescribeInstances", {})                                                         # unrelated
    # Entra ID: user added, role membership added
    _ev(db, "entra-audit:1", "azure", "tenant", "Add user", {"targetResources": [{"userPrincipalName": "ravi@latentview.com"}]})
    _ev(db, "entra-audit:2", "azure", "tenant", "Add member to role",
        {"targetResources": [{"userPrincipalName": "ravi@latentview.com", "modifiedProperties": [{"displayName": "Role.DisplayName", "newValue": "\"Global Reader\""}]}]})
    # Azure RBAC role assignment: access granted, not a user
    _ev(db, "z1", "azure", "sub-1", "Microsoft.Authorization/roleAssignments/write",
        {"properties": {"requestbody": '{"properties":{"principalId":"p-1","roleDefinitionId":"/x/roleDefinitions/acdd72a7"}}'}})
    # GCP: service account (service identity, not a user) and a SetIamPolicy with one add and one remove
    _ev(db, "g1", "gcp", "proj", "google.iam.admin.v1.CreateServiceAccount", {"request": {"accountId": "etl-runner"}})
    _ev(db, "g2", "gcp", "proj", "SetIamPolicy", {"serviceData": {"policyDelta": {"bindingDeltas": [
        {"action": "ADD", "role": "roles/viewer", "member": "user:meena@latentview.com"},
        {"action": "REMOVE", "role": "roles/editor", "member": "user:meena@latentview.com"}]}}})
    # last month: never in this month's counts
    _ev(db, "old", "aws", "111", "CreateUser", {"requestParameters": {"userName": "last.month"}}, minutes=60 * 24 * 40)
    db.commit()


def test_classification_and_counts(db):
    _seed(db)
    start, end, _, _ = IA.month_bounds(now=NOW)
    if (NOW - timedelta(minutes=10)) < start:  # first minutes of a month in IST: nothing meaningful to assert
        return
    data = IA.activity(db, start, end)
    c = data["counts"]
    assert c["user_created"] == 2            # asha (once, despite two records) + ravi; never the role grants or the service account
    assert c["user_deleted"] == 1
    assert c["service_identity_created"] == 1
    assert c["role_assigned"] == 4           # AWS attach, Entra role, Azure RBAC, GCP add
    assert c["role_removed"] == 1            # GCP remove
    assert data["failed_attempts"] == 1      # denied CreateUser is listed, not counted
    targets = {(e["kind"], e["target"]) for e in data["events"]}
    assert ("user_created", "ravi@latentview.com") in targets and ("role_assigned", "user:meena@latentview.com") in targets
    assert all(e["target"] != "last.month" for e in data["events"])
    entra_role = next(e for e in data["events"] if e["event_id"] == "entra-audit:2")
    assert entra_role["role"] == "Global Reader"


def test_api_month_period_coverage_and_rbac(client, db):
    _seed(db)
    login(client, db, "auditor@latentview.com", "auditor")
    r = client.get("/api/v1/access/activity")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["period"]["complete"] is False and "so far" in body["period"]["note"]
    assert {c["provider"] for c in body["coverage"]} == {"aws", "azure", "gcp"}
    assert "role assignments are counted separately" in body["basis"]
    only = client.get("/api/v1/access/activity", params={"kind": "user_deleted"}).json()
    assert only["events"] and all(e["kind"] == "user_deleted" for e in only["events"])
    prev = (NOW.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")
    assert client.get("/api/v1/access/activity", params={"month": prev}).json()["period"]["complete"] is True
    assert client.get("/api/v1/access/activity", params={"month": "2026-1"}).status_code == 422
    login(client, db, "viewer@latentview.com", "viewer")
    assert client.get("/api/v1/access/activity").status_code == 403
