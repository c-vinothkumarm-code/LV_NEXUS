"""Read-only access inventory collectors: Azure RBAC, AWS IAM (+ IAM Identity Center), GCP IAM.

Each collector returns (assignments, identities, coverage notes) for one scope. Calls are read-only; a permission
error is reported as coverage, never as "no access found". Display names that need a directory lookup (Microsoft
Graph, AWS Identity Store) are filled only where that lookup is permitted."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field

from app.services.reliability import GCP_TIMEOUT
from app.services.vuln.common import classify, with_retry

log = logging.getLogger(__name__)

PRIVILEGED_WORDS = ("owner", "administrator", "admin", "contributor", "fullaccess", "editor", "useraccessadministrator",
                    "securityadmin", "iam.securityadmin", "poweruser")


def is_privileged(role: str) -> bool:
    r = role.lower().replace(" ", "").replace("_", "")
    return any(w in r for w in PRIVILEGED_WORDS) and "reader" not in r and "viewer" not in r


def h(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


@dataclass
class Found:
    source: str
    source_id: str
    scope_level: str
    scope_path: str
    principal_id: str
    principal_type: str
    role_name: str
    role_id: str | None = None
    access_type: str = "Direct"
    resource_group: str | None = None
    resource_name: str | None = None
    condition: str | None = None
    pim_state: str | None = None
    display_name: str | None = None
    sign_in_name: str | None = None
    expires_at: object | None = None      # datetime, when the provider reports an end (PIM schedule, IAM condition)
    inherited_from: str | None = None     # parent scope the assignment was made at


@dataclass
class Result:
    assignments: list[Found] = field(default_factory=list)
    coverage: list[dict] = field(default_factory=list)  # [{source, state, message}]
    complete: bool = True  # False = a source failed; nothing is marked removed for this scope


def _cov(res: Result, source: str, exc: Exception | None = None, note: str | None = None) -> None:
    if exc is None:
        res.coverage.append({"source": source, "state": "OK", "message": note or "collected"})
        return
    kind, msg = classify(exc)
    res.coverage.append({"source": source, "state": "ACCESS_DENIED" if kind == "permission" else "ERROR", "message": msg})
    res.complete = False


class AzureRbacCollector:
    provider = "azure"

    def __init__(self, connector):
        self.connector = connector

    def collect(self, sub_id: str) -> Result:
        res = Result()
        try:
            authz = self.connector.clients.authorization(sub_id)
            roles = {d.id.lower(): d.role_name for d in with_retry(lambda: list(authz.role_definitions.list(f"/subscriptions/{sub_id}")))}
            for a in with_retry(lambda: list(authz.role_assignments.list_for_subscription())):
                scope = a.scope or ""
                low = scope.lower()
                if low.startswith("/providers/microsoft.management/managementgroups") or low == "/":
                    level, access = "management_group", "Inherited"
                elif "/resourcegroups/" in low:
                    rest = scope.split("/resourceGroups/", 1)[1] if "/resourceGroups/" in scope else scope.split("/resourcegroups/", 1)[1]
                    rg = rest.split("/", 1)[0]
                    level = "resource" if "/providers/" in rest else "resource_group"
                    access = "Direct"
                else:
                    level, access, rg = "subscription", "Direct", None
                if level in ("subscription", "management_group"):
                    rg = None
                inherited_from = scope if access == "Inherited" else None
                # An assignment made at a management group / root appears in every subscription below it: the subscription is part
                # of the key so each subscription keeps its own inherited copy (the group-level original is stored at mg:<name>).
                source_id = f"{a.id}|via:{sub_id}" if inherited_from else a.id
                ptype = str(getattr(a, "principal_type", None) or "Unknown")
                if ptype.lower() == "group":
                    access = "Group" if access == "Direct" else access
                role = roles.get((a.role_definition_id or "").lower()) or (a.role_definition_id or "").rsplit("/", 1)[-1]
                res.assignments.append(Found(
                    source="azure_rbac", source_id=source_id, scope_level=level, scope_path=scope, principal_id=a.principal_id,
                    principal_type={"ServicePrincipal": "ServicePrincipal", "User": "User", "Group": "Group"}.get(ptype, ptype),
                    role_name=role, role_id=a.role_definition_id, access_type=access, resource_group=rg,
                    resource_name=scope.rsplit("/", 1)[-1] if level == "resource" else None, condition=getattr(a, "condition", None),
                    pim_state="active", inherited_from=inherited_from))
            _cov(res, "azure_rbac", note=f"{len(res.assignments)} active role assignments at subscription, resource group and resource "
                                         "scope, plus those inherited from management groups.")
        except Exception as exc:  # noqa: BLE001 - reported as coverage
            _cov(res, "azure_rbac", exc)
        return res


class AwsIamCollector:
    provider = "aws"

    def __init__(self, connector):
        self.connector = connector

    def collect(self, account_id: str, is_management: bool = False) -> Result:
        res = Result()
        try:
            session = self.connector.session_for(account_id, is_management)
            iam = self.connector.client(session, "iam")
            n = 0
            for page in iam.get_paginator("list_users").paginate():
                for u in page.get("Users", []):
                    arn, name = u["Arn"], u["UserName"]
                    groups = [g["GroupName"] for gp in iam.get_paginator("list_groups_for_user").paginate(UserName=name) for g in gp.get("Groups", [])]
                    for gp in iam.get_paginator("list_attached_user_policies").paginate(UserName=name):
                        for p in gp.get("AttachedPolicies", []):
                            res.assignments.append(Found("aws_iam", f"{arn}|{p['PolicyArn']}", "account", f"arn:aws:iam::{account_id}", arn, "User",
                                                         p["PolicyName"], p["PolicyArn"], "Direct", display_name=name, sign_in_name=name))
                            n += 1
                    for g in groups:
                        for gp in iam.get_paginator("list_attached_group_policies").paginate(GroupName=g):
                            for p in gp.get("AttachedPolicies", []):
                                res.assignments.append(Found("aws_iam", f"{arn}|group:{g}|{p['PolicyArn']}", "account", f"arn:aws:iam::{account_id}",
                                                             arn, "User", p["PolicyName"], p["PolicyArn"], "Group", display_name=name, sign_in_name=name))
                                n += 1
            for page in iam.get_paginator("list_roles").paginate():
                for r in page.get("Roles", []):
                    if "/aws-service-role/" in r.get("Path", "") or r["RoleName"].startswith("AWSServiceRole"):
                        continue
                    federated = "AWSReservedSSO_" in r["RoleName"] or "Federated" in str(r.get("AssumeRolePolicyDocument", ""))
                    for gp in iam.get_paginator("list_attached_role_policies").paginate(RoleName=r["RoleName"]):
                        for p in gp.get("AttachedPolicies", []):
                            res.assignments.append(Found("aws_iam", f"{r['Arn']}|{p['PolicyArn']}", "account", f"arn:aws:iam::{account_id}", r["Arn"],
                                                         "Role", p["PolicyName"], p["PolicyArn"], "Federated" if federated else "Direct",
                                                         display_name=r["RoleName"], sign_in_name=r["RoleName"]))
                            n += 1
            _cov(res, "aws_iam", note=f"{n} policy attachments for IAM users, groups and roles. Inline policies, SCPs and resource "
                                      "policies are not evaluated: this is not an effective-permission calculation.")
        except Exception as exc:  # noqa: BLE001
            _cov(res, "aws_iam", exc)
        return res

    def identity_center(self) -> dict[str, Result]:
        """Permission-set assignments per account from the management account (IAM Identity Center)."""
        out: dict[str, Result] = {}
        try:
            session = self.connector.base_session()
            sso = self.connector.client(session, "sso-admin")
            instances = sso.list_instances().get("Instances", [])
            if not instances:
                return out
            inst = instances[0]["InstanceArn"]
            sets = [ps for page in sso.get_paginator("list_permission_sets").paginate(InstanceArn=inst) for ps in page.get("PermissionSets", [])]
            for ps in sets:
                name = sso.describe_permission_set(InstanceArn=inst, PermissionSetArn=ps)["PermissionSet"]["Name"]
                for page in sso.get_paginator("list_accounts_for_provisioned_permission_set").paginate(InstanceArn=inst, PermissionSetArn=ps):
                    for acct in page.get("AccountIds", []):
                        res = out.setdefault(acct, Result())
                        for ap in sso.get_paginator("list_account_assignments").paginate(InstanceArn=inst, AccountId=acct, PermissionSetArn=ps):
                            for a in ap.get("AccountAssignments", []):
                                res.assignments.append(Found("aws_identity_center", f"{acct}|{ps}|{a['PrincipalType']}|{a['PrincipalId']}", "account",
                                                             f"arn:aws:organizations::{acct}", a["PrincipalId"], a["PrincipalType"].title(), name, ps,
                                                             "Group" if a["PrincipalType"] == "GROUP" else "Federated"))
            for res in out.values():
                _cov(res, "aws_identity_center", note="Identity Center permission-set assignments (principal IDs; names need Identity Store read).")
        except Exception as exc:  # noqa: BLE001
            r = Result()
            _cov(r, "aws_identity_center", exc)
            out["*"] = r
        return out


class GcpIamCollector:
    provider = "gcp"

    def __init__(self, connector):
        self.connector = connector

    def collect(self, project_id: str) -> Result:
        res = Result()
        try:
            policy = with_retry(lambda: self.connector.clients.projects.get_iam_policy(request={"resource": f"projects/{project_id}"}, timeout=GCP_TIMEOUT))
            for b in policy.bindings:
                cond = getattr(getattr(b, "condition", None), "expression", None) or None
                for m in b.members:
                    kind, _, ident = m.partition(":")
                    ptype = {"user": "User", "group": "Group", "serviceAccount": "ServiceAccount", "domain": "Domain",
                             "principal": "Federated", "principalSet": "Federated"}.get(kind, kind or "Special")
                    res.assignments.append(Found("gcp_iam", f"{project_id}|{b.role}|{m}|{cond or ''}", "project", f"projects/{project_id}", m, ptype,
                                                 b.role, b.role, "Group" if ptype == "Group" else ("Federated" if ptype == "Federated" else "Direct"),
                                                 condition=cond, display_name=ident or m, sign_in_name=ident or m))
            _cov(res, "gcp_iam", note=f"{len(res.assignments)} project-level bindings. Organization / folder bindings inherited by the project "
                                      "and resource-level IAM are not collected yet.")
        except Exception as exc:  # noqa: BLE001
            _cov(res, "gcp_iam", exc)
        return res
