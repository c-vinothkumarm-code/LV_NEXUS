"""Directory and hierarchy collectors that complete the access inventory (read-only).

- Azure: Microsoft Graph users / groups / service principals / application credentials / directory roles / PIM
  eligibility; management groups and their RBAC assignments; Azure RBAC PIM eligibility per subscription.
- AWS: IAM users (status, creation, last password use), access-key metadata, inline policies, permission boundaries,
  role trust (cross-account principals); IAM Identity Center users, groups and memberships.
- GCP: organization and folder IAM policies (inherited by every project below them), service accounts and their
  user-managed key metadata, principals the provider reports as deleted.

Every source reports coverage. `identities_complete` is True only when the identity listing finished without error:
only then can an identity that is absent be treated as deleted. Secrets are never read; only credential metadata."""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from app.services.access.collectors import Found, Result, _cov
from app.services.azure.rest import ARM, GRAPH, AzureRest
from app.services.reliability import GCP_TIMEOUT
from app.services.vuln.common import parse_ts, with_retry

log = logging.getLogger(__name__)


@dataclass
class DirIdentity:
    principal_id: str
    principal_type: str
    display_name: str | None = None
    sign_in_name: str | None = None
    enabled: bool | None = None
    user_type: str | None = None
    created_at: datetime | None = None
    last_sign_in_at: datetime | None = None
    attrs: dict = field(default_factory=dict)


@dataclass
class DirMember:
    group_id: str
    group_name: str | None
    member_id: str
    member_type: str


@dataclass
class DirCredential:
    principal_id: str
    credential_id: str
    kind: str
    status: str | None = None
    created_at: datetime | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    scope: str | None = None


@dataclass
class Directory:
    provider: str
    directory_scope: str
    identities: list[DirIdentity] = field(default_factory=list)
    members: list[DirMember] = field(default_factory=list)
    credentials: list[DirCredential] = field(default_factory=list)
    assignments: dict[str, Result] = field(default_factory=dict)  # scope key -> extra assignments (tenant, MG, org, folder, PIM)
    coverage: list[dict] = field(default_factory=list)
    identities_complete: bool = False
    members_complete: bool = False
    credentials_complete: bool = False

    def extra(self, scope_key: str) -> Result:
        return self.assignments.setdefault(scope_key, Result())

    def cover(self, source: str, exc: Exception | None = None, note: str | None = None) -> bool:
        r = Result()
        _cov(r, source, exc, note)
        self.coverage += r.coverage
        return r.complete


def _odata_type(item: dict) -> str:
    t = (item.get("@odata.type") or "").rsplit(".", 1)[-1]
    return {"user": "User", "group": "Group", "servicePrincipal": "ServicePrincipal", "device": "Device"}.get(t, t or "Unknown")


def _try(d: Directory, source: str, fn: Callable[[], str | None]) -> bool:
    try:
        note = fn()
        return d.cover(source, note=note)
    except Exception as exc:  # noqa: BLE001 - recorded as coverage, never as "nothing found"
        return d.cover(source, exc)


# ------------------------------------------------------------------------------------------------ Azure
class AzureDirectory:
    provider = "azure"

    def __init__(self, settings, rest: AzureRest | None = None):
        self.settings = settings
        self.rest = rest or AzureRest(settings)

    def collect(self, subscription_ids: list[str], group_ids: set[str]) -> Directory:
        tenant = self.settings.azure_tenant_id or "tenant"
        d = Directory("azure", tenant)
        users_ok = _try(d, "entra_users", lambda: self._users(d))
        sps_ok = _try(d, "entra_service_principals", lambda: self._service_principals(d))
        d.identities_complete = users_ok and sps_ok
        d.members_complete = _try(d, "entra_group_members", lambda: self._members(d, group_ids))
        d.credentials_complete = _try(d, "entra_app_credentials", lambda: self._app_credentials(d))
        _try(d, "entra_directory_roles", lambda: self._directory_roles(d, tenant))
        _try(d, "entra_pim_eligible", lambda: self._directory_eligible(d, tenant))
        _try(d, "azure_management_groups", lambda: self._management_groups(d))
        for sub in subscription_ids:
            _try(d, f"azure_pim_eligible:{sub}", lambda s=sub: self._rbac_eligible(d, s))
        return d

    def _users(self, d: Directory) -> str:
        n = 0
        for u in self.rest.pages(f"{GRAPH}/users", {"$select": "id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime",
                                                    "$top": "999"}):
            d.identities.append(DirIdentity(u["id"], "User", u.get("displayName"), u.get("userPrincipalName") or u.get("mail"),
                                            u.get("accountEnabled"), u.get("userType"), parse_ts(u.get("createdDateTime"))))
            n += 1
        return f"{n} users (members and guests)"

    def _service_principals(self, d: Directory) -> str:
        n = 0
        for s in self.rest.pages(f"{GRAPH}/servicePrincipals", {"$select": "id,appId,displayName,servicePrincipalType,accountEnabled",
                                                                "$top": "999"}):
            kind = "ManagedIdentity" if s.get("servicePrincipalType") == "ManagedIdentity" else "ServicePrincipal"
            d.identities.append(DirIdentity(s["id"], kind, s.get("displayName"), s.get("appId"), s.get("accountEnabled"),
                                            attrs={"app_id": s.get("appId"), "sp_type": s.get("servicePrincipalType")}))
            n += 1
        return f"{n} service principals and managed identities"

    def _members(self, d: Directory, group_ids: set[str]) -> str:
        for gid in sorted(group_ids):
            for m in self.rest.pages(f"{GRAPH}/groups/{gid}/transitiveMembers", {"$select": "id,displayName,userPrincipalName", "$top": "999"}):
                d.members.append(DirMember(gid, None, m["id"], _odata_type(m)))
        return f"transitive members of {len(group_ids)} groups that hold role assignments"

    def _app_credentials(self, d: Directory) -> str:
        by_app = {i.attrs.get("app_id"): i.principal_id for i in d.identities if i.attrs.get("app_id")}
        n = 0
        for a in self.rest.pages(f"{GRAPH}/applications", {"$select": "appId,displayName,passwordCredentials,keyCredentials", "$top": "999"}):
            owner = by_app.get(a.get("appId")) or a.get("appId")
            for kind, items in (("client_secret", a.get("passwordCredentials") or []), ("certificate", a.get("keyCredentials") or [])):
                for c in items:
                    end = parse_ts(c.get("endDateTime"))
                    d.credentials.append(DirCredential(owner, c.get("keyId"), kind, None, parse_ts(c.get("startDateTime")), end))
                    n += 1
        return f"{n} application secrets / certificates (metadata only)"

    def _directory_roles(self, d: Directory, tenant: str) -> str:
        res = d.extra(f"tenant:{tenant}")
        n = 0
        for a in self.rest.pages(f"{GRAPH}/roleManagement/directory/roleAssignments", {"$expand": "roleDefinition"}):
            role = (a.get("roleDefinition") or {}).get("displayName") or a.get("roleDefinitionId")
            res.assignments.append(Found("entra_directory_role", a["id"], "tenant", f"/tenants/{tenant}{a.get('directoryScopeId') or '/'}",
                                         a["principalId"], "Unknown", role, a.get("roleDefinitionId"), "Direct", pim_state="active"))
            n += 1
        return f"{n} Entra directory role assignments"

    def _directory_eligible(self, d: Directory, tenant: str) -> str:
        res = d.extra(f"tenant:{tenant}")
        n = 0
        for a in self.rest.pages(f"{GRAPH}/roleManagement/directory/roleEligibilitySchedules", {"$expand": "roleDefinition"}):
            role = (a.get("roleDefinition") or {}).get("displayName") or a.get("roleDefinitionId")
            f = Found("entra_pim_eligible", a["id"], "tenant", f"/tenants/{tenant}{a.get('directoryScopeId') or '/'}", a["principalId"],
                      "Unknown", role, a.get("roleDefinitionId"), "Direct", pim_state="eligible")
            f.expires_at = parse_ts(((a.get("scheduleInfo") or {}).get("expiration") or {}).get("endDateTime"))
            res.assignments.append(f)
            n += 1
        return f"{n} PIM-eligible directory role schedules"

    def _management_groups(self, d: Directory) -> str:
        groups = list(self.rest.pages(f"{ARM}/providers/Microsoft.Management/managementGroups", {"api-version": "2021-04-01"}))
        n = 0
        for g in groups:
            mg = g["id"]
            name = g.get("name") or mg.rsplit("/", 1)[-1]
            roles = {r["id"].lower(): (r.get("properties") or {}).get("roleName") for r in
                     self.rest.pages(f"{ARM}{mg}/providers/Microsoft.Authorization/roleDefinitions", {"api-version": "2022-04-01"})}
            res = d.extra(f"mg:{name}")
            for a in self.rest.pages(f"{ARM}{mg}/providers/Microsoft.Authorization/roleAssignments",
                                     {"api-version": "2022-04-01", "$filter": "atScope()"}):
                p = a.get("properties") or {}
                if (p.get("scope") or "").lower() != mg.lower():
                    continue  # assignments above this group are recorded at their own group
                rid = (p.get("roleDefinitionId") or "")
                role = roles.get(rid.lower()) or rid.rsplit("/", 1)[-1]
                res.assignments.append(Found("azure_rbac", a["id"], "management_group", mg, p.get("principalId"), p.get("principalType") or "Unknown",
                                             role, rid, "Group" if p.get("principalType") == "Group" else "Direct",
                                             condition=p.get("condition"), pim_state="active"))
                n += 1
        return f"{len(groups)} management groups, {n} role assignments made at management-group level"

    def _rbac_eligible(self, d: Directory, sub: str) -> str:
        res = d.extra(sub)
        n = 0
        for a in self.rest.pages(f"{ARM}/subscriptions/{sub}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances",
                                 {"api-version": "2020-10-01"}):
            p = a.get("properties") or {}
            exp = p.get("expandedProperties") or {}
            scope = p.get("scope") or f"/subscriptions/{sub}"
            low = scope.lower()
            level = ("management_group" if "managementgroups" in low else "resource" if "/providers/" in low.split("/resourcegroups/")[-1] and
                     "/resourcegroups/" in low else "resource_group" if "/resourcegroups/" in low else "subscription")
            rg = scope.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in scope else None
            f = Found("azure_pim_eligible", f"{a['id']}|via:{sub}", level, scope, p.get("principalId"), p.get("principalType") or "Unknown",
                      (exp.get("roleDefinition") or {}).get("displayName") or (p.get("roleDefinitionId") or "").rsplit("/", 1)[-1],
                      p.get("roleDefinitionId"), "Inherited" if level == "management_group" else "Direct", resource_group=rg,
                      pim_state="eligible", display_name=(exp.get("principal") or {}).get("displayName"),
                      sign_in_name=(exp.get("principal") or {}).get("email"))
            f.expires_at = parse_ts(p.get("endDateTime"))
            if level == "management_group":
                f.inherited_from = scope
            res.assignments.append(f)
            n += 1
        return f"{n} PIM-eligible Azure role assignments"


# ------------------------------------------------------------------------------------------------ AWS
class AwsDirectory:
    provider = "aws"

    def __init__(self, connector):
        self.connector = connector

    def collect(self, account_id: str, is_management: bool) -> Directory:
        d = Directory("aws", account_id)
        try:
            session = self.connector.session_for(account_id, is_management)
            iam = self.connector.client(session, "iam")
        except Exception as exc:  # noqa: BLE001
            d.cover("aws_iam_directory", exc)
            return d
        d.identities_complete = _try(d, "aws_iam_users", lambda: self._users(d, iam, account_id))
        _try(d, "aws_iam_roles", lambda: self._roles(d, iam, account_id))
        d.credentials_complete = d.identities_complete
        d.members_complete = d.identities_complete
        return d

    def _users(self, d: Directory, iam, account_id: str) -> str:
        res = d.extra(account_id)
        for page in iam.get_paginator("list_users").paginate():
            for u in page.get("Users", []):
                arn, name = u["Arn"], u["UserName"]
                detail = with_retry(lambda n=name: iam.get_user(UserName=n)).get("User", {})
                boundary = (detail.get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
                d.identities.append(DirIdentity(arn, "User", name, name, True, None, u.get("CreateDate"), u.get("PasswordLastUsed"),
                                                {"permission_boundary": boundary, "path": u.get("Path")}))
                for gp in iam.get_paginator("list_groups_for_user").paginate(UserName=name):
                    for g in gp.get("Groups", []):
                        d.members.append(DirMember(g["Arn"], g["GroupName"], arn, "User"))
                for kp in iam.get_paginator("list_access_keys").paginate(UserName=name):
                    for k in kp.get("AccessKeyMetadata", []):
                        used = with_retry(lambda kid=k["AccessKeyId"]: iam.get_access_key_last_used(AccessKeyId=kid)).get("AccessKeyLastUsed", {})
                        # only the key ID (an identifier, not a secret) and its dates are kept
                        d.credentials.append(DirCredential(arn, k["AccessKeyId"], "access_key", k.get("Status"), k.get("CreateDate"),
                                                           None, used.get("LastUsedDate"), account_id))
                for pp in iam.get_paginator("list_user_policies").paginate(UserName=name):
                    for pol in pp.get("PolicyNames", []):
                        res.assignments.append(Found("aws_iam_inline", f"{arn}|inline:{pol}", "account", f"arn:aws:iam::{account_id}", arn,
                                                     "User", f"inline:{pol}", None, "Direct", display_name=name, sign_in_name=name))
        return f"{len(d.identities)} IAM users with access-key metadata, inline policies and permission boundaries"

    def _roles(self, d: Directory, iam, account_id: str) -> str:
        res = d.extra(account_id)
        n = 0
        for page in iam.get_paginator("list_roles").paginate():
            for r in page.get("Roles", []):
                if "/aws-service-role/" in r.get("Path", ""):
                    continue
                trust = r.get("AssumeRolePolicyDocument") or {}
                principals: list[str] = []
                for st in (trust.get("Statement") or []) if isinstance(trust, dict) else []:
                    p = (st.get("Principal") or {}).get("AWS") if isinstance(st.get("Principal"), dict) else None
                    principals += p if isinstance(p, list) else [p] if p else []
                cross = sorted({p for p in principals if account_id not in str(p)})
                d.identities.append(DirIdentity(r["Arn"], "Role", r["RoleName"], r["RoleName"], True, None, r.get("CreateDate"),
                                                ((r.get("RoleLastUsed") or {}).get("LastUsedDate")),
                                                {"cross_account_principals": cross, "max_session": r.get("MaxSessionDuration")}))
                for pp in iam.get_paginator("list_role_policies").paginate(RoleName=r["RoleName"]):
                    for pol in pp.get("PolicyNames", []):
                        res.assignments.append(Found("aws_iam_inline", f"{r['Arn']}|inline:{pol}", "account", f"arn:aws:iam::{account_id}",
                                                     r["Arn"], "Role", f"inline:{pol}", None, "Direct", display_name=r["RoleName"]))
                n += 1
        return f"{n} IAM roles with trust relationships ({sum(1 for i in d.identities if i.attrs.get('cross_account_principals'))} trusted cross-account)"

    def identity_center(self) -> Directory:
        d = Directory("aws", "identity-center")
        try:
            sso = self.connector.client(self.connector.base_session(), "sso-admin")
            inst = (sso.list_instances().get("Instances") or [None])[0]
            if not inst:
                d.cover("aws_identity_store", note="IAM Identity Center is not enabled")
                return d
            store = self.connector.client(self.connector.base_session(), "identitystore")
            sid = inst["IdentityStoreId"]
            for page in store.get_paginator("list_users").paginate(IdentityStoreId=sid):
                for u in page.get("Users", []):
                    mail = next((e.get("Value") for e in u.get("Emails", []) if e.get("Primary")), None)
                    d.identities.append(DirIdentity(u["UserId"], "User", u.get("DisplayName"), u.get("UserName") or mail, None))
            for page in store.get_paginator("list_groups").paginate(IdentityStoreId=sid):
                for g in page.get("Groups", []):
                    d.identities.append(DirIdentity(g["GroupId"], "Group", g.get("DisplayName"), g.get("DisplayName")))
                    for mp in store.get_paginator("list_group_memberships").paginate(IdentityStoreId=sid, GroupId=g["GroupId"]):
                        for m in mp.get("GroupMemberships", []):
                            uid = (m.get("MemberId") or {}).get("UserId")
                            if uid:
                                d.members.append(DirMember(g["GroupId"], g.get("DisplayName"), uid, "User"))
            d.identities_complete = d.members_complete = True
            d.cover("aws_identity_store", note=f"{len(d.identities)} Identity Center users and groups")
        except Exception as exc:  # noqa: BLE001
            d.cover("aws_identity_store", exc)
        return d


# ------------------------------------------------------------------------------------------------ GCP
class GcpDirectory:
    provider = "gcp"

    def __init__(self, settings, connector, session=None):
        self.settings, self.connector = settings, connector
        self._session = session

    def _s(self):
        if self._session is None:
            from google.auth.transport.requests import AuthorizedSession
            self._session = AuthorizedSession(self.connector.clients.credentials())
        return self._session

    def _get(self, url: str, params: dict | None = None) -> dict:
        from app.services.vuln.common import HttpError

        def call():
            r = self._s().get(url, params=params, timeout=60)
            if r.status_code >= 400:
                raise HttpError(r.status_code, r.text)
            return r.json()
        return with_retry(call)

    @staticmethod
    def _bindings(policy, scope_key: str, scope_path: str, level: str, res: Result) -> None:
        for b in policy.bindings:
            cond = getattr(getattr(b, "condition", None), "expression", None) or None
            for m in b.members:
                kind, _, ident = m.partition(":")
                ptype = {"user": "User", "group": "Group", "serviceAccount": "ServiceAccount", "domain": "Domain", "deleted": "Deleted",
                         "principal": "Federated", "principalSet": "Federated"}.get(kind, kind or "Special")
                res.assignments.append(Found("gcp_iam", f"{scope_path}|{b.role}|{m}|{cond or ''}", level, scope_path, m, ptype, b.role, b.role,
                                             "Group" if ptype == "Group" else "Direct", condition=cond, display_name=ident or m,
                                             sign_in_name=ident or m))

    def collect(self, projects: list) -> tuple[Directory, dict[str, list[str]]]:
        """Returns the directory and, per project, its ancestor chain (nearest folder first, organization last)."""
        org = f"organizations/{self.settings.gcp_organization_id}"
        d = Directory("gcp", org)
        parents: dict[str, str] = {}

        def walk() -> str:
            queue, n = [org], 0
            while queue:
                p = queue.pop()
                for f in self.connector.clients.folders.list_folders(parent=p, timeout=GCP_TIMEOUT):
                    parents[f.name] = p
                    queue.append(f.name)
                    n += 1
            return f"{n} folders"
        _try(d, "gcp_folders", walk)

        def org_policy() -> str:
            from google.cloud import resourcemanager_v3
            client = resourcemanager_v3.OrganizationsClient(credentials=self.connector.clients.credentials())
            self._bindings(with_retry(lambda: client.get_iam_policy(request={"resource": org}, timeout=GCP_TIMEOUT)), f"org:{self.settings.gcp_organization_id}",
                           org, "organization", d.extra(f"org:{self.settings.gcp_organization_id}"))
            return "organization IAM policy"
        _try(d, "gcp_org_iam", org_policy)

        def folder_policies() -> str:
            for f in parents:
                self._bindings(with_retry(lambda name=f: self.connector.clients.folders.get_iam_policy(request={"resource": name}, timeout=GCP_TIMEOUT)),
                               f"folder:{f.split('/')[-1]}", f, "folder", d.extra(f"folder:{f.split('/')[-1]}"))
            return f"IAM policies of {len(parents)} folders"
        _try(d, "gcp_folder_iam", folder_policies)

        chains: dict[str, list[str]] = {}
        for p in projects:
            chain, cur = [], p.parent
            while cur and cur not in chain:
                chain.append(cur)
                cur = parents.get(cur)
            chains[p.external_id] = chain

        sa_ok = True
        for p in projects:
            def sas(pid=p.external_id) -> str:
                n = 0
                url = f"https://iam.googleapis.com/v1/projects/{pid}/serviceAccounts"
                params: dict | None = {"pageSize": 100}
                while url:
                    data = self._get(url, params)
                    for sa in data.get("accounts", []):
                        email = sa["email"]
                        d.identities.append(DirIdentity(f"serviceAccount:{email}", "ServiceAccount", sa.get("displayName") or email, email,
                                                        not sa.get("disabled", False), attrs={"project": pid}))
                        keys = self._get(f"https://iam.googleapis.com/v1/projects/{pid}/serviceAccounts/{email}/keys",
                                         {"keyTypes": "USER_MANAGED"}).get("keys", [])
                        for k in keys:
                            d.credentials.append(DirCredential(f"serviceAccount:{email}", k["name"].rsplit("/", 1)[-1], "sa_key",
                                                               "Disabled" if k.get("disabled") else "Active", parse_ts(k.get("validAfterTime")),
                                                               parse_ts(k.get("validBeforeTime")), None, pid))
                        n += 1
                    token = data.get("nextPageToken")
                    url, params = (url, {"pageSize": 100, "pageToken": token}) if token else (None, None)
                return f"{n} service accounts in {pid}"
            sa_ok = _try(d, f"gcp_service_accounts:{p.external_id}", sas) and sa_ok
        d.identities_complete = d.credentials_complete = sa_ok and bool(projects)
        return d, chains
