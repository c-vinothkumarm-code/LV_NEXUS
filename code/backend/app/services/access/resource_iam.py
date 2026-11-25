"""Resource-level access (read-only), so the Access page can answer "who has access to what" below the account level.

- AWS: S3 bucket policies and customer-managed KMS key policies (Allow statements naming AWS principals). Identity
  policies are collected elsewhere; SCPs and permission boundaries are not combined, so this is not an effective-permission
  calculation.
- GCP: IAM policies set on individual resources (buckets, datasets, topics, service accounts, ...) via Cloud Asset
  Inventory `searchAllIamPolicies`, and Google group membership via the Cloud Identity API (transitive).
- Azure: resource-group and resource-scope role assignments are already returned by the Authorization API used for RBAC
  (the same data Azure Resource Graph exposes as `authorizationresources`), so no extra collector is needed.

Every call is a read (List*/Get*/search). A source that fails is reported in coverage and makes the result incomplete,
so nothing previously collected is marked removed because of a failed or partial call."""
from __future__ import annotations

import json

from app.services.access.collectors import Found, Result, _cov
from app.services.access.directory import Directory, DirMember

AWS_SOURCE = "aws_resource_policy"
GCP_SOURCE = "gcp_resource_iam"


def _principals(stmt: dict) -> list[tuple[str, str]]:
    p = stmt.get("Principal")
    if p == "*" or p == {"AWS": "*"}:
        return [("*", "Anyone")]
    out: list[tuple[str, str]] = []
    if isinstance(p, dict):
        for kind, vals in p.items():
            for v in [vals] if isinstance(vals, str) else vals or []:
                out.append((v, {"AWS": "Principal", "Service": "Service", "Federated": "Federated", "CanonicalUser": "CanonicalUser"}.get(kind, kind)))
    return out


def _actions(stmt: dict) -> str:
    a = stmt.get("Action") or stmt.get("NotAction") or []
    a = [a] if isinstance(a, str) else a
    s = ", ".join(a[:4]) + (f" (+{len(a) - 4})" if len(a) > 4 else "")
    return ("NOT " + s if "NotAction" in stmt else s)[:255] or "policy statement"


def _ptype(arn: str, kind: str) -> str:
    if kind != "Principal":
        return kind
    if ":role/" in arn or ":assumed-role/" in arn:
        return "Role"
    if ":user/" in arn:
        return "User"
    if arn.endswith(":root") or arn.isdigit():
        return "Account"
    return "Principal"


class AwsResourcePolicies:
    provider = "aws"

    def __init__(self, connector):
        self.connector = connector

    def _policy(self, res: Result, account_id: str, kind: str, name: str, arn: str, doc: str | dict) -> None:
        pol = json.loads(doc) if isinstance(doc, str) else doc
        for i, st in enumerate(pol.get("Statement") or []):
            if st.get("Effect") != "Allow":
                continue
            cond = json.dumps(st["Condition"], sort_keys=True)[:2000] if st.get("Condition") else None
            for principal, pkind in _principals(st):
                ptype = _ptype(principal, pkind)
                external = principal not in ("*",) and pkind == "Principal" and f":{account_id}:" not in principal and principal != account_id
                res.assignments.append(Found(
                    AWS_SOURCE, f"{arn}|{i}|{principal}", "resource", arn, principal, ptype, _actions(st), f"{kind} policy",
                    "Direct", resource_name=name, condition=cond, display_name=principal.rsplit("/", 1)[-1],
                    sign_in_name=principal, inherited_from="cross-account" if external else None))

    def collect(self, account_id: str, is_management: bool = False) -> Result:
        res = Result()
        try:
            session = self.connector.session_for(account_id, is_management)
        except Exception as exc:  # noqa: BLE001
            _cov(res, AWS_SOURCE, exc)
            return res
        try:
            s3 = self.connector.client(session, "s3")
            buckets = s3.list_buckets().get("Buckets", [])
            n = 0
            for b in buckets:
                name = b["Name"]
                try:
                    doc = s3.get_bucket_policy(Bucket=name)["Policy"]
                except Exception as exc:  # noqa: BLE001
                    code = getattr(exc, "response", {}).get("Error", {}).get("Code") if hasattr(exc, "response") else None
                    if code == "NoSuchBucketPolicy":
                        continue
                    raise
                self._policy(res, account_id, "Bucket", name, f"arn:aws:s3:::{name}", doc)
                n += 1
            _cov(res, f"{AWS_SOURCE}:s3", note=f"{n} of {len(buckets)} buckets have a bucket policy")
        except Exception as exc:  # noqa: BLE001
            _cov(res, f"{AWS_SOURCE}:s3", exc)
        try:
            n = 0
            for region in self.connector.regions(session):
                kms = self.connector.client(session, "kms", region)
                for page in kms.get_paginator("list_keys").paginate():
                    for k in page.get("Keys", []):
                        meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
                        if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") == "PendingDeletion":
                            continue
                        doc = kms.get_key_policy(KeyId=k["KeyId"], PolicyName="default")["Policy"]
                        self._policy(res, account_id, "Key", meta.get("Description") or k["KeyId"], k["KeyArn"], doc)
                        n += 1
            _cov(res, f"{AWS_SOURCE}:kms", note=f"{n} customer-managed KMS key policies")
        except Exception as exc:  # noqa: BLE001
            _cov(res, f"{AWS_SOURCE}:kms", exc)
        return res


def _gcp_type(member: str) -> str:
    kind = member.partition(":")[0]
    return {"user": "User", "group": "Group", "serviceAccount": "ServiceAccount", "domain": "Domain", "principal": "Federated",
            "principalSet": "Federated"}.get(kind, "Special")


class GcpResourceIam:
    """Uses the REST session of GcpDirectory (`get(url, params)`) so retries, timeouts and errors are handled one way."""
    provider = "gcp"

    def __init__(self, get):
        self._get = get

    def collect(self, project_id: str) -> Result:
        res = Result()
        try:
            url = f"https://cloudasset.googleapis.com/v1/projects/{project_id}:searchAllIamPolicies"
            params: dict = {"pageSize": 500}
            n = 0
            while True:
                data = self._get(url, params)
                for r in data.get("results", []):
                    resource = r.get("resource", "")
                    if resource.startswith("//cloudresourcemanager.googleapis.com/"):
                        continue  # project / folder / organization bindings are collected by the project and hierarchy collectors
                    short = resource.rsplit("/", 1)[-1]
                    for b in (r.get("policy") or {}).get("bindings", []):
                        cond = (b.get("condition") or {}).get("expression")
                        for m in b.get("members", []):
                            ptype = _gcp_type(m)
                            ident = m.partition(":")[2] or m
                            res.assignments.append(Found(
                                GCP_SOURCE, f"{resource}|{b['role']}|{m}|{cond or ''}", "resource", resource, m, ptype, b["role"], b["role"],
                                "Group" if ptype == "Group" else "Direct", resource_name=short,
                                condition=cond, display_name=ident, sign_in_name=ident))
                            n += 1
                token = data.get("nextPageToken")
                if not token:
                    break
                params = {"pageSize": 500, "pageToken": token}
            _cov(res, GCP_SOURCE, note=f"{n} resource-level bindings (Cloud Asset Inventory)")
        except Exception as exc:  # noqa: BLE001
            _cov(res, GCP_SOURCE, exc)
        return res


class GcpGroupMembers:
    """Transitive Google group membership through the Cloud Identity API (needs the Cloud Identity API enabled and the
    service identity allowed to read groups, e.g. the Groups Reader admin role)."""

    def __init__(self, get, organization: str):
        self._get = get
        self.organization = organization

    def collect(self, groups: set[str]) -> Directory:
        d = Directory("gcp", f"organizations/{self.organization}")
        ok = True
        for g in sorted(groups):
            email = g.partition(":")[2] or g
            try:
                name = self._get("https://cloudidentity.googleapis.com/v1/groups:lookup", {"groupKey.id": email})["name"]
                params: dict = {"pageSize": 500}
                url = f"https://cloudidentity.googleapis.com/v1/{name}/memberships:searchTransitiveMemberships"
                while True:
                    data = self._get(url, params)
                    for m in data.get("memberships", []):
                        for k in m.get("preferredMemberKey", []):
                            mid = k.get("id")
                            if not mid:
                                continue
                            kind = "serviceAccount" if mid.endswith(".gserviceaccount.com") else "user"
                            d.members.append(DirMember(g, email, f"{kind}:{mid}", "ServiceAccount" if kind == "serviceAccount" else "User"))
                    token = data.get("nextPageToken")
                    if not token:
                        break
                    params = {"pageSize": 500, "pageToken": token}
            except Exception as exc:  # noqa: BLE001
                d.cover(f"gcp_group_members:{email}", exc)
                ok = False
        if ok:
            d.cover("gcp_group_members", note=f"transitive membership of {len(groups)} groups")
        d.members_complete = ok and bool(groups)
        return d


def run_resource_access(db, settings, connectors, complete: dict[str, set[str]], summary: dict, failures: list) -> None:
    """Called by access_inventory after the account-level collection. Results are stored under their own source so a
    failure here never removes account-level rows, and vice versa."""
    from sqlalchemy import select

    from app.models.access import AccessAssignment
    from app.services import reliability as rel
    from app.services.access import lifecycle as lc
    from app.services.access.engine import store
    from app.services.scopes import check_passed, eligible_scopes

    def record(provider: str, scope: str, res: Result) -> None:
        key = f"{provider}:{scope}"
        summary.setdefault("coverage", {}).setdefault(key, [])
        summary["coverage"][key] = [*summary["coverage"][key], *res.coverage]
        if not res.complete:
            failures.append({"provider": provider, "scope": scope,
                             "reason": "; ".join(f"{c['source']}: {c['message']}" for c in res.coverage if c["state"] != "OK")})

    if "aws" in connectors:
        col = AwsResourcePolicies(connectors["aws"])
        for scope in eligible_scopes(db, "aws"):
            if not check_passed(scope, "permissions") or rel.scope_gate("aws"):
                continue
            res = col.collect(scope.external_id, scope.is_management)
            store(db, "aws", scope.external_id, res, {AWS_SOURCE})
            db.commit()
            record("aws", scope.external_id, res)
    if "gcp" in connectors:
        from app.services.access.directory import GcpDirectory
        gd = GcpDirectory(settings, connectors["gcp"])
        col = GcpResourceIam(gd._get)
        for scope in eligible_scopes(db, "gcp"):
            if not check_passed(scope, "permissions") or rel.scope_gate("gcp"):
                continue
            res = col.collect(scope.external_id)
            store(db, "gcp", scope.external_id, res, {GCP_SOURCE})
            db.commit()
            record("gcp", scope.external_id, res)
        if settings.gcp_organization_id:
            groups = {a.principal_id for a in db.scalars(select(AccessAssignment).where(
                AccessAssignment.provider == "gcp", AccessAssignment.principal_type == "Group", AccessAssignment.removed_at.is_(None)))}
            if groups:
                d = GcpGroupMembers(gd._get, settings.gcp_organization_id).collect(groups)
                lc.apply_directory(db, d)
                db.commit()
                summary.setdefault("directory", {}).setdefault("gcp", []).append({"directory": d.directory_scope, "coverage": d.coverage})
                for c in d.coverage:
                    if c["state"] != "OK":
                        failures.append({"provider": "gcp", "scope": d.directory_scope, "reason": f"{c['source']}: {c['message']}"})
