"""Cloud resource inventory. Azure: every resource in each onboarded subscription (read-only list call).
VMs on every cloud are inventoried by the vm_metrics job, so they are skipped here to avoid double counting."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import CloudResource, JobStatus, utcnow
from app.scheduler.engine import JobContext, JobResult
from app.services import reliability as rel  # noqa: E402
from app.services.scopes import check_passed, eligible_scopes

log = logging.getLogger(__name__)
VM_TYPES = {"microsoft.compute/virtualmachines"}
MAX_ID = 512


class AzureResourceCollector:
    provider = "azure"

    def __init__(self, settings: Settings, connector):
        self.settings, self.connector = settings, connector

    def collect(self, scope) -> list[dict]:
        out = []
        for r in self.connector.clients.resources(scope.external_id).resources.list():
            rtype = (r.type or "").lower()
            if rtype in VM_TYPES:
                continue
            rg = r.id.split("/resourceGroups/", 1)[1].split("/", 1)[0] if "/resourceGroups/" in r.id else None
            out.append({"resource_id": r.id, "resource_type": r.type, "name": r.name, "region": r.location,
                        "attributes": {"resource_group": rg, "kind": getattr(r, "kind", None),
                                       "sku": getattr(getattr(r, "sku", None), "name", None), "tag_count": len(r.tags or {}),
                                       "tags": {str(k)[:128]: str(v)[:256] for k, v in list((r.tags or {}).items())[:50]}}})
        return out


def store(db: Session, provider: str, scope_id: str, items: list[dict], mark_deleted: bool = True) -> dict:
    now = utcnow()
    existing = {r.resource_id.lower(): r for r in db.scalars(select(CloudResource).where(
        CloudResource.provider == provider, CloudResource.scope_external_id == scope_id, CloudResource.resource_type != "virtual_machine"))}
    seen, created, skipped = set(), 0, 0
    for it in items:
        rid = it["resource_id"]
        if len(rid) > MAX_ID:
            skipped += 1  # reported, never truncated (a truncated ID could collide with another resource)
            continue
        key = rid.lower()
        if key in seen:
            continue
        seen.add(key)
        row = existing.get(key)
        if row is None:
            row = CloudResource(provider=provider, scope_external_id=scope_id, resource_id=rid, resource_type=it["resource_type"][:128])
            db.add(row)
            existing[key] = row
            created += 1
        row.name, row.region, row.state = (it.get("name") or "")[:255], it.get("region"), "present"
        row.attributes, row.last_seen_at = it.get("attributes") or {}, now
    gone = 0
    for key, row in existing.items():
        if mark_deleted and key not in seen and row.state != "deleted":
            row.state = "deleted"
            gone += 1
    return {"resources": len(seen), "created": created, "deleted": gone, "skipped_long_ids": skipped}


def run_resource_inventory(ctx: JobContext, settings: Settings, collectors: list, unsupported: list[str]) -> JobResult:
    db = ctx.db
    summary = {"by_provider": {}, "not_supported": unsupported,
               "note": "VMs on every cloud come from vm_metrics. AWS: EC2 volumes, VPC, subnets, security groups, S3, load balancers, RDS, "
                       "EKS, Lambda, Backup vaults. GCP: Cloud Asset Inventory (all asset types except VM instances)."}
    failures, total, failed = [], 0, 0
    for c in collectors:
        info = summary["by_provider"].setdefault(c.provider, {"scopes": 0, "resources": 0, "created": 0, "deleted": 0})
        for scope in eligible_scopes(db, c.provider):
            total += 1
            if not check_passed(scope, "permissions"):
                failed += 1
                failures.append({"provider": c.provider, "scope": scope.external_id, "name": scope.name, "reason": "Read permissions not validated"})
                continue
            _skip = rel.scope_gate(c.provider)
            if _skip:
                failed += 1
                failures.append({"provider": c.provider, "scope": scope.external_id, "name": scope.name, "reason": _skip})
                continue
            try:
                got = c.collect(scope)
                if isinstance(got, dict):  # AWS / GCP collectors report partial coverage per service / region
                    items, complete = got["items"], got["complete"]
                    failures += [{"provider": c.provider, "scope": scope.external_id, "name": scope.name, "reason": e} for e in got["errors"]]
                else:
                    items, complete = got, True
                stats = store(db, c.provider, scope.external_id, items, mark_deleted=complete)
                db.commit()
                rel.scope_ok(c.provider)
                info["scopes"] += 1
                for k in ("resources", "created", "deleted"):
                    info[k] += stats[k]
                if stats["skipped_long_ids"]:
                    failures.append({"provider": c.provider, "scope": scope.external_id, "reason": f"{stats['skipped_long_ids']} resource ID(s) longer than {MAX_ID} characters were not stored"})
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                log.exception("resource inventory failed for %s %s", c.provider, scope.external_id)
                failed += 1
                failures.append({"provider": c.provider, "scope": scope.external_id, "name": scope.name, "reason": rel.scope_failed(c.provider, exc)})
    if total == 0:
        failures.append({"provider": "*", "scope": "*", "reason": "No onboarded scope with resource inventory"})
        return JobResult(JobStatus.FAILED, 0, 0, summary, failures)
    status = JobStatus.SUCCESS if not failures else JobStatus.FAILED if failed == total else JobStatus.PARTIAL
    return JobResult(status, total, failed, summary, failures)


def _err(service: str, region: str, exc: Exception) -> str:
    from app.services.vuln.common import classify
    kind, msg = classify(exc)
    return f"{service} {region}: {'access denied' if kind == 'permission' else kind}: {msg[:200]}"


class AwsResourceCollector:
    """Read-only Describe/List calls per account and enabled region. A service/region that fails is reported and the
    scope is treated as incomplete (nothing is marked deleted)."""
    provider = "aws"
    REGIONAL = {
        "ebs_volume": ("ec2", "describe_volumes", "Volumes", "VolumeId", None, "State"),
        "vpc": ("ec2", "describe_vpcs", "Vpcs", "VpcId", None, "State"),
        "subnet": ("ec2", "describe_subnets", "Subnets", "SubnetId", None, "State"),
        "security_group": ("ec2", "describe_security_groups", "SecurityGroups", "GroupId", "GroupName", None),
        "load_balancer": ("elbv2", "describe_load_balancers", "LoadBalancers", "LoadBalancerArn", "LoadBalancerName", None),
        "rds_instance": ("rds", "describe_db_instances", "DBInstances", "DBInstanceArn", "DBInstanceIdentifier", "DBInstanceStatus"),
        "lambda_function": ("lambda", "list_functions", "Functions", "FunctionArn", "FunctionName", "State"),
        "backup_vault": ("backup", "list_backup_vaults", "BackupVaultList", "BackupVaultArn", "BackupVaultName", None),
    }

    def __init__(self, settings: Settings, connector):
        self.settings, self.connector = settings, connector

    def collect(self, scope) -> dict:
        items, errors = [], []
        session = self.connector.session_for(scope.external_id, getattr(scope, "is_management", False))
        try:
            s3 = self.connector.client(session, "s3")
            for b in s3.list_buckets().get("Buckets", []):
                items.append({"resource_id": f"arn:aws:s3:::{b['Name']}", "resource_type": "s3_bucket", "name": b["Name"], "region": None,
                              "attributes": {"created": str(b.get("CreationDate"))}})
        except Exception as exc:  # noqa: BLE001
            errors.append(_err("s3", "global", exc))
        for region in self.connector.regions(session):
            for rtype, (svc, op, key, idf, namef, statef) in self.REGIONAL.items():
                try:
                    client = self.connector.client(session, svc, region)
                    pages = client.get_paginator(op).paginate() if client.can_paginate(op) else [getattr(client, op)()]
                    for page in pages:
                        for r in page.get(key, []):
                            tags = {t["Key"]: t["Value"] for t in (r.get("Tags") or r.get("TagList") or []) if "Key" in t}
                            rid = r[idf] if str(r[idf]).startswith("arn:") else f"arn:aws:{svc}:{region}:{scope.external_id}:{rtype}/{r[idf]}"
                            items.append({"resource_id": rid, "resource_type": rtype, "name": tags.get("Name") or (r.get(namef) if namef else r[idf]),
                                          "region": region, "attributes": {"state": str(r.get(statef)) if statef else None,
                                                                           "tags": {str(k)[:128]: str(v)[:256] for k, v in list(tags.items())[:50]},
                                                                           "vpc": r.get("VpcId")}})
                except Exception as exc:  # noqa: BLE001
                    errors.append(_err(svc, region, exc))
            try:
                eks = self.connector.client(session, "eks", region)
                for page in eks.get_paginator("list_clusters").paginate():
                    for name in page.get("clusters", []):
                        items.append({"resource_id": f"arn:aws:eks:{region}:{scope.external_id}:cluster/{name}", "resource_type": "eks_cluster",
                                      "name": name, "region": region, "attributes": {}})
            except Exception as exc:  # noqa: BLE001
                errors.append(_err("eks", region, exc))
        return {"items": items, "complete": not errors, "errors": errors[:20]}


class GcpResourceCollector:
    """Cloud Asset Inventory searchAllResources per project (needs Cloud Asset Viewer). VM instances are skipped (vm_metrics)."""
    provider = "gcp"

    def __init__(self, settings: Settings, connector, session=None):
        self.settings, self.connector, self._session = settings, connector, session

    def _s(self):
        if self._session is None:
            from google.auth.transport.requests import AuthorizedSession
            self._session = AuthorizedSession(self.connector.clients.credentials())
        return self._session

    def collect(self, scope) -> dict:
        from app.services.vuln.common import HttpError, with_retry
        items = []
        url = f"https://cloudasset.googleapis.com/v1/projects/{scope.external_id}:searchAllResources"
        params = {"pageSize": 500}
        while True:
            query = dict(params)

            def call(p=query):
                r = self._s().get(url, params=p, timeout=60)
                if r.status_code >= 400:
                    raise HttpError(r.status_code, r.text)
                return r.json()
            data = with_retry(call)
            for a in data.get("results", []):
                atype = a.get("assetType") or ""
                if atype == "compute.googleapis.com/Instance":
                    continue
                items.append({"resource_id": a["name"], "resource_type": atype.split("/")[-1] or atype, "name": a.get("displayName"),
                              "region": a.get("location"), "attributes": {"asset_type": atype, "state": a.get("state"),
                                                                          "tags": {str(k)[:128]: str(v)[:256] for k, v in list((a.get("labels") or {}).items())[:50]},
                                                                          "created": a.get("createTime"), "updated": a.get("updateTime")}})
            token = data.get("nextPageToken")
            if not token:
                break
            params = {"pageSize": 500, "pageToken": token}
        return {"items": items, "complete": True, "errors": []}
