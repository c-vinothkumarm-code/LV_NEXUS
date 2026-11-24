"""Unified Cloud Inventory: hierarchy, category dashboard, resource list and resource detail across AWS, Azure and GCP.

Everything is read from the inventory collected by the scheduled jobs (`account_discovery`, `resource_inventory`,
`vm_metrics`). Fields a provider API did not return are reported as "not collected", never guessed. Project Owners only
see the accounts / subscriptions / projects assigned to them (enforced here, server-side)."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import require_any
from app.api.serializers import iso
from app.core.security import assigned_scopes, scope_condition
from app.database.session import get_db
from app.models import SCOPE_LABEL, SCOPE_MODELS, AutomationExecutionLog, CloudResource, CloudSecurityFinding, JobStatus, User, VMInventory, VMMetric

router = APIRouter(prefix="/api/v1/inventory", tags=["cloud inventory"])
READ = require_any("inventory:read", "inventory:read_assigned")

# Category by resource type keywords (provider type names differ; the rule is published in the API response).
CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("Virtual machines", ("virtual_machine", "virtualmachines", "compute.instance", "ec2:instance")),
    ("Kubernetes", ("managedclusters", "container.cluster", "eks", "kubernetes", "gke")),
    ("Containers", ("containerinstance", "containerregistry", "containerapps", "ecs", "run.service", "artifactregistry")),
    ("Databases", ("sql", "database", "dbforpostgresql", "dbformysql", "cosmos", "rds", "dynamodb", "spanner", "bigtable", "redis", "firestore")),
    ("Storage", ("storage", "disk", "s3", "bucket", "ebs", "snapshot", "filestore", "netapp", "backup")),
    ("Load balancers", ("loadbalancer", "applicationgateway", "elasticloadbalancing", "frontdoor", "forwardingrule", "targetpool")),
    ("Public IP addresses", ("publicipaddress", "elasticip", "eip", "address")),
    ("Networks", ("network", "vpc", "subnet", "routetable", "privatedns", "dnszone", "firewall", "vpn", "nat")),
    ("Security services", ("keyvault", "security", "kms", "secretsmanager", "waf", "defender", "guardduty", "managedidentity")),
    ("Monitoring", ("insights", "operationalinsights", "monitor", "alertsmanagement", "logging", "cloudwatch")),
]


def category(resource_type: str | None) -> str:
    t = (resource_type or "").lower().replace("/", ".")
    for name, words in CATEGORIES:
        if any(w in t for w in words):
            return name
    return "Other"


def _scopes(db: Session, user: User, provider: str | None = None) -> dict[tuple[str, str], object]:
    allowed = None if "inventory:read" in user.permission_names else assigned_scopes(user)
    out = {}
    for prov, model in SCOPE_MODELS.items():
        if provider and provider != prov:
            continue
        for s in db.scalars(select(model)):
            if allowed is None or (prov, s.external_id) in allowed:
                out[(prov, s.external_id)] = s
    return out


def _last_success(db: Session, job: str) -> str | None:
    return iso(db.scalar(select(func.max(AutomationExecutionLog.finished_at)).where(
        AutomationExecutionLog.job_name == job, AutomationExecutionLog.status.in_([JobStatus.SUCCESS.value, JobStatus.PARTIAL.value]))))


def _resource_filter(q, user, provider, scope, region, environment, resource_group, scopes_env):
    limit = scope_condition(CloudResource, user)
    if limit is not None:
        q = q.where(limit)
    if provider:
        q = q.where(CloudResource.provider == provider)
    if scope:
        q = q.where(CloudResource.scope_external_id == scope)
    if region:
        q = q.where(CloudResource.region == region)
    if environment:
        ids = [k[1] for k, s in scopes_env.items() if (s.environment or "") == environment]
        q = q.where(CloudResource.scope_external_id.in_(ids or ["\x00"]))
    if resource_group:
        q = q.where(CloudResource.resource_id.ilike(f"%/resourcegroups/{resource_group}/%"))
    return q


@router.get("/summary")
def inventory_summary(provider: str | None = None, scope: str | None = None, environment: str | None = None,
                      db: Session = Depends(get_db), user: User = Depends(READ)):
    scopes = _scopes(db, user, provider)
    q = _resource_filter(select(CloudResource.provider, CloudResource.scope_external_id, CloudResource.resource_type, CloudResource.region)
                         .where(CloudResource.not_deleted()), user, provider, scope, None, environment, None, scopes)
    by_cat, by_region, by_env, by_scope, by_provider = Counter(), Counter(), Counter(), Counter(), Counter()
    total = 0
    for prov, sc, rtype, region in db.execute(q):
        total += 1
        by_cat[category(rtype)] += 1
        by_region[region or "global"] += 1
        s = scopes.get((prov, sc))
        by_env[(s.environment if s else None) or "Not labelled"] += 1
        by_scope[f"{prov}:{sc}"] += 1
        by_provider[prov] += 1
    names = {f"{p}:{e}": (s.name or e) for (p, e), s in scopes.items()}
    vm_q = select(VMInventory.public_ip).where(VMInventory.deleted_at.is_(None))
    limit = scope_condition(VMInventory, user)
    vm_q = vm_q.where(limit) if limit is not None else vm_q
    vm_q = vm_q.where(VMInventory.provider == provider) if provider else vm_q
    vm_q = vm_q.where(VMInventory.scope_external_id == scope) if scope else vm_q
    vm_public = sum(1 for (ip,) in db.execute(vm_q) if ip)
    return {"total_resources": total, "by_category": dict(by_cat.most_common()), "by_provider": dict(by_provider),
            "by_region": by_region.most_common(30), "by_environment": dict(by_env.most_common()),
            "by_scope": [{"key": k, "name": names.get(k, k), "count": n} for k, n in by_scope.most_common(30)],
            "vms_with_public_ip": vm_public,
            "scopes": {p: sum(1 for (pp, _), s in scopes.items() if pp == p and s.onboarding_status != "Inactive") for p in SCOPE_MODELS},
            "category_rule": "Category is derived from the provider resource type by keyword; types that match no keyword are 'Other'.",
            "freshness": {"discovery": _last_success(db, "account_discovery"), "resources": _last_success(db, "resource_inventory"),
                          "vms": _last_success(db, "vm_metrics")},
            "generated_at": datetime.now(UTC).isoformat()}


@router.get("/tree")
def inventory_tree(provider: str | None = None, db: Session = Depends(get_db), user: User = Depends(READ)):
    """Provider -> parent (AWS OU / GCP folder or organization / Azure tenant) -> account / project / subscription ->
    Azure resource groups, with resource, VM and open-finding counts."""
    scopes = _scopes(db, user, provider)
    res = Counter((p, s) for p, s in db.execute(select(CloudResource.provider, CloudResource.scope_external_id).where(CloudResource.not_deleted())))
    vms = Counter((p, s) for p, s in db.execute(select(VMInventory.provider, VMInventory.scope_external_id).where(VMInventory.deleted_at.is_(None))))
    fnd = Counter((p, s) for p, s in db.execute(select(CloudSecurityFinding.provider, CloudSecurityFinding.scope_external_id).where(
        CloudSecurityFinding.is_security.is_(True), CloudSecurityFinding.native_state == "ACTIVE",
        CloudSecurityFinding.internal_status.in_(["OPEN", "UNDER_REVIEW", "REOPENED"]))))
    rgs: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for sc, attrs in db.execute(select(CloudResource.scope_external_id, CloudResource.attributes).where(
            CloudResource.provider == "azure", CloudResource.not_deleted())):
        rg = (attrs or {}).get("resource_group")
        if rg:
            rgs[("azure", sc)][rg] += 1
    tree: dict[str, dict[str, list]] = {}
    for (prov, ext), s in sorted(scopes.items(), key=lambda kv: (kv[0][0], (kv[1].name or kv[0][1]).lower())):
        parent = getattr(s, "parent", None) or (f"Tenant {s.tenant_id}" if prov == "azure" and getattr(s, "tenant_id", None) else "Organization root")
        tree.setdefault(prov, {}).setdefault(parent, []).append({
            "provider": prov, "external_id": ext, "name": s.name or ext, "kind": SCOPE_LABEL[prov], "environment": s.environment,
            "status": s.onboarding_status, "resources": res.get((prov, ext), 0), "vms": vms.get((prov, ext), 0),
            "open_findings": fnd.get((prov, ext), 0), "last_seen_at": iso(s.last_seen_at),
            "resource_groups": [{"name": n, "resources": c} for n, c in sorted(rgs.get((prov, ext), Counter()).items())]})
    labels = {"aws": "Organizational unit", "gcp": "Folder / organization", "azure": "Tenant"}
    return {"providers": [{"provider": p, "parent_label": labels[p],
                           "groups": [{"parent": k, "scopes": v} for k, v in sorted(groups.items())]} for p, groups in tree.items()]}


@router.get("/resources")
def list_resources(provider: str | None = None, scope: str | None = None, region: str | None = None, environment: str | None = None,
                   resource_group: str | None = None, category_name: str | None = Query(None, alias="category"), q: str | None = None,
                   include_deleted: bool = False, sort: str = "name", order: str = "asc", page: int = Query(1, ge=1),
                   size: int = Query(50, ge=1, le=200), db: Session = Depends(get_db), user: User = Depends(READ)):
    scopes = _scopes(db, user)
    stmt = _resource_filter(select(CloudResource), user, provider, scope, region, environment, resource_group, scopes)
    if not include_deleted:
        stmt = stmt.where(CloudResource.not_deleted())
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(CloudResource.name.ilike(like), CloudResource.resource_id.ilike(like), CloudResource.resource_type.ilike(like)))
    col = {"name": CloudResource.name, "type": CloudResource.resource_type, "region": CloudResource.region,
           "scope": CloudResource.scope_external_id, "last_seen": CloudResource.last_seen_at}.get(sort, CloudResource.name)
    stmt = stmt.order_by(col.desc() if order == "desc" else col.asc(), CloudResource.id)
    rows = list(db.scalars(stmt))
    if category_name:
        rows = [r for r in rows if category(r.resource_type) == category_name]
    total = len(rows)
    page_rows = rows[(page - 1) * size: page * size]
    open_by_res = _open_findings_by_resource(db, [r.resource_id for r in page_rows])
    return {"total": total, "page": page, "size": size, "categories": [c for c, _ in CATEGORIES] + ["Other"],
            "items": [_resource(r, scopes.get((r.provider, r.scope_external_id)), open_by_res.get(r.resource_id.lower(), 0)) for r in page_rows]}


def _open_findings_by_resource(db: Session, ids: list[str]) -> Counter:
    if not ids:
        return Counter()
    lowered = [i.lower() for i in ids]
    out = Counter()
    for (rid,) in db.execute(select(CloudSecurityFinding.resource_id).where(
            func.lower(CloudSecurityFinding.resource_id).in_(lowered), CloudSecurityFinding.native_state == "ACTIVE",
            CloudSecurityFinding.internal_status.in_(["OPEN", "UNDER_REVIEW", "REOPENED"]))):
        out[(rid or "").lower()] += 1
    return out


def _resource(r: CloudResource, scope, open_findings: int) -> dict:
    attrs = r.attributes or {}
    stale = r.last_seen_at is not None and r.last_seen_at < datetime.now(UTC) - timedelta(days=2)
    return {"id": r.id, "provider": r.provider, "scope": r.scope_external_id, "scope_name": getattr(scope, "name", None) or r.scope_external_id,
            "environment": getattr(scope, "environment", None), "resource_id": r.resource_id, "name": r.name or r.resource_id.rsplit("/", 1)[-1],
            "resource_type": r.resource_type, "category": category(r.resource_type), "region": r.region,
            "resource_group": attrs.get("resource_group"), "state": r.state, "tags": attrs.get("tags"),
            "owner": _owner(attrs.get("tags")), "last_seen_at": iso(r.last_seen_at), "stale": stale, "open_findings": open_findings}


def _owner(tags) -> str | None:
    for k, v in (tags or {}).items():
        if k.lower() in ("owner", "owned-by", "ownedby", "created-by", "createdby", "contact", "team"):
            return str(v)[:255]
    return None


@router.get("/resources/{resource_pk}")
def resource_detail(resource_pk: int, db: Session = Depends(get_db), user: User = Depends(READ)):
    r = db.get(CloudResource, resource_pk)
    if r is None:
        raise HTTPException(404, "Resource not found")
    if "inventory:read" not in user.permission_names and (r.provider, r.scope_external_id) not in assigned_scopes(user):
        raise HTTPException(404, "Resource not found")
    scope = _scopes(db, user, r.provider).get((r.provider, r.scope_external_id))
    findings = []
    if {"vuln:read", "vuln:read_assigned"} & user.permission_names:
        for f in db.scalars(select(CloudSecurityFinding).where(func.lower(CloudSecurityFinding.resource_id) == r.resource_id.lower())
                            .order_by(CloudSecurityFinding.id.desc()).limit(50)):
            findings.append({"id": f.id, "title": f.title, "severity": f.severity, "status": f.internal_status, "native_state": f.native_state,
                             "source": f.source, "last_observed_at": iso(f.last_observed_at)})
    vm = None
    v = db.scalar(select(VMInventory).where(VMInventory.provider == r.provider, func.lower(VMInventory.instance_id) == r.resource_id.lower()))
    if v is not None:
        m = db.scalar(select(VMMetric).where(VMMetric.vm_id == v.id).order_by(VMMetric.id.desc()).limit(1))
        reporting = bool(m and m.collected_at and m.collected_at >= datetime.now(UTC) - timedelta(hours=2))
        vm = {"power_state": v.power_state, "instance_type": v.instance_type, "health_status": v.health_status, "private_ip": v.private_ip,
              "public_ip": v.public_ip, "exposed_ports": v.exposed_ports, "launched_at": iso(v.launched_at),
              "monitoring": "Reporting" if reporting else ("Not reporting (last sample older than 2 h)" if m else "No metrics collected"),
              "metrics": None if m is None else {"collected_at": iso(m.collected_at), "cpu_percent": m.cpu_percent, "memory_percent": m.memory_percent,
                                                  "disk_percent": m.disk_percent, "network_in_bytes": m.network_in_bytes,
                                                  "network_out_bytes": m.network_out_bytes, "missing": m.missing_metrics},
              "not_collected": ["operating system", "vCPU", "memory size", "disk configuration", "backup status"]}
    return {**_resource(r, scope, sum(1 for f in findings if f["status"] in ("OPEN", "UNDER_REVIEW", "REOPENED") and f["native_state"] == "ACTIVE")),
            "attributes": r.attributes or {}, "created_at": iso(r.created_at), "findings": findings, "vm": vm,
            "cost": {"available": False, "note": "Resource-level cost is not collected yet; cost is collected per account / subscription / project and service."},
            "scope_status": getattr(scope, "onboarding_status", None)}
