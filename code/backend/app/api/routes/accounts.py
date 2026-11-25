"""Cloud accounts workspace: one tree per cloud with health, cost and findings at every level.

Azure:  tenant → management group (when known) → subscription → resource group → resources
AWS:    organization → organizational unit → account → region → resources
GCP:    organization → folder → project → region → resources

Every count comes from stored collections (discovery, resource inventory, VM metrics, billing, cost detail, security
findings). Cost below the account level comes from the detailed cost collection; where a cloud does not provide it the
node shows "not collected" (null), never zero."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import require_any
from app.api.serializers import iso
from app.core.security import assigned_scopes, audit, current_user, require
from app.database.session import get_db
from app.models import SCOPE_MODELS, AccountOwnership, BillingRecord, CloudResource, CloudSecurityFinding, User, VMInventory
from app.models.platform import CostDetailRecord

router = APIRouter(prefix="/api/v1/accounts", tags=["cloud accounts"])
READ = require_any("inventory:read", "inventory:read_assigned")
OPEN = ("OPEN", "UNDER_REVIEW", "REOPENED")
KIND = {"aws": "Account", "azure": "Subscription", "gcp": "Project"}
SUB_KIND = {"aws": "Region", "azure": "Resource group", "gcp": "Region"}


def _rg(resource_id: str | None, attrs: dict | None = None) -> str | None:
    if attrs and attrs.get("resource_group"):
        return attrs["resource_group"]
    low = (resource_id or "").lower()
    if "/resourcegroups/" in low:
        i = low.index("/resourcegroups/") + len("/resourcegroups/")
        return resource_id[i:].split("/")[0]
    return None


def _region(r: str | None) -> str:
    return (r or "global").lower()


def _visible(db: Session, user: User, provider: str | None):
    allowed = None if "inventory:read" in user.permission_names else assigned_scopes(user)
    out = {}
    for p, model in SCOPE_MODELS.items():
        if provider and p != provider:
            continue
        for s in db.scalars(select(model)):
            if allowed is None or (p, s.external_id) in allowed:
                out[(p, s.external_id)] = s
    return out


def _node(**kw) -> dict:
    base = {"resources": 0, "vms": 0, "vms_unhealthy": 0, "critical": 0, "high": 0, "findings": 0, "cost_mtd": None, "children": []}
    return {**base, **kw}


@router.get("/tree")
def tree(provider: str | None = None, db: Session = Depends(get_db), user: User = Depends(READ)):
    scopes = _visible(db, user, provider)
    keys = set(scopes)
    m0 = datetime.now(UTC).date().replace(day=1)
    # second level key: (provider, scope, child) where child = resource group (Azure) or region (AWS/GCP)
    res, vms, bad, fcrit, fhigh, fall = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    for p, sc, rid, _rtype, region, attrs in db.execute(select(CloudResource.provider, CloudResource.scope_external_id, CloudResource.resource_id,
                                                              CloudResource.resource_type, CloudResource.region, CloudResource.attributes)
                                                       .where(CloudResource.not_deleted())):
        if (p, sc) in keys:
            res[(p, sc, _rg(rid, attrs) if p == "azure" else _region(region))] += 1
    for p, sc, iid, region, health in db.execute(select(VMInventory.provider, VMInventory.scope_external_id, VMInventory.instance_id,
                                                        VMInventory.region, VMInventory.health_status).where(VMInventory.deleted_at.is_(None))):
        if (p, sc) in keys:
            k = (p, sc, _rg(iid) if p == "azure" else _region(region))
            vms[k] += 1
            if health in ("warning", "critical"):
                bad[k] += 1
    for p, sc, rid, rg, region, sev in db.execute(select(CloudSecurityFinding.provider, CloudSecurityFinding.scope_external_id, CloudSecurityFinding.resource_id,
                                                         CloudSecurityFinding.resource_group, CloudSecurityFinding.region, CloudSecurityFinding.severity).where(
            CloudSecurityFinding.is_security.is_(True), CloudSecurityFinding.native_state == "ACTIVE", CloudSecurityFinding.internal_status.in_(OPEN))):
        if (p, sc) in keys:
            k = (p, sc, (rg or _rg(rid)) if p == "azure" else _region(region))
            fall[k] += 1
            fcrit[k] += sev == "Critical"
            fhigh[k] += sev == "High"
    scope_cost = {(p, sc): float(v or 0) for p, sc, v in db.execute(select(BillingRecord.provider, BillingRecord.scope_external_id, func.sum(BillingRecord.cost_usd))
                                                                     .where(BillingRecord.usage_date >= m0, BillingRecord.cost_usd.is_not(None))
                                                                     .group_by(BillingRecord.provider, BillingRecord.scope_external_id)).all()}
    child_cost: dict = {}
    for p, sc, rg, region, v in db.execute(select(CostDetailRecord.provider, CostDetailRecord.scope_external_id, CostDetailRecord.resource_group,
                                                  CostDetailRecord.region, func.sum(CostDetailRecord.amount_usd)).where(
            CostDetailRecord.usage_date >= m0, CostDetailRecord.cost_type == "actual", CostDetailRecord.amount_usd.is_not(None),
            or_((CostDetailRecord.provider == "azure") & (CostDetailRecord.breakdown == "resource"),
                (CostDetailRecord.provider == "aws") & (CostDetailRecord.breakdown == "service_region"),
                (CostDetailRecord.provider == "gcp") & (CostDetailRecord.breakdown == "sku")))
            .group_by(CostDetailRecord.provider, CostDetailRecord.scope_external_id, CostDetailRecord.resource_group, CostDetailRecord.region)).all():
        k = (p, sc, rg if p == "azure" else _region(region))
        child_cost[k] = child_cost.get(k, 0.0) + float(v or 0)

    def add(target: dict, src: dict) -> None:
        for f in ("resources", "vms", "vms_unhealthy", "critical", "high", "findings"):
            target[f] += src[f]
        if src["cost_mtd"] is not None:
            target["cost_mtd"] = (target["cost_mtd"] or 0.0) + src["cost_mtd"]

    clouds = []
    for p in ("azure", "aws", "gcp"):
        if provider and p != provider:
            continue
        mine = {k: s for k, s in scopes.items() if k[0] == p}
        root_label = {"azure": "Tenant", "aws": "Organization", "gcp": "Organization"}[p]
        root = _node(id=p, level="cloud", name={"azure": "Microsoft Azure", "aws": "Amazon Web Services", "gcp": "Google Cloud"}[p], provider=p)
        groups: dict[str, dict] = {}
        for (_, ext), s in sorted(mine.items(), key=lambda kv: (kv[1].name or kv[0][1]).lower()):
            parent = s.parent or (f"{root_label} {getattr(s, 'tenant_id', None)}" if p == "azure" and getattr(s, "tenant_id", None) else f"{root_label} root")
            g = groups.setdefault(parent, _node(id=f"{p}|g|{parent}", level="group", name=parent.split("/")[-1] if "/" in parent else parent,
                                                 kind={"azure": "Tenant / management group", "aws": "Organizational unit", "gcp": "Folder / organization"}[p],
                                                 provider=p, path=parent))
            sn = _node(id=f"{p}|s|{ext}", level="scope", name=s.name or ext, external_id=ext, kind=KIND[p], provider=p, environment=s.environment,
                       status=s.onboarding_status, last_seen_at=iso(s.last_seen_at), cost_mtd=scope_cost.get((p, ext)),
                       health="Healthy" if s.onboarding_status == "Fully Onboarded" else "Attention" if s.onboarding_status != "Inactive" else "Inactive")
            subs = {k[2] for c in (res, vms, fall, child_cost) for k in c if k[0] == p and k[1] == ext}
            for child in sorted(subs, key=lambda x: (x is None, str(x).lower())):
                k = (p, ext, child)
                cn = _node(id=f"{p}|c|{ext}|{child}", level="child", kind=SUB_KIND[p], name=child or ("(no resource group)" if p == "azure" else "global"),
                           child=child, external_id=ext, provider=p, resources=res[k], vms=vms[k], vms_unhealthy=bad[k], critical=fcrit[k], high=fhigh[k],
                           findings=fall[k], cost_mtd=round(child_cost[k], 2) if k in child_cost else None)
                sn["children"].append(cn)
                for f in ("resources", "vms", "vms_unhealthy", "critical", "high", "findings"):
                    sn[f] += cn[f]
            sn["subcost_collected"] = any(c["cost_mtd"] is not None for c in sn["children"])
            g["children"].append(sn)
            add(g, sn)
        for g in groups.values():
            root["children"].append(g)
            add(root, g)
        root["scopes"] = len(mine)
        clouds.append(root)
    return {"clouds": clouds, "generated_at": iso(datetime.now(UTC)),
            "notes": ["Cost below account level comes from the detailed cost collection (Azure per resource group, AWS / GCP per region).",
                      "Unhealthy VMs = VM health warning or critical from the latest metrics."]}


@router.get("/node")
def node(provider: str, scope: str, child: str | None = None, q: str | None = None, page: int = Query(1, ge=1), size: int = Query(100, ge=1, le=500),
         db: Session = Depends(get_db), user: User = Depends(READ)):
    """Resources, VMs and open findings under one account / subscription / project, optionally one resource group or region."""
    scopes = _visible(db, user, provider)
    if (provider, scope) not in scopes:
        return {"items": [], "vms": [], "findings": [], "total": 0}
    rq = select(CloudResource).where(CloudResource.provider == provider, CloudResource.scope_external_id == scope,
                                     CloudResource.not_deleted())
    if q:
        rq = rq.where(or_(CloudResource.name.ilike(f"%{q}%"), CloudResource.resource_type.ilike(f"%{q}%")))
    rows = [r for r in db.scalars(rq.order_by(CloudResource.resource_type, CloudResource.name))
            if child is None or ((_rg(r.resource_id, r.attributes) if provider == "azure" else _region(r.region)) or "").lower() == child.lower()]
    vrows = [v for v in db.scalars(select(VMInventory).where(VMInventory.provider == provider, VMInventory.scope_external_id == scope, VMInventory.deleted_at.is_(None)))
             if child is None or ((_rg(v.instance_id) if provider == "azure" else _region(v.region)) or "").lower() == child.lower()]
    frows = [f for f in db.scalars(select(CloudSecurityFinding).where(CloudSecurityFinding.provider == provider, CloudSecurityFinding.scope_external_id == scope,
                                                                       CloudSecurityFinding.is_security.is_(True), CloudSecurityFinding.native_state == "ACTIVE",
                                                                       CloudSecurityFinding.internal_status.in_(OPEN)))
             if child is None or (((f.resource_group or _rg(f.resource_id)) if provider == "azure" else _region(f.region)) or "").lower() == child.lower()]
    by_res = Counter((f.resource_id or "").lower() for f in frows)
    cost_by_res: dict = defaultdict(float)
    m0 = datetime.now(UTC).date().replace(day=1)
    for rid, v in db.execute(select(CostDetailRecord.resource_id, func.sum(CostDetailRecord.amount_usd)).where(
            CostDetailRecord.provider == provider, CostDetailRecord.scope_external_id == scope, CostDetailRecord.breakdown == "resource",
            CostDetailRecord.cost_type == "actual", CostDetailRecord.usage_date >= m0).group_by(CostDetailRecord.resource_id)).all():
        cost_by_res[(rid or "").lower()] += float(v or 0)
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    stale = datetime.now(UTC) - timedelta(days=2)
    total = len(rows)
    page_rows = rows[(page - 1) * size: page * size]
    return {
        "total": total,
        "items": [{"id": r.id, "name": r.name or r.resource_id.rsplit("/", 1)[-1], "resource_id": r.resource_id, "type": r.resource_type, "region": r.region,
                   "resource_group": _rg(r.resource_id, r.attributes), "tags": (r.attributes or {}).get("tags") or {},
                   "findings": by_res.get(r.resource_id.lower(), 0), "cost_mtd": round(cost_by_res[r.resource_id.lower()], 2) if r.resource_id.lower() in cost_by_res else None,
                   "last_seen_at": iso(r.last_seen_at), "stale": bool(r.last_seen_at and (r.last_seen_at if r.last_seen_at.tzinfo else r.last_seen_at.replace(tzinfo=UTC)) < stale)}
                  for r in page_rows],
        "vms": [{"name": v.name, "instance_id": v.instance_id, "type": v.instance_type, "region": v.region, "power_state": v.power_state, "health": v.health_status,
                 "public_ip": bool(v.public_ip), "exposed_ports": v.exposed_ports or [], "last_seen_at": iso(v.last_seen_at)} for v in vrows],
        "findings": [{"id": f.id, "title": f.title, "severity": f.severity, "resource": f.resource_name or f.resource_id, "source": f.source}
                     for f in sorted(frows, key=lambda f: sev_rank.get(f.severity, 9))[:50]],
    }


@router.get("/names")
def scope_names(db: Session = Depends(get_db), user: User = Depends(current_user)):
    """Display names of the accounts / subscriptions / projects this user may see, so every page can show
    'Pay-As-You-Go-IT' instead of a subscription ID (the ID stays available as secondary detail)."""
    allowed = None if "inventory:read" in user.permission_names else assigned_scopes(user)
    out: dict[str, dict[str, str]] = {p: {} for p in SCOPE_MODELS}
    for p, model in SCOPE_MODELS.items():
        for sid, name in db.execute(select(model.external_id, model.name)).all():
            if name and (allowed is None or (p, sid) in allowed):
                out[p][sid] = name
    return out


# ---------------------------------------------------------------- account ownership

class OwnershipBody(BaseModel):
    fields: dict[str, str | None] = Field(default_factory=dict)


@router.get("/ownership")
def ownership_list(provider: str | None = None, db: Session = Depends(get_db), user: User = Depends(READ)):
    """Every discovered account / subscription / project with its ownership details and the approved budget from the budget
    tracker (business contact details only)."""
    from app.services import ownership as OWN
    rows = {(o.provider, o.scope_external_id): o for o in db.scalars(select(AccountOwnership))}
    out = []
    for (p, sc) in sorted(_visible(db, user, provider)):
        out.append(OWN.to_dict(db, p, sc, rows.get((p, sc))))
    return {"items": out, "can_edit": "connections:manage" in user.permission_names}


@router.get("/ownership/{provider}/{scope}")
def ownership_get(provider: str, scope: str, db: Session = Depends(get_db), user: User = Depends(READ)):
    from app.services import ownership as OWN
    if (provider, scope) not in _visible(db, user, provider):
        raise HTTPException(404, "Not found")
    return {**OWN.to_dict(db, provider, scope, OWN.get(db, provider, scope)), "history": OWN.history(db, provider, scope),
            "can_edit": "connections:manage" in user.permission_names}


@router.put("/ownership/{provider}/{scope}")
def ownership_save(provider: str, scope: str, body: OwnershipBody, db: Session = Depends(get_db), user: User = Depends(require("connections:manage"))):
    from app.services import ownership as OWN
    try:
        _row, changed = OWN.save(db, provider, scope, body.fields, user.email)
    except OWN.OwnershipError as exc:
        raise HTTPException(422, str(exc)) from None
    audit(db, user.email, "account.ownership", f"{provider}:{scope}", changed_fields=changed)
    db.commit()
    return {**OWN.to_dict(db, provider, scope, OWN.get(db, provider, scope)), "history": OWN.history(db, provider, scope), "changed": changed, "can_edit": True}
