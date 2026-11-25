"""The asset register: one row per server (vm_inventory) and per other cloud service (cloud_resources), combined with
collected details, business metadata, activity, cost and backup status.

Every value comes from collected data or from a person; a value that was not collected is None and listed in `gaps`
with the reason - never a guess and never zero. The same rows feed the UI table, the KPIs, the CSV / Excel export
and the daily activity review, so they always agree."""
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import assigned_scopes
from app.models import (
    MANUAL_COLUMNS,
    SCOPE_MODELS,
    AssetActivitySnapshot,
    AssetDetail,
    AssetMetadata,
    AuditEvent,
    CloudResource,
    CostDetailRecord,
    User,
    VMInventory,
    VMMetric,
    resource_key,
)
from app.services.assets import activity as A
from app.services.assets import policy as P

LOGIN_EVENTS = {
    "aws": {"startsession", "sendsshpublickey", "sendserialconsolesshpublickey"},
    "azure": {"microsoft.compute/virtualmachines/login/action", "microsoft.compute/virtualmachines/loginasadmin/action"},
    "gcp": {"authorizeuser", "google.cloud.oslogin.v1.osloginservice.getloginprofile"},
}
STOP_EVENTS = {"stopinstances", "microsoft.compute/virtualmachines/deallocate/action", "microsoft.compute/virtualmachines/poweroff/action",
               "v1.compute.instances.stop", "beta.compute.instances.stop", "v1.compute.instances.suspend"}
LOGIN_SOURCE = {"aws": "Session Manager / EC2 Instance Connect events", "azure": "Entra ID VM login events",
                "gcp": "IAP / OS Login events"}
NOT_LOGIN = ("Not collected: no remote-login event recorded in the cloud audit logs (guest OS logins need log forwarding "
             "of the server's security / auth logs)")


def _aware(v):
    return None if v is None else v if v.tzinfo else v.replace(tzinfo=UTC)


def _iso(v):
    if v is None:
        return None
    if isinstance(v, datetime):
        return _aware(v).isoformat()
    return v.isoformat() if isinstance(v, date) else v


def visible_scopes(db: Session, user: User | None) -> dict[tuple[str, str], object]:
    allowed = None if user is None or "inventory:read" in user.permission_names else assigned_scopes(user)
    out = {}
    for prov, model in SCOPE_MODELS.items():
        for s in db.scalars(select(model)):
            if allowed is None or (prov, s.external_id) in allowed:
                out[(prov, s.external_id)] = s
    return out


def _metrics(db: Session, vm_ids: list[int], since: datetime) -> dict[int, dict]:
    if not vm_ids:
        return {}
    out = {}
    q = (select(VMMetric.vm_id, func.avg(VMMetric.cpu_percent), func.count(VMMetric.cpu_percent),
                func.sum(func.coalesce(VMMetric.network_in_bytes, 0) + func.coalesce(VMMetric.network_out_bytes, 0)),
                func.count(VMMetric.network_in_bytes), func.min(VMMetric.collected_at), func.max(VMMetric.collected_at))
         .where(VMMetric.collected_at >= since).group_by(VMMetric.vm_id))
    for vm_id, cpu, n_cpu, net, n_net, first, last in db.execute(q):
        first, last = _aware(first), _aware(last)
        hours = ((last - first).total_seconds() / 3600) if first and last else 0.0
        days = max(hours / 24, 1 / 24)
        out[vm_id] = {"cpu_avg": float(cpu) if cpu is not None else None, "samples": int(n_cpu or 0), "coverage_hours": hours,
                      "network_mb_per_day": (float(net) / 1_048_576 / days) if n_net else None}
    return out


def _latest_metric(db: Session, vm_ids: list[int]) -> dict[int, VMMetric]:
    if not vm_ids:
        return {}
    last = (select(VMMetric.vm_id, func.max(VMMetric.collected_at).label("at")).where(VMMetric.vm_id.in_(vm_ids))
            .group_by(VMMetric.vm_id).subquery())
    out: dict[int, VMMetric] = {}
    for m in db.scalars(select(VMMetric).join(last, (VMMetric.vm_id == last.c.vm_id) & (VMMetric.collected_at == last.c.at)).order_by(VMMetric.id)):
        out[m.vm_id] = m  # newest sample by collection time (not by insert order)
    return out


def _events(db: Session, since: datetime) -> tuple[dict, dict, dict]:
    """Latest management activity, remote login and stop event per resource reference (lower-case)."""
    activity, login, stop = {}, {}, {}
    q = (select(AuditEvent.provider, func.lower(AuditEvent.resource_id), func.lower(AuditEvent.event_name), func.max(AuditEvent.event_timestamp))
         .where(AuditEvent.resource_id.is_not(None), AuditEvent.event_timestamp >= since)
         .group_by(AuditEvent.provider, func.lower(AuditEvent.resource_id), func.lower(AuditEvent.event_name)))
    for prov, rid, name, ts in db.execute(q):
        ts = _aware(ts)
        for ref in ({rid, rid.rsplit("/", 1)[-1]} if prov == "aws" else {rid}):  # AWS ARN tail = instance ID; elsewhere names repeat
            k = (prov, ref)
            if ts and (k not in activity or ts > activity[k]):
                activity[k] = ts
            if name in LOGIN_EVENTS.get(prov, ()) and (k not in login or ts > login[k]):
                login[k] = ts
            if name in STOP_EVENTS and (k not in stop or ts > stop[k]):
                stop[k] = ts
    return activity, login, stop


def _costs(db: Session, since: date) -> dict:
    out = defaultdict(float)
    q = (select(CostDetailRecord.provider, func.lower(CostDetailRecord.resource_id), func.sum(func.coalesce(CostDetailRecord.amount_usd, 0)),
                func.count(CostDetailRecord.amount_usd))
         .where(CostDetailRecord.breakdown == "resource", CostDetailRecord.cost_type == "actual", CostDetailRecord.usage_date >= since,
                CostDetailRecord.resource_id.is_not(None))
         .group_by(CostDetailRecord.provider, func.lower(CostDetailRecord.resource_id)))
    for prov, rid, amount, n in db.execute(q):
        if n:
            out[(prov, rid)] += float(amount)
            if prov == "aws":
                out[(prov, rid.rsplit("/", 1)[-1])] += float(amount)
    return out


def _stopped_streaks(db: Session) -> dict[str, date]:
    """First day of the current 'Stopped' streak per asset, from the daily snapshots."""
    last_running = dict(db.execute(select(AssetActivitySnapshot.resource_key, func.max(AssetActivitySnapshot.day))
                                   .where(AssetActivitySnapshot.classification != A.STOPPED).group_by(AssetActivitySnapshot.resource_key)).all())
    first_stopped = dict(db.execute(select(AssetActivitySnapshot.resource_key, func.min(AssetActivitySnapshot.day))
                                    .where(AssetActivitySnapshot.classification == A.STOPPED).group_by(AssetActivitySnapshot.resource_key)).all())
    out = {}
    for key, first in first_stopped.items():
        lr = last_running.get(key)
        if lr is not None and lr >= first:
            out[key] = lr + timedelta(days=1)  # seen running before: the streak start is known (to the day)
        # never seen running: when it stopped is unknown, so no duration is claimed
    return out


def _lookup(table: dict, prov: str, refs: list[str]):
    vals = [table[(prov, r.lower())] for r in refs if r and (prov, r.lower()) in table]
    return max(vals) if vals else None


def build(db: Session, user: User | None = None, *, include_deleted: bool = True, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(UTC)
    pol = P.get(db)
    scopes = visible_scopes(db, user)
    meta = {m.resource_key: m for m in db.scalars(select(AssetMetadata))}
    details = {d.resource_key: d for d in db.scalars(select(AssetDetail))}
    vms = [v for v in db.scalars(select(VMInventory)) if (v.provider, v.scope_external_id) in scopes]
    res = [r for r in db.scalars(select(CloudResource)) if (r.provider, r.scope_external_id) in scopes]
    vm_ids = [v.id for v in vms]
    metrics = _metrics(db, vm_ids, now - timedelta(days=pol["window_days"]))
    latest = _latest_metric(db, vm_ids)
    activity, login, stop = _events(db, now - timedelta(days=pol["activity_lookback_days"]))
    costs = _costs(db, (now - timedelta(days=30)).date())
    streaks = _stopped_streaks(db)
    from app.api.routes.explorer import _owner, category
    rows = []
    for v in vms:
        key = resource_key(v.provider, v.instance_id)
        refs = _vm_refs(v)
        rows.append(_row(kind="server", key=key, provider=v.provider, scope=v.scope_external_id, scope_obj=scopes.get((v.provider, v.scope_external_id)),
                         resource_id=v.instance_id, name=v.name or v.instance_id.rsplit("/", 1)[-1], resource_type="Virtual machine",
                         category="Virtual machines", region=v.region, state=v.power_state, deleted=v.deleted_at is not None,
                         private_ip=v.private_ip, public_ip=v.public_ip, size=v.instance_type, launched_at=v.launched_at, first_seen=v.created_at,
                         tag_owner=None, meta=meta.get(key), detail=details.get(key), metrics=metrics.get(v.id), latest=latest.get(v.id),
                         last_activity=_lookup(activity, v.provider, refs), last_login=_lookup(login, v.provider, refs),
                         last_stop=_lookup(stop, v.provider, refs), cost=_cost(costs, v.provider, refs), streak=streaks.get(key), pol=pol, now=now))
    for r in res:
        key = resource_key(r.provider, r.resource_id)
        attrs = r.attributes or {}
        refs = [r.resource_id] + ([r.resource_id.rsplit("/", 1)[-1]] if r.provider == "aws" else [])
        rows.append(_row(kind="service", key=key, provider=r.provider, scope=r.scope_external_id, scope_obj=scopes.get((r.provider, r.scope_external_id)),
                         resource_id=r.resource_id, name=r.name or r.resource_id.rsplit("/", 1)[-1], resource_type=r.resource_type,
                         category=category(r.resource_type), region=r.region, state=r.state, deleted=(r.state or "").lower() == "deleted",
                         private_ip=None, public_ip=None, size=attrs.get("sku"), launched_at=None, first_seen=r.created_at,
                         tag_owner=_owner(attrs.get("tags")), meta=meta.get(key), detail=details.get(key), metrics=None, latest=None,
                         last_activity=_lookup(activity, r.provider, refs), last_login=None, last_stop=None, cost=_cost(costs, r.provider, refs),
                         streak=streaks.get(key), pol=pol, now=now))
    if not include_deleted:
        rows = [x for x in rows if x["activity_status"] != A.GONE]
    return rows


def _vm_refs(v: VMInventory) -> list[str]:
    """How audit and cost records name this VM: AWS instance ID (also the ARN tail), Azure full resource ID,
    GCP projects/<project>/zones/<zone>/instances/<name> or the numeric instance ID."""
    if v.provider == "gcp":
        return [v.instance_id] + ([f"projects/{v.scope_external_id}/zones/{v.region}/instances/{v.name}"] if v.name and v.region else [])
    return [v.instance_id]


def _cost(costs: dict, prov: str, refs: list[str]):
    for r in refs:
        if r and (prov, r.lower()) in costs:
            return round(costs[(prov, r.lower())], 2)
    return None


def _row(*, kind, key, provider, scope, scope_obj, resource_id, name, resource_type, category, region, state, deleted, private_ip, public_ip,
         size, launched_at, first_seen, tag_owner, meta, detail, metrics, latest, last_activity, last_login, last_stop, cost, streak, pol, now) -> dict:
    gaps = dict((detail.gaps or {}) if detail else {})
    m = {c: getattr(meta, c) if meta else None for c in MANUAL_COLUMNS}
    if kind == "server" and detail is None:
        gaps.setdefault("details", "Server details not collected yet (job asset_details_sync)")
    # used space: agent metrics only (guest file-system usage is not visible to the cloud control plane)
    used, used_src = None, None
    if latest is not None and latest.disk_used_gb is not None:
        used, used_src = round(latest.disk_used_gb, 1), "guest agent"
    elif latest is not None and latest.disk_percent is not None and detail and detail.provisioned_gb:
        used, used_src = round(latest.disk_percent / 100 * detail.provisioned_gb, 1), "guest agent disk % × provisioned"
    elif kind == "server":
        gaps.setdefault("used_space", "Not collected: needs a guest agent (CloudWatch agent / Azure Monitor agent / Ops Agent)")
    stopped_since = _aware(last_stop) or (datetime.combine(streak, datetime.min.time(), UTC) if streak else None)
    cls, reason = A.classify(kind=kind, state=state, deleted=deleted, metrics=metrics, last_activity_at=last_activity,
                             stopped_since=stopped_since, policy=pol, now=now)
    native = detail.native_backup_status if detail else None
    commvault = m["commvault_backup_status"]
    protected = True if (native in ("Protected", "Snapshot schedule") or commvault == "Protected") else (
        False if (native in ("Not protected", "Protection stopped") or commvault in ("Not protected", "Failed")) else None)
    env = m["environment_classification"] or getattr(scope_obj, "environment", None)
    stopped_days = ((now - stopped_since).total_seconds() / 86400) if stopped_since else None
    action = A.recommend(cls, kind=kind, stopped_days=stopped_days, policy=pol, backup_protected=protected, environment=env,
                         planned_end_date=m["planned_end_date"], today=now.date())
    if kind == "server" and last_login is None:
        gaps.setdefault("last_login", NOT_LOGIN)
    if cost is None:
        gaps.setdefault("estimated_monthly_cost", "Not collected: no resource-level cost for this resource (cost_detail_refresh)")
    created = (detail.created_at_provider if detail and detail.created_at_provider else launched_at)
    return {
        "key": key, "kind": kind, "provider": provider, "scope": scope, "scope_name": getattr(scope_obj, "name", None) or scope,
        "environment": env, "resource_id": resource_id, "name": name, "server_name": name if kind == "server" else None,
        "hostname": detail.hostname if detail else None, "ip_address": private_ip, "public_ip": public_ip,
        "region": region, "resource_type": resource_type, "category": category, "size": size, "server_status": state or None,
        "guest_os": detail.guest_os if detail else None, "guest_os_source": detail.guest_os_source if detail else None,
        "cpus": detail.cpus if detail else None, "memory_gb": detail.memory_gb if detail else None, "nic_count": detail.nic_count if detail else None,
        "provisioned_gb": detail.provisioned_gb if detail else None, "used_gb": used, "used_source": used_src,
        "native_backup_status": native, "native_backup_last_at": _iso(detail.native_backup_last_at) if detail else None,
        "native_backup_detail": detail.native_backup_detail if detail else None, "commvault_backup_status": commvault,
        "backup_protected": protected,
        "create_date": _iso(created) if created else None, "create_date_source": "provider" if created else None,
        "first_seen_at": _iso(first_seen),
        "last_activity_at": _iso(last_activity), "last_login_at": _iso(last_login),
        "last_login_source": LOGIN_SOURCE.get(provider) if last_login else None,
        "last_monitoring_at": _iso(latest.collected_at) if latest is not None else None,
        "cpu_avg": round(metrics["cpu_avg"], 2) if metrics and metrics.get("cpu_avg") is not None else None,
        "network_mb_per_day": round(metrics["network_mb_per_day"], 1) if metrics and metrics.get("network_mb_per_day") is not None else None,
        "activity_status": cls, "activity_reason": reason, "recommended_action": action,
        "stopped_since": _iso(stopped_since), "estimated_monthly_cost_usd": cost,
        "tag_owner": tag_owner, "details_collected_at": _iso(detail.collected_at) if detail else None,
        **{c: (_iso(v) if isinstance(v, date) else v) for c, v in m.items()},
        "gaps": gaps,
    }


BACKUP_FILTERS = {"protected": lambda r: r["backup_protected"] is True, "not_protected": lambda r: r["backup_protected"] is False,
                  "unknown": lambda r: r["backup_protected"] is None}


def filter_rows(rows: list[dict], *, provider=None, scope=None, kind=None, department=None, spoc=None, activity=None, backup=None,
                environment=None, missing_spoc=None, q=None) -> list[dict]:
    out = rows
    if provider:
        out = [r for r in out if r["provider"] == provider]
    if scope:
        out = [r for r in out if r["scope"] == scope]
    if kind:
        out = [r for r in out if r["kind"] == kind]
    if department:
        out = [r for r in out if (r["department"] or "").lower() == department.lower()]
    if spoc:
        s = spoc.lower()
        out = [r for r in out if s in (r["server_spoc_email"] or "").lower() or s in (r["server_spoc_name"] or "").lower()]
    if activity:
        wanted = set(activity.split(","))
        out = [r for r in out if r["activity_status"] in wanted]
    if backup in BACKUP_FILTERS:
        out = [r for r in out if BACKUP_FILTERS[backup](r)]
    if environment:
        out = [r for r in out if (r["environment"] or "").lower() == environment.lower()]
    if missing_spoc:
        out = [r for r in out if not r["server_spoc_email"]]
    if q:
        s = q.lower()
        fields = ("name", "resource_id", "hostname", "ip_address", "public_ip", "server_spoc_name", "server_spoc_email", "asset_owner", "department",
                  "resource_type", "scope_name")
        out = [r for r in out if any(s in str(r.get(f) or "").lower() for f in fields)]
    return out


def kpis(rows: list[dict]) -> dict:
    by_class = {c: 0 for c in A.CLASSES}
    for r in rows:
        by_class[r["activity_status"]] += 1
    live = [r for r in rows if r["activity_status"] != A.GONE]
    servers = [r for r in live if r["kind"] == "server"]
    idle_cost = [r["estimated_monthly_cost_usd"] for r in live if r["activity_status"] in (A.INACTIVE, A.STOPPED) and r["estimated_monthly_cost_usd"] is not None]
    return {"total": len(live), "servers": len(servers), "services": len(live) - len(servers), "by_activity": by_class,
            "missing_spoc": sum(1 for r in live if not r["server_spoc_email"]),
            "servers_not_backed_up": sum(1 for r in servers if r["backup_protected"] is False),
            "servers_backup_unknown": sum(1 for r in servers if r["backup_protected"] is None),
            "pii_assets": sum(1 for r in live if r["pii_classification"] in ("PII", "Sensitive PII")),
            "idle_monthly_cost_usd": round(sum(idle_cost), 2) if idle_cost else None,
            "idle_cost_assets_with_cost": len(idle_cost),
            "details_missing": sum(1 for r in servers if r["details_collected_at"] is None)}


def facets(rows: list[dict]) -> dict:
    def vals(f):
        return sorted({r[f] for r in rows if r.get(f)})
    return {"providers": vals("provider"), "scopes": sorted({(r["provider"], r["scope"], r["scope_name"]) for r in rows}),
            "departments": vals("department"), "spocs": vals("server_spoc_email"), "environments": vals("environment"),
            "activity": list(A.CLASSES)}
