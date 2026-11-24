"""VM monitoring job: inventory + metrics + health history + alerts."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import CloudResource, JobStatus, Severity, VMAlert, VMInventory, VMMetric, utcnow
from app.scheduler.engine import JobContext, JobResult
from app.services import reliability as rel  # noqa: E402
from app.services.scopes import check_passed, eligible_scopes

from .health import evaluate

log = logging.getLogger(__name__)
_STATE_ALERTS = ("cpu_high", "memory_high", "disk_high", "missing_metrics", "public_port_exposure")


def _event_alert(db: Session, vm: VMInventory, kind: str, severity: Severity, message: str) -> None:
    db.add(VMAlert(vm_id=vm.id, alert_type=kind, severity=severity.value, message=message, status="recorded", resolved_at=utcnow()))


def _sync_alerts(db: Session, vm: VMInventory, alerts: list[dict]) -> int:
    open_alerts = {a.alert_type: a for a in db.scalars(select(VMAlert).where(VMAlert.vm_id == vm.id, VMAlert.status == "open"))}
    current = {a["type"]: a for a in alerts}
    opened = 0
    for kind, a in current.items():
        existing = open_alerts.get(kind)
        if existing is None:
            db.add(VMAlert(vm_id=vm.id, alert_type=kind, severity=a["severity"], message=a["message"], value=a.get("value"),
                           threshold=a.get("threshold"), status="open"))
            opened += 1
        else:
            existing.severity, existing.message, existing.value, existing.threshold = a["severity"], a["message"], a.get("value"), a.get("threshold")
    for kind in _STATE_ALERTS:
        if kind in open_alerts and kind not in current:
            open_alerts[kind].status, open_alerts[kind].resolved_at = "resolved", utcnow()
    return opened


def store_scope(db: Session, settings: Settings, provider: str, scope_id: str, vms: list[dict]) -> dict:
    now = utcnow()
    known = {v.instance_id: v for v in db.scalars(select(VMInventory).where(VMInventory.provider == provider, VMInventory.scope_external_id == scope_id))}
    resources = {r.resource_id: r for r in db.scalars(select(CloudResource).where(
        CloudResource.provider == provider, CloudResource.scope_external_id == scope_id, CloudResource.resource_type == "virtual_machine"))}
    stats = {"vms": len(vms), "created": 0, "deleted": 0, "alerts_opened": 0}
    for data in vms:
        iid = str(data["instance_id"])[:512]
        row = known.get(iid)
        created = row is None
        if created:
            row = VMInventory(provider=provider, scope_external_id=scope_id, instance_id=iid, health_status="unknown", exposed_ports=[])
            db.add(row)
        previous_type, was_deleted = row.instance_type, row.deleted_at is not None
        for k in ("name", "region", "instance_type", "power_state", "public_ip", "private_ip", "environment", "launched_at"):
            setattr(row, k, data.get(k))
        row.exposed_ports, row.last_seen_at, row.deleted_at = list(data.get("exposed_ports") or []), now, None
        health, missing, alerts = evaluate(data, settings)
        row.health_status = health
        db.flush()
        if created or was_deleted:
            stats["created"] += 1
            _event_alert(db, row, "vm_created", Severity.INFORMATIONAL, f"VM {row.name} first seen in {scope_id}")
        elif previous_type and data.get("instance_type") and previous_type != data["instance_type"]:
            _event_alert(db, row, "vm_resized", Severity.LOW, f"VM {row.name} resized from {previous_type} to {data['instance_type']}")
        if data["power_state"] == "running":
            m = data["metrics"]
            db.add(VMMetric(vm_id=row.id, collected_at=now, missing_metrics=missing, **{k: m.get(k) for k in (
                "cpu_percent", "memory_percent", "disk_total_gb", "disk_used_gb", "disk_percent", "network_in_bytes", "network_out_bytes")}))
        stats["alerts_opened"] += _sync_alerts(db, row, alerts)
        res = resources.get(iid)
        if res is None:
            res = CloudResource(provider=provider, scope_external_id=scope_id, resource_id=iid, resource_type="virtual_machine")
            db.add(res)
        res.name, res.region, res.state, res.last_seen_at = row.name, row.region, row.power_state, now
    seen = {str(v["instance_id"])[:512] for v in vms}
    for iid, row in known.items():
        if iid not in seen and row.deleted_at is None:
            row.deleted_at, row.health_status = now, "unknown"
            stats["deleted"] += 1
            _event_alert(db, row, "vm_deleted", Severity.MEDIUM, f"VM {row.name} is no longer present in {scope_id}")
            _sync_alerts(db, row, [])
            if iid in resources:
                resources[iid].state = "deleted"
    return stats


def run_vm_metrics(ctx: JobContext, settings: Settings, collectors: list) -> JobResult:
    db = ctx.db
    failures, summary = [], {"vms": 0, "created": 0, "deleted": 0, "alerts_opened": 0, "by_provider": {}}
    total = failed = 0
    for c in collectors:
        p = c.provider
        info = summary["by_provider"].setdefault(p, {"scopes": 0, "vms": 0})
        for scope in eligible_scopes(db, p):
            total += 1
            if not check_passed(scope, "monitoring"):
                failed += 1
                failures.append({"provider": p, "scope": scope.external_id, "name": scope.name, "reason": "Monitoring access not validated (see onboarding checks)"})
                continue
            _skip = rel.scope_gate(p)
            if _skip:
                failed += 1
                failures.append({"provider": p, "scope": scope.external_id, "reason": _skip})
                continue
            try:
                stats = store_scope(db, settings, p, scope.external_id, c.collect(scope))
                db.commit()
                rel.scope_ok(p)
                info["scopes"] += 1
                info["vms"] += stats["vms"]
                for k in ("vms", "created", "deleted", "alerts_opened"):
                    summary[k] += stats[k]
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                log.exception("vm collection failed for %s %s", p, scope.external_id)
                failed += 1
                failures.append({"provider": p, "scope": scope.external_id, "name": scope.name, "reason": rel.scope_failed(p, exc)})
    if total == 0:
        failures.append({"provider": "*", "scope": "*", "reason": "No cloud provider is enabled or no onboarded scopes"})
        return JobResult(JobStatus.FAILED, 0, 0, summary, failures)
    status = JobStatus.SUCCESS if not failures else JobStatus.FAILED if failed == total else JobStatus.PARTIAL
    return JobResult(status, total, failed, summary, failures)
