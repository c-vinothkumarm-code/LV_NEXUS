"""Scheduled jobs of Cloud Services & Asset Management.

asset_details_sync     read-only collection of server details per onboarded scope (see collectors.py). Writes only
                       asset_details (never business metadata) and records every observed change (append-only).
asset_activity_review  daily: classifies every asset, stores the day's snapshot (activity history), records state / IP /
                       size changes, and e-mails one digest per Server SPOC (CC Reporting Manager) for inactive or long
                       stopped assets. No resource is ever stopped or deleted."""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, date, datetime

from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import AssetActivitySnapshot, AssetDetail, AssetInventoryChange, JobStatus, NotificationRule, resource_key, utcnow
from app.scheduler.engine import JobContext, JobResult
from app.services import reliability as rel
from app.services.assets import catalog
from app.services.assets import policy as P
from app.services.scopes import eligible_scopes

log = logging.getLogger(__name__)
DETAIL_FIELDS = ("hostname", "guest_os", "guest_os_source", "cpus", "memory_gb", "nic_count", "provisioned_gb", "native_backup_status",
                 "native_backup_last_at", "native_backup_detail", "created_at_provider")
TRACKED = ("hostname", "guest_os", "cpus", "memory_gb", "nic_count", "provisioned_gb", "native_backup_status")
SNAPSHOT_TRACKED = ("server_status", "ip_address", "public_ip", "size", "region")
EVENT = "asset_inactivity"


def _s(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return (v if v.tzinfo else v.replace(tzinfo=UTC)).isoformat()
    return str(v)


def store_details(db: Session, provider: str, scope: str, items: list[dict]) -> dict:
    now = utcnow()
    created = changed = 0
    for it in items:
        key = resource_key(provider, it["resource_id"])
        row = db.scalar(select(AssetDetail).where(AssetDetail.resource_key == key))
        if row is None:
            row = AssetDetail(resource_key=key, provider=provider, scope_external_id=scope, resource_id=it["resource_id"])
            db.add(row)
            created += 1
        else:
            for f in TRACKED:
                old, new = getattr(row, f), it.get(f)
                if _s(old) != _s(new) and new is not None:  # a field that could not be read this time is not a change
                    db.add(AssetInventoryChange(resource_key=key, provider=provider, scope_external_id=scope, field=f, old_value=_s(old),
                                                new_value=_s(new), source="asset_details_sync"))
                    changed += 1
        for f in DETAIL_FIELDS:
            new = it.get(f)
            if new is not None or f not in TRACKED:
                setattr(row, f, new)
        row.gaps, row.collected_at, row.scope_external_id = it.get("gaps") or {}, now, scope
    return {"servers": len(items), "created": created, "changes": changed}


def run_asset_details(ctx: JobContext, settings: Settings, collectors: list) -> JobResult:
    db = ctx.db
    failures, summary = [], {"servers": 0, "created": 0, "changes": 0, "by_provider": {}}
    total = failed = 0
    for c in collectors:
        p = c.provider
        info = summary["by_provider"].setdefault(p, {"scopes": 0, "servers": 0, "fields_not_collected": 0})
        for scope in eligible_scopes(db, p):
            total += 1
            skip = rel.scope_gate(p)
            if skip:
                failed += 1
                failures.append({"provider": p, "scope": scope.external_id, "reason": skip})
                continue
            try:
                items = c.collect(scope)
                stats = store_details(db, p, scope.external_id, items)
                db.commit()
                rel.scope_ok(p)
                info["scopes"] += 1
                info["servers"] += stats["servers"]
                info["fields_not_collected"] += sum(len(i.get("gaps") or {}) for i in items)
                for k in ("servers", "created", "changes"):
                    summary[k] += stats[k]
            except Exception as exc:  # noqa: BLE001 - one scope never stops the others
                db.rollback()
                log.exception("asset details failed for %s %s", p, scope.external_id)
                failed += 1
                failures.append({"provider": p, "scope": scope.external_id, "name": getattr(scope, "name", None), "reason": rel.scope_failed(p, exc)})
    if total == 0:
        failures.append({"provider": "*", "scope": "*", "reason": "No cloud provider is enabled or no onboarded scopes"})
        return JobResult(JobStatus.FAILED, 0, 0, summary, failures)
    status = JobStatus.SUCCESS if not failures else JobStatus.FAILED if failed == total else JobStatus.PARTIAL
    return JobResult(status, total, failed, summary, failures)


# ------------------------------------------------------------------------------------ daily activity review

def ensure_rule(db: Session) -> None:
    if db.scalar(select(NotificationRule).where(NotificationRule.event_type == EVENT)) is None:
        db.add(NotificationRule(event_type=EVENT, description="Inactive or long-stopped cloud assets (digest to the Server SPOC, copy to the Reporting Manager)",
                                enabled=True, channels="email"))
        db.flush()


def snapshot(db: Session, rows: list[dict], day: date) -> dict:
    """Store today's classification per asset (one row per asset per day) and record state / IP / size changes."""
    keys = [r["key"] for r in rows]
    last = (select(AssetActivitySnapshot.resource_key, func.max(AssetActivitySnapshot.day).label("d"))
            .where(AssetActivitySnapshot.day < day).group_by(AssetActivitySnapshot.resource_key).subquery())
    prev = {s.resource_key: s for s in db.scalars(select(AssetActivitySnapshot).join(
        last, and_(AssetActivitySnapshot.resource_key == last.c.resource_key, AssetActivitySnapshot.day == last.c.d)))}
    today = {s.resource_key: s for s in db.scalars(select(AssetActivitySnapshot).where(AssetActivitySnapshot.day == day))}
    changes = 0
    for r in rows:
        snap = {f: r.get(f) for f in SNAPSHOT_TRACKED}
        p = prev.get(r["key"])
        if p is not None:
            for f in SNAPSHOT_TRACKED:
                if (p.snapshot or {}).get(f) != snap[f] and snap[f] is not None:
                    db.add(AssetInventoryChange(resource_key=r["key"], provider=r["provider"], scope_external_id=r["scope"], field=f,
                                                old_value=_s((p.snapshot or {}).get(f)), new_value=_s(snap[f]), source="asset_activity_review"))
                    changes += 1
        row = today.get(r["key"])
        if row is None:
            row = AssetActivitySnapshot(resource_key=r["key"], provider=r["provider"], scope_external_id=r["scope"], day=day)
            db.add(row)
        row.classification, row.reason, row.state = r["activity_status"], r["activity_reason"][:2000], r["server_status"]
        row.cpu_avg, row.network_mb_per_day, row.snapshot = r["cpu_avg"], r["network_mb_per_day"], snap
        row.last_activity_at = datetime.fromisoformat(r["last_activity_at"]) if r["last_activity_at"] else None
    return {"assets": len(keys), "changes": changes}


def _digest(spoc: str, items: list[dict]) -> tuple[str, str]:
    subject = f"[LV NEXUS] {len(items)} cloud asset(s) need your review – inactive or stopped"
    lines = [f"Dear {items[0].get('server_spoc_name') or 'Server SPOC'},", "",
             "The following cloud assets assigned to you are inactive or have been stopped (from collected monitoring and audit data):", ""]
    for r in items:
        cost = f"${r['estimated_monthly_cost_usd']:,.2f}/month" if r["estimated_monthly_cost_usd"] is not None else "cost not collected"
        lines.append(f"- {r['name']} ({r['provider'].upper()} {r['scope_name']}, {r['region'] or '-'}): {r['activity_status']} – {r['activity_reason']}. "
                     f"Last activity: {r['last_activity_at'] or 'not recorded'}. {cost}. Recommended: {r['recommended_action']}.")
    lines += ["", "Please confirm whether each asset is still needed (Cloud Services Management → asset → Business metadata).",
              "No resource is stopped or deleted automatically: any change needs business validation and approval through the change process.",
              "", "Cloud Team – LatentView Analytics (sent by LV NEXUS)"]
    return subject, "\n".join(lines)


def run_activity_review(ctx: JobContext, settings: Settings) -> JobResult:
    db = ctx.db
    pol = P.get(db)
    now = datetime.now(UTC)
    rows = catalog.build(db, None, now=now)
    stats = snapshot(db, rows, now.date())
    db.commit()
    summary = {**stats, "by_activity": catalog.kpis(rows)["by_activity"], "notifications_queued": 0, "already_sent": 0, "without_spoc": 0}
    failures = []
    if pol["notify_enabled"]:
        ensure_rule(db)
        from app.services.vuln.notify import notify
        wanted = set(pol["notify_classifications"])
        due = [r for r in rows if r["activity_status"] in wanted and not (r["activity_status"] == "Stopped" and "re-check" in r["recommended_action"])]
        by_spoc: dict[str, list[dict]] = defaultdict(list)
        for r in due:
            if r["server_spoc_email"]:
                by_spoc[r["server_spoc_email"]].append(r)
            else:
                summary["without_spoc"] += 1
        if summary["without_spoc"]:
            failures.append({"provider": "*", "scope": "*", "reason": f"{summary['without_spoc']} inactive / stopped asset(s) have no Server SPOC: "
                                                                    "not notified (set the SPOC in Cloud Services Management)"})
        period = now.date().toordinal() // pol["notify_every_days"]
        for spoc, items in sorted(by_spoc.items()):
            cc = sorted({r["reporting_manager_email"] for r in items if r["reporting_manager_email"] and r["reporting_manager_email"] != spoc})
            subject, body = _digest(spoc, items)
            if notify(db, EVENT, f"{spoc}:{period}", subject, body, getattr(ctx, "execution_id", None), recipients=[spoc, *[f"cc:{c}" for c in cc]]):
                summary["notifications_queued"] += 1
            else:
                summary["already_sent"] += 1
        db.commit()
    status = JobStatus.SUCCESS if not failures else JobStatus.PARTIAL
    return JobResult(status, len(rows), 0, summary, failures)
