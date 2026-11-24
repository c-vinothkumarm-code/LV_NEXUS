"""Overview (home) for the enterprise shell: one call, every section with its own freshness.

Each section reports `updated_at` (last successful collection of its data), `status` (fresh | stale | never | degraded)
and the data itself. A failed latest run never blanks a section: the last stored data is returned with its time and the
reason, so the page always has something truthful to show."""
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.serializers import iso
from app.core.config import Settings, get_settings
from app.core.security import require
from app.database.session import get_db
from app.models import (
    SCOPE_MODELS,
    AccessAssignment,
    AuditEvent,
    AuditInvestigation,
    AutomationExecutionLog,
    BillingForecast,
    BillingRecord,
    CloudResource,
    CloudSecurityFinding,
    JobStatus,
    User,
    VMInventory,
)

router = APIRouter(prefix="/api/v1/home", tags=["overview"])
OK_STATES = (JobStatus.SUCCESS.value, JobStatus.PARTIAL.value)
SECTION_JOBS = {"accounts": ["account_discovery", "resource_inventory", "vm_metrics"], "cost": ["billing_refresh", "cost_detail_refresh"],
                "security": ["security_findings_sync"], "audit": ["security_events", "entra_activity"], "access": ["access_inventory"]}
STALE_AFTER = {"accounts": timedelta(hours=2), "cost": timedelta(hours=6), "security": timedelta(hours=30), "audit": timedelta(minutes=30),
               "access": timedelta(hours=2)}


def _aware(dt):
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _data_time(db: Session, key: str):
    """Newest collection timestamp of the stored data itself (used when no job run is recorded, e.g. after a restore)."""
    col = {"accounts": [m.last_seen_at for m in SCOPE_MODELS.values()], "cost": [BillingRecord.collected_at], "security": [CloudSecurityFinding.updated_at],
           "audit": [AuditEvent.collected_at], "access": [AccessAssignment.last_seen_at]}[key]
    times = [db.scalar(select(func.max(c))) for c in col]
    times = [_aware(t) for t in times if t is not None]
    return max(times) if times else None


def _freshness(db: Session, key: str) -> dict:
    jobs = SECTION_JOBS[key]
    last_ok = db.scalar(select(func.max(AutomationExecutionLog.finished_at)).where(AutomationExecutionLog.job_name.in_(jobs),
                                                                                AutomationExecutionLog.status.in_(OK_STATES)))
    last_ok = last_ok or _data_time(db, key)
    last = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name.in_(jobs),
                                                          AutomationExecutionLog.status != JobStatus.SKIPPED_OVERLAP.value)
                     .order_by(AutomationExecutionLog.id.desc()).limit(1))
    now = datetime.now(UTC)
    if last_ok is None:
        status = "never"
    elif last is not None and last.status == JobStatus.FAILED.value:
        status = "degraded"
    elif now - _aware(last_ok) > STALE_AFTER[key]:
        status = "stale"
    else:
        status = "fresh"
    reason = None
    if last is not None and last.status in (JobStatus.FAILED.value, JobStatus.PARTIAL.value):
        reason = (last.error or "; ".join(f.get("reason", "") for f in (last.failures or [])[:2]))[:300] or None
    return {"updated_at": iso(last_ok), "status": status, "reason": reason, "jobs": jobs}


@router.get("")
def overview(db: Session = Depends(get_db), _: User = Depends(require("inventory:read"))):
    today = datetime.now(UTC).date()
    m0 = today.replace(day=1)
    pm0 = (m0 - timedelta(days=1)).replace(day=1)
    clouds: dict = {p: {"scopes": 0, "healthy_scopes": 0, "resources": 0, "vms": 0, "vms_running": 0, "cost_mtd": None,
                        "critical": 0, "high": 0, "events_24h": 0, "flagged_24h": 0, "privileged": 0} for p in ("aws", "azure", "gcp")}
    for p, model in SCOPE_MODELS.items():
        rows = list(db.scalars(select(model)))
        clouds[p]["scopes"] = len(rows)
        clouds[p]["healthy_scopes"] = sum(1 for s in rows if s.onboarding_status == "Fully Onboarded")
    for p, n in db.execute(select(CloudResource.provider, func.count()).where(CloudResource.not_deleted()).group_by(CloudResource.provider)).all():
        clouds[p]["resources"] += n
    for p, n in db.execute(select(VMInventory.provider, func.count()).where(VMInventory.deleted_at.is_(None)).group_by(VMInventory.provider)).all():
        clouds[p]["vms"] = n
    for p, n in db.execute(select(VMInventory.provider, func.count()).where(VMInventory.deleted_at.is_(None), func.lower(VMInventory.power_state).in_(
            ["running", "vm running", "poweredon"])).group_by(VMInventory.provider)).all():
        clouds[p]["vms_running"] = n
    for p, v in db.execute(select(BillingRecord.provider, func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date >= m0,
                                                                                                    BillingRecord.cost_usd.is_not(None)).group_by(BillingRecord.provider)).all():
        clouds[p]["cost_mtd"] = float(v or 0)
    open_q = [CloudSecurityFinding.is_security.is_(True), CloudSecurityFinding.native_state == "ACTIVE",
              CloudSecurityFinding.internal_status.in_(["OPEN", "UNDER_REVIEW", "REOPENED"])]
    for p, sev, n in db.execute(select(CloudSecurityFinding.provider, CloudSecurityFinding.severity, func.count()).where(*open_q)
                                .group_by(CloudSecurityFinding.provider, CloudSecurityFinding.severity)).all():
        if sev in ("Critical", "High"):
            clouds[p][sev.lower()] += n
    day = datetime.now(UTC) - timedelta(hours=24)
    for p, n in db.execute(select(AuditEvent.provider, func.count()).where(AuditEvent.event_timestamp >= day).group_by(AuditEvent.provider)).all():
        clouds[p]["events_24h"] = n
    flagged_q = select(AuditEvent.provider, func.count()).join(AuditInvestigation, AuditInvestigation.audit_event_id == AuditEvent.id).where(
        AuditEvent.event_timestamp >= day, AuditInvestigation.classification.in_(["SUSPICIOUS", "RULE_VIOLATION", "REVIEW_REQUIRED"])).group_by(AuditEvent.provider)
    for p, n in db.execute(flagged_q).all():
        clouds[p]["flagged_24h"] = n
    for p, n in db.execute(select(AccessAssignment.provider, func.count()).where(AccessAssignment.removed_at.is_(None), AccessAssignment.privileged.is_(True))
                           .group_by(AccessAssignment.provider)).all():
        clouds[p]["privileged"] = n

    # cost
    mtd = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date >= m0, BillingRecord.cost_usd.is_not(None)))
    last_month = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date.between(pm0, m0 - timedelta(days=1)),
                                                                          BillingRecord.cost_usd.is_not(None)))
    forecast = None
    fc = list(db.scalars(select(BillingForecast).where(BillingForecast.period_start == m0)))
    if fc:
        by_scope: dict = {}
        for f in fc:
            if f.currency == "USD" and (f.method.startswith("provider:") or (f.provider, f.scope_external_id) not in by_scope):
                by_scope[(f.provider, f.scope_external_id)] = f
        mtd_by = {(p, s): float(v or 0) for p, s, v in db.execute(select(BillingRecord.provider, BillingRecord.scope_external_id, func.sum(BillingRecord.cost_usd))
                                                                  .where(BillingRecord.usage_date >= m0, BillingRecord.cost_usd.is_not(None))
                                                                  .group_by(BillingRecord.provider, BillingRecord.scope_external_id)).all()}
        forecast = sum((mtd_by.get(k, 0) + float(f.forecast_amount)) if f.method.startswith("provider:") else float(f.forecast_amount) for k, f in by_scope.items())
    trend = defaultdict(dict)
    for p, d, v in db.execute(select(BillingRecord.provider, BillingRecord.usage_date, func.sum(BillingRecord.cost_usd)).where(
            BillingRecord.usage_date >= today - timedelta(days=29), BillingRecord.cost_usd.is_not(None)).group_by(BillingRecord.provider, BillingRecord.usage_date)).all():
        trend[d.isoformat() if isinstance(d, date) else str(d)][p] = round(float(v or 0), 2)

    # security
    sev_counts = dict(db.execute(select(CloudSecurityFinding.severity, func.count()).where(*open_q).group_by(CloudSecurityFinding.severity)).all())
    top = [{"id": f.id, "title": f.title, "severity": f.severity, "provider": f.provider, "scope": f.scope_external_id, "resource": f.resource_name}
           for f in db.scalars(select(CloudSecurityFinding).where(*open_q, CloudSecurityFinding.severity.in_(["Critical", "High"]))
                               .order_by(CloudSecurityFinding.severity, CloudSecurityFinding.id.desc()).limit(5))]

    # audit
    flagged = [{"id": e.id, "time": iso(e.event_timestamp), "provider": e.provider, "operation": e.event_name, "actor": e.principal,
                "classification": i.classification, "severity": i.severity}
               for e, i in db.execute(select(AuditEvent, AuditInvestigation).join(AuditInvestigation, AuditInvestigation.audit_event_id == AuditEvent.id)
                                      .where(AuditInvestigation.classification.in_(["SUSPICIOUS", "RULE_VIOLATION"]))
                                      .order_by(AuditEvent.event_timestamp.desc()).limit(5)).all()]
    events_24h = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.event_timestamp >= day)) or 0

    # access
    holders = db.scalar(select(func.count(func.distinct(AccessAssignment.principal_id))).where(AccessAssignment.removed_at.is_(None))) or 0
    priv = db.scalar(select(func.count()).select_from(AccessAssignment).where(AccessAssignment.removed_at.is_(None), AccessAssignment.privileged.is_(True))) or 0

    # health
    jobs = {}
    for name in sorted({j for v in SECTION_JOBS.values() for j in v}):
        last = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == name, AutomationExecutionLog.status != JobStatus.SKIPPED_OVERLAP.value)
                         .order_by(AutomationExecutionLog.id.desc()).limit(1))
        jobs[name] = {"status": last.status if last else "never", "at": iso(last.finished_at or last.started_at) if last else None}
    ok = sum(1 for j in jobs.values() if j["status"] == "success")
    return {
        "generated_at": iso(datetime.now(UTC)),
        "clouds": clouds,
        "accounts": {**_freshness(db, "accounts"), "total_scopes": sum(c["scopes"] for c in clouds.values()),
                     "resources": sum(c["resources"] for c in clouds.values()), "vms": sum(c["vms"] for c in clouds.values())},
        "cost": {**_freshness(db, "cost"), "month_to_date": float(mtd) if mtd is not None else None,
                 "last_month": float(last_month) if last_month is not None else None, "forecast_month": round(forecast, 2) if forecast is not None else None,
                 "trend": [{"date": d, **v} for d, v in sorted(trend.items())]},
        "security": {**_freshness(db, "security"), "by_severity": sev_counts, "top": top},
        "audit": {**_freshness(db, "audit"), "events_24h": events_24h, "flagged_24h": sum(c["flagged_24h"] for c in clouds.values()), "recent_flagged": flagged},
        "access": {**_freshness(db, "access"), "identities_with_access": holders, "privileged_assignments": priv},
        "health": {"jobs": jobs, "success": ok, "total": len(jobs)},
    }


@router.get("/brief")
def brief(db: Session = Depends(get_db), user: User = Depends(require("inventory:read"))):
    """Executive brief: the verified headline facts (position, top risks, trends, pending actions, platform health) from the
    same tools the assistant uses, limited to what the caller's role may see. No AI model involved."""
    from app.services.intelligence.assistant_tools import t_executive_summary
    r = t_executive_summary(db, {"_perms": set(user.permission_names)})
    sections: dict[str, list] = {}
    for f in r["facts"]:
        sections.setdefault(f.get("section") or "Position", []).append({"fact": f["fact"], "link": f.get("link")})
    return {"generated_at": r["as_of"], "source": r["source"], "sections": [{"title": k, "facts": v} for k, v in sections.items()]}


@router.get("/metrics")
def metrics(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(require("inventory:read"))):
    """Executive Overview metrics, each with definition, source, calculation, timestamp, scope and availability. Only the
    sections the caller's role may open are included; missing data is reported as missing, never as zero."""
    from app.services.metrics.executive import executive_metrics
    return executive_metrics(db, settings, set(user.permission_names))
