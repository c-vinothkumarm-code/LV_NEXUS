"""Cross-module read models for the dashboards: provider health, data freshness, trends, recent activity.

Everything here is computed from stored records. Absence of data is returned as None or "not_collected",
never as zero or "healthy"."""
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

from croniter import croniter
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    SCOPE_MODELS,
    AuditEvent,
    AutomationExecutionLog,
    AutomationJob,
    BillingRecord,
    CloudConnection,
    JobStatus,
    NotificationLog,
    OnboardingStatus,
    SecurityFinding,
    VMAlert,
    VMInventory,
    VMMetric,
)

PROVIDERS = ("aws", "gcp", "azure")
COLLECTION_JOBS = ("account_discovery", "security_events", "billing_refresh", "vm_metrics")
AUDIT_SOURCE = {"aws": "AWS CloudTrail", "gcp": "GCP Cloud Audit Logs", "azure": "Azure Activity Log"}
RESOLVED = ("Confirmed Legitimate", "Closed")
SCHEDULER_STALE_MINUTES = 15


def _iso(dt):
    return dt.isoformat() if dt else None


def _latest(db: Session, job: str, ok_only: bool = False):
    q = select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == job,
                                             AutomationExecutionLog.status != JobStatus.SKIPPED_OVERLAP.value)
    if ok_only:
        q = q.where(AutomationExecutionLog.status.in_([JobStatus.SUCCESS.value, JobStatus.PARTIAL.value]))
    return db.scalar(q.order_by(AutomationExecutionLog.started_at.desc()).limit(1))


def freshness(db: Session) -> dict:
    """Last run and last successful (or partial) run of each collection job."""
    out = {}
    for job in COLLECTION_JOBS:
        last, good = _latest(db, job), _latest(db, job, ok_only=True)
        out[job] = {"last_run_at": _iso(last.finished_at or last.started_at) if last else None, "last_status": last.status if last else None,
                    "last_success_at": _iso(good.finished_at) if good else None}
    return out


def scheduler_status(db: Session) -> dict:
    """The scheduler is 'active' when a job it started (trigger=schedule) began in the last 15 minutes.
    The 5-minute security_events job makes this a reliable heartbeat without a separate table."""
    last = db.scalar(select(func.max(AutomationExecutionLog.started_at)).where(AutomationExecutionLog.trigger == "schedule"))
    if last is None:
        return {"state": "never_run", "last_scheduled_run_at": None}
    age = datetime.now(UTC) - last
    return {"state": "active" if age <= timedelta(minutes=SCHEDULER_STALE_MINUTES) else "stale", "last_scheduled_run_at": _iso(last),
            "minutes_since": round(age.total_seconds() / 60, 1)}


def jobs_overview(db: Session) -> list[dict]:
    now = datetime.now(UTC)
    out = []
    for j in db.scalars(select(AutomationJob).order_by(AutomationJob.id)):
        nxt = None
        if j.enabled and j.implemented and j.schedule:
            local = now.astimezone(ZoneInfo(j.schedule_timezone))
            nxt = croniter(j.schedule, local).get_next(datetime).astimezone(UTC).isoformat()
        out.append({"name": j.name, "description": j.description, "last_status": j.last_status, "last_finished_at": _iso(j.last_finished_at),
                    "next_run_at": nxt, "implemented": j.implemented, "enabled": j.enabled, "running": j.lock_owner is not None})
    return out


def provider_health(db: Session, settings: Settings) -> dict:
    """Per cloud: connected?, scope counts and the failures reported by the latest run of each collection job."""
    enabled = {"aws": settings.aws_enabled, "gcp": settings.gcp_enabled, "azure": settings.azure_enabled}
    tests = {c.provider: c for c in db.scalars(select(CloudConnection))}
    latest = {job: _latest(db, job) for job in COLLECTION_JOBS}
    out = {}
    for p in PROVIDERS:
        model = SCOPE_MODELS[p]
        counts = dict(db.execute(select(model.onboarding_status, func.count()).group_by(model.onboarding_status)).all())
        active = sum(v for k, v in counts.items() if k != OnboardingStatus.INACTIVE.value)
        failures = []
        for job, run in latest.items():
            for f in (run.failures or []) if run else []:
                if f.get("provider") == p:
                    failures.append({"job": job, "scope": f.get("scope"), "reason": f.get("reason")})
        discovery = (latest["account_discovery"].summary or {}).get("providers", {}).get(p, {}) if latest["account_discovery"] else {}
        if not enabled[p]:
            state = "not_connected"
        elif discovery.get("status") in ("discovery_failed", "not_configured"):
            state = "failing"
        elif not active:
            state = "pending"
        elif failures or counts.get(OnboardingStatus.ACCESS_FAILED.value):
            state = "degraded"
        else:
            state = "healthy"
        t = tests.get(p)
        out[p] = {"state": state, "enabled": enabled[p], "scopes_active": active,
                  "fully_onboarded": counts.get(OnboardingStatus.FULLY_ONBOARDED.value, 0),
                  "access_failed": counts.get(OnboardingStatus.ACCESS_FAILED.value, 0), "failures": failures[:10],
                  "failure_count": len(failures),
                  "last_connection_test": {"at": _iso(t.last_test_at), "ok": t.last_test_ok, "detail": t.last_test_detail} if t and t.last_test_at else None}
    return out


def cost_series(db: Session, start: date, end: date, provider: str | None = None, scope: str | None = None) -> list[dict]:
    """Daily USD per provider, one row per day in the range (days without records are absent, not zero)."""
    q = (select(BillingRecord.usage_date, BillingRecord.provider, func.sum(BillingRecord.cost_usd))
         .where(BillingRecord.usage_date >= start, BillingRecord.usage_date <= end, BillingRecord.cost_usd.is_not(None)))
    if provider:
        q = q.where(BillingRecord.provider == provider)
    if scope:
        q = q.where(BillingRecord.scope_external_id == scope)
    rows: dict = defaultdict(dict)
    for d, p, c in db.execute(q.group_by(BillingRecord.usage_date, BillingRecord.provider)).all():
        rows[d.isoformat()][p] = round(float(c or 0), 2)
    return [{"date": d, **v} for d, v in sorted(rows.items())]


def monthly_costs(db: Session, months: int = 12, provider: str | None = None, scope: str | None = None) -> list[dict]:
    first = date.today().replace(day=1)
    start = first
    for _ in range(months - 1):
        start = (start - timedelta(days=1)).replace(day=1)
    q = (select(BillingRecord.usage_date, BillingRecord.provider, BillingRecord.cost_usd)
         .where(BillingRecord.usage_date >= start, BillingRecord.cost_usd.is_not(None)))
    if provider:
        q = q.where(BillingRecord.provider == provider)
    if scope:
        q = q.where(BillingRecord.scope_external_id == scope)
    totals: dict = defaultdict(lambda: defaultdict(float))
    # Portable month bucketing: group in Python (a year of daily rows per scope and service is small).
    for d, p, c in db.execute(q).all():
        totals[d.strftime("%Y-%m")][p] += float(c or 0)
    return [{"month": m, **{p: round(v, 2) for p, v in vals.items()}} for m, vals in sorted(totals.items())]


def billing_metadata(db: Session, settings: Settings) -> dict:
    cur = dict(db.execute(select(BillingRecord.currency_original, func.count()).group_by(BillingRecord.currency_original)).all())
    prov = db.scalar(select(func.count()).select_from(BillingRecord).where(BillingRecord.is_final.is_(False))) or 0
    total = db.scalar(select(func.count()).select_from(BillingRecord)) or 0
    azure_periods = [{"scope": s, "period_start": d.isoformat()} for s, d in db.execute(
        select(BillingRecord.scope_external_id, func.max(BillingRecord.billing_period_start))
        .where(BillingRecord.provider == "azure", BillingRecord.billing_period_start.is_not(None))
        .group_by(BillingRecord.scope_external_id)).all() if d]
    return {"last_collected_at": _iso(db.scalar(select(func.max(BillingRecord.collected_at)))),
            "original_currencies": cur, "reporting_currency": "USD", "fx_usd_inr_rate": settings.fx_usd_inr_rate,
            "provisional_records": prov, "total_records": total,
            "periods": {"aws": "Calendar month", "gcp": "Calendar month", "azure": "Each subscription's own billing period"},
            "azure_period_starts": azure_periods}


def recent_events(db: Session, limit: int = 10, provider: str | None = None, scope: str | None = None, flagged_only: bool = False) -> list[dict]:
    q = select(AuditEvent).order_by(AuditEvent.event_timestamp.desc())
    if provider:
        q = q.where(AuditEvent.provider == provider)
    if scope:
        q = q.where(AuditEvent.scope_external_id == scope)
    if flagged_only:
        q = q.where(AuditEvent.detection_status == "flagged")
    return [{"id": e.id, "provider": e.provider, "scope": e.scope_external_id, "time": _iso(e.event_timestamp), "event_name": e.event_name,
             "principal": e.principal, "source_ip": e.source_ip, "resource_id": e.resource_id, "severity": e.severity,
             "outcome": (e.raw or {}).get("outcome"), "flagged": e.detection_status == "flagged", "source": AUDIT_SOURCE.get(e.provider)}
            for e in db.scalars(q.limit(limit))]


def alerts(db: Session, settings: Settings) -> list[dict]:
    """Operational alerts derived from current state: what an operator should look at now."""
    from app.services.finops import analysis

    now = datetime.now(UTC)
    out = []
    n = db.scalar(select(func.count()).select_from(SecurityFinding).where(SecurityFinding.first_seen_at >= now - timedelta(hours=24),
                                                                         SecurityFinding.severity.in_(["Critical", "High"])))
    if n:
        out.append({"level": "critical", "area": "soc", "text": f"{n} new Critical/High finding{'s' if n > 1 else ''} in the last 24 hours, pending review"})
    n = db.scalar(select(func.count()).select_from(VMAlert).where(VMAlert.status == "open", VMAlert.severity.in_(["Critical", "High"])))
    if n:
        out.append({"level": "serious", "area": "infrastructure", "text": f"{n} open Critical/High VM alert{'s' if n > 1 else ''}"})
    for b in analysis.budget_status(db):
        if b["level"] in ("exceeded", "high", "warning"):
            out.append({"level": "critical" if b["level"] == "exceeded" else "warning", "area": "finops",
                        "text": f"{b['provider'].upper()} {b['scope']}: {b['utilisation_percent']}% of budget ({b['level_label']})"})
    for job in COLLECTION_JOBS:
        run = _latest(db, job)
        if run and run.status in (JobStatus.FAILED.value, JobStatus.PARTIAL.value) and run.started_at >= now - timedelta(hours=24):
            out.append({"level": "critical" if run.status == JobStatus.FAILED.value else "warning", "area": "automation",
                        "text": f"{job} {run.status}: {len(run.failures or [])} scope(s) reported a problem"})
    sched = scheduler_status(db)
    if sched["state"] == "stale":
        out.append({"level": "critical", "area": "automation", "text": f"Scheduler has not started a job for {sched['minutes_since']:.0f} minutes"})
    n = db.scalar(select(func.count()).select_from(NotificationLog).where(NotificationLog.status == "failed"))
    if n:
        out.append({"level": "warning", "area": "automation", "text": f"{n} notification{'s' if n > 1 else ''} could not be delivered"})
    return out


def vm_utilisation(db: Session, provider: str | None = None, scope: str | None = None) -> dict:
    latest = select(VMMetric.vm_id, func.max(VMMetric.id).label("mid")).group_by(VMMetric.vm_id).subquery()
    q = (select(VMMetric).join(latest, VMMetric.id == latest.c.mid).join(VMInventory, VMInventory.id == VMMetric.vm_id)
         .where(VMInventory.deleted_at.is_(None), VMInventory.power_state == "running"))
    if provider:
        q = q.where(VMInventory.provider == provider)
    if scope:
        q = q.where(VMInventory.scope_external_id == scope)
    rows = db.scalars(q).all()

    def stat(key):
        vals = [getattr(m, key) for m in rows if getattr(m, key) is not None]
        return {"average": round(sum(vals) / len(vals), 1) if vals else None, "max": round(max(vals), 1) if vals else None,
                "reporting": len(vals), "missing": len(rows) - len(vals)}

    return {"running_with_samples": len(rows), "cpu": stat("cpu_percent"), "memory": stat("memory_percent"), "disk": stat("disk_percent")}


def finding_groups(db: Session, provider: str | None = None, scope: str | None = None) -> dict:
    q = select(SecurityFinding.provider, SecurityFinding.severity, SecurityFinding.review_status, func.count()).group_by(
        SecurityFinding.provider, SecurityFinding.severity, SecurityFinding.review_status)
    if provider:
        q = q.where(SecurityFinding.provider == provider)
    if scope:
        q = q.where(SecurityFinding.scope_external_id == scope)
    posture: dict = {p: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "open": 0, "resolved": 0} for p in PROVIDERS}
    for p, sev, status, n in db.execute(q).all():
        slot = posture.setdefault(p, {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0, "open": 0, "resolved": 0})
        if status in RESOLVED:
            slot["resolved"] += n
        else:
            slot["open"] += n
            slot[sev] = slot.get(sev, 0) + n
    return posture
