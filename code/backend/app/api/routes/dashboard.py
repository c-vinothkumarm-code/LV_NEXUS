"""Dashboard aggregates. Every figure is computed from database records; an empty table yields
zero/None plus a `collection` marker so the UI can say "not collected yet" instead of implying health."""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.api.deps import require_any
from app.api.serializers import execution_dict, iso, query_scopes
from app.core.config import Settings, get_settings
from app.core.security import require, scope_condition
from app.database.session import get_db
from app.models import (
    AuditEvent,
    AutomationExecutionLog,
    AutomationJob,
    BillingBudget,
    BillingForecast,
    BillingRecord,
    CloudResource,
    JobStatus,
    NotificationLog,
    OnboardingStatus,
    RemediationRecord,
    ReviewStatus,
    SecurityFinding,
    User,
    VMAlert,
    VMInventory,
    VMMetric,
)
from app.services import insights
from app.services.connections import effective_settings
from app.services.finops import analysis

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])

_OPEN_REVIEW = [ReviewStatus.PENDING_REVIEW.value, ReviewStatus.UNDER_INVESTIGATION.value,
                ReviewStatus.CONFIRMED_SUSPICIOUS.value, ReviewStatus.REMEDIATION_REQUIRED.value,
                ReviewStatus.ESCALATED.value]
_PENDING = [ReviewStatus.PENDING_REVIEW.value, ReviewStatus.UNDER_INVESTIGATION.value]


def _last_run(db: Session, job_name: str) -> dict:
    """collected = at least one run produced data; failed = runs exist but none ever succeeded."""
    base = select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == job_name)
    last = db.scalar(base.where(AutomationExecutionLog.status != JobStatus.SKIPPED_OVERLAP.value)
                     .order_by(AutomationExecutionLog.started_at.desc()).limit(1))
    if last is None:
        return {"job": job_name, "state": "not_collected", "last_run_at": None, "last_status": None}
    good = db.scalar(base.where(AutomationExecutionLog.status.in_([JobStatus.SUCCESS.value, JobStatus.PARTIAL.value])).limit(1))
    return {"job": job_name, "state": "collected" if good is not None else "failed",
            "last_run_at": iso(last.finished_at or last.started_at), "last_status": last.status}


def _daily_trend(timestamps) -> list[dict]:
    """Findings per UTC day, bucketed in Python so it behaves the same on MySQL, Azure SQL, PostgreSQL and SQLite."""
    counts: dict[str, int] = {}
    for ts in timestamps:
        if ts is not None:
            counts[ts.date().isoformat()] = counts.get(ts.date().isoformat(), 0) + 1
    return [{"date": d, "findings": n} for d, n in sorted(counts.items())]


def _filter(stmt, model, provider=None, scope=None, region=None):
    if provider:
        stmt = stmt.where(model.provider == provider)
    if scope:
        stmt = stmt.where(model.scope_external_id == scope)
    if region and hasattr(model, "region"):
        stmt = stmt.where(model.region == region)
    return stmt


def _group(db: Session, col, stmt_filter=lambda s: s) -> dict:
    return {k or "unknown": v for k, v in db.execute(stmt_filter(select(col, func.count()).group_by(col))).all()}


def _success_rate(db: Session, since: datetime) -> dict:
    counts = dict(db.execute(select(AutomationExecutionLog.status, func.count())
                             .where(AutomationExecutionLog.started_at >= since)
                             .group_by(AutomationExecutionLog.status)).all())
    done = sum(counts.get(s.value, 0) for s in (JobStatus.SUCCESS, JobStatus.PARTIAL, JobStatus.FAILED))
    rate = round(100 * counts.get(JobStatus.SUCCESS.value, 0) / done, 1) if done else None
    return {"success_rate_percent": rate, "counts": counts, "window_days": 7}


def _mtd_cost(db: Session, provider=None, scope=None) -> dict:
    start = date.today().replace(day=1)
    provisional = func.sum(case((BillingRecord.is_final.is_(False), 1), else_=0))
    stmt = _filter(select(BillingRecord.provider, func.sum(BillingRecord.cost_usd), provisional)
                   .where(analysis.current_period_filter()).group_by(BillingRecord.provider), BillingRecord, provider, scope)
    rows = db.execute(stmt).all()
    return {"period_start": start.isoformat(), "currency": "USD",
            "by_provider": {p: float(c or 0) for p, c, _ in rows},
            "total": float(sum((c or 0) for _, c, _ in rows)) if rows else None,
            "is_final": bool(rows) and all(not f for _, _, f in rows)}


@router.get("/overview")
def overview(provider: str | None = None, scope: str | None = None, date_from: date | None = None, date_to: date | None = None,
             db: Session = Depends(get_db), settings: Settings = Depends(get_settings), _: User = Depends(require("inventory:read"))):
    scopes = query_scopes(db, provider)
    active = [s for s in scopes if s.onboarding_status != OnboardingStatus.INACTIVE.value]
    per_provider = {p: {"total": 0, "fully_onboarded": 0} for p in ("aws", "gcp", "azure")}
    for s in active:
        per_provider[s.provider]["total"] += 1
        per_provider[s.provider]["fully_onboarded"] += s.onboarding_status == OnboardingStatus.FULLY_ONBOARDED.value
    sev = _group(db, SecurityFinding.severity, lambda q: _filter(q.where(SecurityFinding.review_status.in_(_OPEN_REVIEW)), SecurityFinding, provider))
    pending = db.scalar(_filter(select(func.count()).select_from(SecurityFinding).where(SecurityFinding.review_status.in_(_PENDING)), SecurityFinding, provider))
    vm_health = _group(db, VMInventory.health_status, lambda q: _filter(q.where(VMInventory.deleted_at.is_(None)), VMInventory, provider))
    cost = _mtd_cost(db, provider)
    budget = db.scalar(_filter(select(func.sum(BillingBudget.amount)).where(
        BillingBudget.period_start <= date.today(), BillingBudget.period_end >= date.today(), BillingBudget.service == "*"), BillingBudget, provider))
    utilisation = round(100 * cost["total"] / float(budget), 1) if budget and cost["total"] is not None else None
    return {
        "scopes": per_provider,
        "total_resources": db.scalar(_filter(select(func.count()).select_from(CloudResource), CloudResource, provider)),
        "vms": {"total": sum(vm_health.values()), "healthy": vm_health.get("healthy", 0),
                "unhealthy": vm_health.get("warning", 0) + vm_health.get("critical", 0),
                "unknown": vm_health.get("unknown", 0) + vm_health.get("partial", 0), "stopped": vm_health.get("stopped", 0)},
        "findings": {"critical": sev.get("Critical", 0), "high": sev.get("High", 0), "pending_investigations": pending},
        "cost": cost, "budget": {"approved": float(budget) if budget else None, "utilisation_percent": utilisation},
        "automation": _success_rate(db, datetime.now(UTC) - timedelta(days=7)),
        "collection": {"inventory": _last_run(db, "account_discovery"), "soc": _last_run(db, "security_events"),
                       "finops": _last_run(db, "billing_refresh"), "infrastructure": _last_run(db, "vm_metrics")},
        **_overview_extras(db, settings, provider, scope, date_from, date_to),
    }


def _overview_extras(db: Session, settings: Settings, provider, scope, date_from, date_to) -> dict:
    eff = effective_settings(db, settings)
    end = date_to or date.today()
    start = date_from or end - timedelta(days=30)
    sev = _group(db, SecurityFinding.severity, lambda q: _filter(q.where(SecurityFinding.review_status.in_(_OPEN_REVIEW)), SecurityFinding, provider, scope))
    return {
        "filters": {"provider": provider, "scope": scope, "from": start.isoformat(), "to": end.isoformat()},
        "findings_open_by_severity": {k: sev.get(k, 0) for k in ("Critical", "High", "Medium", "Low", "Informational")},
        "provider_health": insights.provider_health(db, eff),
        "freshness": insights.freshness(db),
        "scheduler": insights.scheduler_status(db),
        "jobs": insights.jobs_overview(db),
        "cost_daily": insights.cost_series(db, start, end, provider, scope),
        "cost_monthly": insights.monthly_costs(db, 6, provider, scope),
        "cost_weekly": analysis.weekly_summary(db),
        "recent_events": insights.recent_events(db, 8, provider, scope),
        "alerts": insights.alerts(db, eff),
        "vm_utilisation": insights.vm_utilisation(db, provider, scope),
        "resources_by_type": _group(db, CloudResource.resource_type, lambda q: _filter(q, CloudResource, provider, scope)),
        "generated_at": datetime.now(UTC).isoformat(),
    }


@router.get("/soc")
def soc(provider: str | None = None, scope: str | None = None, severity: str | None = None,
        review_status: str | None = None, date_from: date | None = None, date_to: date | None = None,
        db: Session = Depends(get_db), _: User = Depends(require("soc:read"))):
    def f(q):
        q = _filter(q, SecurityFinding, provider, scope)
        if severity:
            q = q.where(SecurityFinding.severity == severity)
        if review_status:
            q = q.where(SecurityFinding.review_status == review_status)
        if date_from:
            q = q.where(SecurityFinding.last_seen_at >= date_from)
        if date_to:
            q = q.where(SecurityFinding.last_seen_at < date_to + timedelta(days=1))
        return q

    def ev(q):
        q = _filter(q, AuditEvent, provider, scope)
        if date_from:
            q = q.where(AuditEvent.event_timestamp >= date_from)
        if date_to:
            q = q.where(AuditEvent.event_timestamp < date_to + timedelta(days=1))
        return q

    recent = db.scalars(f(select(SecurityFinding)).order_by(SecurityFinding.risk_score.desc(), SecurityFinding.last_seen_at.desc()).limit(50)).all()
    return {
        "collection": _last_run(db, "security_events"),
        "events_collected": db.scalar(ev(select(func.count()).select_from(AuditEvent))),
        "by_cloud": _group(db, SecurityFinding.provider, f), "by_severity": _group(db, SecurityFinding.severity, f),
        "by_review_status": _group(db, SecurityFinding.review_status, f),
        "by_scope": _group(db, SecurityFinding.scope_external_id, f),
        "by_principal": dict(db.execute(ev(select(AuditEvent.principal, func.count()).group_by(AuditEvent.principal))
                                        .order_by(func.count().desc()).limit(10)).all()),
        "trend": _daily_trend(db.scalars(f(select(SecurityFinding.first_seen_at))).all()),
        "remediation": _group(db, RemediationRecord.status, lambda q: q.where(RemediationRecord.category == "security")),
        "recent_findings": [{"id": x.id, "provider": x.provider, "scope": x.scope_external_id, "title": x.title,
                             "severity": x.severity, "review_status": x.review_status, "principal": x.principal,
                             "rule_id": x.rule_id, "risk_score": x.risk_score, "occurrences": x.occurrence_count,
                             "recommended_action": x.recommended_action, "ai_analysis": x.ai_analysis,
                             "resource_id": x.resource_id, "first_seen_at": iso(x.first_seen_at), "updated_at": iso(x.updated_at),
                             "source": insights.AUDIT_SOURCE.get(x.provider),
                             "last_seen_at": iso(x.last_seen_at)} for x in recent],
        "incidents": _group(db, RemediationRecord.status, lambda q: q.where(RemediationRecord.category == "incident")),
        "posture": insights.finding_groups(db, provider, scope),
        "recent_events": insights.recent_events(db, 15, provider, scope),
        "affected_resources": [{"resource": r, "findings": n} for r, n in db.execute(
            f(select(SecurityFinding.resource_id, func.count()).where(SecurityFinding.resource_id.is_not(None))
              .group_by(SecurityFinding.resource_id)).order_by(func.count().desc()).limit(8)).all()],
        "generated_at": datetime.now(UTC).isoformat(),
    }


@router.get("/finops")
def finops(provider: str | None = None, scope: str | None = None, date_from: date | None = None,
           date_to: date | None = None, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
           _: User = Depends(require("finops:read"))):
    end = date_to or date.today()
    start = date_from or end - timedelta(days=30)

    def f(q):
        return _filter(q.where(BillingRecord.usage_date >= start, BillingRecord.usage_date <= end), BillingRecord, provider, scope)

    daily = db.execute(f(select(BillingRecord.usage_date, BillingRecord.provider, func.sum(BillingRecord.cost_usd))
                         .group_by(BillingRecord.usage_date, BillingRecord.provider)).order_by(BillingRecord.usage_date)).all()
    top = lambda col: [{"name": n, "cost_usd": float(c or 0)} for n, c in db.execute(  # noqa: E731
        f(select(col, func.sum(BillingRecord.cost_usd)).group_by(col)).order_by(func.sum(BillingRecord.cost_usd).desc()).limit(10)).all()]
    return {"collection": _last_run(db, "billing_refresh"), "range": {"from": start.isoformat(), "to": end.isoformat()},
            "month_to_date": _mtd_cost(db, provider, scope),
            "daily": [{"date": d.isoformat(), "provider": p, "cost_usd": float(c or 0)} for d, p, c in daily],
            "by_service": top(BillingRecord.service), "by_scope": top(BillingRecord.scope_external_id),
            "budgets": db.scalar(select(func.count()).select_from(BillingBudget)),
            "budget_status": [b for b in analysis.budget_status(db) if not provider or b["provider"] == provider],
            "anomalies": [a for a in analysis.anomalies(db, settings) if not provider or a["provider"] == provider],
            "weekly": analysis.weekly_summary(db),
            "forecast_total": float(db.scalar(_filter(select(func.sum(BillingForecast.forecast_amount)).where(
                BillingForecast.period_start == date.today().replace(day=1)), BillingForecast, provider, scope)) or 0) or None,
            "fx_configured": bool(settings.fx_usd_inr_rate),
            "monthly": insights.monthly_costs(db, 12, provider, scope),
            "previous_month": analysis.monthly_summary(db),
            "metadata": insights.billing_metadata(db, settings),
            "by_provider_range": {p: float(c or 0) for p, c in db.execute(f(select(BillingRecord.provider, func.sum(BillingRecord.cost_usd))
                                                                             .group_by(BillingRecord.provider))).all()},
            "generated_at": datetime.now(UTC).isoformat()}


@router.get("/infrastructure")
def infrastructure(provider: str | None = None, scope: str | None = None, region: str | None = None,
                   environment: str | None = None, db: Session = Depends(get_db),
                   user: User = Depends(require_any("infra:read", "inventory:read_assigned"))):
    limit_vm = scope_condition(VMInventory, user) if "infra:read" not in user.permission_names else None
    limit_res = scope_condition(CloudResource, user) if limit_vm is not None else None

    def f(q):
        q = _filter(q.where(VMInventory.deleted_at.is_(None)), VMInventory, provider, scope, region)
        if limit_vm is not None:
            q = q.where(limit_vm)
        return q.where(VMInventory.environment == environment) if environment else q

    vms = db.scalars(f(select(VMInventory)).order_by(VMInventory.name).limit(500)).all()
    latest = select(VMMetric.vm_id, func.max(VMMetric.id).label("mid")).group_by(VMMetric.vm_id).subquery()
    metrics = {m.vm_id: m for m in db.scalars(select(VMMetric).join(latest, VMMetric.id == latest.c.mid))}
    names = {v.id: v for v in vms}
    alerts = db.scalars(select(VMAlert).where(VMAlert.status == "open").order_by(VMAlert.created_at.desc()).limit(100)).all()
    if limit_vm is not None:  # only alerts for VMs this person may see
        alerts = [a for a in alerts if a.vm_id in names]

    def metric(v, key):
        m = metrics.get(v.id)
        value = getattr(m, key, None) if m else None
        return round(value, 1) if value is not None else None

    return {"collection": _last_run(db, "vm_metrics"),
            "by_health": _group(db, VMInventory.health_status, f), "by_power_state": _group(db, VMInventory.power_state, f),
            "by_provider": _group(db, VMInventory.provider, f),
            "public_ip_count": db.scalar(f(select(func.count()).select_from(VMInventory).where(VMInventory.public_ip.is_not(None)))),
            "exposed_count": sum(1 for v in vms if v.public_ip and v.exposed_ports),
            "by_region": _group(db, VMInventory.region, f),
            "by_scope": _group(db, VMInventory.scope_external_id, f),
            "utilisation": insights.vm_utilisation(db, provider, scope) if limit_vm is None else None,
            "resources_by_type": _group(db, CloudResource.resource_type, lambda q: _filter(
                q if limit_res is None else q.where(limit_res), CloudResource, provider, scope)),
            "generated_at": datetime.now(UTC).isoformat(),
            "vms": [{"provider": v.provider, "scope": v.scope_external_id, "name": v.name, "region": v.region,
                     "instance_type": v.instance_type, "power_state": v.power_state, "public_ip": v.public_ip,
                     "private_ip": v.private_ip, "health_status": v.health_status, "exposed_ports": v.exposed_ports,
                     "cpu_percent": metric(v, "cpu_percent"), "memory_percent": metric(v, "memory_percent"),
                     "disk_percent": metric(v, "disk_percent"), "network_in_bytes": metric(v, "network_in_bytes"),
                     "network_out_bytes": metric(v, "network_out_bytes"),
                     "missing_metrics": (metrics[v.id].missing_metrics if v.id in metrics else None)} for v in vms],
            "open_alerts": [{"vm_id": a.vm_id, "vm": names[a.vm_id].name if a.vm_id in names else None, "type": a.alert_type,
                             "provider": names[a.vm_id].provider if a.vm_id in names else None,
                             "severity": a.severity, "message": a.message, "created_at": iso(a.created_at)} for a in alerts]}


@router.get("/automation")
def automation(job: str | None = None, status: str | None = None, date_from: date | None = None,
               date_to: date | None = None, db: Session = Depends(get_db), _: User = Depends(require("automation:read"))):
    stmt = select(AutomationExecutionLog).order_by(AutomationExecutionLog.started_at.desc())
    if job:
        stmt = stmt.where(AutomationExecutionLog.job_name == job)
    if status:
        stmt = stmt.where(AutomationExecutionLog.status == status)
    if date_from:
        stmt = stmt.where(AutomationExecutionLog.started_at >= date_from)
    if date_to:
        stmt = stmt.where(AutomationExecutionLog.started_at < date_to + timedelta(days=1))
    jobs = db.scalars(select(AutomationJob).order_by(AutomationJob.id)).all()
    return {
        "jobs": [{"name": j.name, "description": j.description, "schedule": j.schedule, "timezone": j.schedule_timezone,
                  "enabled": j.enabled, "implemented": j.implemented, "last_status": j.last_status,
                  "last_started_at": iso(j.last_started_at), "last_finished_at": iso(j.last_finished_at),
                  "running": j.lock_owner is not None} for j in jobs],
        "executions": [execution_dict(e) for e in db.scalars(stmt.limit(100))],
        "stats": _success_rate(db, datetime.now(UTC) - timedelta(days=7)),
        "notifications": _group(db, NotificationLog.status),
        "scheduler": insights.scheduler_status(db),
        "freshness": insights.freshness(db),
        "next_runs": {j["name"]: j["next_run_at"] for j in insights.jobs_overview(db)},
    }
