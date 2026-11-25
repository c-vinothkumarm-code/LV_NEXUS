"""Unified Cloud Cost Intelligence: one explorer across AWS, Azure and GCP with period selection, drilldown
(provider -> account / subscription / project -> service), the underlying billing records, and optimisation candidates.

Cost definitions are disclosed per provider. Today is partial and is excluded from complete-day figures. Missing
billing data is reported as not collected, never as zero. Optimisation candidates are recommendations only."""
from __future__ import annotations

import calendar
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.serializers import iso
from app.core.config import Settings, get_settings
from app.core.security import require
from app.database.session import get_db
from app.models import SCOPE_MODELS, BillingForecast, BillingRecord, CloudResource, User, VMInventory, VMMetric
from app.services.finops import analysis

router = APIRouter(prefix="/api/v1/cost", tags=["cloud cost intelligence"])
DEFINITIONS = {
    "aws": "AWS Cost Explorer UnblendedCost (actual, before Savings Plans / RI amortisation), per linked account and service.",
    "azure": "Azure Cost Management ActualCost (pre-tax), per subscription and service; Azure months follow each subscription's billing period.",
    "gcp": "Cloud Billing BigQuery export: cost net of credits, per project and service, by usage date (UTC).",
    "usd": "Amounts are converted to USD at collection with the rate and timestamp stored on each record.",
    "not_available": "Amortized cost, taxes and separate credit lines are not collected yet and are not mixed into these figures.",
}
PERIODS = ("daily", "weekly", "monthly", "quarterly", "yearly", "custom")


def period_range(period: str, start: date | None, end: date | None, today: date | None = None) -> tuple[date, date]:
    today = today or datetime.now(UTC).date()
    if period == "custom":
        if not start or not end or end < start:
            raise HTTPException(422, "A custom period needs a start and an end date")
        return start, end
    if period == "daily":
        return today - timedelta(days=30), today
    if period == "weekly":
        s = today - timedelta(days=today.weekday())
        return s - timedelta(weeks=11), today
    if period == "monthly":
        return today.replace(day=1), today
    if period == "quarterly":
        q = (today.month - 1) // 3 * 3 + 1
        return today.replace(month=q, day=1), today
    if period == "yearly":
        return today.replace(month=1, day=1), today
    raise HTTPException(422, f"period must be one of {', '.join(PERIODS)}")


def _where(provider, scope, service, start, end):
    w = [BillingRecord.usage_date >= start, BillingRecord.usage_date <= end, BillingRecord.cost_usd.is_not(None)]
    if provider:
        w.append(BillingRecord.provider == provider)
    if scope:
        w.append(BillingRecord.scope_external_id == scope)
    if service:
        w.append(BillingRecord.service == service)
    return w


@router.get("/explorer")
def explorer(period: str = "monthly", start: date | None = None, end: date | None = None, provider: str | None = None, scope: str | None = None,
             service: str | None = None, db: Session = Depends(get_db), _: User = Depends(require("finops:read"))):
    s, e = period_range(period, start, end)
    today = datetime.now(UTC).date()
    w = _where(provider, scope, service, s, e)
    count, total, provisional = db.execute(select(func.count(), func.sum(BillingRecord.cost_usd),
                                                  func.sum(func.cast(BillingRecord.is_final.is_(False), BillingRecord.id.type))).where(*w)).one()
    names = {(p, x.external_id): x.name or x.external_id for p, m in SCOPE_MODELS.items() for x in db.scalars(select(m))}
    envs = {(p, x.external_id): x.environment or "Not labelled" for p, m in SCOPE_MODELS.items() for x in db.scalars(select(m))}

    def group(*cols):
        return db.execute(select(*cols, func.sum(BillingRecord.cost_usd)).where(*w).group_by(*cols).order_by(func.sum(BillingRecord.cost_usd).desc())).all()

    by_scope = [{"provider": p, "scope": sc, "name": names.get((p, sc), sc), "environment": envs.get((p, sc), "Not labelled"), "cost_usd": float(c or 0)}
                for p, sc, c in group(BillingRecord.provider, BillingRecord.scope_external_id)]
    by_env = defaultdict(float)
    for r in by_scope:
        by_env[r["environment"]] += r["cost_usd"]
    daily = defaultdict(lambda: defaultdict(float))
    for d, p, c in db.execute(select(BillingRecord.usage_date, BillingRecord.provider, func.sum(BillingRecord.cost_usd)).where(*w)
                              .group_by(BillingRecord.usage_date, BillingRecord.provider)):
        daily[d.isoformat()][p] = float(c or 0)
    month_start = today.replace(day=1)
    fc = db.scalar(select(func.sum(BillingForecast.forecast_amount)).where(BillingForecast.period_start == month_start,
                                                                           *([BillingForecast.provider == provider] if provider else []),
                                                                           *([BillingForecast.scope_external_id == scope] if scope else [])))
    prev_end = month_start - timedelta(days=1)
    prev = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(*_where(provider, scope, service, prev_end.replace(day=1), prev_end)))
    ytd = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(*_where(provider, scope, service, today.replace(month=1, day=1), today)))
    mtd = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(*_where(provider, scope, service, month_start, today)))
    complete = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(*_where(provider, scope, service, s, min(e, today - timedelta(days=1)))))
    return {"period": period, "start": s.isoformat(), "end": e.isoformat(), "collected": bool(count),
            "total_usd": float(total) if count else None, "complete_days_usd": float(complete) if complete is not None else None,
            "includes_today_partial": e >= today, "provisional_records": int(provisional or 0), "records": int(count or 0),
            "month_to_date_usd": float(mtd) if mtd is not None else None, "previous_month_usd": float(prev) if prev is not None else None,
            "year_to_date_usd": float(ytd) if ytd is not None else None, "forecast_month_usd": float(fc) if fc is not None else None,
            "forecast_note": "Provider-reported or run-rate forecast as collected by billing_refresh (estimate).",
            "by_provider": [{"provider": p, "cost_usd": float(c or 0)} for p, c in group(BillingRecord.provider)],
            "by_scope": by_scope[:50], "by_service": [{"service": sv, "cost_usd": float(c or 0)} for sv, c in group(BillingRecord.service)][:50],
            "by_environment": [{"environment": k, "cost_usd": v} for k, v in sorted(by_env.items(), key=lambda kv: -kv[1])],
            "daily": [{"date": d, **v} for d, v in sorted(daily.items())],
            "not_available": {"by_region": "Region is not collected on billing records yet.", "by_resource": "Resource-level cost is not collected yet."},
            "definitions": DEFINITIONS,
            "calculation": "Sum of cost_usd over the billing records matching the filters and the period (usage date, inclusive). Each record is one "
                           "provider x scope x service x day, so totals across providers, scopes and services do not double count."}


@router.get("/records")
def records(period: str = "monthly", start: date | None = None, end: date | None = None, provider: str | None = None, scope: str | None = None,
            service: str | None = None, page: int = Query(1, ge=1), size: int = Query(100, ge=1, le=500),
            db: Session = Depends(get_db), _: User = Depends(require("finops:read"))):
    """The billing records behind a figure, so every total can be checked."""
    s, e = period_range(period, start, end)
    stmt = select(BillingRecord).where(*_where(provider, scope, service, s, e))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(BillingRecord.usage_date.desc(), BillingRecord.provider, BillingRecord.scope_external_id)
                      .offset((page - 1) * size).limit(size))
    return {"total": total, "items": [{"provider": r.provider, "scope": r.scope_external_id, "service": r.service, "usage_date": r.usage_date.isoformat(),
                                       "cost_original": float(r.cost_original), "currency_original": r.currency_original,
                                       "cost_usd": float(r.cost_usd) if r.cost_usd is not None else None,
                                       "conversion_rate": float(r.conversion_rate) if r.conversion_rate is not None else None,
                                       "is_final": r.is_final, "collected_at": iso(r.collected_at)} for r in rows]}


@router.get("/optimization")
def optimization(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), _: User = Depends(require("finops:read"))):
    """Recommendations with evidence and confidence. Nothing is changed; any action needs separate human approval."""
    now = datetime.now(UTC)
    out = []
    since = now - timedelta(days=7)
    for v in db.scalars(select(VMInventory).where(VMInventory.deleted_at.is_(None))):
        state = (v.power_state or "").lower()
        if state == "running":
            samples = [m.cpu_percent for m in db.scalars(select(VMMetric).where(VMMetric.vm_id == v.id, VMMetric.collected_at >= since,
                                                                                 VMMetric.cpu_percent.is_not(None)))]
            if len(samples) >= 12:
                avg, peak = sum(samples) / len(samples), max(samples)
                if peak < 10:
                    kind, title = ("idle_vm", "Idle VM") if avg < 3 else ("underutilized_vm", "Underutilized VM")
                    out.append({"type": kind, "title": f"{title}: {v.name}", "provider": v.provider, "scope": v.scope_external_id,
                                "resource": v.instance_id, "evidence": f"Average CPU {avg:.1f}%, peak {peak:.1f}% over {len(samples)} samples in 7 days; size {v.instance_type or 'not collected'}",
                                "confidence": "High" if len(samples) >= 100 else "Medium", "estimated_savings_usd": None,
                                "savings_note": "Not estimated: resource-level cost is not collected.",
                                "recommended_action": "Confirm with the owner, then stop, schedule or resize through change approval."})
        elif state in ("stopped", "deallocated", "terminated") and v.public_ip:
            out.append({"type": "unused_public_ip", "title": f"Public IP held by a stopped VM: {v.name}", "provider": v.provider, "scope": v.scope_external_id,
                        "resource": v.instance_id, "evidence": f"Power state {v.power_state}; public IP {v.public_ip}", "confidence": "Medium",
                        "estimated_savings_usd": None, "savings_note": "Not estimated: resource-level cost is not collected.",
                        "recommended_action": "Release the address if it is not needed (through change approval)."})
    for r in db.scalars(select(CloudResource).where(CloudResource.provider == "azure", CloudResource.not_deleted(),
                                                    func.lower(CloudResource.resource_type) == "microsoft.compute/disks")):
        if (r.attributes or {}).get("managed_by") is None and "managed_by" in (r.attributes or {}):
            out.append({"type": "unattached_disk", "title": f"Unattached disk: {r.name}", "provider": "azure", "scope": r.scope_external_id,
                        "resource": r.resource_id, "evidence": "Disk has no managing VM", "confidence": "High", "estimated_savings_usd": None,
                        "savings_note": "Not estimated: resource-level cost is not collected.", "recommended_action": "Snapshot if needed, then delete through change approval."})
    for a in analysis.anomalies(db, settings):
        out.append({"type": "cost_anomaly", "title": f"Unusual cost increase: {a.get('provider', '').upper()} {a.get('scope')}", "provider": a.get("provider"),
                    "scope": a.get("scope"), "resource": None,
                    "evidence": f"{a.get('date')}: {a.get('cost_usd'):,.2f} USD against a {a.get('baseline_mean_usd'):,.2f} USD daily baseline",
                    "confidence": "Medium", "estimated_savings_usd": None, "savings_note": "Investigate the cost driver first.",
                    "recommended_action": "Review the services that changed in the cost explorer and confirm the increase is expected."})
    month = now.date().replace(day=1)
    top = db.execute(select(BillingRecord.service, func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date >= month)
                     .group_by(BillingRecord.service).order_by(func.sum(BillingRecord.cost_usd).desc()).limit(3)).all()
    for sv, c in top:
        out.append({"type": "expensive_service", "title": f"Top cost driver this month: {sv}", "provider": None, "scope": None, "resource": None,
                    "evidence": f"{float(c or 0):,.2f} USD month to date", "confidence": "High", "estimated_savings_usd": None,
                    "savings_note": "Review for commitments (Savings Plans, reservations) or rightsizing.",
                    "recommended_action": "Review usage with the service owners."})
    return {"items": out, "not_detected": ["Unattached disks need disk attachment data (collected for Azure disks only when the inventory provides it)",
                                           "Unused load balancers and oversized resources need resource-level metrics and cost (not collected yet)"],
            "note": "Recommendations only. LV NEXUS does not stop, resize or delete anything; every action needs human approval.",
            "days_in_month": calendar.monthrange(now.year, now.month)[1]}
