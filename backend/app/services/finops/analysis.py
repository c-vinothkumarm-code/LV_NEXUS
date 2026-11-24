"""FinOps calculations over stored billing records (USD). Used by the dashboard, reports and Sheets."""
from __future__ import annotations

import statistics
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import BillingBudget, BillingForecast, BillingRecord

from .collectors import month_bounds

LEVELS = (("exceeded", "Budget Exceeded"), ("high", "High Warning"), ("warning", "Warning"), ("info", "Information"))


def _today() -> date:
    return datetime.now(UTC).date()


def _sum(db: Session, *where, group=None):
    cols = (group, func.sum(BillingRecord.cost_usd)) if group is not None else (func.sum(BillingRecord.cost_usd),)
    stmt = select(*cols).where(*where)
    if group is not None:
        return {k: float(v or 0) for k, v in db.execute(stmt.group_by(group)).all()}
    return float(db.scalar(stmt) or 0)


def current_period_filter(today: date | None = None):
    """AWS and GCP bill by calendar month. Azure uses each subscription's own billing period where the
    provider reported it, falling back to the calendar month only when it did not."""
    today = today or _today()
    month_start = today.replace(day=1)
    calendar_month = BillingRecord.usage_date >= month_start
    azure_period = and_(BillingRecord.billing_period_start.is_not(None), BillingRecord.billing_period_start >= today - timedelta(days=45),
                        BillingRecord.usage_date >= BillingRecord.billing_period_start)
    return or_(and_(BillingRecord.provider != "azure", calendar_month),
               and_(BillingRecord.provider == "azure", or_(azure_period, and_(BillingRecord.billing_period_start.is_(None), calendar_month))))


def daily_summary(db: Session, today: date | None = None) -> dict:
    today = today or _today()
    y, d2 = today - timedelta(days=1), today - timedelta(days=2)
    prev, before = _sum(db, BillingRecord.usage_date == y, group=BillingRecord.provider), _sum(db, BillingRecord.usage_date == d2, group=BillingRecord.provider)
    return {"date": y.isoformat(), "previous_day": prev, "day_before": before,
            "change": {p: round(prev.get(p, 0) - before.get(p, 0), 2) for p in set(prev) | set(before)},
            "period_to_date": _sum(db, current_period_filter(today), group=BillingRecord.provider)}


def weekly_summary(db: Session, today: date | None = None) -> dict:
    today = today or _today()
    this_start = today - timedelta(days=7)
    last_start = this_start - timedelta(days=7)
    cur = lambda g=None: _sum(db, BillingRecord.usage_date >= this_start, BillingRecord.usage_date < today, group=g)  # noqa: E731
    prv = lambda g=None: _sum(db, BillingRecord.usage_date >= last_start, BillingRecord.usage_date < this_start, group=g)  # noqa: E731
    c, p = cur(), prv()
    cs, ps = cur(BillingRecord.service), prv(BillingRecord.service)
    risers = sorted(({"service": s, "increase_usd": round(cs[s] - ps.get(s, 0), 2), "new": s not in ps} for s in cs if cs[s] - ps.get(s, 0) > 0),
                    key=lambda r: -r["increase_usd"])[:10]
    return {"week": {"from": this_start.isoformat(), "to": (today - timedelta(days=1)).isoformat()}, "current_week": round(c, 2),
            "previous_week": round(p, 2), "variation_percent": round(100 * (c - p) / p, 1) if p else None,
            "by_provider": cur(BillingRecord.provider), "top_increasing_services": risers}


def monthly_summary(db: Session, month: date | None = None) -> dict:
    start, end = month_bounds(month or (_today().replace(day=1) - timedelta(days=1)))
    pstart, pend = month_bounds(start - timedelta(days=1))
    rng = (BillingRecord.usage_date >= start, BillingRecord.usage_date <= end)
    total, prev = _sum(db, *rng), _sum(db, BillingRecord.usage_date >= pstart, BillingRecord.usage_date <= pend)
    provisional = db.scalar(select(func.count()).select_from(BillingRecord).where(*rng, BillingRecord.is_final.is_(False)))
    budget = float(db.scalar(select(func.sum(BillingBudget.amount)).where(BillingBudget.period_start <= end, BillingBudget.period_end >= start,
                                                                         BillingBudget.service == "*", BillingBudget.currency == "USD")) or 0)
    forecast = float(db.scalar(select(func.sum(BillingForecast.forecast_amount)).where(BillingForecast.period_start == start)) or 0)
    return {"month": start.strftime("%Y-%m"), "total_actual": round(total, 2), "is_final": provisional == 0 and total > 0,
            "previous_month": round(prev, 2), "mom_variation_percent": round(100 * (total - prev) / prev, 1) if prev else None,
            "approved_budget": budget or None, "budget_variance": round(budget - total, 2) if budget else None,
            "forecast": round(forecast, 2) if forecast else None,
            "by_provider": _sum(db, *rng, group=BillingRecord.provider), "by_scope": _sum(db, *rng, group=BillingRecord.scope_external_id),
            "by_service": _sum(db, *rng, group=BillingRecord.service)}


def budget_status(db: Session, today: date | None = None) -> list[dict]:
    """Utilisation of every budget active today, with the threshold level it has reached."""
    today = today or _today()
    out = []
    for b in db.scalars(select(BillingBudget).where(BillingBudget.period_start <= today, BillingBudget.period_end >= today)):
        col = BillingRecord.cost_inr if b.currency == "INR" else BillingRecord.cost_usd
        where = [BillingRecord.provider == b.provider, BillingRecord.usage_date >= b.period_start, BillingRecord.usage_date <= b.period_end]
        if b.scope_external_id != "*":
            where.append(BillingRecord.scope_external_id == b.scope_external_id)
        if b.service != "*":
            where.append(BillingRecord.service == b.service)
        actual = float(db.scalar(select(func.sum(col)).where(*where)) or 0)
        amount = float(b.amount)
        pct = round(100 * actual / amount, 1) if amount else None
        thresholds = {"exceeded": b.threshold_exceeded, "high": b.threshold_high, "warning": b.threshold_warning, "info": b.threshold_info}
        level = next(((k, label) for k, label in LEVELS if pct is not None and pct >= thresholds[k]), (None, "Within budget"))
        fc = None
        if b.scope_external_id != "*" and b.service == "*" and b.currency == "USD":
            fc = db.scalar(select(BillingForecast.forecast_amount).where(BillingForecast.provider == b.provider,
                           BillingForecast.scope_external_id == b.scope_external_id, BillingForecast.period_start == b.period_start))
        out.append({"id": b.id, "provider": b.provider, "scope": b.scope_external_id, "service": b.service, "currency": b.currency,
                    "period_start": b.period_start.isoformat(), "period_end": b.period_end.isoformat(), "approved": amount,
                    "actual": round(actual, 2), "utilisation_percent": pct, "remaining": round(amount - actual, 2),
                    "level": level[0], "level_label": level[1], "forecast": float(fc) if fc is not None else None})
    return sorted(out, key=lambda r: -(r["utilisation_percent"] or 0))


def anomalies(db: Session, settings: Settings, today: date | None = None, window: int = 14) -> list[dict]:
    """A scope's latest complete day is abnormal when it exceeds its trailing mean by N standard deviations
    and by a minimum absolute amount. Needs at least 7 days of history; otherwise nothing is reported."""
    today = today or _today()
    last = today - timedelta(days=1)
    rows = db.execute(select(BillingRecord.provider, BillingRecord.scope_external_id, BillingRecord.usage_date, func.sum(BillingRecord.cost_usd))
                      .where(BillingRecord.usage_date >= last - timedelta(days=window), BillingRecord.usage_date <= last)
                      .group_by(BillingRecord.provider, BillingRecord.scope_external_id, BillingRecord.usage_date)).all()
    series: dict[tuple, dict[date, float]] = {}
    for p, s, d, c in rows:
        series.setdefault((p, s), {})[d] = float(c or 0)
    out = []
    for (p, s), days in series.items():
        history = [v for d, v in days.items() if d < last]
        if last not in days or len(history) < 7:
            continue
        mean, sd = statistics.fmean(history), statistics.pstdev(history)
        value = days[last]
        if value - mean >= settings.finops_anomaly_min_usd and value > mean + settings.finops_anomaly_sigma * max(sd, 0.01 * mean):
            out.append({"provider": p, "scope": s, "date": last.isoformat(), "cost_usd": round(value, 2), "baseline_mean_usd": round(mean, 2),
                        "increase_percent": round(100 * (value - mean) / mean, 1) if mean else None})
    return sorted(out, key=lambda r: -(r["cost_usd"] - r["baseline_mean_usd"]))
