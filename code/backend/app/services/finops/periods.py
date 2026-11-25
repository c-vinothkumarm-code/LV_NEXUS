"""Per-subscription billing periods and their totals (Azure).

Azure Pay-As-You-Go subscriptions bill on the subscription's own cycle (for example the 5th to the 4th), so a calendar
month is the wrong unit for "this billing period". This module reads the real periods from
Microsoft.Billing/billingPeriods (read-only, covered by the Reader role) and attaches a total to each one:

- closed periods: one Cost Management query per period (granularity None), stored and not queried again once final;
- the current period: summed from the daily billing records already collected (no extra cost query).

When Azure does not publish billing periods for the subscription's agreement (MCA / EA bill by calendar month) the
calendar month is used and labelled as such. Nothing is estimated: a total that could not be read stays empty."""
from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import BillingPeriod, BillingRecord, utcnow
from app.services.finops.collectors import month_bounds

log = logging.getLogger(__name__)
ARM = "https://management.azure.com"
PERIODS_API = "2018-03-01-preview"
COST_API = "2025-03-01"
CALENDAR_NOTE = ("Azure does not publish billing periods for this subscription's agreement (typical for Microsoft Customer "
                 "Agreement and Enterprise Agreement, which bill by calendar month); calendar months are shown.")


def _d(value) -> date:
    return date.fromisoformat(str(value)[:10])


def _status(exc: Exception) -> int | None:
    return getattr(exc, "status", None)


class AzureBillingPeriods:
    def __init__(self, settings: Settings, rest=None):
        from app.services.azure.rest import AzureRest
        self.settings, self.rest = settings, rest or AzureRest(settings)

    def list(self, sub: str) -> list[dict]:
        """[{name, start, end, invoice_ids}] newest first. Raises on failure (caller decides on the calendar fallback)."""
        url = f"{ARM}/subscriptions/{sub}/providers/Microsoft.Billing/billingPeriods"
        out = []
        for it in self.rest.pages(url, {"api-version": PERIODS_API}):
            p = it.get("properties") or {}
            if p.get("billingPeriodStartDate") and p.get("billingPeriodEndDate"):
                out.append({"name": str(it.get("name") or p["billingPeriodStartDate"])[:32], "start": _d(p["billingPeriodStartDate"]),
                            "end": _d(p["billingPeriodEndDate"]), "invoice_ids": [str(i).rsplit("/", 1)[-1] for i in (p.get("invoiceIds") or [])]})
        return sorted(out, key=lambda r: r["start"], reverse=True)

    def total(self, sub: str, start: date, end: date) -> tuple[Decimal, str | None]:
        """Actual cost for [start, end] in the billing currency, as Azure reports it."""
        body = {"type": "ActualCost", "timeframe": "Custom",
                "timePeriod": {"from": f"{start.isoformat()}T00:00:00Z", "to": f"{end.isoformat()}T23:59:59Z"},
                "dataset": {"granularity": "None", "aggregation": {"totalCost": {"name": "Cost", "function": "Sum"}}}}
        data = self.rest.request("POST", f"{ARM}/subscriptions/{sub}/providers/Microsoft.CostManagement/query",
                                 params={"api-version": COST_API}, json=body)
        props = data.get("properties") or {}
        cols = [c.get("name") for c in props.get("columns") or []]
        total, currency = Decimal("0"), None
        for row in props.get("rows") or []:
            r = dict(zip(cols, row, strict=False))
            total += Decimal(str(r.get("Cost", r.get("PreTaxCost", 0)) or 0))
            currency = currency or r.get("Currency")
        return total, (currency or None) and str(currency).upper()[:3]


def calendar_periods(today: date, count: int) -> list[dict]:
    out, d = [], today
    for _ in range(count):
        s, e = month_bounds(d)
        out.append({"name": s.strftime("%Y%m"), "start": s, "end": e, "invoice_ids": []})
        d = s - timedelta(days=1)
    return out


def _convert(db_settings: Settings, amount: Decimal | None, currency: str | None):
    from app.services.finops.engine import convert
    if amount is None or not currency:
        return None, None
    usd, inr, _ = convert(amount, currency, db_settings.fx_usd_inr_rate)
    return usd, inr


def refresh_scope(db: Session, settings: Settings, sub: str, client: AzureBillingPeriods | None = None,
                  today: date | None = None, max_queries: int | None = None) -> dict:
    """Store the current and the last N billing periods of one subscription with their totals.
    Returns {"source", "periods", "queried", "gaps": [reason, ...]}. Raises only when the subscription cannot be read at all."""
    today = today or datetime.now(UTC).date()
    client = client or AzureBillingPeriods(settings)
    keep = max(1, settings.billing_periods_history) + 1
    gaps: list[str] = []
    try:
        listed = [p for p in client.list(sub) if p["start"] <= today][:keep]
        source = "provider"
        if not listed:
            listed, source = calendar_periods(today, keep), "calendar_month"
    except Exception as exc:  # noqa: BLE001 - classified below
        status = _status(exc)
        if status in (400, 404, 405):  # not offered for this agreement type
            listed, source = calendar_periods(today, keep), "calendar_month"
        elif status in (401, 403):
            raise PermissionError("billing periods unavailable – missing permission: Microsoft.Billing/billingPeriods/read "
                                  "(Reader on the subscription)") from exc
        else:
            raise
    now = utcnow()
    existing = {p.name: p for p in db.scalars(select(BillingPeriod).where(BillingPeriod.provider == "azure", BillingPeriod.scope_external_id == sub))}
    budget = settings.billing_periods_history if max_queries is None else max_queries
    queried = 0
    for p in listed:
        row = existing.get(p["name"])
        if row is None:
            row = BillingPeriod(provider="azure", scope_external_id=sub, name=p["name"], is_final=False)
            db.add(row)
        row.period_start, row.period_end, row.source, row.last_seen_at = p["start"], p["end"], source, now
        row.invoice_ids = p["invoice_ids"] or None
        current = p["start"] <= today <= p["end"]
        if current:
            amount, currency = _daily_total(db, sub, p["start"], min(p["end"], today))
            row.total_original, row.currency, row.total_source, row.is_final = amount, currency, "daily_records", False
            row.total_usd, row.total_inr = _daily_converted(db, sub, p["start"], min(p["end"], today))
            row.total_collected_at = now
        elif not (row.is_final and row.total_original is not None and row.total_source == "provider_query"):
            if queried >= budget:
                gaps.append(f"{p['name']}: total queued for the next run (Cost Management allows few queries per minute)")
                continue
            try:
                amount, currency = client.total(sub, p["start"], p["end"])
                queried += 1
            except Exception as exc:  # noqa: BLE001 - one period failing must not hide the others
                queried += 1
                gaps.append(f"{p['name']}: total not read – {str(exc)[:160]}")
                continue
            row.total_original, row.currency, row.total_source = amount, currency, "provider_query"
            row.total_usd, row.total_inr = _convert(settings, amount, currency)
            row.is_final = today > p["end"] + timedelta(days=settings.finops_final_after_days)
            row.total_collected_at = now
        # Stamp the period on the daily records it covers so every cost view agrees on the boundaries.
        db.execute(update(BillingRecord).where(BillingRecord.provider == "azure", BillingRecord.scope_external_id == sub,
                                               BillingRecord.usage_date.between(p["start"], p["end"]))
                   .values(billing_period_start=p["start"], billing_period_end=p["end"]))
    db.flush()
    return {"source": source, "periods": len(listed), "queried": queried, "gaps": gaps}


def _daily_total(db: Session, sub: str, start: date, end: date) -> tuple[Decimal | None, str | None]:
    rows = db.execute(select(BillingRecord.currency_original, func.sum(BillingRecord.cost_original))
                      .where(BillingRecord.provider == "azure", BillingRecord.scope_external_id == sub,
                             BillingRecord.usage_date.between(start, end)).group_by(BillingRecord.currency_original)).all()
    if len(rows) != 1:  # none collected, or mixed currencies (shown in USD only)
        return None, None
    return Decimal(rows[0][1] or 0), rows[0][0]


def _daily_converted(db: Session, sub: str, start: date, end: date):
    """A converted total is shown only when every record in the range has a converted amount (no partial sums)."""
    usd, inr, n, n_usd, n_inr = db.execute(select(func.sum(BillingRecord.cost_usd), func.sum(BillingRecord.cost_inr), func.count(BillingRecord.id),
                                                  func.count(BillingRecord.cost_usd), func.count(BillingRecord.cost_inr))
                                           .where(BillingRecord.provider == "azure", BillingRecord.scope_external_id == sub,
                                                  BillingRecord.usage_date.between(start, end))).one()
    if not n:
        return None, None
    return (Decimal(usd) if n_usd == n else None, Decimal(inr) if n_inr == n else None)


def current_period(db: Session, sub: str, today: date | None = None) -> BillingPeriod | None:
    today = today or datetime.now(UTC).date()
    return db.scalar(select(BillingPeriod).where(BillingPeriod.provider == "azure", BillingPeriod.scope_external_id == sub,
                                                 BillingPeriod.period_start <= today, BillingPeriod.period_end >= today))
