"""Billing refresh job: collect -> convert currency -> idempotent upsert -> forecasts."""
from __future__ import annotations

import calendar
import logging
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import BillingForecast, BillingRecord, JobStatus, utcnow
from app.scheduler.engine import JobContext, JobResult
from app.services import reliability as rel  # noqa: E402
from app.services.scopes import check_passed, eligible_scopes

log = logging.getLogger(__name__)


def convert(cost: Decimal, currency: str, rate: float | None) -> tuple[Decimal | None, Decimal | None, Decimal | None]:
    """Returns (usd, inr, rate_used). An amount is left empty when no rate is configured - never guessed."""
    r = Decimal(str(rate)) if rate else None
    if currency == "USD":
        return cost, (cost * r if r else None), r
    if currency == "INR":
        return (cost / r if r else None), cost, r
    return None, None, None


def upsert_records(db: Session, settings: Settings, rows: list[dict]) -> tuple[int, int]:
    if not rows:
        return 0, 0
    provider = rows[0]["provider"]
    lo, hi = min(r["usage_date"] for r in rows), max(r["usage_date"] for r in rows)
    existing = {(b.scope_external_id, b.service, b.usage_date): b for b in db.scalars(select(BillingRecord).where(
        BillingRecord.provider == provider, BillingRecord.usage_date >= lo, BillingRecord.usage_date <= hi))}
    now, inserted, updated = utcnow(), 0, 0
    for r in rows:
        usd, inr, rate = convert(r["cost"], r["currency"], settings.fx_usd_inr_rate)
        key = (r["scope_external_id"], r["service"], r["usage_date"])
        rec = existing.get(key)
        if rec is None:
            rec = BillingRecord(provider=provider, scope_external_id=key[0], service=key[1], usage_date=key[2])
            db.add(rec)
            existing[key] = rec
            inserted += 1
        elif rec.is_final and not r["is_final"]:
            continue  # never replace final figures with provisional ones
        else:
            updated += 1
        rec.cost_original, rec.currency_original, rec.is_final = r["cost"], r["currency"], r["is_final"]
        rec.cost_usd, rec.cost_inr = usd, inr
        rec.conversion_rate, rec.conversion_timestamp = rate, (now if rate else None)
        rec.billing_period_start, rec.billing_period_end, rec.collected_at = r["billing_period_start"], r["billing_period_end"], now
    return inserted, updated


def refresh_forecasts(db: Session, today: date | None = None) -> int:
    """Run-rate forecast for the current calendar month per scope: month-to-date / days elapsed x days in month."""
    today = today or datetime.now(UTC).date()
    start = today.replace(day=1)
    end = start.replace(day=calendar.monthrange(start.year, start.month)[1])
    complete_days = (today - start).days  # today's data is incomplete, so it is excluded
    if complete_days < 1:
        return 0
    rows = db.execute(select(BillingRecord.provider, BillingRecord.scope_external_id, func.sum(BillingRecord.cost_usd))
                      .where(BillingRecord.usage_date >= start, BillingRecord.usage_date < today, BillingRecord.cost_usd.is_not(None))
                      .group_by(BillingRecord.provider, BillingRecord.scope_external_id)).all()
    db.execute(delete(BillingForecast).where(BillingForecast.period_start == start))
    for provider, scope, mtd in rows:
        db.add(BillingForecast(provider=provider, scope_external_id=scope, period_start=start, period_end=end, currency="USD",
                               forecast_amount=Decimal(mtd) / complete_days * end.day, method="run_rate"))
    return len(rows)


def _reason(exc: BaseException) -> str:
    kind, msg = rel.classify(exc)
    hint = rel.FIX_HINTS.get(kind)
    return f"[{kind}] {msg}" + (f" Fix: {hint}" if hint else "")


def _billing_periods(db: Session, settings: Settings, scope, summary: dict, failures: list) -> None:
    """The subscription's own billing periods with totals. A failure here is reported; the daily data already stored stays."""
    from app.services.finops import periods
    try:
        res = periods.refresh_scope(db, settings, scope.external_id)
        db.commit()
        summary.setdefault("billing_periods", {})[scope.external_id] = {k: res[k] for k in ("source", "periods", "queried")}
        queued = [g for g in res["gaps"] if "queued for the next run" in g]
        if queued:
            summary["billing_periods"][scope.external_id]["queued"] = len(queued)
        for g in res["gaps"]:
            if g not in queued:
                failures.append({"provider": "azure", "scope": scope.external_id, "name": scope.name, "reason": f"Billing period {g}"})
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log.warning("billing periods failed for %s", scope.external_id)
        failures.append({"provider": "azure", "scope": scope.external_id, "name": scope.name,
                         "reason": str(exc) if isinstance(exc, PermissionError) else f"Billing periods not refreshed (previous data kept): {_reason(exc)}"})


def run_billing_refresh(ctx: JobContext, settings: Settings, collectors: list) -> JobResult:
    db = ctx.db
    end = datetime.now(UTC).date()
    start = end - timedelta(days=settings.finops_lookback_days)
    failures, summary = [], {"inserted": 0, "updated": 0, "by_provider": {}}
    total = failed = 0
    for c in collectors:
        p = c.provider
        info = summary["by_provider"].setdefault(p, {"rows": 0})
        missing = c.missing_configuration() if hasattr(c, "missing_configuration") else []
        if missing:
            total, failed = total + 1, failed + 1
            failures.append({"provider": p, "scope": "*", "reason": f"Billing not configured: missing {', '.join(missing)}"})
            continue
        targets = eligible_scopes(db, p) if c.per_scope else [None]
        for scope in targets:
            total += 1
            label = scope.external_id if scope is not None else "*"
            if scope is not None and not check_passed(scope, "billing"):
                failed += 1
                failures.append({"provider": p, "scope": label, "name": scope.name, "reason": "Billing access not validated (see onboarding checks)"})
                continue
            _skip = rel.scope_gate(p)
            if _skip:
                failed += 1
                failures.append({"provider": p, "scope": label, "reason": _skip})
                continue
            try:
                rows = list(c.collect(scope, start, end) if c.per_scope else c.collect(start, end))
                ins, upd = upsert_records(db, settings, rows)
                db.commit()
                rel.scope_ok(p)
                info["rows"] += len(rows)
                summary["inserted"] += ins
                summary["updated"] += upd
                if p == "azure" and scope is not None:
                    _billing_periods(db, settings, scope, summary, failures)
                unconverted = {r["currency"] for r in rows if r["currency"] not in ("USD", "INR")}
                if unconverted:
                    failures.append({"provider": p, "scope": label, "reason": f"No conversion for currency {', '.join(sorted(unconverted))}; stored in original currency only"})
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                log.exception("billing collection failed for %s %s", p, label)
                failed += 1
                failures.append({"provider": p, "scope": label, "name": getattr(scope, "name", None), "reason": rel.scope_failed(p, exc)})
    summary["forecasts"] = refresh_forecasts(db)
    summary["fx_usd_inr_rate_configured"] = bool(settings.fx_usd_inr_rate)
    db.commit()
    if total == 0:
        failures.append({"provider": "*", "scope": "*", "reason": "No cloud provider is enabled or no onboarded scopes"})
        return JobResult(JobStatus.FAILED, 0, 0, summary, failures)
    status = JobStatus.SUCCESS if not failures else JobStatus.FAILED if failed == total else JobStatus.PARTIAL
    return JobResult(status, total, failed, summary, failures)
