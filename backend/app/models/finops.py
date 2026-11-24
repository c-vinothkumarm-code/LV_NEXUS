from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import Boolean, Date, Index, Integer, Numeric, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, utcnow

Money = Numeric(18, 6)


class BillingRecord(TimestampMixin, Base):
    __tablename__ = "billing_records"
    __table_args__ = (
        UniqueConstraint("provider", "scope_external_id", "service", "usage_date", name="uq_billing_records_key"),
        Index("ix_billing_records_date", "usage_date", "provider"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    service: Mapped[str] = mapped_column(String(255))
    usage_date: Mapped[date] = mapped_column(Date)
    billing_period_start: Mapped[date | None] = mapped_column(Date)
    billing_period_end: Mapped[date | None] = mapped_column(Date)
    cost_original: Mapped[Decimal] = mapped_column(Money)
    currency_original: Mapped[str] = mapped_column(String(3))
    cost_usd: Mapped[Decimal | None] = mapped_column(Money)
    cost_inr: Mapped[Decimal | None] = mapped_column(Money)
    conversion_rate: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    conversion_timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime)
    is_final: Mapped[bool] = mapped_column(Boolean, default=False)  # provisional until the provider finalises
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class BillingBudget(TimestampMixin, Base):
    __tablename__ = "billing_budgets"
    __table_args__ = (
        UniqueConstraint("provider", "scope_external_id", "service", "period_start", name="uq_billing_budgets_key"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    service: Mapped[str] = mapped_column(String(255), default="*")
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    amount: Mapped[Decimal] = mapped_column(Money)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    threshold_info: Mapped[int] = mapped_column(Integer, default=70)
    threshold_warning: Mapped[int] = mapped_column(Integer, default=80)
    threshold_high: Mapped[int] = mapped_column(Integer, default=90)
    threshold_exceeded: Mapped[int] = mapped_column(Integer, default=100)
    approved_by: Mapped[str | None] = mapped_column(String(255))


class BillingForecast(Base):
    __tablename__ = "billing_forecasts"
    __table_args__ = (Index("ix_billing_forecasts_scope", "provider", "scope_external_id", "period_start"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    forecast_amount: Mapped[Decimal] = mapped_column(Money)
    currency: Mapped[str] = mapped_column(String(3))
    method: Mapped[str] = mapped_column(String(64))
    generated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class BillingPeriod(TimestampMixin, Base):
    """A subscription's own billing period (Azure Pay-As-You-Go bills on the subscription's anniversary day, not the 1st).
    `source` says where the dates came from: 'provider' (Microsoft.Billing/billingPeriods) or 'calendar_month' when the
    provider does not publish periods for the agreement (MCA / EA bill by calendar month). Totals are never estimated:
    closed periods come from one Cost Management query per period, the current period from the collected daily records."""
    __tablename__ = "billing_periods"
    __table_args__ = (UniqueConstraint("provider", "scope_external_id", "name", name="uq_billing_periods_key"),
                      Index("ix_billing_periods_scope", "provider", "scope_external_id", "period_start"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(32))
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date)
    source: Mapped[str] = mapped_column(String(16), default="provider")
    invoice_ids: Mapped[list | None] = mapped_column(JSONType)
    total_original: Mapped[Decimal | None] = mapped_column(Money)
    currency: Mapped[str | None] = mapped_column(String(3))
    total_usd: Mapped[Decimal | None] = mapped_column(Money)
    total_inr: Mapped[Decimal | None] = mapped_column(Money)
    total_source: Mapped[str | None] = mapped_column(String(16))  # provider_query | daily_records
    is_final: Mapped[bool] = mapped_column(Boolean, default=False)
    total_collected_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
