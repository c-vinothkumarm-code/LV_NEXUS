"""Cost detail, provider budgets, the tamper-evident central audit trail, structured AI analyses and management decisions."""
from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import Boolean, Date, Index, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, make_immutable, utcnow

Money = Numeric(18, 6)


class CostDetailRecord(TimestampMixin, Base):
    """Detailed daily cost with region, resource group, resource, SKU, usage type and allocation tags.

    `breakdown` names the provider query the row came from, because providers limit how many dimensions one query can
    group by: rows of different breakdowns are never summed together (the API filters on one breakdown at a time)."""
    __tablename__ = "cost_detail_records"
    __table_args__ = (UniqueConstraint("row_hash", name="uq_cost_detail_row"),
                      Index("ix_cost_detail_date", "usage_date", "provider", "breakdown"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    row_hash: Mapped[str] = mapped_column(String(64))
    provider: Mapped[str] = mapped_column(String(16))
    breakdown: Mapped[str] = mapped_column(String(24))   # resource | service_region | usage_type | sku
    cost_type: Mapped[str] = mapped_column(String(12), default="actual")  # actual | amortized
    billing_account: Mapped[str | None] = mapped_column(String(128))
    scope_external_id: Mapped[str] = mapped_column(String(128), index=True)
    billing_period: Mapped[str | None] = mapped_column(String(16))  # e.g. 2026-11 (calendar) or provider invoice month
    usage_date: Mapped[date] = mapped_column(Date)
    currency: Mapped[str] = mapped_column(String(3))
    amount: Mapped[Decimal] = mapped_column(Money)
    amount_usd: Mapped[Decimal | None] = mapped_column(Money)
    credits: Mapped[Decimal | None] = mapped_column(Money)     # GCP credits (negative), included in amount
    service: Mapped[str | None] = mapped_column(String(255))
    region: Mapped[str | None] = mapped_column(String(64))
    resource_group: Mapped[str | None] = mapped_column(String(255))
    resource_id: Mapped[str | None] = mapped_column(Text)
    resource_name: Mapped[str | None] = mapped_column(String(512))
    resource_type: Mapped[str | None] = mapped_column(String(255))
    sku: Mapped[str | None] = mapped_column(String(255))
    usage_type: Mapped[str | None] = mapped_column(String(255))
    tags: Mapped[dict] = mapped_column(JSONType, default=dict)  # environment / cost_center / business_entity when tagged
    is_final: Mapped[bool] = mapped_column(Boolean, default=False)
    provider_refreshed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class ProviderBudget(TimestampMixin, Base):
    """Budget configured in the provider (AWS Budgets, Azure Consumption budgets). Alert configuration only: it is never an
    approved business budget (those live in cloud_budgets)."""
    __tablename__ = "provider_budgets"
    __table_args__ = (UniqueConstraint("provider", "native_id", name="uq_provider_budget"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    native_id: Mapped[str] = mapped_column(String(512))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    name: Mapped[str] = mapped_column(String(255))
    time_grain: Mapped[str | None] = mapped_column(String(24))
    amount: Mapped[Decimal] = mapped_column(Money)
    currency: Mapped[str] = mapped_column(String(3))
    current_spend: Mapped[Decimal | None] = mapped_column(Money)
    forecast_spend: Mapped[Decimal | None] = mapped_column(Money)
    period_start: Mapped[date | None] = mapped_column(Date)
    period_end: Mapped[date | None] = mapped_column(Date)
    thresholds: Mapped[list] = mapped_column(JSONType, default=list)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AuditTrail(Base):
    """Central append-only audit trail. Each row carries the SHA-256 of the previous row (hash chain), so a deleted or
    altered row breaks verification. Database triggers additionally block UPDATE and DELETE."""
    __tablename__ = "audit_trail"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_id: Mapped[str] = mapped_column(String(36), unique=True)
    category: Mapped[str] = mapped_column(String(32), index=True)  # platform | identity | access | revocation | budget | cost | security | automation | configuration
    provider: Mapped[str | None] = mapped_column(String(16))
    scope: Mapped[str | None] = mapped_column(String(512))
    actor: Mapped[str] = mapped_column(String(512), index=True)
    action: Mapped[str] = mapped_column(String(96), index=True)
    target: Mapped[str | None] = mapped_column(String(512))
    previous_state: Mapped[dict | None] = mapped_column(JSONType)
    new_state: Mapped[dict | None] = mapped_column(JSONType)
    approval_reference: Mapped[str | None] = mapped_column(String(64))
    execution_result: Mapped[str | None] = mapped_column(String(32))
    verification_result: Mapped[str | None] = mapped_column(String(32))
    evidence_reference: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64))


class AIAnalysisResult(Base):
    """Structured AI (or rule-template) assessment of an activity event, identity change, finding or cost anomaly.
    Always labelled as an assessment: it never changes the underlying record."""
    __tablename__ = "ai_analysis_results"
    __table_args__ = (Index("ix_ai_analysis_subject", "subject_type", "subject_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(32))  # activity_event | identity_change | finding | cost_anomaly
    subject_id: Mapped[str] = mapped_column(String(64))
    summary: Mapped[str] = mapped_column(Text)
    evidence: Mapped[list] = mapped_column(JSONType, default=list)
    risk: Mapped[str] = mapped_column(String(16))
    business_impact: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(16))
    recommended_action: Mapped[str | None] = mapped_column(Text)
    supporting_event_ids: Mapped[list] = mapped_column(JSONType, default=list)
    affected_resources: Mapped[list] = mapped_column(JSONType, default=list)
    human_approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    generated_by: Mapped[str] = mapped_column(String(64))  # model name or "rule template"
    requested_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class ManagementDecision(TimestampMixin, Base):
    """An executive decision item raised from a risk, with an accountable owner and a due date."""
    __tablename__ = "management_decisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    decision_key: Mapped[str] = mapped_column(String(32), unique=True)
    title: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(64))       # e.g. finding:123, iam_exception:5, budget:7
    risk_summary: Mapped[str] = mapped_column(Text)
    business_impact: Mapped[str] = mapped_column(Text)
    recommended_action: Mapped[str] = mapped_column(Text)
    priority: Mapped[str] = mapped_column(String(16))
    owner: Mapped[str] = mapped_column(String(255))
    due_date: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(24), default="OPEN", index=True)  # OPEN | DECIDED | DEFERRED | CLOSED
    decision: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_by: Mapped[str] = mapped_column(String(255))


for _m in (AuditTrail, AIAnalysisResult):
    make_immutable(_m)


class AuditAnomaly(TimestampMixin, Base):
    """Unusual activity found by comparing new audit events with each principal's own recent history (read-only
    detection: acknowledging an anomaly records a human decision, it never changes anything in a cloud)."""
    __tablename__ = "audit_anomalies"
    __table_args__ = (UniqueConstraint("dedupe_key", name="uq_audit_anomaly_key"), Index("ix_audit_anomaly_seen", "last_event_at"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(64))
    rule: Mapped[str] = mapped_column(String(32), index=True)  # new_source_ip | new_country | unusual_hours | failure_spike | privilege_change | mass_deletion
    severity: Mapped[str] = mapped_column(String(16), index=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    principal: Mapped[str | None] = mapped_column(String(512), index=True)
    title: Mapped[str] = mapped_column(String(512))
    detail: Mapped[dict] = mapped_column(JSONType, default=dict)     # evidence: counts, IPs, countries, operations, baseline size
    event_ids: Mapped[list] = mapped_column(JSONType, default=list)  # audit_events.id (up to 50)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    first_event_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_event_at: Mapped[datetime] = mapped_column(UTCDateTime)
    status: Mapped[str] = mapped_column(String(16), default="OPEN", index=True)  # OPEN | ACKNOWLEDGED
    acknowledged_by: Mapped[str | None] = mapped_column(String(255))
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    note: Mapped[str | None] = mapped_column(Text)
