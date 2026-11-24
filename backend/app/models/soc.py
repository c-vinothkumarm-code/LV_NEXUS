"""SOC tables. Collection, detection and human review are tracked separately."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, ReviewStatus, TimestampMixin, UTCDateTime, make_immutable, utcnow


class AuditEvent(Base):
    """Unified audit event schema across AWS CloudTrail, GCP Audit Logs, Azure Activity Logs."""

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("provider", "event_id", name="uq_audit_events_provider_event"),
        Index("ix_audit_events_scope_time", "provider", "scope_external_id", "event_timestamp"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(255))
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))  # account / project / subscription id
    region: Mapped[str | None] = mapped_column(String(64))
    event_timestamp: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    event_name: Mapped[str] = mapped_column(String(255), index=True)
    principal: Mapped[str | None] = mapped_column(String(512), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(1024))
    resource_type: Mapped[str | None] = mapped_column(String(128))
    event_category: Mapped[str | None] = mapped_column(String(64))
    severity: Mapped[str | None] = mapped_column(String(16))
    risk_score: Mapped[int | None] = mapped_column(Integer)
    description: Mapped[str | None] = mapped_column(Text)
    ai_analysis: Mapped[str | None] = mapped_column(Text)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    detection_status: Mapped[str] = mapped_column(String(32), default="not_evaluated")
    review_status: Mapped[str] = mapped_column(String(32), default=ReviewStatus.PENDING_REVIEW.value, index=True)
    evidence_reference: Mapped[str | None] = mapped_column(String(1024))
    review_owner: Mapped[str | None] = mapped_column(String(255))
    review_timestamp: Mapped[datetime | None] = mapped_column(UTCDateTime)
    raw: Mapped[dict] = mapped_column(JSONType, default=dict)
    collected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class SecurityFinding(TimestampMixin, Base):
    __tablename__ = "security_findings"
    __table_args__ = (Index("ix_security_findings_scope", "provider", "scope_external_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    principal: Mapped[str | None] = mapped_column(String(512))
    resource_id: Mapped[str | None] = mapped_column(String(1024))
    evidence: Mapped[dict] = mapped_column(JSONType, default=dict)
    ai_analysis: Mapped[str | None] = mapped_column(Text)
    recommended_action: Mapped[str | None] = mapped_column(Text)
    review_status: Mapped[str] = mapped_column(String(32), default=ReviewStatus.PENDING_REVIEW.value, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)


@make_immutable
class SecurityReview(Base):
    """Append-only human review history. Review evidence is never overwritten."""

    __tablename__ = "security_reviews"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("security_findings.id"), index=True)
    previous_status: Mapped[str | None] = mapped_column(String(32))
    new_status: Mapped[str] = mapped_column(String(32))
    reviewer: Mapped[str] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    evidence_reference: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class RemediationRecord(TimestampMixin, Base):
    """Human-approved tasks. The platform records decisions; it never executes cloud changes."""

    __tablename__ = "remediation_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True)
    category: Mapped[str] = mapped_column(String(32), index=True)  # onboarding | security | finops | infrastructure
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    finding_id: Mapped[int | None] = mapped_column(ForeignKey("security_findings.id"))
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    proposed_action: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="pending_approval", index=True)
    # pending_approval | approved | rejected | resolved
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    decision_notes: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
