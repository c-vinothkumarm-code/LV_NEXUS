"""Governance & Compliance: frameworks, controls mapped to native findings, evidence, and the cloud onboarding workflow.

Control status is derived from native security findings (and evidence people attach). A pass rate is reported, never a
certification: the platform does not claim compliance with any framework."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, Date, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, make_immutable, utcnow


class ComplianceFramework(TimestampMixin, Base):
    __tablename__ = "compliance_frameworks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(16))  # native (from provider findings) | custom (imported by an administrator)
    match_standard: Mapped[str | None] = mapped_column(String(255))  # substring of the finding compliance_standard (native frameworks)
    owner: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[str] = mapped_column(String(255))


class ComplianceControl(TimestampMixin, Base):
    __tablename__ = "compliance_controls"
    __table_args__ = (UniqueConstraint("framework_id", "control_id", name="uq_framework_control"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework_id: Mapped[int] = mapped_column(ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), index=True)
    control_id: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    # how native findings map to this control: native control IDs and/or category / title keywords
    mapped_control_ids: Mapped[list] = mapped_column(JSONType, default=list)
    mapped_keywords: Mapped[list] = mapped_column(JSONType, default=list)
    owner: Mapped[str | None] = mapped_column(String(255))
    remediation_owner: Mapped[str | None] = mapped_column(String(255))
    review_date: Mapped[date | None] = mapped_column(Date)
    manual_status: Mapped[str | None] = mapped_column(String(24))  # for controls not covered by findings: PASS | FAIL | NOT_ASSESSED (needs evidence)
    updated_by: Mapped[str | None] = mapped_column(String(255))


class ControlEvidence(Base):
    __tablename__ = "control_evidence"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    control_id: Mapped[int] = mapped_column(ForeignKey("compliance_controls.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(24))  # document | link | finding_export | screenshot | note
    reference: Mapped[str] = mapped_column(String(1024))
    notes: Mapped[str | None] = mapped_column(Text)
    added_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class GovernanceAuditEvent(Base):
    __tablename__ = "governance_audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity: Mapped[str] = mapped_column(String(32))
    entity_id: Mapped[int | None] = mapped_column(Integer, index=True)
    action: Mapped[str] = mapped_column(String(48))
    actor: Mapped[str] = mapped_column(String(255))
    detail: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class OnboardingRequest(TimestampMixin, Base):
    """Cloud onboarding governance: requirement form through production approval."""
    __tablename__ = "onboarding_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_key: Mapped[str] = mapped_column(String(16), unique=True)  # ONB-0001
    title: Mapped[str] = mapped_column(String(255))
    business_purpose: Mapped[str] = mapped_column(Text)
    provider: Mapped[str] = mapped_column(String(16))
    environment: Mapped[str] = mapped_column(String(32))
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    estimated_monthly_cost_usd: Mapped[float | None] = mapped_column()
    scope_external_id: Mapped[str | None] = mapped_column(String(128))  # set when the account / subscription / project exists
    requester: Mapped[str] = mapped_column(String(255))
    stages: Mapped[list] = mapped_column(JSONType)  # [{key, label, permission, status, by, at, evidence, notes}]
    current_stage: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(24), default="IN_PROGRESS")  # IN_PROGRESS | APPROVED_FOR_PRODUCTION | REJECTED | WITHDRAWN


for _m in (ControlEvidence, GovernanceAuditEvent):
    make_immutable(_m)
