"""Compliance policy library state: per-policy settings (enable, severity, owner, attestation) and evaluation results."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, Date, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, utcnow


class CompliancePolicySetting(TimestampMixin, Base):
    """Administrator choices for one library policy. Absent row = library defaults. Attestation is for controls that
    cannot be read from a cloud API (for example a tested DR plan): a person states the result with evidence and a
    validity date; after that date the policy goes back to 'not assessed'."""
    __tablename__ = "compliance_policy_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    policy_key: Mapped[str] = mapped_column(String(32), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str | None] = mapped_column(String(16))      # override of the library severity
    params: Mapped[dict | None] = mapped_column(JSONType)         # e.g. {"max_privileged": 5}
    owner: Mapped[str | None] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    attested_status: Mapped[str | None] = mapped_column(String(16))  # PASS | FAIL
    attested_by: Mapped[str | None] = mapped_column(String(255))
    attested_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    attestation_evidence: Mapped[str | None] = mapped_column(String(1024))
    attestation_valid_until: Mapped[date | None] = mapped_column(Date)
    updated_by: Mapped[str | None] = mapped_column(String(255))


class ComplianceRun(Base):
    __tablename__ = "compliance_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    trigger: Mapped[str] = mapped_column(String(32), default="schedule")
    triggered_by: Mapped[str | None] = mapped_column(String(255))
    totals: Mapped[dict | None] = mapped_column(JSONType)   # {"PASS": n, "FAIL": n, "NOT_ASSESSED": n}
    scores: Mapped[dict | None] = mapped_column(JSONType)   # framework key -> {"score", "coverage", ...}


class ComplianceResult(Base):
    """One policy x one scope (account / subscription / project, or 'platform') in one run."""
    __tablename__ = "compliance_results"
    __table_args__ = (Index("ix_compliance_results_run_policy", "run_id", "policy_key"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("compliance_runs.id"), index=True)
    policy_key: Mapped[str] = mapped_column(String(32))
    provider: Mapped[str] = mapped_column(String(16))         # aws | azure | gcp | platform
    scope_external_id: Mapped[str] = mapped_column(String(128))
    scope_name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(16))           # PASS | FAIL | NOT_ASSESSED
    severity: Mapped[str] = mapped_column(String(16))
    failing: Mapped[int] = mapped_column(Integer, default=0)
    assessed: Mapped[int] = mapped_column(Integer, default=0)
    detail: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[list | None] = mapped_column(JSONType)   # up to 20 items that explain the result
    basis: Mapped[str | None] = mapped_column(String(255))    # where the result came from
