"""Cloud Budget Management: the authoritative internal register of Finance-approved budgets.

An approved budget is never overwritten: the original amount stays on the budget row and every later change is a
BudgetRevision. Approval chains are configurable per request type. Alerts raised by LV NEXUS are stored separately
from the provider's own budget alert configuration (only its name is recorded here)."""
from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import Boolean, Date, ForeignKey, Index, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, make_immutable, utcnow

Money = Numeric(18, 2)
LEVELS = ("organization", "provider", "environment", "account", "business_entity", "project", "service")
BUDGET_STATUSES = ("DRAFT", "PENDING", "APPROVED", "ACTIVE", "EXPIRED", "REJECTED")


class CloudBudget(TimestampMixin, Base):
    __tablename__ = "cloud_budgets"
    __table_args__ = (Index("ix_cloud_budgets_scope", "provider", "scope_external_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    budget_key: Mapped[str] = mapped_column(String(16), unique=True)  # BUD-0001
    name: Mapped[str] = mapped_column(String(255))
    level: Mapped[str] = mapped_column(String(24))
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("cloud_budgets.id"), index=True)  # allocation carved out of a parent budget
    environment: Mapped[str | None] = mapped_column(String(32))     # Production / UAT / Development / POC / Sandbox
    provider: Mapped[str | None] = mapped_column(String(16))
    account_name: Mapped[str | None] = mapped_column(String(255))
    scope_external_id: Mapped[str | None] = mapped_column(String(128))  # AWS account / Azure subscription / GCP project
    scopes: Mapped[list] = mapped_column(JSONType, default=list)      # extra [{provider, scope}] for multi-account budgets
    project_application: Mapped[str | None] = mapped_column(String(255))
    business_entity: Mapped[str | None] = mapped_column(String(255))
    service: Mapped[str | None] = mapped_column(String(255))
    # amounts: original approval in its own currency, plus the USD figures used for comparison
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    original_monthly_amount: Mapped[Decimal] = mapped_column(Money)    # as approved, in `currency`; never changed after approval
    original_annual_amount: Mapped[Decimal | None] = mapped_column(Money)
    fx_rate_to_usd: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))  # 1 unit of `currency` in USD; 1 for USD
    fx_rate_date: Mapped[date | None] = mapped_column(Date)
    original_monthly_usd: Mapped[Decimal] = mapped_column(Money)
    original_annual_usd: Mapped[Decimal | None] = mapped_column(Money)
    current_monthly_usd: Mapped[Decimal] = mapped_column(Money)        # original + approved revisions
    current_annual_usd: Mapped[Decimal | None] = mapped_column(Money)
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date] = mapped_column(Date)
    email_subject: Mapped[str | None] = mapped_column(String(512))
    native_alert_name: Mapped[str | None] = mapped_column(String(255))  # the provider's budget alert, if one exists (not managed here)
    owner: Mapped[str | None] = mapped_column(String(255))
    # approval record (migration 0012)
    budget_type: Mapped[str | None] = mapped_column(String(24))       # initial | additional | temporary | extension | revised
    approver_name: Mapped[str | None] = mapped_column(String(255))
    approver_email: Mapped[str | None] = mapped_column(String(255))
    approval_reference: Mapped[str | None] = mapped_column(String(255))
    approval_evidence: Mapped[list | None] = mapped_column(JSONType)  # [{kind, reference, note}]
    status: Mapped[str] = mapped_column(String(16), default="DRAFT", index=True)
    thresholds: Mapped[list | None] = mapped_column(JSONType)          # per-budget override of the global thresholds
    created_by: Mapped[str] = mapped_column(String(255))
    updated_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class BudgetRevision(Base):
    """An approved change to a budget's amount (append-only). The budget's current amount = original + all revisions."""
    __tablename__ = "budget_revisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    budget_id: Mapped[int] = mapped_column(ForeignKey("cloud_budgets.id"), index=True)
    request_id: Mapped[int | None] = mapped_column(ForeignKey("budget_requests.id"))
    change_monthly_usd: Mapped[Decimal] = mapped_column(Money)        # + increase / - decrease
    change_annual_usd: Mapped[Decimal | None] = mapped_column(Money)
    previous_monthly_usd: Mapped[Decimal] = mapped_column(Money)
    revised_monthly_usd: Mapped[Decimal] = mapped_column(Money)
    effective_date: Mapped[date] = mapped_column(Date)
    reason: Mapped[str] = mapped_column(Text)
    approvers: Mapped[list] = mapped_column(JSONType, default=list)
    email_reference: Mapped[str | None] = mapped_column(String(512))
    evidence: Mapped[list] = mapped_column(JSONType, default=list)
    recorded_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class ApprovalWorkflow(TimestampMixin, Base):
    """Configurable approval chain: which steps a request of this type (and size) needs, in order."""
    __tablename__ = "approval_workflows"
    __table_args__ = (UniqueConstraint("request_type", "min_amount_usd", name="uq_workflow_type_amount"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_type: Mapped[str] = mapped_column(String(32))   # new_budget | additional_budget | new_service | budget_decrease
    min_amount_usd: Mapped[Decimal] = mapped_column(Money, default=0)  # chain applies from this monthly USD amount upward
    steps: Mapped[list] = mapped_column(JSONType)            # [{"key": "finance", "label": "Finance approval", "permission": "budget:approve"}]
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[str | None] = mapped_column(String(255))


class BudgetRequest(TimestampMixin, Base):
    """A request that needs approval: a new budget, additional budget, a decrease, or a new cloud service."""
    __tablename__ = "budget_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_key: Mapped[str] = mapped_column(String(16), unique=True)  # BRQ-0001
    request_type: Mapped[str] = mapped_column(String(32), index=True)
    budget_id: Mapped[int | None] = mapped_column(ForeignKey("cloud_budgets.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default="PENDING", index=True)  # PENDING | APPROVED | REJECTED | WITHDRAWN | MORE_INFO
    steps: Mapped[list] = mapped_column(JSONType)            # snapshot of the chain at submission
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    # amounts (USD): existing, actual and forecast are captured from the platform at submission time
    existing_monthly_usd: Mapped[Decimal | None] = mapped_column(Money)
    actual_mtd_usd: Mapped[Decimal | None] = mapped_column(Money)
    forecast_month_usd: Mapped[Decimal | None] = mapped_column(Money)
    amount_monthly_usd: Mapped[Decimal] = mapped_column(Money)   # additional (or new) monthly amount requested; negative for a decrease
    amount_annual_usd: Mapped[Decimal | None] = mapped_column(Money)
    proposed_monthly_usd: Mapped[Decimal | None] = mapped_column(Money)
    justification: Mapped[str] = mapped_column(Text)
    project_service: Mapped[str | None] = mapped_column(String(255))
    requesting_team: Mapped[str | None] = mapped_column(String(255))
    requester: Mapped[str] = mapped_column(String(255))
    effective_date: Mapped[date | None] = mapped_column(Date)
    email_subject: Mapped[str | None] = mapped_column(String(512))
    email_reference: Mapped[str | None] = mapped_column(String(512))
    supporting_documents: Mapped[list] = mapped_column(JSONType, default=list)
    # new cloud service requests
    service_details: Mapped[dict | None] = mapped_column(JSONType)  # {business_purpose, provider, scope, service, technical_requirements, ...}
    outcome_note: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class BudgetApproval(Base):
    """One approval step decision (append-only)."""
    __tablename__ = "budget_approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("budget_requests.id"), index=True)
    step_key: Mapped[str] = mapped_column(String(32))
    step_label: Mapped[str] = mapped_column(String(128))
    decision: Mapped[str] = mapped_column(String(16))   # APPROVED | REJECTED | MORE_INFO | INFO_PROVIDED | SUBMITTED | WITHDRAWN
    actor: Mapped[str] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    email_reference: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class BudgetAlert(Base):
    """A LV NEXUS (internal) threshold alert. One per budget, month and threshold."""
    __tablename__ = "budget_alerts"
    __table_args__ = (UniqueConstraint("budget_id", "period_start", "threshold", name="uq_budget_alert"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    budget_id: Mapped[int] = mapped_column(ForeignKey("cloud_budgets.id"), index=True)
    period_start: Mapped[date] = mapped_column(Date)
    threshold: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(24))      # Informational | Warning | High warning | Budget reached | Budget exceeded
    approved_usd: Mapped[Decimal] = mapped_column(Money)
    actual_usd: Mapped[Decimal] = mapped_column(Money)
    forecast_usd: Mapped[Decimal | None] = mapped_column(Money)
    utilisation_percent: Mapped[Decimal] = mapped_column(Numeric(9, 2))
    owner: Mapped[str | None] = mapped_column(String(255))
    required_action: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(16), default="cloudnexus")
    notified: Mapped[list] = mapped_column(JSONType, default=list)  # [{channel, at, ok}]
    acknowledged_by: Mapped[str | None] = mapped_column(String(255))
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class BudgetAuditEvent(Base):
    """Every change to a budget, request or setting (append-only)."""
    __tablename__ = "budget_audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    budget_id: Mapped[int | None] = mapped_column(Integer, index=True)
    request_id: Mapped[int | None] = mapped_column(Integer, index=True)
    action: Mapped[str] = mapped_column(String(48))
    actor: Mapped[str] = mapped_column(String(255))
    detail: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class BudgetSetting(TimestampMixin, Base):
    """Platform-wide budget settings, e.g. key 'thresholds' -> [50, 75, 90, 100]."""
    __tablename__ = "budget_settings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    value: Mapped[dict | list] = mapped_column(JSONType)
    updated_by: Mapped[str | None] = mapped_column(String(255))


for _m in (BudgetRevision, BudgetApproval, BudgetAuditEvent):
    make_immutable(_m)
