"""Account ownership: who is accountable for each AWS account / Azure subscription / GCP project, with a change history.

Business contact details only (names and work e-mail addresses). The approved budget is NOT stored here: it is read
from the budget tracker so the two can never disagree."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UTCDateTime, utcnow

OWNERSHIP_FIELDS = ("spoc_name", "spoc_email", "owner_name", "owner_email", "entity", "entity_lead", "entity_lead_email",
                    "cloud_admin_email", "finops_spoc_name", "finops_spoc_email", "cost_centre", "notes")


class AccountOwnership(TimestampMixin, Base):
    __tablename__ = "account_ownership"
    __table_args__ = (UniqueConstraint("provider", "scope_external_id", name="uq_account_ownership_scope"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    spoc_name: Mapped[str | None] = mapped_column(String(255))
    spoc_email: Mapped[str | None] = mapped_column(String(255))
    owner_name: Mapped[str | None] = mapped_column(String(255))
    owner_email: Mapped[str | None] = mapped_column(String(255))
    entity: Mapped[str | None] = mapped_column(String(255))
    entity_lead: Mapped[str | None] = mapped_column(String(255))
    entity_lead_email: Mapped[str | None] = mapped_column(String(255))
    cloud_admin_email: Mapped[str | None] = mapped_column(String(255))
    finops_spoc_name: Mapped[str | None] = mapped_column(String(255))
    finops_spoc_email: Mapped[str | None] = mapped_column(String(255))
    cost_centre: Mapped[str | None] = mapped_column(String(128))
    notes: Mapped[str | None] = mapped_column(Text)
    updated_by: Mapped[str | None] = mapped_column(String(255))


class AccountOwnershipHistory(Base):
    """One row per changed field: who changed what, from what, when. Never updated or deleted by the application."""
    __tablename__ = "account_ownership_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ownership_id: Mapped[int] = mapped_column(ForeignKey("account_ownership.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128), index=True)
    field: Mapped[str] = mapped_column(String(64))
    old_value: Mapped[str | None] = mapped_column(Text)
    new_value: Mapped[str | None] = mapped_column(Text)
    changed_by: Mapped[str] = mapped_column(String(255))
    changed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
