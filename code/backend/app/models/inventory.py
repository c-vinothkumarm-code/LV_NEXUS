"""Cloud scope inventory: AWS accounts, GCP projects, Azure subscriptions, resources."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, OnboardingStatus, Provider, TimestampMixin, UTCDateTime, make_immutable, utcnow


class ScopeMixin(TimestampMixin):
    """Columns shared by every cloud scope table."""

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    external_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), default="")
    provider_state: Mapped[str] = mapped_column(String(64), default="")
    parent: Mapped[str | None] = mapped_column(String(255))
    environment: Mapped[str | None] = mapped_column(String(32))
    onboarding_status: Mapped[str] = mapped_column(String(32), default=OnboardingStatus.DISCOVERED.value, index=True)
    checks: Mapped[dict] = mapped_column(JSONType, default=dict)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    first_discovered_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_validated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class CloudAccount(ScopeMixin, Base):
    __tablename__ = "cloud_accounts"
    provider = Provider.AWS.value
    email: Mapped[str | None] = mapped_column(String(255))
    is_management: Mapped[bool] = mapped_column(Boolean, default=False)


class CloudProject(ScopeMixin, Base):
    __tablename__ = "cloud_projects"
    provider = Provider.GCP.value
    project_number: Mapped[str | None] = mapped_column(String(32))
    billing_account: Mapped[str | None] = mapped_column(String(128))


class CloudSubscription(ScopeMixin, Base):
    __tablename__ = "cloud_subscriptions"
    provider = Provider.AZURE.value
    tenant_id: Mapped[str | None] = mapped_column(String(64))


SCOPE_MODELS: dict[str, type] = {
    Provider.AWS.value: CloudAccount,
    Provider.GCP.value: CloudProject,
    Provider.AZURE.value: CloudSubscription,
}
SCOPE_LABEL = {"aws": "account", "gcp": "project", "azure": "subscription"}


class CloudResource(TimestampMixin, Base):
    __tablename__ = "cloud_resources"
    __table_args__ = (
        UniqueConstraint("provider", "resource_id", name="uq_cloud_resources_provider_resource"),
        Index("ix_cloud_resources_scope", "provider", "scope_external_id"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    resource_id: Mapped[str] = mapped_column(String(512))
    resource_type: Mapped[str] = mapped_column(String(128), index=True)
    name: Mapped[str | None] = mapped_column(String(255))
    region: Mapped[str | None] = mapped_column(String(64))
    state: Mapped[str | None] = mapped_column(String(64))
    attributes: Mapped[dict] = mapped_column(JSONType, default=dict)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)

    @classmethod
    def not_deleted(cls):
        """Resources that exist. NULL state means the provider did not report one, not that it is deleted: a plain
        `state != 'deleted'` silently drops those rows in SQL (NULL comparisons are never true)."""
        from sqlalchemy import or_
        return or_(cls.state.is_(None), cls.state != "deleted")


@make_immutable
class OnboardingRecord(Base):
    """Append-only onboarding history and audit evidence."""

    __tablename__ = "onboarding_records"
    __table_args__ = (Index("ix_onboarding_records_scope", "provider", "scope_external_id", "created_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    scope_name: Mapped[str | None] = mapped_column(String(255))
    event_type: Mapped[str] = mapped_column(String(32))  # discovered | status_changed | validated | inactive
    previous_status: Mapped[str | None] = mapped_column(String(32))
    new_status: Mapped[str] = mapped_column(String(32))
    checks: Mapped[dict] = mapped_column(JSONType, default=dict)
    detail: Mapped[str | None] = mapped_column(Text)
    execution_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
