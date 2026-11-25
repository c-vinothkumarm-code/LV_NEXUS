from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, event
from sqlalchemy.dialects import mssql, mysql
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

JSONType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetimes on every database.

    MySQL DATETIME and SQL Server DATETIME2 have no timezone, so values are stored as UTC and
    returned as aware UTC datetimes. PostgreSQL keeps its native timestamptz."""

    impl = DateTime
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "mysql":
            return dialect.type_descriptor(mysql.DATETIME(fsp=6))
        if dialect.name == "mssql":
            return dialect.type_descriptor(mssql.DATETIME2())
        return dialect.type_descriptor(DateTime(timezone=True))

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if not isinstance(value, datetime):  # a plain date used as a range boundary
            value = datetime(value.year, value.month, value.day, tzinfo=UTC)
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        return value if dialect.name == "postgresql" else value.replace(tzinfo=None)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)


class Provider(enum.StrEnum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class OnboardingStatus(enum.StrEnum):
    DISCOVERED = "Discovered"
    PENDING_ACCESS = "Pending Access"
    PENDING_CONFIGURATION = "Pending Configuration"
    PARTIALLY_ONBOARDED = "Partially Onboarded"
    FULLY_ONBOARDED = "Fully Onboarded"
    ACCESS_FAILED = "Access Failed"
    MONITORING_DISABLED = "Monitoring Disabled"
    INACTIVE = "Inactive"


class Severity(enum.StrEnum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class ReviewStatus(enum.StrEnum):
    PENDING_REVIEW = "Pending Review"
    UNDER_INVESTIGATION = "Under Investigation"
    CONFIRMED_LEGITIMATE = "Confirmed Legitimate"
    CONFIRMED_SUSPICIOUS = "Confirmed Suspicious"
    REMEDIATION_REQUIRED = "Remediation Required"
    ESCALATED = "Escalated"
    CLOSED = "Closed"


class JobStatus(enum.StrEnum):
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED_OVERLAP = "skipped_overlap"


class ImmutableRecordError(RuntimeError):
    """Raised when code tries to change or delete append-only history."""


def make_immutable(model: type) -> type:
    """Append-only guard at the ORM layer (PostgreSQL triggers enforce it in the database too)."""

    def _deny(mapper, connection, target):
        raise ImmutableRecordError(f"{model.__tablename__} is append-only")

    event.listen(model, "before_update", _deny)
    event.listen(model, "before_delete", _deny)
    return model
