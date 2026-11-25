from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, utcnow


class AutomationJob(TimestampMixin, Base):
    __tablename__ = "automation_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str | None] = mapped_column(String(255))
    schedule: Mapped[str | None] = mapped_column(String(64))  # cron, evaluated in schedule_timezone
    schedule_timezone: Mapped[str] = mapped_column(String(64), default="Asia/Kolkata")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    implemented: Mapped[bool] = mapped_column(Boolean, default=False)
    lock_owner: Mapped[str | None] = mapped_column(String(64))
    lock_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    checkpoint: Mapped[dict] = mapped_column(JSONType, default=dict)
    last_status: Mapped[str | None] = mapped_column(String(32))
    last_started_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AutomationExecutionLog(Base):
    __tablename__ = "automation_execution_logs"
    __table_args__ = (Index("ix_execution_logs_job_time", "job_name", "started_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("automation_jobs.id"))
    job_name: Mapped[str] = mapped_column(String(64))
    trigger: Mapped[str] = mapped_column(String(32), default="schedule")  # schedule | manual | event
    triggered_by: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), index=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    scopes_total: Mapped[int] = mapped_column(Integer, default=0)
    scopes_failed: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict] = mapped_column(JSONType, default=dict)
    failures: Mapped[list] = mapped_column(JSONType, default=list)  # [{provider, scope, reason}]
    error: Mapped[str | None] = mapped_column(Text)


class NotificationLog(Base):
    __tablename__ = "notification_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    channel: Mapped[str] = mapped_column(String(32))  # email | google_chat
    category: Mapped[str] = mapped_column(String(64), index=True)
    subject: Mapped[str] = mapped_column(String(255))
    body: Mapped[str | None] = mapped_column(Text)
    body_html: Mapped[str | None] = mapped_column(Text)  # e-mail only: the dashboard version of the same report
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)  # queued | sent | failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    execution_id: Mapped[int | None] = mapped_column(Integer)
    recipients: Mapped[list | None] = mapped_column(JSONType)  # e-mail only; default = NOTIFY_EMAIL_TO
    attachments: Mapped[list | None] = mapped_column(JSONType)  # e-mail only: [{filename, content_type, text}] (migration 0012)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class CloudConnection(TimestampMixin, Base):
    """Connection settings for one cloud, entered in the dashboard. Holds identifiers only:
    passwords, client secrets and access keys are never stored here."""

    __tablename__ = "cloud_connections"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    config: Mapped[dict] = mapped_column(JSONType, default=dict)
    updated_by: Mapped[str | None] = mapped_column(String(255))
    last_test_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_test_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_test_detail: Mapped[str | None] = mapped_column(Text)
