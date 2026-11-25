"""Scheduled reports and the archive of generated report files."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, utcnow

Blob = LargeBinary().with_variant(mysql.LONGBLOB(), "mysql")


class ReportSchedule(TimestampMixin, Base):
    __tablename__ = "report_schedules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_key: Mapped[str] = mapped_column(String(64))
    format: Mapped[str] = mapped_column(String(8), default="xlsx")
    frequency: Mapped[str] = mapped_column(String(8))          # daily | weekly | monthly
    day: Mapped[int | None] = mapped_column(Integer)           # weekday 0-6 (weekly) or day of month 1-28 (monthly)
    hour_utc: Mapped[int] = mapped_column(Integer, default=3)
    recipients: Mapped[list] = mapped_column(JSONType, default=list)
    filters: Mapped[dict] = mapped_column(JSONType, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_email: Mapped[str] = mapped_column(String(255))     # generated with this person's current permissions
    last_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    next_run_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    last_status: Mapped[str | None] = mapped_column(String(255))


class ReportArchive(Base):
    __tablename__ = "report_archive"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    schedule_id: Mapped[int | None] = mapped_column(ForeignKey("report_schedules.id"), index=True)
    report_key: Mapped[str] = mapped_column(String(64), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    mime: Mapped[str] = mapped_column(String(128))
    content: Mapped[bytes] = mapped_column(Blob)
    size: Mapped[int] = mapped_column(Integer)
    generated_for: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
