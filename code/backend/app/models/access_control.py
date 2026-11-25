"""Platform access control: server-side sessions, the sign-in audit log and scope assignments for scoped roles."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, UTCDateTime, make_immutable, utcnow


class UserSession(Base):
    """Server-side record of every application session, so logout and revocation take effect immediately."""
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), unique=True)  # random; carried in the signed cookie
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    auth_time: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)  # original sign-in; renewals cannot extend past the absolute limit
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    revoked_reason: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    auth_method: Mapped[str] = mapped_column(String(16))


class AccessAuditLog(Base):
    """Every sign-in attempt, denial, logout and revocation (append-only). Used for throttling and monitoring."""
    __tablename__ = "access_audit_logs"
    __table_args__ = (Index("ix_access_audit_ip_time", "ip_address", "created_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event: Mapped[str] = mapped_column(String(32), index=True)  # login_success | login_denied | logout | session_revoked | throttled
    reason: Mapped[str | None] = mapped_column(String(64))       # external_account | not_provisioned | disabled | expired | invalid_token | state ...
    email: Mapped[str | None] = mapped_column(String(255), index=True)  # as asserted by the verified token; never from the browser
    google_sub: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)


class UserScopeAssignment(Base):
    """Accounts / subscriptions / projects a scoped user (Project Owner) may see. Set by an administrator."""
    __tablename__ = "user_scope_assignments"
    __table_args__ = (UniqueConstraint("user_id", "provider", "scope_external_id", name="uq_user_scope"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    assigned_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


make_immutable(AccessAuditLog)
