from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, JSONType, TimestampMixin, UTCDateTime, make_immutable, utcnow

user_roles = Table(
    "user_roles", Base.metadata,
    Column("user_id", ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)
role_permissions = Table(
    "role_permissions", Base.metadata,
    Column("role_id", ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column("permission_id", ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True),
)


class Permission(Base):
    __tablename__ = "permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str | None] = mapped_column(String(255))


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str | None] = mapped_column(String(255))
    permissions: Mapped[list[Permission]] = relationship(secondary=role_permissions, lazy="selectin")


class User(TimestampMixin, Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    display_name: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # access registry (who authorized this person, until when, and the Google identity bound at first sign-in)
    google_sub: Mapped[str | None] = mapped_column(String(64), unique=True)
    access_status: Mapped[str] = mapped_column(String(16), default="ACTIVE")  # ACTIVE | SUSPENDED | REVOKED
    access_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    authorized_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    role_source: Mapped[str] = mapped_column(String(160), default="allowlist")  # allowlist | google_group:<group> | bootstrap
    created_by: Mapped[str | None] = mapped_column(String(255))
    modified_by: Mapped[str | None] = mapped_column(String(255))
    roles: Mapped[list[Role]] = relationship(secondary=user_roles, lazy="selectin")
    scope_assignments: Mapped[list["UserScopeAssignment"]] = relationship(  # noqa: F821 - defined in access_control
        lazy="selectin", cascade="all, delete-orphan", passive_deletes=True)

    @property
    def permission_names(self) -> set[str]:
        return {p.name for r in self.roles for p in r.permissions}


@make_immutable
class AdminAuditLog(Base):
    """Append-only audit of administrative actions taken inside the application."""

    __tablename__ = "admin_audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(255), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str | None] = mapped_column(String(255))
    detail: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
