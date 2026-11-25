"""Identity governance: directory objects, credentials, group membership, effective access, identity lifecycle,
access-revocation plans and approval-vs-actual exceptions.

Everything here is derived from provider data (written by collectors) except revocation plans and exception
resolutions, which are written by people. A provider listing that failed or was incomplete never marks anything
deleted, disabled or removed."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, make_immutable, utcnow

LIFECYCLE = ("Active", "New", "Disabled", "Deleted", "Access Revocation Pending", "Access Revoked", "Reconciliation Required")


class IdentityGroupMember(TimestampMixin, Base):
    """Group -> member (transitive where the provider returns it), used to expand group-based access to people."""
    __tablename__ = "identity_group_members"
    __table_args__ = (UniqueConstraint("provider", "group_id", "member_id", name="uq_group_member"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    group_id: Mapped[str] = mapped_column(String(255), index=True)
    group_name: Mapped[str | None] = mapped_column(String(255))
    member_id: Mapped[str] = mapped_column(String(255), index=True)
    member_type: Mapped[str] = mapped_column(String(32))
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class IamCredential(TimestampMixin, Base):
    """Credential metadata only (AWS access keys, GCP service-account keys, Entra app secrets/certificates). Never the secret."""
    __tablename__ = "iam_credentials"
    __table_args__ = (UniqueConstraint("provider", "credential_id", name="uq_iam_credential"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str | None] = mapped_column(String(128))
    principal_id: Mapped[str] = mapped_column(String(255), index=True)
    credential_id: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32))          # access_key | sa_key | client_secret | certificate
    status: Mapped[str | None] = mapped_column(String(24))  # Active | Inactive | Disabled | Expired
    created_at_provider: Mapped[datetime | None] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class IamEffectiveAccess(TimestampMixin, Base):
    """Who effectively holds a role at a scope: direct assignments plus group assignments expanded to members.
    Rebuilt after each access inventory run from access_assignments + identity_group_members."""
    __tablename__ = "iam_effective_access"
    __table_args__ = (Index("ix_effective_principal", "provider", "principal_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    principal_id: Mapped[str] = mapped_column(String(255))
    principal_type: Mapped[str] = mapped_column(String(32))
    assignment_id: Mapped[int] = mapped_column(Integer, index=True)
    scope_external_id: Mapped[str] = mapped_column(String(128))
    scope_level: Mapped[str] = mapped_column(String(24))
    scope_path: Mapped[str] = mapped_column(Text)
    role_name: Mapped[str] = mapped_column(String(255))
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    via: Mapped[str] = mapped_column(String(16))             # Direct | Group | Inherited
    via_group: Mapped[str | None] = mapped_column(String(255))
    inherited_from: Mapped[str | None] = mapped_column(Text)


class IdentityChangeEvent(Base):
    """Append-only identity lifecycle and permission change history, derived by comparing complete inventories."""
    __tablename__ = "identity_change_events"
    __table_args__ = (Index("ix_identity_change_time", "detected_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    scope_external_id: Mapped[str | None] = mapped_column(String(128))
    principal_id: Mapped[str] = mapped_column(String(255), index=True)
    principal_name: Mapped[str | None] = mapped_column(String(255))
    principal_type: Mapped[str | None] = mapped_column(String(32))
    change_type: Mapped[str] = mapped_column(String(40), index=True)
    # NEW_IDENTITY | NEW_SERVICE_PRINCIPAL | PERMISSION_ADDED | PERMISSION_REMOVED | ROLE_CHANGED | GROUP_MEMBER_ADDED |
    # GROUP_MEMBER_REMOVED | IDENTITY_DISABLED | IDENTITY_ENABLED | IDENTITY_DELETED | CREDENTIAL_ADDED
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    previous_state: Mapped[dict | None] = mapped_column(JSONType)
    new_state: Mapped[dict | None] = mapped_column(JSONType)
    approval_reference: Mapped[str | None] = mapped_column(String(64))  # matching approved grant key, when one exists
    source_event_id: Mapped[int | None] = mapped_column(Integer)          # audit_events.id of the provider event, when found
    initiated_by: Mapped[str | None] = mapped_column(String(512))         # from that provider event
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AccessRevocationPlan(TimestampMixin, Base):
    """Complete revocation plan for a departed / disabled identity. LV NEXUS never removes access itself: an
    administrator executes the plan in the provider; each item is verified against the next complete inventory."""
    __tablename__ = "access_revocation_plans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan_key: Mapped[str] = mapped_column(String(32), unique=True)
    provider: Mapped[str] = mapped_column(String(16))
    principal_id: Mapped[str] = mapped_column(String(255), index=True)
    principal_name: Mapped[str | None] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(48))       # deleted | disabled | offboarding | security_incident
    status: Mapped[str] = mapped_column(String(32), default="DRAFT", index=True)
    # DRAFT | APPROVAL_REQUESTED | APPROVED | REJECTED | EXECUTING | VERIFIED | PARTIALLY_VERIFIED | VERIFICATION_FAILED | CANCELLED
    created_by: Mapped[str] = mapped_column(String(255))
    approved_by: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    executed_by: Mapped[str | None] = mapped_column(String(255))
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    notes: Mapped[str | None] = mapped_column(Text)
    before_snapshot: Mapped[list] = mapped_column(JSONType, default=list)
    after_snapshot: Mapped[list | None] = mapped_column(JSONType)


class AccessRevocationItem(TimestampMixin, Base):
    __tablename__ = "access_revocation_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan_id: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(24))        # assignment | group_membership | credential | inherited
    target_id: Mapped[int | None] = mapped_column(Integer)  # access_assignments.id / identity_group_members.id / iam_credentials.id
    description: Mapped[str] = mapped_column(Text)
    scope_path: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(String(32))      # remove | disable | review_shared | remove_at_parent
    auto_allowed: Mapped[bool] = mapped_column(Boolean, default=True)  # False for shared / service identities
    status: Mapped[str] = mapped_column(String(24), default="PENDING")  # PENDING | SKIPPED | VERIFIED | STILL_PRESENT
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class IamException(TimestampMixin, Base):
    """Approval-vs-actual reconciliation exception with an owner and a resolution."""
    __tablename__ = "iam_exceptions"
    __table_args__ = (UniqueConstraint("dedup_key", name="uq_iam_exception"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    exception_key: Mapped[str] = mapped_column(String(32), unique=True)
    dedup_key: Mapped[str] = mapped_column(String(64))
    category: Mapped[str] = mapped_column(String(40), index=True)
    # PROVISIONED_WITHOUT_APPROVAL | APPROVED_NOT_PROVISIONED | EXPIRED_STILL_ACTIVE | EXCESSIVE_ACCESS | SCOPE_MISMATCH |
    # DELETED_IDENTITY_WITH_ACCESS | UNAUTHORIZED_PRIVILEGE_CHANGE | MISSING_ACCESS
    provider: Mapped[str] = mapped_column(String(16))
    principal_id: Mapped[str] = mapped_column(String(255), index=True)
    principal_name: Mapped[str | None] = mapped_column(String(255))
    scope_path: Mapped[str | None] = mapped_column(Text)
    expected: Mapped[str | None] = mapped_column(Text)
    actual: Mapped[str | None] = mapped_column(Text)
    risk: Mapped[str] = mapped_column(String(16))
    owner: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(24), default="OPEN", index=True)  # OPEN | IN_PROGRESS | RESOLVED | ACCEPTED
    evidence: Mapped[dict] = mapped_column(JSONType, default=dict)
    resolution_notes: Mapped[str | None] = mapped_column(Text)
    resolved_by: Mapped[str | None] = mapped_column(String(255))
    last_detected_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    cleared_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # condition no longer present in the data


make_immutable(IdentityChangeEvent)
