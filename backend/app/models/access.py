"""Cloud Access Management.

Two records are kept apart on purpose:
- AccessAssignment: what actually exists in AWS / Azure / GCP, written only by the access inventory collector.
- AccessGrant: what the business authorized (internal approval record), written only by people and the approval workflow.
They are compared to find unapproved, missing, expired-but-active and unverified access. One never proves the other."""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, Date, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, make_immutable, utcnow


class CloudIdentity(TimestampMixin, Base):
    __tablename__ = "cloud_identities"
    __table_args__ = (UniqueConstraint("provider", "principal_id", name="uq_identity_principal"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    principal_id: Mapped[str] = mapped_column(String(255))       # Azure object ID, AWS ARN / Identity Center ID, GCP member string
    principal_type: Mapped[str] = mapped_column(String(32))      # User | Group | ServicePrincipal | ManagedIdentity | Role | ServiceAccount | Federated
    display_name: Mapped[str | None] = mapped_column(String(255))
    sign_in_name: Mapped[str | None] = mapped_column(String(255), index=True)
    last_sign_in_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # only where the provider exposes it
    attributes: Mapped[dict] = mapped_column(JSONType, default=dict)
    last_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # identity lifecycle (filled from directory listings: Entra ID, IAM, service accounts)
    directory_scope: Mapped[str | None] = mapped_column(String(128))     # tenant / account / organization the identity lives in
    enabled: Mapped[bool | None] = mapped_column(Boolean)                 # None = the provider did not say
    user_type: Mapped[str | None] = mapped_column(String(16))             # Member | Guest (Entra)
    provider_created_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    first_seen_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    lifecycle_status: Mapped[str] = mapped_column(String(32), default="Active", index=True)
    status_changed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    missing_since: Mapped[datetime | None] = mapped_column(UTCDateTime)   # absent from a complete directory listing
    shared: Mapped[bool] = mapped_column(Boolean, default=False)          # shared / break-glass: never in an automatic revocation plan


class AccessAssignment(TimestampMixin, Base):
    """An actual role assignment / binding / account assignment read from the provider."""
    __tablename__ = "access_assignments"
    __table_args__ = (UniqueConstraint("provider", "source_id_hash", name="uq_access_assignment_source"),
                      Index("ix_access_assignment_scope", "provider", "scope_external_id"))
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(48))              # azure_rbac | aws_iam | aws_identity_center | gcp_iam
    source_id: Mapped[str] = mapped_column(Text)                 # provider's assignment ID (or a stable composite)
    source_id_hash: Mapped[str] = mapped_column(String(64))
    scope_external_id: Mapped[str] = mapped_column(String(128))  # account / subscription / project
    scope_level: Mapped[str] = mapped_column(String(24))         # organization | management_group | folder | account | subscription | project | resource_group | resource
    scope_path: Mapped[str] = mapped_column(Text)                # full provider scope string
    resource_group: Mapped[str | None] = mapped_column(String(255))
    resource_name: Mapped[str | None] = mapped_column(String(512))
    principal_id: Mapped[str] = mapped_column(String(255), index=True)
    principal_type: Mapped[str] = mapped_column(String(32))
    role_name: Mapped[str] = mapped_column(String(255), index=True)
    role_id: Mapped[str | None] = mapped_column(String(512))
    access_type: Mapped[str] = mapped_column(String(16))         # Direct | Group | Inherited | Federated
    privileged: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    condition: Mapped[str | None] = mapped_column(Text)          # GCP IAM condition / Azure ABAC condition
    pim_state: Mapped[str | None] = mapped_column(String(16))    # Azure PIM: active | eligible (when collected)
    inherited_from: Mapped[str | None] = mapped_column(Text)     # parent scope (management group / organization / folder)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime)  # PIM schedule end / IAM condition expiry, when the provider reports it
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    removed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)  # no longer returned by the provider


class AccessGrant(TimestampMixin, Base):
    """Internal approval record: what the business authorized (the business access-tracking register)."""
    __tablename__ = "access_grants"
    __table_args__ = (Index("ix_access_grant_match", "provider", "scope_external_id", "sign_in_name"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    grant_key: Mapped[str] = mapped_column(String(16), unique=True)  # ACG-0001
    provider: Mapped[str] = mapped_column(String(16))
    environment: Mapped[str | None] = mapped_column(String(32))
    account_name: Mapped[str | None] = mapped_column(String(255))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    resource_group: Mapped[str | None] = mapped_column(String(255))
    resource_name: Mapped[str | None] = mapped_column(String(512))
    display_name: Mapped[str | None] = mapped_column(String(255))
    sign_in_name: Mapped[str] = mapped_column(String(255))       # principal sign-in name / e-mail / ARN / member
    principal_id: Mapped[str | None] = mapped_column(String(255))  # filled when matched to an actual assignment
    identity_type: Mapped[str] = mapped_column(String(32), default="User")
    access_details: Mapped[str] = mapped_column(String(255))     # role name as approved
    access_scope: Mapped[str] = mapped_column(String(24), default="subscription")
    manager_approved_by: Mapped[str | None] = mapped_column(String(255))
    it_manager_approved_by: Mapped[str | None] = mapped_column(String(255))
    access_given_date: Mapped[date | None] = mapped_column(Date)
    access_extended_date: Mapped[date | None] = mapped_column(Date)
    access_expiry_date: Mapped[date | None] = mapped_column(Date, index=True)
    access_revocation_date: Mapped[date | None] = mapped_column(Date)
    email_subject: Mapped[str | None] = mapped_column(String(512))
    approval_reference: Mapped[str | None] = mapped_column(String(255))
    # lifecycle of the authorization itself (provider presence is evaluated separately)
    state: Mapped[str] = mapped_column(String(24), default="APPROVED", index=True)
    # REQUESTED (approval in progress) | APPROVED (authorized, awaiting provisioning) | PROVISIONED (admin says done, awaiting verification) | ACTIVE (verified present)
    # | REVOKE_REQUESTED | REVOKED (verified absent) | EXPIRED (past expiry) | REJECTED
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    source: Mapped[str] = mapped_column(String(16), default="workflow")  # workflow | import
    created_by: Mapped[str] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)


class AccessRequest(TimestampMixin, Base):
    __tablename__ = "access_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_key: Mapped[str] = mapped_column(String(16), unique=True)  # ACR-0001
    request_type: Mapped[str] = mapped_column(String(16), index=True)  # grant | extension | revocation
    grant_id: Mapped[int | None] = mapped_column(ForeignKey("access_grants.id"), index=True)
    assignment_id: Mapped[int | None] = mapped_column(ForeignKey("access_assignments.id"))  # revocation of unapproved access
    status: Mapped[str] = mapped_column(String(24), default="PENDING", index=True)
    # PENDING | MORE_INFO | APPROVED (awaiting execution) | EXECUTED (awaiting verification) | VERIFIED | VERIFICATION_FAILED | REJECTED | WITHDRAWN
    steps: Mapped[list] = mapped_column(JSONType)
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    provider: Mapped[str] = mapped_column(String(16))
    environment: Mapped[str | None] = mapped_column(String(32))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    resource_group: Mapped[str | None] = mapped_column(String(255))
    resource_name: Mapped[str | None] = mapped_column(String(512))
    sign_in_name: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(255))
    identity_type: Mapped[str] = mapped_column(String(32), default="User")
    role_name: Mapped[str] = mapped_column(String(255))
    privileged: Mapped[bool] = mapped_column(Boolean, default=False)
    justification: Mapped[str] = mapped_column(Text)
    requested_expiry: Mapped[date | None] = mapped_column(Date)
    reason: Mapped[str | None] = mapped_column(String(48))       # revocation reason category
    requester: Mapped[str] = mapped_column(String(255))
    email_subject: Mapped[str | None] = mapped_column(String(512))
    approval_reference: Mapped[str | None] = mapped_column(String(255))
    executed_by: Mapped[str | None] = mapped_column(String(255))
    executed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    execution_note: Mapped[str | None] = mapped_column(Text)
    verified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    verification_result: Mapped[str | None] = mapped_column(Text)


class AccessApproval(Base):
    """Every step decision and lifecycle event of an access request (append-only)."""
    __tablename__ = "access_approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[int] = mapped_column(ForeignKey("access_requests.id"), index=True)
    step_key: Mapped[str] = mapped_column(String(32))
    step_label: Mapped[str] = mapped_column(String(128))
    decision: Mapped[str] = mapped_column(String(24))
    actor: Mapped[str] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AccessReview(TimestampMixin, Base):
    __tablename__ = "access_reviews"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    provider: Mapped[str | None] = mapped_column(String(16))
    scope_external_id: Mapped[str | None] = mapped_column(String(128))
    privileged_only: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewer: Mapped[str] = mapped_column(String(255))
    due_date: Mapped[date] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(16), default="OPEN")  # OPEN | COMPLETED
    created_by: Mapped[str] = mapped_column(String(255))
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AccessReviewItem(TimestampMixin, Base):
    __tablename__ = "access_review_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    review_id: Mapped[int] = mapped_column(ForeignKey("access_reviews.id"), index=True)
    assignment_id: Mapped[int] = mapped_column(ForeignKey("access_assignments.id"))
    snapshot: Mapped[dict] = mapped_column(JSONType)             # assignment as it was when the review started
    decision: Mapped[str | None] = mapped_column(String(24))     # KEEP | REMOVE | REDUCE | INVESTIGATE
    comment: Mapped[str | None] = mapped_column(Text)
    remediation_owner: Mapped[str | None] = mapped_column(String(255))
    decided_by: Mapped[str | None] = mapped_column(String(255))
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    follow_up_request_id: Mapped[int | None] = mapped_column(Integer)


class AccessAuditEvent(Base):
    __tablename__ = "access_audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    grant_id: Mapped[int | None] = mapped_column(Integer, index=True)
    request_id: Mapped[int | None] = mapped_column(Integer, index=True)
    action: Mapped[str] = mapped_column(String(48))
    actor: Mapped[str] = mapped_column(String(255))
    detail: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


for _m in (AccessApproval, AccessAuditEvent):
    make_immutable(_m)
