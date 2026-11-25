"""Vulnerability management, CSPM, audit investigation and security synchronisation.

Native cloud findings (AWS Security Hub, Azure Advisor, Google Security Command Center) live in
`cloud_security_findings`. They are separate from `security_findings`, which holds the platform's own rule-based
detections from audit logs.

Two independent states are kept on every finding and never overwrite each other:
  * native_state / native_workflow_status - what the cloud provider reports, refreshed by every sync;
  * internal_status - the platform workflow (OPEN, UNDER_REVIEW, EXCEPTION, RESOLVED, REOPENED, FALSE_POSITIVE),
    changed only by a person or by an explicit, recorded reconciliation rule.
History, comments, evidence and approvals are append-only.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import Boolean, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, JSONType, TimestampMixin, UTCDateTime, make_immutable, utcnow


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    UNDER_REVIEW = "UNDER_REVIEW"
    EXCEPTION = "EXCEPTION"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class NativeState(StrEnum):
    ACTIVE = "ACTIVE"            # provider reports the issue as present
    RESOLVED = "RESOLVED"        # provider reports it fixed / passed / inactive / archived
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SUPPRESSED = "SUPPRESSED"    # muted / suppressed in the provider; still stored


class ExceptionStatus(StrEnum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ACTIVE = "ACTIVE"            # approved and not expired
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CLOSED = "CLOSED"


class AuditClass(StrEnum):
    """Outcome of the rule engine for every collected audit event."""
    NORMAL = "NORMAL"                    # no rule matched: retained, no investigation
    AUTHORIZED = "AUTHORIZED"            # covered by an approved, scoped authorization rule
    RULE_VIOLATION = "RULE_VIOLATION"    # a violation rule matched: flagged, case opened
    SUSPICIOUS = "SUSPICIOUS"            # a threshold / pattern rule matched: flagged for review, case per threshold
    REVIEW_REQUIRED = "REVIEW_REQUIRED"  # needs manual validation: review queue, no incident declared


FLAGGED = (AuditClass.RULE_VIOLATION.value, AuditClass.SUSPICIOUS.value, AuditClass.REVIEW_REQUIRED.value)


DISPOSITIONS = {
    "suspicious": "Suspicious activity (under review)",
    "confirmed_malicious": "Confirmed malicious activity",
    "expected_legitimate": "Expected / legitimate activity",
    "approved_admin": "Approved administrative activity",
    "false_positive": "False positive",
    "insufficient_evidence": "Insufficient evidence",
}


class AuditStatus(StrEnum):
    """Investigation workflow: only flagged events have one."""
    DETECTED = "DETECTED"
    AUTHORIZED = "AUTHORIZED"
    REVIEWING = "REVIEWING"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    NO_ACTION_REQUIRED = "NO_ACTION_REQUIRED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


class SyncStatus(StrEnum):
    SCHEDULED = "SCHEDULED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    RETRYING = "RETRYING"


class CloudSecurityFinding(TimestampMixin, Base):
    __tablename__ = "cloud_security_findings"
    __table_args__ = (
        UniqueConstraint("provider", "native_id_hash", name="uq_csf_provider_native"),
        Index("ix_csf_scope", "provider", "scope_external_id"),
        Index("ix_csf_status_sev", "internal_status", "severity"),
        Index("ix_csf_due", "sla_due_at"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(48))            # security_hub | azure_advisor | scc
    is_security: Mapped[bool] = mapped_column(Boolean, default=True, index=True)  # False: Advisor cost/reliability/performance/operational
    native_id: Mapped[str] = mapped_column(Text)               # full provider ID (ARNs and SCC names can exceed index limits)
    native_id_hash: Mapped[str] = mapped_column(String(64))    # sha256 of native_id: the stable, indexable identity
    scope_external_id: Mapped[str] = mapped_column(String(128))  # AWS account / Azure subscription / GCP project
    organization_id: Mapped[str | None] = mapped_column(String(128))  # AWS org / Azure tenant / GCP organization
    parent_id: Mapped[str | None] = mapped_column(String(255))  # management group / folder, when known
    region: Mapped[str | None] = mapped_column(String(64), index=True)
    resource_id: Mapped[str | None] = mapped_column(Text)
    resource_name: Mapped[str | None] = mapped_column(String(512))
    resource_type: Mapped[str | None] = mapped_column(String(255), index=True)
    resource_group: Mapped[str | None] = mapped_column(String(255))
    title: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)  # Critical | High | Medium | Low | Informational
    category: Mapped[str | None] = mapped_column(String(128), index=True)
    finding_type: Mapped[str | None] = mapped_column(String(512))
    compliance_standard: Mapped[str | None] = mapped_column(String(512))
    control_id: Mapped[str | None] = mapped_column(String(128))
    remediation: Mapped[str | None] = mapped_column(Text)
    remediation_url: Mapped[str | None] = mapped_column(String(1024))
    native_state: Mapped[str] = mapped_column(String(24), default=NativeState.ACTIVE.value, index=True)
    native_workflow_status: Mapped[str | None] = mapped_column(String(64))  # e.g. Security Hub Workflow.Status, Azure status code
    native_record_state: Mapped[str | None] = mapped_column(String(64))     # e.g. Security Hub RecordState, SCC state
    mute_state: Mapped[str | None] = mapped_column(String(32))
    first_observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_observed_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    native_updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    native_resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    first_synced_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_synced_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    environment: Mapped[str | None] = mapped_column(String(64))
    # internal workflow (never written by a sync except the recorded reappearance rule)
    internal_status: Mapped[str] = mapped_column(String(24), default=FindingStatus.OPEN.value)
    owner: Mapped[str | None] = mapped_column(String(255), index=True)
    analyst: Mapped[str | None] = mapped_column(String(255))
    sla_due_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    sla_paused: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    resolved_by: Mapped[str | None] = mapped_column(String(255))
    reopen_count: Mapped[int] = mapped_column(Integer, default=0)
    needs_reassessment: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_analysis: Mapped[dict | None] = mapped_column(JSONType)
    raw: Mapped[dict] = mapped_column(JSONType, default=dict)


class FindingStatusHistory(Base):
    __tablename__ = "finding_status_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("cloud_security_findings.id"), index=True)
    field: Mapped[str] = mapped_column(String(32), default="internal_status")  # internal_status | owner | analyst | native_state | sla
    previous_value: Mapped[str | None] = mapped_column(String(255))
    new_value: Mapped[str | None] = mapped_column(String(255))
    actor: Mapped[str] = mapped_column(String(255))     # user email, or "sync" for a recorded reconciliation
    reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class FindingComment(Base):
    __tablename__ = "finding_comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("cloud_security_findings.id"), index=True)
    kind: Mapped[str] = mapped_column(String(24), default="comment")  # comment | investigation_note | verification_request
    author: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class SecurityEvidence(Base):
    """Remediation evidence (findings) and audit evidence (audit events, cases). Files are stored outside the database."""
    __tablename__ = "security_evidence"
    __table_args__ = (Index("ix_evidence_subject", "subject_type", "subject_id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(24))  # finding | audit_event | case | exception
    subject_id: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(16))          # file | link | ticket | text
    name: Mapped[str] = mapped_column(String(255))
    reference: Mapped[str | None] = mapped_column(String(1024))  # URL, ticket ID, or stored file name
    sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(128))
    note: Mapped[str | None] = mapped_column(Text)
    uploaded_by: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class FindingException(TimestampMixin, Base):
    __tablename__ = "finding_exceptions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("cloud_security_findings.id"), index=True)
    status: Mapped[str] = mapped_column(String(24), default=ExceptionStatus.PENDING_APPROVAL.value, index=True)
    business_justification: Mapped[str] = mapped_column(Text)
    risk_acceptance: Mapped[str] = mapped_column(Text)
    business_impact: Mapped[str | None] = mapped_column(Text)
    compensating_controls: Mapped[str | None] = mapped_column(Text)
    risk_owner: Mapped[str] = mapped_column(String(255))
    technical_owner: Mapped[str | None] = mapped_column(String(255))
    requester: Mapped[str] = mapped_column(String(255))
    approver: Mapped[str | None] = mapped_column(String(255))
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    decision_notes: Mapped[str | None] = mapped_column(Text)
    previous_internal_status: Mapped[str | None] = mapped_column(String(24))
    expiry_notified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class ExceptionApproval(Base):
    __tablename__ = "exception_approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    exception_id: Mapped[int] = mapped_column(ForeignKey("finding_exceptions.id"), index=True)
    action: Mapped[str] = mapped_column(String(24))  # requested | approved | rejected | expired | closed | renewal_requested
    actor: Mapped[str] = mapped_column(String(255))
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class SecuritySlaPolicy(TimestampMixin, Base):
    __tablename__ = "security_sla_policies"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    severity: Mapped[str] = mapped_column(String(16), unique=True)
    target_hours: Mapped[int] = mapped_column(Integer)
    pause_on_exception: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[str | None] = mapped_column(String(255))


class AuditStatusHistory(Base):
    __tablename__ = "audit_status_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_event_id: Mapped[int] = mapped_column(ForeignKey("audit_events.id"), index=True)
    previous_status: Mapped[str | None] = mapped_column(String(24))
    new_status: Mapped[str] = mapped_column(String(24))
    actor: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict] = mapped_column(JSONType, default=dict)  # authorization reference, ticket, validity, rule id
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AuditInvestigation(TimestampMixin, Base):
    """Rule-engine evaluation of one audit event (1:1 with audit_events) and, for flagged events only, its investigation."""
    __tablename__ = "audit_investigations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_event_id: Mapped[int] = mapped_column(ForeignKey("audit_events.id"), unique=True)
    classification: Mapped[str] = mapped_column(String(24), index=True)  # AuditClass
    category: Mapped[str | None] = mapped_column(String(64), index=True)  # activity category (IAM change, firewall change, ...)
    matched_rules: Mapped[list] = mapped_column(JSONType, default=list)   # [{id, name, severity, action, explanation}]
    severity: Mapped[str | None] = mapped_column(String(16), index=True)  # highest matched rule severity
    explanation: Mapped[str | None] = mapped_column(Text)
    evaluated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    status: Mapped[str | None] = mapped_column(String(24), index=True)    # AuditStatus; NULL for NORMAL / AUTHORIZED events
    detected_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    investigator: Mapped[str | None] = mapped_column(String(255), index=True)
    authorized_by: Mapped[str | None] = mapped_column(String(255))
    authorization_reason: Mapped[str | None] = mapped_column(Text)
    authorization_reference: Mapped[str | None] = mapped_column(String(255))
    change_ticket: Mapped[str | None] = mapped_column(String(255))
    authorized_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    authorization_rule_id: Mapped[int | None] = mapped_column(Integer)
    closure_reason: Mapped[str | None] = mapped_column(Text)
    escalated_to: Mapped[str | None] = mapped_column(String(64))
    case_id: Mapped[int | None] = mapped_column(Integer, index=True)
    ai_analysis: Mapped[dict | None] = mapped_column(JSONType)


class AuditNote(Base):
    __tablename__ = "audit_notes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    subject_type: Mapped[str] = mapped_column(String(16), default="audit_event")  # audit_event | case
    subject_id: Mapped[int] = mapped_column(Integer, index=True)
    author: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class DetectionRule(TimestampMixin, Base):
    """Administrator-defined audit detection rule. `conditions` is a tree of all / any / not over event attributes."""
    __tablename__ = "audit_detection_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_key: Mapped[str] = mapped_column(String(64), unique=True)   # stable human-readable rule ID, e.g. AUD-001
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    provider: Mapped[str | None] = mapped_column(String(16))          # NULL = any cloud
    category: Mapped[str | None] = mapped_column(String(64))
    conditions: Mapped[dict] = mapped_column(JSONType, default=dict)
    action: Mapped[str] = mapped_column(String(24))                   # RULE_VIOLATION | SUSPICIOUS | REVIEW_REQUIRED
    severity: Mapped[str] = mapped_column(String(16))
    threshold_count: Mapped[int] = mapped_column(Integer, default=1)  # matches needed within the window to fire
    threshold_window_minutes: Mapped[int] = mapped_column(Integer, default=0)
    group_by: Mapped[str] = mapped_column(String(32), default="principal")  # principal | source_ip | resource_id | scope
    change_window: Mapped[dict | None] = mapped_column(JSONType)      # {"days":[0-6], "start":"09:00", "end":"18:00", "tz":"Asia/Kolkata"}
    approved_change_reference: Mapped[str | None] = mapped_column(String(255))
    create_case: Mapped[bool] = mapped_column(Boolean, default=True)
    notify: Mapped[bool] = mapped_column(Boolean, default=False)
    owner: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[str | None] = mapped_column(String(255))
    # SOC library metadata (migration 0012)
    soc_category: Mapped[str | None] = mapped_column(String(2))         # A..G, see services/audit/soc_library.py
    mitre: Mapped[list | None] = mapped_column(JSONType)                # [{"id": "T1098.003", "name": "..."}]
    investigation_steps: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    exclusions: Mapped[list | None] = mapped_column(JSONType)           # conditions; any match = not a detection (provider-managed, approved)
    data_requirements: Mapped[list | None] = mapped_column(JSONType)    # e.g. ["aws_read_events"]: rule only fires when that data is collected
    last_triggered_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    match_count: Mapped[int] = mapped_column(Integer, default=0)


class DetectionRuleHistory(Base):
    """Every create / change / enable / disable of a detection rule, with the full rule as it was saved."""
    __tablename__ = "audit_rule_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("audit_detection_rules.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(24))  # created | updated | enabled | disabled
    actor: Mapped[str] = mapped_column(String(255))
    snapshot: Mapped[dict] = mapped_column(JSONType)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AuthorizationRule(TimestampMixin, Base):
    """An explicitly approved, scoped rule that authorizes matching future events. Never created automatically."""
    __tablename__ = "authorization_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    provider: Mapped[str | None] = mapped_column(String(16))
    scope_external_id: Mapped[str | None] = mapped_column(String(128))
    actor: Mapped[str] = mapped_column(String(512))          # exact principal; wildcards are not allowed
    operation: Mapped[str] = mapped_column(String(255))      # exact API operation
    resource_prefix: Mapped[str | None] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(Text)
    approval_reference: Mapped[str] = mapped_column(String(255))
    approved_by: Mapped[str] = mapped_column(String(255))
    valid_from: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    valid_until: Mapped[datetime] = mapped_column(UTCDateTime)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class InvestigationCase(TimestampMixin, Base):
    __tablename__ = "investigation_cases"
    __table_args__ = (UniqueConstraint("correlation_key", name="uq_case_correlation"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(24), default="DETECTED", index=True)  # AuditStatus, or PROPOSED for correlation suggestions
    origin: Mapped[str] = mapped_column(String(24))  # detection_rule | correlation | ai | manual
    rule_id: Mapped[int | None] = mapped_column(Integer)
    correlation_key: Mapped[str | None] = mapped_column(String(255))
    correlation_type: Mapped[str | None] = mapped_column(String(32))  # actor | resource | ip | account | finding
    actor: Mapped[str | None] = mapped_column(String(512))
    provider: Mapped[str | None] = mapped_column(String(16))
    scope_external_id: Mapped[str | None] = mapped_column(String(128))
    risk: Mapped[str] = mapped_column(String(16), default="Medium")
    risk_assessment: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(255))
    outcome: Mapped[str | None] = mapped_column(Text)
    validated_by: Mapped[str | None] = mapped_column(String(255))
    event_ids: Mapped[list] = mapped_column(JSONType, default=list)
    resources: Mapped[list] = mapped_column(JSONType, default=list)
    finding_ids: Mapped[list] = mapped_column(JSONType, default=list)
    closure_reason: Mapped[str | None] = mapped_column(Text)
    first_event_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_event_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    # analyst conclusion, separate from the workflow status (migration 0012)
    disposition: Mapped[str | None] = mapped_column(String(32))   # see DISPOSITIONS
    confidence: Mapped[str | None] = mapped_column(String(8))     # High | Medium | Low (how strongly the rule indicates a real issue)
    summary: Mapped[str | None] = mapped_column(Text)             # generated investigation summary
    notified_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class SyncRun(Base):
    __tablename__ = "synchronization_history"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    execution_id: Mapped[int | None] = mapped_column(Integer)
    trigger: Mapped[str] = mapped_column(String(16))   # schedule | manual | retry
    triggered_by: Mapped[str | None] = mapped_column(String(255))
    mode: Mapped[str] = mapped_column(String(16))      # full | incremental | retry
    status: Mapped[str] = mapped_column(String(24), default=SyncStatus.RUNNING.value, index=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    counts: Mapped[dict] = mapped_column(JSONType, default=dict)   # retrieved/new/updated/resolved/reappeared + per provider coverage
    errors: Mapped[list] = mapped_column(JSONType, default=list)   # [{provider, scope, region, kind, message}]


class SyncCheckpoint(TimestampMixin, Base):
    """Per (provider, source, scope, region): coverage, the incremental watermark and the last error."""
    __tablename__ = "synchronization_checkpoints"
    __table_args__ = (UniqueConstraint("provider", "source", "scope_external_id", "region", name="uq_sync_checkpoint"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(48))
    scope_external_id: Mapped[str] = mapped_column(String(128))
    region: Mapped[str] = mapped_column(String(64), default="global")
    state: Mapped[str] = mapped_column(String(24))  # OK | PARTIALLY_CONFIGURED | ACCESS_DENIED | NOT_ENABLED | ERROR
    watermark: Mapped[datetime | None] = mapped_column(UTCDateTime)  # provider "updated at" high-water mark
    last_attempt_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_full_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    findings_seen: Mapped[int] = mapped_column(Integer, default=0)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)


class NotificationRule(TimestampMixin, Base):
    __tablename__ = "notification_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_type: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    channels: Mapped[str] = mapped_column(String(64), default="email,google_chat")
    updated_by: Mapped[str | None] = mapped_column(String(255))


class NotificationKey(Base):
    """One row per notification already queued: stops the same alert being sent twice."""
    __tablename__ = "notification_dedup"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(255), unique=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


for _m in (FindingStatusHistory, FindingComment, SecurityEvidence, ExceptionApproval, AuditStatusHistory, AuditNote, DetectionRuleHistory):
    make_immutable(_m)

APPEND_ONLY_TABLES = ("finding_status_history", "finding_comments", "security_evidence", "exception_approvals",
                      "audit_status_history", "audit_notes", "audit_rule_history")
