"""Finding workflow, risk exceptions, evidence and remediation SLA. Every change writes append-only history."""
from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    CloudSecurityFinding,
    ExceptionApproval,
    ExceptionStatus,
    FindingComment,
    FindingException,
    FindingStatus,
    FindingStatusHistory,
    SecurityEvidence,
    SecuritySlaPolicy,
    User,
)

from .notify import notify

S = FindingStatus
# EXCEPTION is entered only through an approved exception; RESOLVED / FALSE_POSITIVE are left only by reopening.
TRANSITIONS: dict[str, set[str]] = {
    S.OPEN: {S.UNDER_REVIEW, S.RESOLVED, S.FALSE_POSITIVE},
    S.UNDER_REVIEW: {S.OPEN, S.RESOLVED, S.FALSE_POSITIVE},
    S.REOPENED: {S.OPEN, S.UNDER_REVIEW, S.RESOLVED, S.FALSE_POSITIVE},
    S.RESOLVED: {S.REOPENED},
    S.FALSE_POSITIVE: {S.REOPENED},
    S.EXCEPTION: set(),
}
NEEDS_REASON = {S.RESOLVED, S.FALSE_POSITIVE, S.REOPENED}
OPEN_STATES = (S.OPEN.value, S.UNDER_REVIEW.value, S.REOPENED.value)


class WorkflowError(ValueError):
    """A request the workflow does not allow; the API answers 409 or 422 with this message."""


def now() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=UTC) if dt and dt.tzinfo is None else dt


def history(db: Session, f: CloudSecurityFinding, field: str, old, new, actor: str, reason: str | None = None) -> None:
    db.add(FindingStatusHistory(finding_id=f.id, field=field, previous_value=None if old is None else str(old)[:255],
                                new_value=None if new is None else str(new)[:255], actor=actor, reason=reason))


# ---------------------------------------------------------------------------------------------------------- SLA
def sla_hours(db: Session, severity: str) -> int | None:
    p = db.scalar(select(SecuritySlaPolicy).where(SecuritySlaPolicy.severity == severity))
    return p.target_hours if p else None


def apply_sla(db: Session, f: CloudSecurityFinding, actor: str = "sync", reason: str = "SLA policy") -> None:
    hours = sla_hours(db, f.severity)
    start = _aware(f.first_observed_at) or _aware(f.first_synced_at) or now()
    due = start + timedelta(hours=hours) if hours else None
    if _aware(f.sla_due_at) != due:
        history(db, f, "sla_due_at", f.sla_due_at.isoformat() if f.sla_due_at else None, due.isoformat() if due else None, actor, reason)
        f.sla_due_at = due


def is_overdue(f: CloudSecurityFinding, at: datetime | None = None) -> bool:
    return bool(f.sla_due_at and not f.sla_paused and f.internal_status in OPEN_STATES and _aware(f.sla_due_at) < (at or now()))


# ---------------------------------------------------------------------------------------------------------- workflow
def set_status(db: Session, f: CloudSecurityFinding, new: str, user: User, reason: str | None) -> None:
    new = FindingStatus(new)
    cur = FindingStatus(f.internal_status)
    if new == cur:
        raise WorkflowError(f"Finding is already {cur.value}")
    if new == S.EXCEPTION:
        raise WorkflowError("A finding becomes EXCEPTION only when a risk exception is approved")
    if new not in TRANSITIONS[cur]:
        raise WorkflowError(f"Cannot move from {cur.value} to {new.value}")
    if new in NEEDS_REASON and not (reason or "").strip():
        raise WorkflowError(f"A reason is required to mark the finding {new.value}")
    if new == S.FALSE_POSITIVE and not ({"exception:approve", "security:admin"} & user.permission_names):
        raise WorkflowError("Marking a false positive needs an exception approver or security administrator")
    history(db, f, "internal_status", cur.value, new.value, user.email, reason)
    f.internal_status = new.value
    if new == S.RESOLVED:
        f.resolved_at, f.resolved_by = now(), user.email
    if new == S.REOPENED:
        f.reopen_count = (f.reopen_count or 0) + 1
    if new in (S.OPEN, S.UNDER_REVIEW):
        f.needs_reassessment = False


def assign(db: Session, f: CloudSecurityFinding, field: str, value: str | None, actor: str) -> None:
    if field not in ("owner", "analyst"):
        raise WorkflowError("Only owner or analyst can be assigned")
    old = getattr(f, field)
    if old == value:
        return
    history(db, f, field, old, value, actor)
    setattr(f, field, value or None)


def comment(db: Session, f: CloudSecurityFinding, kind: str, body: str, author: str) -> FindingComment:
    if kind not in ("comment", "investigation_note", "verification_request"):
        raise WorkflowError("Unknown comment type")
    if not body.strip():
        raise WorkflowError("Comment is empty")
    c = FindingComment(finding_id=f.id, kind=kind, author=author, body=body.strip()[:20000])
    db.add(c)
    return c


# ---------------------------------------------------------------------------------------------------------- exceptions
def active_exception(db: Session, finding_id: int) -> FindingException | None:
    return db.scalar(select(FindingException).where(FindingException.finding_id == finding_id, FindingException.status.in_(
        [ExceptionStatus.PENDING_APPROVAL.value, ExceptionStatus.ACTIVE.value])))


def request_exception(db: Session, s: Settings, f: CloudSecurityFinding, data: dict, user: User) -> FindingException:
    if f.internal_status in (S.RESOLVED, S.FALSE_POSITIVE):
        raise WorkflowError(f"Finding is {f.internal_status}; reopen it before requesting an exception")
    if active_exception(db, f.id):
        raise WorkflowError("This finding already has a pending or active exception")
    just = (data.get("business_justification") or "").strip()
    risk = (data.get("risk_acceptance") or "").strip()
    if len(just) < 20 or len(risk) < 10:
        raise WorkflowError("A business justification (20+ characters) and a risk acceptance description are required")
    if not (data.get("risk_owner") or "").strip():
        raise WorkflowError("A risk owner is required")
    days = int(data.get("validity_days") or s.exception_default_days)
    if not 1 <= days <= s.exception_max_days:
        raise WorkflowError(f"Validity must be between 1 and {s.exception_max_days} days")
    e = FindingException(finding_id=f.id, business_justification=just, risk_acceptance=risk, business_impact=data.get("business_impact"),
                         compensating_controls=data.get("compensating_controls"), risk_owner=data["risk_owner"].strip(),
                         technical_owner=data.get("technical_owner"), requester=user.email, expires_at=now() + timedelta(days=days))
    db.add(e)
    db.flush()
    db.add(ExceptionApproval(exception_id=e.id, action="requested", actor=user.email, notes=f"validity {days} days"))
    history(db, f, "exception", None, f"#{e.id} PENDING_APPROVAL", user.email, just[:500])
    notify(db, "exception_pending", f"exc-{e.id}", f"[LV NEXUS] Exception #{e.id} awaiting approval: {f.title[:120]}",
           f"Finding #{f.id} ({f.severity}, {f.provider} {f.scope_external_id})\nRequested by {user.email}\nRisk owner {e.risk_owner}\n"
           f"Justification: {just[:800]}\nExpires (if approved): {e.expires_at:%Y-%m-%d}")
    return e


def decide_exception(db: Session, e: FindingException, f: CloudSecurityFinding, approve: bool, user: User, notes: str | None) -> None:
    if e.status != ExceptionStatus.PENDING_APPROVAL:
        raise WorkflowError(f"Exception is {e.status}, not pending approval")
    if "exception:approve" not in user.permission_names:
        raise WorkflowError("Only an exception approver can decide")
    if user.email == e.requester:
        raise WorkflowError("The requester cannot approve their own exception")
    if not approve and not (notes or "").strip():
        raise WorkflowError("A reason is required to reject an exception")
    e.approver, e.decision_notes = user.email, notes
    db.add(ExceptionApproval(exception_id=e.id, action="approved" if approve else "rejected", actor=user.email, notes=notes))
    if not approve:
        e.status = ExceptionStatus.REJECTED.value
        history(db, f, "exception", f"#{e.id} PENDING_APPROVAL", f"#{e.id} REJECTED", user.email, notes)
        return
    e.status, e.approved_at, e.previous_internal_status = ExceptionStatus.ACTIVE.value, now(), f.internal_status
    history(db, f, "internal_status", f.internal_status, S.EXCEPTION.value, user.email, f"Exception #{e.id} approved: {notes or ''}".strip())
    f.internal_status = S.EXCEPTION.value  # native_state is untouched: the risk is accepted, not removed
    policy = db.scalar(select(SecuritySlaPolicy).where(SecuritySlaPolicy.severity == f.severity))
    if policy and policy.pause_on_exception and not f.sla_paused:
        f.sla_paused = True
        history(db, f, "sla_paused", False, True, user.email, f"Paused by approved exception #{e.id} (policy)")


def end_exception(db: Session, e: FindingException, f: CloudSecurityFinding, status: str, actor: str, notes: str | None) -> None:
    """CLOSED by a person, or EXPIRED by the SLA job. The finding returns to OPEN for reassessment."""
    if e.status != ExceptionStatus.ACTIVE:
        raise WorkflowError(f"Exception is {e.status}, not active")
    e.status = status
    db.add(ExceptionApproval(exception_id=e.id, action=status.lower(), actor=actor, notes=notes))
    if f.internal_status == S.EXCEPTION:
        history(db, f, "internal_status", S.EXCEPTION.value, S.OPEN.value, actor, f"Exception #{e.id} {status.lower()}: reassessment required")
        f.internal_status, f.needs_reassessment = S.OPEN.value, True
    if f.sla_paused:
        f.sla_paused = False
        history(db, f, "sla_paused", True, False, actor, f"Exception #{e.id} {status.lower()}")


# ---------------------------------------------------------------------------------------------------------- evidence
def add_evidence(db: Session, s: Settings, subject_type: str, subject_id: int, data: dict, user: User) -> SecurityEvidence:
    kind = data.get("kind")
    name = (data.get("name") or "").strip()[:255]
    if kind not in ("file", "link", "ticket", "text") or not name:
        raise WorkflowError("Evidence needs a kind (file, link, ticket, text) and a name")
    ev = SecurityEvidence(subject_type=subject_type, subject_id=subject_id, kind=kind, name=name, note=data.get("note"), uploaded_by=user.email)
    if kind == "file":
        try:
            blob = base64.b64decode(data.get("content_base64") or "", validate=True)
        except Exception as exc:  # noqa: BLE001
            raise WorkflowError("File content must be base64") from exc
        if not blob or len(blob) > s.evidence_max_bytes:
            raise WorkflowError(f"File must be between 1 byte and {s.evidence_max_bytes // (1024 * 1024)} MB")
        digest = hashlib.sha256(blob).hexdigest()
        store = Path(s.evidence_dir)
        store.mkdir(parents=True, exist_ok=True)
        target = store / digest
        if not target.exists():
            target.write_bytes(blob)
        ev.reference, ev.sha256, ev.size_bytes = digest, digest, len(blob)
        ev.content_type = (data.get("content_type") or "application/octet-stream")[:128]
    else:
        ref = (data.get("reference") or "").strip()
        if not ref:
            raise WorkflowError("A link, ticket ID or text is required")
        if kind == "link" and not ref.lower().startswith(("https://", "http://")):
            raise WorkflowError("Links must start with https:// or http://")
        ev.reference = ref[:1024]
    db.add(ev)
    return ev


def evidence_path(s: Settings, ev: SecurityEvidence) -> Path | None:
    if ev.kind != "file" or not ev.sha256 or any(c not in "0123456789abcdef" for c in ev.sha256):
        return None
    p = Path(s.evidence_dir) / ev.sha256
    return p if p.exists() else None
