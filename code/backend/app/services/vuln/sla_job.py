"""Hourly: overdue findings, unassigned Critical findings, exception expiry and overdue investigations.
Notifications are de-duplicated per item and day, so an hourly run does not repeat them."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import AuditEvent, AuditInvestigation, CloudSecurityFinding, ExceptionStatus, FindingException, InvestigationCase, JobStatus
from app.scheduler.engine import JobContext, JobResult

from .lifecycle import OPEN_STATES, end_exception, is_overdue
from .notify import notify

ACTIVE_INVESTIGATION = ("DETECTED", "REVIEWING", "INVESTIGATING", "ESCALATED", "REOPENED")


def run_sla_check(ctx: JobContext, s: Settings) -> JobResult:
    db: Session = ctx.db
    now = datetime.now(UTC)
    day = now.strftime("%Y%m%d")
    c = {"overdue": 0, "unassigned_critical": 0, "exceptions_expiring": 0, "exceptions_expired": 0, "investigations_overdue": 0}
    for f in db.scalars(select(CloudSecurityFinding).where(CloudSecurityFinding.is_security.is_(True), CloudSecurityFinding.internal_status.in_(OPEN_STATES),
                                                           CloudSecurityFinding.sla_due_at.is_not(None))):
        if is_overdue(f, now):
            c["overdue"] += 1
            esc = " ESCALATION" if f.severity in ("Critical", "High") else ""
            notify(db, "finding_overdue", f"f{f.id}-{day}", f"[LV NEXUS]{esc} Overdue {f.severity} finding: {f.title[:140]}",
                   f"Finding #{f.id} was due {f.sla_due_at:%Y-%m-%d %H:%M} UTC.\nOwner: {f.owner or 'UNASSIGNED'}\n{f.provider.upper()} {f.scope_external_id}\n"
                   f"Resource: {f.resource_id or '-'}")
        created = f.first_synced_at if f.first_synced_at.tzinfo else f.first_synced_at.replace(tzinfo=UTC)
        if f.severity == "Critical" and not f.owner and created < now - timedelta(hours=s.critical_unassigned_hours):
            c["unassigned_critical"] += 1
            notify(db, "critical_unassigned", f"f{f.id}-{day}", f"[LV NEXUS] ESCALATION: Critical finding unassigned: {f.title[:140]}",
                   f"Finding #{f.id} has had no owner for more than {s.critical_unassigned_hours} hours.")
    for e in db.scalars(select(FindingException).where(FindingException.status == ExceptionStatus.ACTIVE.value)):
        exp = e.expires_at if e.expires_at.tzinfo else e.expires_at.replace(tzinfo=UTC)
        f = db.get(CloudSecurityFinding, e.finding_id)
        if exp <= now:
            end_exception(db, e, f, ExceptionStatus.EXPIRED.value, "system", "Validity period ended")
            c["exceptions_expired"] += 1
            notify(db, "exception_expired", f"exc{e.id}-expired", f"[LV NEXUS] Exception #{e.id} expired: reassessment required",
                   f"Finding #{f.id} ({f.severity}) {f.title[:200]}\nRisk owner {e.risk_owner}; approver {e.approver}.\nThe finding is OPEN again for reassessment.")
        elif exp <= now + timedelta(days=s.exception_expiry_notice_days):
            c["exceptions_expiring"] += 1
            if notify(db, "exception_expiring", f"exc{e.id}-expiring", f"[LV NEXUS] Exception #{e.id} expires {exp:%Y-%m-%d}",
                      f"Finding #{f.id} ({f.severity}) {f.title[:200]}\nRisk owner {e.risk_owner}; technical owner {e.technical_owner or '-'}; "
                      f"approver {e.approver}.\nRenew (new request) or remediate before expiry."):
                e.expiry_notified_at = now
    limit = now - timedelta(hours=s.investigation_sla_hours)
    for case in db.scalars(select(InvestigationCase).where(InvestigationCase.status.in_(ACTIVE_INVESTIGATION), InvestigationCase.created_at < limit)):
        c["investigations_overdue"] += 1
        notify(db, "investigation_overdue", f"case{case.id}-{day}", f"[LV NEXUS] ESCALATION: investigation #{case.id} open > {s.investigation_sla_hours} h",
               f"{case.title}\nStatus {case.status}; owner {case.owner or 'UNASSIGNED'}; risk {case.risk}")
    stale = db.scalar(select(AuditInvestigation.id).join(AuditEvent, AuditEvent.id == AuditInvestigation.audit_event_id)
                      .where(AuditInvestigation.status.in_(ACTIVE_INVESTIGATION), AuditInvestigation.case_id.is_(None),
                             AuditInvestigation.detected_at < limit).limit(1))
    if stale:
        c["review_queue_overdue"] = 1
    db.commit()
    return JobResult(JobStatus.SUCCESS, summary=c)
