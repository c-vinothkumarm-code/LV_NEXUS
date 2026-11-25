"""Monthly audit e-mails: one per account / subscription / project, on the 1st of the month, for the previous month.

TO = account SPOC; CC = entity lead, account owner, cloud admin, FinOps SPOC (when configured). Queued through the
existing notification queue (de-duplicated per scope and month, retried by the dispatcher, logged in NotificationLog).
A scope without an account SPOC e-mail is reported as not sent with the reason; it is never skipped silently."""
from __future__ import annotations

from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import safe_error
from app.models import SCOPE_MODELS, JobStatus, NotificationRule
from app.scheduler.engine import JobContext, JobResult
from app.services import ownership as OWN
from app.services.reports.audit_report import package, previous_month
from app.services.vuln.notify import notify

EVENT = "monthly_audit_report"


def ensure_rule(db: Session) -> None:
    if db.scalar(select(NotificationRule).where(NotificationRule.event_type == EVENT)) is None:
        db.add(NotificationRule(event_type=EVENT, description="Monthly Cloud Security & Governance Audit report per account (e-mail to the account SPOC)",
                                enabled=True, channels="email"))
        db.flush()


def send_one(db: Session, settings: Settings, provider: str, scope: str, month: date, execution_id: int | None = None) -> dict:
    ensure_rule(db)
    to, cc = OWN.recipients(OWN.get(db, provider, scope))
    if not to:
        return {"provider": provider, "scope": scope, "status": "not_sent", "reason": "no Account SPOC e-mail configured (Cloud Accounts → Ownership)"}
    pkg = package(db, settings, provider, scope, month)
    queued = notify(db, EVENT, f"{provider}:{scope}:{month:%Y-%m}", pkg["subject"], pkg["body"], execution_id,
                    recipients=[to, *[f"cc:{c}" for c in cc]], attachments=pkg["attachments"])
    return {"provider": provider, "scope": scope, "status": "queued" if queued else "already_sent", "to": to, "cc": cc, "subject": pkg["subject"],
            "attachments": [a["filename"] for a in pkg["attachments"]]}


def run_monthly_audit_reports(ctx: JobContext, settings: Settings) -> JobResult:
    month = previous_month()
    results, failures = [], []
    for provider, model in SCOPE_MODELS.items():
        for s in ctx.db.scalars(select(model)):
            if (getattr(s, "provider_state", "") or "").lower() in ("suspended", "disabled", "deleted", "closed", "delete_requested", "pending_closure"):
                continue
            try:
                r = send_one(ctx.db, settings, provider, s.external_id, month, getattr(ctx, "execution_id", None))
            except Exception as exc:  # noqa: BLE001 - one scope never stops the others
                r = {"provider": provider, "scope": s.external_id, "status": "failed", "reason": safe_error(exc, 300)}
            results.append(r)
            if r["status"] in ("failed", "not_sent"):
                failures.append({"scope": f"{provider}:{s.external_id}", "reason": r["reason"]})
            ctx.db.commit()
    queued = sum(r["status"] == "queued" for r in results)
    status = JobStatus.SUCCESS if not failures else JobStatus.PARTIAL if queued or any(r["status"] == "already_sent" for r in results) else JobStatus.FAILED
    if not results:
        status = JobStatus.SUCCESS
    return JobResult(status, len(results), len(failures), {"month": f"{month:%Y-%m}", "queued": queued,
                                                           "already_sent": sum(r["status"] == "already_sent" for r in results),
                                                           "not_sent": sum(r["status"] == "not_sent" for r in results)}, failures)
