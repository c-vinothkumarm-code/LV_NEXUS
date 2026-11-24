"""Job execution engine: overlap prevention, execution history, honest status reporting."""
from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.logging import safe_error
from app.models import AutomationExecutionLog, AutomationJob, JobStatus, utcnow

log = logging.getLogger(__name__)


@dataclass
class JobResult:
    status: JobStatus
    scopes_total: int = 0
    scopes_failed: int = 0
    summary: dict = field(default_factory=dict)
    failures: list[dict] = field(default_factory=list)


@dataclass
class JobContext:
    db: Session
    execution_id: int
    job: AutomationJob


def _acquire(db: Session, name: str, owner: str, ttl: int) -> bool:
    now = utcnow()
    res = db.execute(
        update(AutomationJob)
        .where(AutomationJob.name == name,
               or_(AutomationJob.lock_owner.is_(None), AutomationJob.lock_expires_at < now))
        .values(lock_owner=owner, lock_expires_at=now + timedelta(seconds=ttl))
        .execution_options(synchronize_session=False)
    )
    db.commit()
    return res.rowcount == 1


def run_job(session_factory: sessionmaker[Session], name: str, fn: Callable[[JobContext], JobResult], *,
            trigger: str = "schedule", triggered_by: str | None = None, lock_ttl: int = 840) -> AutomationExecutionLog:
    """Run `fn` as job `name`. Only one execution of a job can hold the lock at a time."""
    owner = uuid.uuid4().hex
    with session_factory() as db:
        job = db.scalar(select(AutomationJob).where(AutomationJob.name == name))
        if job is None:
            raise ValueError(f"Unknown job: {name}")
        if not _acquire(db, name, owner, lock_ttl):
            entry = AutomationExecutionLog(job_id=job.id, job_name=name, trigger=trigger, triggered_by=triggered_by,
                                           status=JobStatus.SKIPPED_OVERLAP.value, finished_at=utcnow(),
                                           error="Previous execution still running")
            db.add(entry)
            db.commit()
            return entry
        db.refresh(job)
        # A run still marked "running" now that we hold the lock was abandoned (process stopped, machine slept).
        for stale in db.scalars(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == name,
                                                                     AutomationExecutionLog.status == JobStatus.RUNNING.value)):
            stale.status, stale.finished_at = JobStatus.FAILED.value, utcnow()
            stale.error = "Abandoned: the process stopped before the run finished (recorded when the next run started)"
        entry = AutomationExecutionLog(job_id=job.id, job_name=name, trigger=trigger, triggered_by=triggered_by,
                                       status=JobStatus.RUNNING.value)
        db.add(entry)
        job.last_started_at = entry.started_at = utcnow()
        db.commit()
        from app.core.config import get_settings
        from app.services import reliability
        settings = get_settings()
        run, token = reliability.start_run(name, dry_run=settings.dry_run)
        for p in ("aws", "azure", "gcp"):
            run.guard(p).threshold = settings.circuit_breaker_threshold
        try:
            result = fn(JobContext(db=db, execution_id=entry.id, job=job))
            entry.status = result.status.value
            entry.scopes_total, entry.scopes_failed = result.scopes_total, result.scopes_failed
            entry.summary, entry.failures = {**(result.summary or {}), "run": run.report()}, result.failures
        except Exception as exc:  # noqa: BLE001 - a job must always record its failure
            db.rollback()
            log.exception("job %s failed", name)
            entry = db.get(AutomationExecutionLog, entry.id)
            job = db.get(AutomationJob, job.id)
            entry.status, entry.error = JobStatus.FAILED.value, safe_error(exc)
            entry.summary = {"run": run.report()}
        finally:
            reliability.end_run(token)
        rep = (entry.summary or {}).get("run", {})
        log.info('{"event": "job_finished", "job": "%s", "run_id": "%s", "status": "%s", "scopes_total": %d, "scopes_failed": %d, '
                 '"api_errors": %d, "retries": %d, "duration_ms": %d}', name, rep.get("run_id"), entry.status, entry.scopes_total or 0,
                 entry.scopes_failed or 0, rep.get("api_errors", 0), rep.get("retries", 0), rep.get("duration_ms", 0))
        entry.finished_at = job.last_finished_at = utcnow()
        job.last_status = entry.status
        db.execute(update(AutomationJob).where(AutomationJob.name == name, AutomationJob.lock_owner == owner)
                   .values(lock_owner=None, lock_expires_at=None).execution_options(synchronize_session=False))
        db.commit()
        db.refresh(entry)
        if entry.status in (JobStatus.FAILED.value, JobStatus.PARTIAL.value) and name not in ("notification_dispatch", "security_findings_sync"):
            try:
                alert_run_problem(db, name, entry)
                db.commit()
            except Exception:  # noqa: BLE001 - an alert problem must never change the recorded run result
                db.rollback()
                log.exception("could not queue the run-problem alert for %s", name)
        return entry


def alert_run_problem(db: Session, name: str, entry: AutomationExecutionLog) -> bool:
    """One alert per job, status and day when a run fails or only partly completes. Reasons are redacted and masked; the
    message states plainly that data may be incomplete (never a success message)."""
    from app.core.logging import mask, redact
    from app.services.vuln.notify import notify
    reasons = [f"- {f.get('provider') or '*'} {f.get('scope') or '*'}: {f.get('reason')}" for f in (entry.failures or [])[:5]]
    if entry.error:
        reasons.insert(0, f"- {entry.error}")
    more = len(entry.failures or []) - 5
    body = (f"The scheduled run of '{name}' {'FAILED' if entry.status == JobStatus.FAILED.value else 'only PARTLY completed'} "
            f"({entry.scopes_failed or 0} of {entry.scopes_total or 0} scopes failed). Data from the failed scopes may be out of date; "
            "the last good data is kept.\n" + "\n".join(reasons) + (f"\n... and {more} more" if more > 0 else "") +
            "\nOpen System health in LV NEXUS for the fix for each failing check.")
    day = (entry.finished_at or utcnow()).date().isoformat()
    return notify(db, "job_run_problem", f"{name}:{entry.status}:{day}", f"[LV NEXUS] {name}: run {entry.status}", mask(redact(body)),
                  execution_id=entry.id)
