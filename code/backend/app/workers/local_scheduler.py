"""Local scheduler for development (run it in a VS Code terminal). It reads the job catalogue from the
database and starts each implemented, enabled job on its cron schedule in the job's own timezone.

In production the same jobs are started by a cloud scheduler calling `python -m app.workers.run <job>`.
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from croniter import croniter
from sqlalchemy import select

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.database.seed import seed_reference_data
from app.database.session import get_session_factory
from app.models import AutomationJob
from app.workers.jobs import JOB_FUNCTIONS, execute, job_ready

POLL_SECONDS = 20
log = logging.getLogger("local_scheduler")


def due_jobs(db, settings, now: datetime, last_fired: dict[str, datetime]) -> list[str]:
    """Jobs whose most recent scheduled time has not been run yet in this scheduler session."""
    due = []
    for job in db.scalars(select(AutomationJob).where(AutomationJob.enabled.is_(True), AutomationJob.implemented.is_(True)).order_by(AutomationJob.id)):
        if job.name not in JOB_FUNCTIONS or not job.schedule or not job_ready(settings, job.name):
            continue
        local = now.astimezone(ZoneInfo(job.schedule_timezone))
        slot = croniter(job.schedule, local + timedelta(seconds=1)).get_prev(datetime)  # a slot is due from its exact minute
        if last_fired.get(job.name) != slot:
            last_fired[job.name] = slot
            due.append(job.name)
    return due


def main() -> None:
    """Runs until stopped. A database outage or a failing job is logged and retried; it never ends the scheduler."""
    from app.services.connections import effective_settings

    configure_logging()
    base = get_settings()
    factory = get_session_factory()
    last_fired: dict[str, datetime] = {}
    while True:  # start-up: wait for the database instead of exiting
        try:
            with factory() as db:
                seed_reference_data(db)
                due_jobs(db, effective_settings(db, base), datetime.now(ZoneInfo("UTC")), last_fired)  # do not replay past slots
            break
        except Exception:  # noqa: BLE001
            log.exception("scheduler start-up failed; retrying in %ss", POLL_SECONDS)
            time.sleep(POLL_SECONDS)
    log.info("local scheduler started; %d jobs registered", len(last_fired))
    while True:
        try:
            with factory() as db:
                names = due_jobs(db, effective_settings(db, base), datetime.now(ZoneInfo("UTC")), last_fired)
        except Exception:  # noqa: BLE001 - e.g. the database restarted; try again next poll
            log.exception("could not read the job schedule; retrying in %ss", POLL_SECONDS)
            names = []
        for name in names:
            try:
                entry = execute(name)
                log.info("%s finished: %s (%d scopes, %d failed)", name, entry.status, entry.scopes_total, entry.scopes_failed)
            except Exception:  # noqa: BLE001 - the job engine records job errors; this catches infrastructure errors
                log.exception("%s could not be started", name)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
