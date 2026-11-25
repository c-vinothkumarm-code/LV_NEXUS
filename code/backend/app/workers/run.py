"""Batch entrypoint (Cloud Run Jobs, Azure Container Apps jobs, or a terminal):

    python -m app.workers.run account_discovery
    python -m app.workers.run --list
"""
from __future__ import annotations

import sys

from app.core.logging import configure_logging
from app.database.seed import seed_reference_data
from app.database.session import get_session_factory
from app.models import JobStatus
from app.workers.jobs import JOB_FUNCTIONS, execute


class _Jobs(dict):
    """name -> callable(trigger, triggered_by), kept for the API's manual-run endpoint."""

    def __missing__(self, name):
        raise KeyError(name)


JOBS = _Jobs({name: (lambda trigger="schedule", triggered_by=None, _n=name: execute(_n, trigger, triggered_by)) for name in JOB_FUNCTIONS})


def run_account_discovery(trigger: str = "schedule", triggered_by: str | None = None, session_factory=None):
    return execute("account_discovery", trigger, triggered_by, session_factory)


def main(argv: list[str]) -> int:
    configure_logging()
    if len(argv) == 2 and argv[1] == "--list":
        print("\n".join(JOB_FUNCTIONS))
        return 0
    if len(argv) != 2 or argv[1] not in JOB_FUNCTIONS:
        print(f"usage: python -m app.workers.run [{' | '.join(JOB_FUNCTIONS)}]", file=sys.stderr)
        return 2
    with get_session_factory()() as db:
        seed_reference_data(db)
    entry = execute(argv[1])
    print(f"{entry.job_name}: {entry.status} scopes={entry.scopes_total} failed={entry.scopes_failed}")
    if entry.error:
        print(f"  ERROR {entry.error}")
    for f in entry.failures or []:
        print(f"  FAILED {f.get('provider')}/{f.get('scope')}: {f.get('reason')}")
    # Non-zero exit for failed runs so the hosting scheduler retries and alerts; partial is reported, not retried.
    return 1 if entry.status == JobStatus.FAILED.value else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
