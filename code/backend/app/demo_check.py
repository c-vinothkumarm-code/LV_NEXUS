"""Demo-readiness check: pre-flight + dry run, ending in one PASS or FAIL.

    python -m app.demo_check                       # pre-flight + dry run of every collection workflow
    python -m app.demo_check --jobs billing_refresh,access_inventory
    python -m app.demo_check --preflight-only

Pre-flight reads the real database and makes read-only calls to each cloud. The dry run executes the collection
workflows for real (read-only provider APIs) but writes their results into a throw-away SQLite copy of the scope list,
with notifications, e-mail, Chat and Sheets switched off, so the production database is never touched and nobody is
messaged. The verdict is PASS only if pre-flight has no FAIL and every workflow finished with status success; a partial
run is a FAIL by default (data would be incomplete in the demo) unless --allow-partial is given. A report without secrets
(e-mails / IPs masked) is written to demo_check_report.md."""
from __future__ import annotations

import argparse
import sys
import tempfile
import time
from pathlib import Path

from sqlalchemy import create_engine, insert, select, update
from sqlalchemy.orm import sessionmaker

DRY_RUN_JOBS = ["account_discovery", "resource_inventory", "vm_metrics", "billing_refresh", "cost_detail_refresh", "security_events",
                "entra_activity", "access_inventory", "security_findings_sync", "anomaly_detection"]


def _copy_reference(src, dst) -> int:
    from app.models import SCOPE_MODELS
    from app.models.automation import CloudConnection
    n = 0
    for model in [*SCOPE_MODELS.values(), CloudConnection]:
        cols = [c.key for c in model.__table__.columns]
        rows = [{c: getattr(o, c) for c in cols} for o in src.scalars(select(model))]
        if model is CloudConnection:
            dst.execute(model.__table__.delete())
        if rows:
            dst.execute(insert(model), rows)
            n += len(rows)
    dst.commit()
    return n


def dry_run(settings, jobs: list[str], out=print) -> list[dict]:
    from app.database.seed import seed_reference_data
    from app.database.session import get_session_factory
    from app.models import NotificationRule
    from app.models.base import Base
    from app.scheduler.engine import run_job
    from app.services.connections import effective_settings
    from app.workers.jobs import JOB_FUNCTIONS, job_ready

    tmp = Path(tempfile.mkdtemp(prefix="cloudnexus-dryrun-")) / "dry_run.db"
    engine = create_engine(f"sqlite+pysqlite:///{tmp}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as dst, get_session_factory()() as src:
        seed_reference_data(dst)
        dst.commit()
        copied = _copy_reference(src, dst)
        dst.execute(update(NotificationRule).values(enabled=False))  # nobody is messaged from a dry run
        dst.commit()
    out(f"Dry run database: {tmp} ({copied} scopes / connections copied; production database untouched)")
    quiet = settings.model_copy(update={"dry_run": True, "sheets_enabled": False, "notify_email_enabled": False, "chat_webhook_url": None})
    results = []
    for name in jobs:
        eff = None
        with factory() as db:
            eff = effective_settings(db, quiet)
        if not job_ready(eff, name):
            results.append({"job": name, "status": "skipped", "verdict": "SKIP", "seconds": 0, "problems": ["not enabled / not configured"]})
            out(f"  SKIP  {name:24s} not enabled or not configured")
            continue
        t0 = time.monotonic()
        entry = run_job(factory, name, lambda ctx, n=name: JOB_FUNCTIONS[n](ctx, effective_settings(ctx.db, quiet)), trigger="manual",
                        triggered_by="demo_check", lock_ttl=3600)
        secs = round(time.monotonic() - t0, 1)
        problems = ([entry.error] if entry.error else []) + [f"{f.get('provider')} {f.get('scope')}: {f.get('reason')}" for f in (entry.failures or [])]
        verdict = {"success": "PASS", "partial": "PARTIAL"}.get(entry.status, "FAIL")
        results.append({"job": name, "status": entry.status, "verdict": verdict, "seconds": secs, "scopes": entry.scopes_total,
                        "scopes_failed": entry.scopes_failed, "problems": problems[:10]})
        out(f"  {verdict:7s} {name:24s} {entry.status:8s} {entry.scopes_failed or 0}/{entry.scopes_total or 0} scopes failed  {secs}s")
        for p in problems[:3]:
            out(f"          - {p[:220]}")
    return results


def main(argv: list[str] | None = None) -> int:
    from app.core.config import get_settings
    from app.core.logging import mask, redact
    from app.database.session import get_session_factory
    from app.services.preflight import FAIL, run_preflight

    ap = argparse.ArgumentParser(description="LV NEXUS demo-readiness check (pre-flight + dry run)")
    ap.add_argument("--jobs", help="comma-separated workflows for the dry run (default: all collection workflows)")
    ap.add_argument("--preflight-only", action="store_true")
    ap.add_argument("--allow-partial", action="store_true", help="treat partially completed workflows as a pass")
    ap.add_argument("--report", default="demo_check_report.md")
    a = ap.parse_args(argv)
    lines: list[str] = []

    def out(s: str = "") -> None:
        s = mask(redact(s))
        print(s)
        lines.append(s)

    settings = get_settings()
    out("== LV NEXUS demo-readiness check ==")
    out("1. Pre-flight (read-only)")
    with get_session_factory()() as db:
        pre = run_preflight(db, settings)
    for c in pre["checks"]:
        where = " / ".join(x for x in (c["cloud"], c["scope"]) if x) or c["area"]
        out(f"  {c['status']:4s}  {where[:40]:40s} {c['check']}: {c['message'][:160]}")
        if c["fix"]:
            out(f"        Fix: {c['fix'][:220]}")
    out(f"  Pre-flight: {pre['verdict']}  ({pre['counts']['PASS']} pass, {pre['counts']['WARN']} warn, {pre['counts']['FAIL']} fail)")
    results: list[dict] = []
    if not a.preflight_only:
        out("2. Dry run (real read-only collection into a throw-away database, no messages)")
        results = dry_run(settings, a.jobs.split(",") if a.jobs else DRY_RUN_JOBS, out)
    bad = [r for r in results if r["verdict"] == "FAIL" or (r["verdict"] == "PARTIAL" and not a.allow_partial)]
    verdict = "FAIL" if pre["verdict"] == FAIL or bad else "PASS"
    out()
    out(f"RESULT: {verdict}" + (f" — fix: {', '.join(r['job'] for r in bad)}" if bad else "") +
        (" — pre-flight has failing checks" if pre["verdict"] == FAIL else ""))
    Path(a.report).write_text("```\n" + "\n".join(lines) + "\n```\n", encoding="utf-8")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
