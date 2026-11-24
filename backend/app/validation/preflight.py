"""Readiness checks that need no cloud call: configuration, database, migrations, triggers, scheduler, delivery."""
from __future__ import annotations

import sys
from pathlib import Path

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.database.triggers import IMMUTABLE_TABLES
from app.models import AutomationExecutionLog, CloudConnection, NotificationLog
from app.services import insights

from .report import FAIL, PASS, SKIP, WARN, Report

FREQ_MINUTES = {"security_events": 5, "account_discovery": 15, "vm_metrics": 15, "billing_refresh": 60}


def run_preflight(db: Session, s: Settings, for_review: bool = True) -> Report:
    r = Report("Platform preflight")
    r.add("P1", "Python version", PASS if sys.version_info[:2] >= (3, 13) else FAIL, sys.version.split()[0])
    try:
        db.execute(text("SELECT 1"))
        r.add("P2", "Database reachable", PASS, f"{db.bind.dialect.name} at {db.bind.url.host or 'local'} / {db.bind.url.database}")
    except Exception as exc:  # noqa: BLE001
        r.add("P2", "Database reachable", FAIL, str(exc).splitlines()[0][:200])
        return r
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    head = ScriptDirectory.from_config(Config(str(Path(__file__).resolve().parents[2] / "alembic.ini"))).get_current_head()
    try:
        current = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
    except Exception:  # noqa: BLE001 - no migration history at all
        db.rollback()
        current = None
    r.add("P3", "Schema migrations", PASS if current == head else FAIL,
          f"database at {current or 'no migration history'}, code expects {head}" + ("" if current == head else "; run python -m alembic upgrade head"))
    if db.bind.dialect.name == "mysql":
        n = db.execute(text("SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema = DATABASE() AND trigger_name LIKE '%_no_%'")).scalar()
        r.add("P4", "Append-only history triggers", PASS if n >= 2 * len(IMMUTABLE_TABLES) else FAIL,
              f"{n} of {2 * len(IMMUTABLE_TABLES)} triggers present" + ("" if n else "; run python -m app.database.triggers"))
    else:
        r.add("P4", "Append-only history triggers", SKIP, f"checked for MySQL only; dialect is {db.bind.dialect.name}")
    weak = s.secret_key == "change-me-local-only" or len(s.secret_key) < 32  # noqa: S105 - comparing with the known default
    if s.auth_mode == "dev":
        r.add("P5", "Sign-in", FAIL if for_review else WARN, "AUTH_MODE=dev: anyone reaching the app is an administrator (blocker B2)")
    else:
        from app.api.routes.auth import provider_ready
        r.add("P5", "Sign-in", PASS if provider_ready(s) and not weak else FAIL,
              f"AUTH_MODE={s.auth_mode}; provider configured: {provider_ready(s)}; session key strong: {not weak}; "
              f"allowed domains: {', '.join(s.allowed_email_domains) or 'none'}; auto-provision new users: {s.auth_auto_provision}")
    conn = db.scalar(select(CloudConnection).where(CloudConnection.provider == "azure"))
    if not s.azure_enabled:
        r.add("P6", "Azure connection", FAIL, "Azure is not enabled (Account Onboarding > Connect your clouds)")
    else:
        from app.services.azure.connector import AzureClients
        ident = AzureClients(s).identity_kind()
        test = (f"; last test {'passed' if conn.last_test_ok else 'FAILED'} at {conn.last_test_at:%Y-%m-%d %H:%M} UTC" if conn and conn.last_test_at else "; never tested")
        r.add("P6", "Azure connection", PASS if conn and conn.last_test_ok else WARN, f"tenant {s.azure_tenant_id}; identity: {ident}{test}")
    sched = insights.scheduler_status(db)
    r.add("P7", "Scheduler running unattended", {"active": PASS, "stale": FAIL, "never_run": FAIL}[sched["state"]],
          f"state {sched['state']}; last scheduled job start {sched['last_scheduled_run_at'] or 'never'}")
    fresh = insights.freshness(db)
    stale = []
    from datetime import UTC, datetime, timedelta
    for job, minutes in FREQ_MINUTES.items():
        t = fresh[job]["last_success_at"]
        if t is None or datetime.now(UTC) - datetime.fromisoformat(t) > timedelta(minutes=3 * minutes):
            stale.append(f"{job} (last success {t or 'never'})")
    r.add("P8", "Data freshness", PASS if not stale else FAIL, "all collection jobs fresh" if not stale else "stale: " + "; ".join(stale), freshness=fresh)
    failed_24h = db.scalar(select(func.count()).select_from(AutomationExecutionLog).where(
        AutomationExecutionLog.status == "failed", AutomationExecutionLog.started_at >= datetime.now(UTC) - timedelta(hours=24)))
    r.add("P9", "Failed jobs in the last 24 hours", PASS if not failed_24h else WARN, f"{failed_24h} failed run(s)")
    channels = [n for n, ok in (("Google Chat", bool(s.chat_webhook_url)), ("Email", s.notify_email_enabled and bool(s.gmail_sender))) if ok]
    undelivered = db.scalar(select(func.count()).select_from(NotificationLog).where(NotificationLog.status != "sent"))
    r.add("P10", "Notifications", PASS if channels else WARN, f"configured: {', '.join(channels) or 'none'} (blocker B4); {undelivered} message(s) not delivered")
    dist = Path(s.frontend_dist) if s.frontend_dist else None
    r.add("P11", "Dashboard served by the API", PASS if dist and (dist / "index.html").exists() else WARN,
          f"FRONTEND_DIST={s.frontend_dist}" if dist else "FRONTEND_DIST not set: the dashboard needs a separate npm process")
    r.add("P12", "Environment", PASS if s.app_env == "production" else WARN, f"APP_ENV={s.app_env}")
    return r
