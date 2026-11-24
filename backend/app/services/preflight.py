"""Pre-flight: one PASS / WARN / FAIL list that says whether the platform can collect everything, and how to fix what it
cannot. Every check is read-only (token requests, list calls, TCP connects); nothing is created or changed.

Checks
- platform: database reachable, schema at the latest migration, secrets source (Key Vault in production), no stuck runs
- per cloud: credentials work and the account / subscription / project list can be read (live), discovered vs. known scopes
- per scope and data source: the latest result of each collection (authentication, permissions, activity, cost, IAM,
  security, metrics) with the provider's reason and the fix
- integrations: Google Chat webhook and e-mail reachability, Google Sheets credentials (only when enabled)

A FAIL means data for that cloud / scope / source is missing or stale; the overall verdict is FAIL if any check fails."""
from __future__ import annotations

import os
import socket
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import safe_error
from app.models import SCOPE_MODELS, AutomationExecutionLog, AutomationJob, JobStatus
from app.services.reliability import FIX_HINTS

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
SECRET_ENV_OK = ("local", "development", "dev", "test")


def _check(area: str, name: str, status: str, message: str, fix: str | None = None, cloud: str | None = None, scope: str | None = None) -> dict:
    return {"area": area, "cloud": cloud, "scope": scope, "check": name, "status": status, "message": message, "fix": fix if status != PASS else None}


def fix_for(reason: str | None) -> str:
    r = (reason or "").lower()
    if "fix:" in r:
        return reason[r.index("fix:") + 4:].strip()
    for kind, words in (("auth_expired", ("expired", "401", "invalid_grant", "authentication", "credential")),
                        ("permission", ("denied", "403", "forbidden", "authorization", "permission", "not authorized")),
                        ("not_enabled", ("not enabled", "service_disabled", "has not been used", "subscriptionnotregistered", "not subscribed")),
                        ("throttle", ("throttl", "429", "rate exceeded", "too many")), ("timeout", ("timeout", "timed out"))):
        if any(w in r for w in words):
            return FIX_HINTS[kind]
    return "Open the run in Automation for the full error; re-run the collection after fixing it."


def _platform(db: Session, settings: Settings) -> list[dict]:
    from app.core import secrets
    out = []
    try:
        db.execute(text("SELECT 1"))
        out.append(_check("platform", "Database reachable", PASS, f"{db.bind.dialect.name} connection OK"))
    except Exception as exc:  # noqa: BLE001
        out.append(_check("platform", "Database reachable", FAIL, safe_error(exc), "Check DATABASE_URL and that the database server is running."))
        return out
    try:
        import pathlib

        from alembic.config import Config
        from alembic.runtime.migration import MigrationContext
        from alembic.script import ScriptDirectory
        cfg = Config(str(pathlib.Path(__file__).resolve().parents[2] / "alembic.ini"))
        cfg.set_main_option("script_location", str(pathlib.Path(__file__).resolve().parents[2] / "migrations"))
        head = ScriptDirectory.from_config(cfg).get_current_head()
        current = MigrationContext.configure(db.connection()).get_current_revision()
        if current is None and db.bind.dialect.name == "sqlite":
            out.append(_check("platform", "Database schema", WARN, "No migration version recorded (test / SQLite database)."))
        else:
            out.append(_check("platform", "Database schema", PASS if current == head else FAIL, f"current {current}, latest {head}",
                              "Run: alembic upgrade head (keeps existing data)."))
    except Exception as exc:  # noqa: BLE001
        out.append(_check("platform", "Database schema", WARN, f"Could not read the migration version: {safe_error(exc)}"))
    prod = settings.app_env not in SECRET_ENV_OK
    kv = secrets.STATUS
    if settings.azure_key_vault_url:
        out.append(_check("platform", "Secrets from Azure Key Vault", PASS if kv["state"] == "ok" else FAIL, kv["message"],
                          "Give the app identity 'Key Vault Secrets User' on the vault and check AZURE_KEY_VAULT_URL."))
    else:
        out.append(_check("platform", "Secrets from Azure Key Vault", FAIL if prod else PASS,
                          "AZURE_KEY_VAULT_URL is not set (required in production)" if prod
                          else "Not required for local use (APP_ENV=local): secrets come from backend/.env; Key Vault is required before production",
                          "Create the secrets listed in the README in Key Vault and set AZURE_KEY_VAULT_URL."))
    if prod:
        loose = [k for k, v in secrets.SOURCES.items() if v in ("dotenv", "environment")]
        if loose:
            out.append(_check("platform", "No secrets outside Key Vault", FAIL if any(secrets.SOURCES[k] == "dotenv" for k in loose) else WARN,
                              f"Read from {'.env' if any(secrets.SOURCES[k] == 'dotenv' for k in loose) else 'environment variables'}: {', '.join(loose)}",
                              "Move these values into Key Vault and remove them from .env / the environment."))
    stuck = list(db.scalars(select(AutomationExecutionLog).where(AutomationExecutionLog.status == JobStatus.RUNNING.value,
                                                                 AutomationExecutionLog.started_at < datetime.now(UTC) - timedelta(hours=3))))
    out.append(_check("platform", "No stuck runs", WARN if stuck else PASS,
                      f"{len(stuck)} run(s) marked running for more than 3 hours: {', '.join(sorted({s.job_name for s in stuck}))}" if stuck else "none",
                      "Restart the worker; the next run of each job records the abandoned run as failed."))
    return out


def _clouds(settings: Settings, db: Session, connectors: list | None) -> list[dict]:
    from app.services.registry import build_connectors
    out = []
    enabled = {"aws": settings.aws_enabled, "azure": settings.azure_enabled, "gcp": settings.gcp_enabled}
    if not any(enabled.values()):
        return [_check("cloud", "Cloud connections", FAIL, "No cloud is enabled (AWS_ENABLED / AZURE_ENABLED / GCP_ENABLED).",
                       "Enable and configure at least one cloud under Cloud connections.")]
    conns = {c.provider: c for c in (connectors if connectors is not None else build_connectors(settings))}
    for p, on in enabled.items():
        if not on:
            # A cloud switched off in the configuration is out of scope by decision, not a defect; it is stated plainly.
            out.append(_check("cloud", "In scope", PASS, f"Not in scope ({p.upper()}_ENABLED=false): no data is collected for this cloud.",
                              f"Set {p.upper()}_ENABLED=true and its credentials if it should be covered.", cloud=p))
            continue
        if p == "gcp" and settings.gcp_credentials_file and not os.path.isfile(settings.gcp_credentials_file):
            out.append(_check("cloud", "Credential file", FAIL, f"GCP_CREDENTIALS_FILE points to a file that does not exist ({os.path.basename(settings.gcp_credentials_file)})",
                              "Copy the key / federation file to that path, readable only by the service account running LV NEXUS.", cloud=p))
            continue
        c = conns.get(p)
        missing = c.missing_configuration() if c else ["connector"]
        if missing:
            out.append(_check("cloud", "Configuration", FAIL, f"Missing settings: {', '.join(missing)}", "Fill these in under Cloud connections.", cloud=p))
            continue
        known = {s.external_id for s in db.scalars(select(SCOPE_MODELS[p]))}
        try:
            found = {s.external_id for s in c.discover()}
            out.append(_check("cloud", "Credentials and discovery", PASS, f"Credentials work; {len(found)} {'accounts' if p == 'aws' else 'subscriptions' if p == 'azure' else 'projects'} visible",
                              cloud=p))
            gone = known - found
            if gone:
                out.append(_check("cloud", "All known scopes visible", WARN, f"{len(gone)} known scope(s) not returned now: {', '.join(sorted(gone)[:5])}",
                                  "Check whether access to these scopes was removed (they are not treated as deleted).", cloud=p))
        except Exception as exc:  # noqa: BLE001
            reason = safe_error(exc)
            out.append(_check("cloud", "Credentials and discovery", FAIL, reason, fix_for(reason), cloud=p))
    return out


def _scopes(db: Session) -> list[dict]:
    from app.services.connections_health import SOURCES, registry
    out = []
    for it in registry(db)["items"]:
        if it["onboarding_status"] == "Inactive":
            continue
        p, sid = it["provider"], it["external_id"]
        label = it["name"] or sid
        for key, src in it["sources"].items():
            state = src["state"]
            name = f"{SOURCES[key][2].get(p, key)}"
            if state == "OK":
                out.append(_check("scope", name, PASS, f"last success {src['last_success']:%Y-%m-%d %H:%M} UTC" if src["last_success"] else "ok", cloud=p, scope=label))
            elif state == "NEVER_SYNCHRONIZED":
                out.append(_check("scope", name, WARN, "Not collected yet for this scope.", f"Run the '{SOURCES[key][0]}' job once (Automation) and re-check.",
                                  cloud=p, scope=label))
            elif state == "NOT_PERMITTED":
                out.append(_check("scope", name, FAIL, f"Permission check '{src['gate_check']}' failed: {it.get('permission_detail') or 'missing permission'}",
                                  FIX_HINTS["permission"], cloud=p, scope=label))
            else:
                out.append(_check("scope", name, FAIL, src["failure_reason"] or "latest run failed for this scope", fix_for(src["failure_reason"]),
                                  cloud=p, scope=label))
    return out


def _last_summary(db: Session, job: str) -> dict | None:
    run = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == job, AutomationExecutionLog.status != JobStatus.RUNNING.value)
                    .order_by(AutomationExecutionLog.id.desc()).limit(1))
    return None if run is None else (run.summary or {})


def _directories(db: Session, settings: Settings) -> list[dict]:
    """Tenant / organization-level sources (Entra directory, management groups, Identity Center, GCP org and folders,
    Entra audit and sign-in logs). These belong to no single subscription, so they get their own checks."""
    from app.services.azure.permissions import fix_for_source, graph_fix
    out = []
    names = {"entra_users": "Entra users", "entra_service_principals": "Entra service principals", "entra_group_members": "Entra group members",
             "entra_app_credentials": "Entra app credentials", "entra_directory_roles": "Entra admin roles", "entra_pim_eligible": "PIM eligible roles",
             "azure_management_groups": "Management groups (inherited access)"}
    acc = _last_summary(db, "access_inventory")
    if acc is not None:
        for provider, dirs in (acc.get("directory") or {}).items():
            seen: dict[str, dict] = {}
            for d in dirs or []:
                for c in d.get("coverage") or []:
                    src = c["source"].split(":", 1)[0]
                    if src not in seen or c["state"] != "OK":
                        seen[src] = c
            for src, c in sorted(seen.items()):
                label = names.get(src, src.replace("_", " "))
                if c["state"] == "OK":
                    out.append(_check("directory", label, PASS, str(c.get("message") or "collected"), cloud=provider, scope="tenant / organization"))
                else:
                    fix = c.get("fix") or (fix_for_source(settings, src, c.get("message")) if provider == "azure" else None) or fix_for(c.get("message"))
                    what = "Missing permission" if c["state"] == "ACCESS_DENIED" else "Failed"
                    out.append(_check("directory", label, FAIL, f"{what}: {str(c.get('message') or '')[:200]}", fix, cloud=provider, scope="tenant / organization"))
    ent = _last_summary(db, "entra_activity")
    if ent is not None and settings.azure_enabled:
        for src, label in (("directory_audits", "Entra audit logs"), ("sign_ins", "Entra sign-in logs")):
            v = (ent.get("sources") or {}).get(src)
            if v is None:
                continue
            if v.get("unavailable") == "licence":
                out.append(_check("directory", label, WARN, v.get("note") or "Not available without Entra ID P1/P2",
                                  "Buy / assign an Entra ID P1 or P2 licence if sign-in monitoring is required.", cloud="azure", scope="tenant"))
            elif v.get("unavailable"):
                out.append(_check("directory", label, FAIL, "Missing permission", v.get("fix") or graph_fix(settings, src), cloud="azure", scope="tenant"))
            elif v.get("error"):
                out.append(_check("directory", label, FAIL, v["error"], fix_for(v["error"]), cloud="azure", scope="tenant"))
            else:
                out.append(_check("directory", label, PASS, f"{v.get('read', 0)} events read on the last run", cloud="azure", scope="tenant"))
    return out


def _tcp(host: str, port: int) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=5):
            return None
    except OSError as exc:
        return str(exc)


def _integrations(settings: Settings) -> list[dict]:
    out = []
    if settings.chat_webhook_url:
        host = urlparse(settings.chat_webhook_url).hostname or ""
        err = _tcp(host, 443)
        out.append(_check("integration", "Google Chat webhook reachable", FAIL if err else PASS, err or f"{host}:443 reachable (no message sent)",
                          "Allow outbound HTTPS to chat.googleapis.com from this server."))
    else:
        out.append(_check("integration", "Google Chat webhook", WARN, "Not configured: alerts are not posted to Chat.", "Set CHAT_WEBHOOK_URL (in Key Vault)."))
    if settings.notify_email_enabled:
        from app.services.notifications.channels import GmailChannel
        miss = GmailChannel(settings).missing()
        if miss:
            out.append(_check("integration", "E-mail", FAIL, f"Enabled but incomplete: missing {', '.join(miss)}", "Fill the missing values in backend/.env."))
        elif settings.email_transport == "smtp":
            err = _tcp(settings.smtp_host, settings.smtp_port)
            out.append(_check("integration", "E-mail (SMTP) reachable", FAIL if err else PASS, err or f"{settings.smtp_host}:{settings.smtp_port} reachable (no e-mail sent)",
                              "Allow outbound SMTP to the mail server; check SMTP_HOST / SMTP_PORT."))
        else:
            err = _tcp("gmail.googleapis.com", 443)
            out.append(_check("integration", "E-mail (Gmail API) reachable", FAIL if err else PASS, err or "gmail.googleapis.com:443 reachable (no e-mail sent)",
                              "Allow outbound HTTPS to gmail.googleapis.com and check the delegated sender."))
    else:
        out.append(_check("integration", "E-mail", WARN, "Not enabled: the daily governance dashboard is not e-mailed.",
                          "Set NOTIFY_EMAIL_ENABLED=true, GMAIL_SENDER, NOTIFY_EMAIL_TO and SMTP_HOST / SMTP_USERNAME / SMTP_PASSWORD."))
    if settings.sheets_enabled:
        try:
            from app.services.google_sheets.backend import SCOPES
            from app.services.notifications.channels import google_credentials
            creds = google_credentials(settings, SCOPES)
            who = getattr(creds, "service_account_email", None)
            out.append(_check("integration", "Google Sheets credentials", PASS if settings.sheets_spreadsheet_id else WARN,
                              (f"Service account {who}" if who else "Service identity credentials found")
                              + ("" if settings.sheets_spreadsheet_id else "; SHEETS_SPREADSHEET_ID is empty (a new register is created on first sync)"),
                              "Share the register spreadsheet with the service account as Editor." if who else ""))
        except Exception as exc:  # noqa: BLE001
            out.append(_check("integration", "Google Sheets credentials", FAIL, safe_error(exc),
                              "Set GOOGLE_APPLICATION_CREDENTIALS in backend/.env to the service-account key file (outside the project folder)."))
    return out


def run_preflight(db: Session, settings: Settings, connectors: list | None = None, live: bool = True) -> dict:
    checks = _platform(db, settings)
    if live:
        checks += _clouds(settings, db, connectors)
    checks += _scopes(db) + _directories(db, settings) + _integrations(settings)
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in (PASS, WARN, FAIL)}
    return {"verdict": FAIL if counts[FAIL] else PASS, "counts": counts, "checks": checks, "generated_at": datetime.now(UTC).isoformat()}


def run_preflight_job(ctx, settings: Settings):
    from app.scheduler.engine import JobResult
    rep = run_preflight(ctx.db, settings)
    failures = [{"provider": c["cloud"] or "*", "scope": c["scope"] or c["area"], "reason": f"{c['check']}: {c['message']} Fix: {c['fix']}"}
                for c in rep["checks"] if c["status"] == FAIL]
    status = JobStatus.SUCCESS if not failures else JobStatus.PARTIAL
    return JobResult(status, len(rep["checks"]), len(failures), {"preflight": rep}, failures)


def job_overview(db: Session) -> list[dict]:
    """Per job: last run, last success, consecutive problems, next scheduled run and the first reasons with fixes."""
    from zoneinfo import ZoneInfo

    from croniter import croniter
    out = []
    now = datetime.now(UTC)
    for j in db.scalars(select(AutomationJob).order_by(AutomationJob.name)):
        runs = list(db.scalars(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == j.name)
                               .order_by(AutomationExecutionLog.id.desc()).limit(20)))
        last = runs[0] if runs else None
        ok = next((r for r in runs if r.status == JobStatus.SUCCESS.value), None)
        streak = 0
        for r in runs:
            if r.status in (JobStatus.FAILED.value, JobStatus.PARTIAL.value):
                streak += 1
            elif r.status == JobStatus.SUCCESS.value:
                break
        try:
            tz = ZoneInfo(j.schedule_timezone or "Asia/Kolkata")
            nxt = croniter(j.schedule, now.astimezone(tz)).get_next(datetime).astimezone(UTC).isoformat() if j.enabled and j.schedule else None
        except Exception:  # noqa: BLE001
            nxt = None
        problems = []
        if last and last.status != JobStatus.SUCCESS.value:
            if last.error:
                problems.append({"scope": "*", "reason": last.error, "fix": fix_for(last.error)})
            for f in (last.failures or [])[:3]:
                problems.append({"scope": f"{f.get('provider') or '*'} {f.get('scope') or ''}".strip(), "reason": f.get("reason"), "fix": fix_for(f.get("reason"))})
        out.append({"name": j.name, "description": j.description, "enabled": j.enabled, "schedule": j.schedule,
                    "last_status": last.status if last else "never", "last_run_at": (last.finished_at or last.started_at).isoformat() if last else None,
                    "last_success_at": (ok.finished_at or ok.started_at).isoformat() if ok else None, "problem_streak": streak,
                    "scopes_total": last.scopes_total if last else 0, "scopes_failed": last.scopes_failed if last else 0, "next_run_at": nxt,
                    "problems": problems})
    return out
