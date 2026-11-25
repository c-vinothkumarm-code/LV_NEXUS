"""Builds the review evidence pack: exports of the application's own records plus the validation reports."""
from __future__ import annotations

import csv
import json
import platform
import shutil
import subprocess
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    AdminAuditLog,
    AutomationExecutionLog,
    CloudAccount,
    CloudConnection,
    CloudProject,
    CloudSubscription,
    NotificationLog,
    OnboardingRecord,
    RemediationRecord,
    SecurityFinding,
    SecurityReview,
    User,
)
from app.services.registry import prerequisites

BACKEND = Path(__file__).resolve().parents[2]


def _csv(path: Path, header: list[str], rows) -> int:
    n = 0
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        for r in rows:
            w.writerow(["" if v is None else (v.isoformat() if hasattr(v, "isoformat") else v) for v in r])
            n += 1
    return n


def build_pack(db: Session, s: Settings, out_root: Path, days: int = 14, run_tests: bool = False, extra: list[Path] | None = None) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    out = out_root / f"evidence-{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    since = datetime.now(UTC) - timedelta(days=days)
    manifest = {"generated_at": datetime.now(UTC).isoformat(), "application": s.app_name, "environment": s.app_env, "window_days": days, "files": {}}

    def add(name, header, rows):
        manifest["files"][name] = _csv(out / name, header, rows)

    add("job_executions.csv", ["id", "job", "trigger", "triggered_by", "status", "started_utc", "finished_utc", "scopes", "scopes_failed", "failures", "error"],
        ((e.id, e.job_name, e.trigger, e.triggered_by, e.status, e.started_at, e.finished_at, e.scopes_total, e.scopes_failed,
          json.dumps(e.failures or [])[:4000], e.error) for e in db.scalars(select(AutomationExecutionLog).where(
              AutomationExecutionLog.started_at >= since).order_by(AutomationExecutionLog.id))))
    add("admin_audit_log.csv", ["id", "actor", "action", "target", "detail", "time_utc"],
        ((a.id, a.actor, a.action, a.target, json.dumps(a.detail), a.created_at) for a in db.scalars(select(AdminAuditLog).order_by(AdminAuditLog.id))))
    add("onboarding_history.csv", ["id", "provider", "scope", "name", "event", "from", "to", "detail", "time_utc"],
        ((r.id, r.provider, r.scope_external_id, r.scope_name, r.event_type, r.previous_status, r.new_status, r.detail, r.created_at)
         for r in db.scalars(select(OnboardingRecord).order_by(OnboardingRecord.id))))
    scopes = []
    for model in (CloudAccount, CloudProject, CloudSubscription):
        for r in db.scalars(select(model)):
            scopes.append((r.provider, r.external_id, r.name, r.provider_state, r.onboarding_status,
                           *[((r.checks or {}).get(c) or {}).get("status", "") for c in ("authentication", "permissions", "audit_logs", "billing", "monitoring")],
                           r.last_validated_at))
    add("cloud_scopes.csv", ["provider", "id", "name", "provider_state", "onboarding_status", "auth", "permissions", "audit_logs", "billing", "monitoring", "last_validated_utc"], scopes)
    add("security_findings.csv", ["id", "provider", "scope", "rule", "title", "severity", "risk", "principal", "resource", "occurrences", "first_seen_utc", "last_seen_utc", "review_status"],
        ((f.id, f.provider, f.scope_external_id, f.rule_id, f.title, f.severity, f.risk_score, f.principal, f.resource_id, f.occurrence_count,
          f.first_seen_at, f.last_seen_at, f.review_status) for f in db.scalars(select(SecurityFinding).order_by(SecurityFinding.id))))
    add("security_reviews.csv", ["id", "finding", "from", "to", "reviewer", "notes", "evidence", "time_utc"],
        ((r.id, r.finding_id, r.previous_status, r.new_status, r.reviewer, r.notes, r.evidence_reference, r.created_at) for r in db.scalars(select(SecurityReview))))
    add("approval_tasks.csv", ["id", "category", "provider", "scope", "title", "status", "decided_by", "decided_utc", "resolved_utc"],
        ((t.id, t.category, t.provider, t.scope_external_id, t.title, t.status, t.decided_by, t.decided_at, t.resolved_at) for t in db.scalars(select(RemediationRecord))))
    add("notifications.csv", ["id", "channel", "category", "subject", "status", "attempts", "created_utc", "sent_utc", "error"],
        ((n.id, n.channel, n.category, n.subject, n.status, n.attempts, n.created_at, n.sent_at, n.error) for n in db.scalars(select(NotificationLog).order_by(NotificationLog.id))))
    add("users_and_roles.csv", ["email", "roles", "active", "last_login_utc"],
        ((u.email, ";".join(r.name for r in u.roles), u.is_active, u.last_login_at) for u in db.scalars(select(User).order_by(User.email))))
    add("connection_tests.csv", ["provider", "enabled", "last_test_utc", "ok", "detail", "updated_by"],
        ((c.provider, c.enabled, c.last_test_at, c.last_test_ok, c.last_test_detail, c.updated_by) for c in db.scalars(select(CloudConnection))))
    # Configuration: which settings are present. Values are never written.
    (out / "configuration_presence.json").write_text(json.dumps({"auth_mode": s.auth_mode, "app_env": s.app_env, "providers": prerequisites(s),
        "sheets_enabled": s.sheets_enabled, "chat_configured": bool(s.chat_webhook_url), "email_enabled": s.notify_email_enabled,
        "ai_provider": s.ai_provider}, indent=2), encoding="utf-8")
    versions = {"python": platform.python_version(), "platform": platform.platform()}
    try:
        git = shutil.which("git")
        versions["git_commit"] = (subprocess.run([git, "rev-parse", "HEAD"], cwd=BACKEND, capture_output=True, text=True, timeout=10,  # noqa: S603 - fixed arguments
                                                 check=False).stdout.strip() if git else "unavailable")
    except Exception:  # noqa: BLE001
        versions["git_commit"] = "unavailable"
    (out / "versions.json").write_text(json.dumps(versions, indent=2), encoding="utf-8")
    if run_tests:
        res = subprocess.run([__import__("sys").executable, "-m", "pytest", "-W", "ignore", "-q", f"--junitxml={out / 'tests_junit.xml'}"],
                             cwd=BACKEND, capture_output=True, text=True, timeout=1800, check=False)  # noqa: S603 - fixed arguments
        (out / "tests_output.txt").write_text(res.stdout[-200000:] + res.stderr[-20000:], encoding="utf-8")
        manifest["tests_exit_code"] = res.returncode
    for p in extra or []:
        if p.exists():
            (out / p.name).write_bytes(p.read_bytes())
            manifest["files"][p.name] = "copied"
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    zip_path = out.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(out.rglob("*")):
            z.write(f, f.relative_to(out.parent))
    return zip_path
