"""Dynamic onboarding workflow: discover -> compare -> register -> validate -> status -> notify.

Read-only by design. When a scope needs IAM/RBAC or configuration work, the engine creates a task
for human approval; it never changes anything in a cloud environment.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import safe_error
from app.models import (
    SCOPE_LABEL,
    SCOPE_MODELS,
    JobStatus,
    NotificationLog,
    OnboardingRecord,
    OnboardingStatus,
    RemediationRecord,
    utcnow,
)
from app.scheduler.engine import JobContext, JobResult
from app.services.connector import ALL_CHECKS, CHECK_AUTH, FAIL, PASS, UNKNOWN, CheckResult, CloudConnector, DiscoveredScope

from .status import derive_status

log = logging.getLogger(__name__)


def _record(db: Session, row, event: str, prev: str | None, execution_id: int | None, detail: str | None = None):
    db.add(OnboardingRecord(provider=row.provider, scope_external_id=row.external_id, scope_name=row.name,
                            event_type=event, previous_status=prev, new_status=row.onboarding_status,
                            checks=row.checks or {}, detail=detail, execution_id=execution_id))


def _sync_tasks(db: Session, row, checks: dict[str, dict]) -> int:
    """Open one approval task per failed check; resolve tasks whose check now passes."""
    opened = 0
    label = SCOPE_LABEL[row.provider]
    existing = {t.dedupe_key: t for t in db.scalars(select(RemediationRecord).where(
        RemediationRecord.category == "onboarding", RemediationRecord.provider == row.provider,
        RemediationRecord.scope_external_id == row.external_id))}
    for name in ALL_CHECKS:
        check = checks.get(name)
        if not check:
            continue
        key = f"onboarding:{row.provider}:{row.external_id}:{name}"
        task = existing.get(key)
        needs_task = check["status"] == FAIL and check.get("remediation")
        if needs_task and (task is None or task.status in ("resolved", "rejected")):
            if task is None:
                task = RemediationRecord(dedupe_key=key, category="onboarding", provider=row.provider,
                                         scope_external_id=row.external_id, title="", status="pending_approval")
                db.add(task)
            elif task.status == "rejected":
                continue  # a human already declined this; do not re-open automatically
            task.title = f"{row.provider.upper()} {label} {row.name or row.external_id}: {name.replace('_', ' ')} failed"
            task.description, task.proposed_action = check.get("detail"), check["remediation"]
            task.status, task.resolved_at, task.decided_by, task.decided_at = "pending_approval", None, None, None
            opened += 1
        elif check["status"] == PASS and task is not None and task.status in ("pending_approval", "approved"):
            task.status, task.resolved_at = "resolved", utcnow()
    return opened


def _reconcile(db: Session, provider: str, discovered: list[DiscoveredScope], execution_id: int | None):
    model = SCOPE_MODELS[provider]
    now = utcnow()
    rows = {r.external_id: r for r in db.scalars(select(model))}
    new_rows = []
    for scope in discovered:
        row = rows.get(scope.external_id)
        if row is None:
            row = model(external_id=scope.external_id, onboarding_status=OnboardingStatus.DISCOVERED.value,
                        checks={}, monitoring_enabled=True, first_discovered_at=now)
            db.add(row)
            rows[scope.external_id] = row
            new_rows.append(row)
        row.name, row.provider_state, row.parent, row.last_seen_at = scope.name, scope.provider_state, scope.parent, now
        for key, value in scope.attrs.items():
            if hasattr(row, key) and value is not None:
                setattr(row, key, value)
    for row in new_rows:
        _record(db, row, "discovered", None, execution_id, "New scope found in organisation")
    seen = {s.external_id for s in discovered}
    for ext_id, row in rows.items():  # previously known scopes that the provider no longer returns
        if ext_id not in seen and row.onboarding_status != OnboardingStatus.INACTIVE.value:
            prev, row.onboarding_status = row.onboarding_status, OnboardingStatus.INACTIVE.value
            row.provider_state = "NOT_RETURNED_BY_PROVIDER"
            _record(db, row, "inactive", prev, execution_id, "Scope no longer returned by provider discovery")
    return rows, new_rows


def run_discovery(ctx: JobContext, connectors: Iterable[CloudConnector]) -> JobResult:
    db, exec_id = ctx.db, ctx.execution_id
    summary: dict = {"providers": {}}
    failures: list[dict] = []
    total = failed = 0
    providers_ok = providers_total = 0
    new_scopes: list = []

    for conn in connectors:
        providers_total += 1
        p = conn.provider
        info: dict = {"status": "ok", "discovered": 0, "new": 0, "validated": 0}
        summary["providers"][p] = info
        missing = conn.missing_configuration()
        if missing:
            info.update(status="not_configured", missing=missing)
            failures.append({"provider": p, "scope": "*", "reason": f"Provider not configured: missing {', '.join(missing)}"})
            continue
        try:
            discovered = conn.discover()
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            log.exception("%s discovery failed", p)
            info.update(status="discovery_failed", error=safe_error(exc))
            failures.append({"provider": p, "scope": "*", "reason": f"Discovery failed: {safe_error(exc)}"})
            continue  # inventory is left untouched: a failed listing must not mark scopes inactive

        rows, new_rows = _reconcile(db, p, discovered, exec_id)
        new_scopes += new_rows
        info.update(discovered=len(discovered), new=len(new_rows))
        providers_ok += 1

        for scope in discovered:
            total += 1
            row = rows[scope.external_id]
            prev_status, prev_checks = row.onboarding_status, dict(row.checks or {})
            checks: dict[str, dict] = {}
            if scope.is_active and row.monitoring_enabled:
                try:
                    checks = {k: v.to_dict() for k, v in conn.validate(scope).items()}
                    info["validated"] += 1
                except Exception as exc:  # noqa: BLE001
                    log.exception("%s validation failed for %s", p, scope.external_id)
                    checks = {CHECK_AUTH: CheckResult(UNKNOWN, f"Validation error: {safe_error(exc)}").to_dict()}
                for key, value in scope.attrs.items():  # validation may enrich attributes (e.g. billing account)
                    if hasattr(row, key) and value is not None:
                        setattr(row, key, value)
                row.checks, row.last_validated_at = checks, utcnow()
            status = derive_status(checks, is_active=scope.is_active, monitoring_enabled=row.monitoring_enabled)
            row.onboarding_status = status.value
            if status == OnboardingStatus.ACCESS_FAILED:
                failed += 1
                failures.append({"provider": p, "scope": scope.external_id, "name": scope.name,
                                 "reason": checks.get(CHECK_AUTH, {}).get("detail", "Access failed")})
            if checks:
                info["tasks_opened"] = info.get("tasks_opened", 0) + _sync_tasks(db, row, checks)
            statuses = {k: v.get("status") for k, v in checks.items()}
            if status.value != prev_status:
                _record(db, row, "status_changed", prev_status, exec_id)
            elif statuses != {k: v.get("status") for k, v in prev_checks.items()}:
                _record(db, row, "validated", prev_status, exec_id, "Check results changed")
        db.commit()

    if new_scopes:
        lines = [f"- {r.provider.upper()} {SCOPE_LABEL[r.provider]} {r.name} ({r.external_id}): {r.onboarding_status}"
                 for r in new_scopes]
        for channel in ("email", "google_chat"):
            # Queued only. Delivery (Gmail / Google Chat) marks it sent; nothing here claims delivery.
            db.add(NotificationLog(channel=channel, category="onboarding_new_scope", execution_id=exec_id,
                                   subject=f"{len(new_scopes)} new cloud scope(s) discovered",
                                   body="\n".join(lines), status="queued"))
    summary.update(new_scopes=len(new_scopes), providers_ok=providers_ok, providers_total=providers_total)
    db.commit()

    if providers_total == 0 or providers_ok == 0:
        status = JobStatus.FAILED
        if providers_total == 0:
            failures.append({"provider": "*", "scope": "*", "reason": "No cloud provider is enabled (set AWS_ENABLED / GCP_ENABLED / AZURE_ENABLED)"})
    elif failures:
        status = JobStatus.PARTIAL
    else:
        status = JobStatus.SUCCESS
    return JobResult(status=status, scopes_total=total, scopes_failed=failed, summary=summary, failures=failures)
