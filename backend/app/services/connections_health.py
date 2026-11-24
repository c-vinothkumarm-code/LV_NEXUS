"""Cloud connection registry: one row per discovered account / subscription / project with authentication, permission
validation, per-data-source sync state (last success, last failure, reason), data coverage and freshness.

Built from what the platform already records (onboarding checks, job executions with per-scope failures, collected data),
so it shows only observed facts. A scope that a job has never processed shows "never synchronized", not "healthy"."""
from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    AccessAssignment,
    AuditEvent,
    AutomationExecutionLog,
    BillingRecord,
    CloudResource,
    CloudSecurityFinding,
    CloudSubscription,
    JobStatus,
)
from app.models.inventory import SCOPE_MODELS
from app.scheduler.engine import JobContext, JobResult

# data source -> (job, onboarding check that gates it, capability label per provider)
SOURCES = {
    "discovery": ("account_discovery", "authentication", {"aws": "AWS Organizations", "azure": "Azure Resource Manager subscriptions",
                                                          "gcp": "Resource Manager (organization, folders, projects)"}),
    "inventory": ("resource_inventory", "permissions", {"aws": "EC2 (via vm_metrics)", "azure": "Azure Resource Manager resources",
                                                        "gcp": "Compute Engine (via vm_metrics)"}),
    "activity": ("security_events", "audit_logs", {"aws": "CloudTrail", "azure": "Azure Activity Log", "gcp": "Cloud Audit Logs"}),
    "cost": ("billing_refresh", "billing", {"aws": "Cost Explorer", "azure": "Cost Management", "gcp": "BigQuery billing export"}),
    "cost_detail": ("cost_detail_refresh", "billing", {"aws": "Cost Explorer (service / region / usage type / tags), Budgets",
                                                       "azure": "Cost Management Query, Forecast, Consumption Budgets",
                                                       "gcp": "BigQuery billing export (SKU / location / labels)"}),
    "iam": ("access_inventory", "permissions", {"aws": "IAM, IAM Identity Center", "azure": "Azure RBAC role assignments",
                                                "gcp": "Cloud IAM (org / folder / project), IAM service accounts"}),
    "security": ("security_findings_sync", "permissions", {"aws": "Security Hub", "azure": "Advisor, Defender for Cloud, Azure Policy",
                                                           "gcp": "Security Command Center"}),
    "metrics": ("vm_metrics", "monitoring", {"aws": "CloudWatch", "azure": "Azure Monitor", "gcp": "Cloud Monitoring"}),
}


def _aware(dt):
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _job_state(db: Session, job: str, since: datetime) -> list[AutomationExecutionLog]:
    return list(db.scalars(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == job, AutomationExecutionLog.started_at >= since,
                                                                AutomationExecutionLog.status != JobStatus.SKIPPED_OVERLAP.value)
                           .order_by(AutomationExecutionLog.id.desc()).limit(200)))


def registry(db: Session, provider: str | None = None) -> dict:
    since = datetime.now(UTC) - timedelta(days=7)
    runs = {key: _job_state(db, job, since) for key, (job, _, _) in SOURCES.items()}
    day = datetime.now(UTC) - timedelta(hours=24)
    counts = {
        "resources": dict(db.execute(select(CloudResource.scope_external_id, func.count()).group_by(CloudResource.scope_external_id)).all()),
        "events_24h": dict(db.execute(select(AuditEvent.scope_external_id, func.count()).where(AuditEvent.collected_at >= day)
                                      .group_by(AuditEvent.scope_external_id)).all()),
        "last_cost_day": dict(db.execute(select(BillingRecord.scope_external_id, func.max(BillingRecord.usage_date)).group_by(BillingRecord.scope_external_id)).all()),
        "assignments": dict(db.execute(select(AccessAssignment.scope_external_id, func.count()).where(AccessAssignment.removed_at.is_(None))
                                       .group_by(AccessAssignment.scope_external_id)).all()),
        "findings": dict(db.execute(select(CloudSecurityFinding.scope_external_id, func.count()).group_by(CloudSecurityFinding.scope_external_id)).all()),
    }
    items = []
    for p, model in SCOPE_MODELS.items():
        if provider and p != provider:
            continue
        for s in db.scalars(select(model).order_by(model.name)):
            checks = s.checks or {}
            sources = {}
            for key, (_job, gate, labels) in SOURCES.items():
                last_ok = last_fail = reason = None
                processed = False
                for r in runs[key]:
                    failed_here = next((f for f in (r.failures or []) if f.get("scope") in (s.external_id, "*") and
                                        f.get("provider") in (p, "*", None)), None)
                    in_scope = failed_here is not None or r.status in (JobStatus.SUCCESS.value, JobStatus.PARTIAL.value)
                    if not in_scope:
                        continue
                    processed = True
                    if failed_here and last_fail is None:
                        last_fail, reason = r.finished_at or r.started_at, failed_here.get("reason")
                    if not failed_here and last_ok is None and r.status in (JobStatus.SUCCESS.value, JobStatus.PARTIAL.value):
                        last_ok = r.finished_at or r.started_at
                    if last_ok and last_fail:
                        break
                gate_ok = (checks.get(gate) or {}).get("status")
                state = ("NOT_PERMITTED" if gate_ok == "fail" else "NEVER_SYNCHRONIZED" if not processed else
                         "FAILING" if last_fail and (not last_ok or _aware(last_fail) > _aware(last_ok)) else "OK")
                sources[key] = {"api": labels.get(p), "state": state, "last_success": last_ok, "last_failure": last_fail, "failure_reason": reason,
                                "gate_check": gate, "gate_status": gate_ok or "unknown"}
            ok = sum(1 for v in sources.values() if v["state"] == "OK")
            items.append({
                "provider": p, "external_id": s.external_id, "name": s.name, "parent": s.parent, "environment": s.environment,
                "organization": getattr(s, "tenant_id", None) if p == "azure" else s.parent,
                "billing_account": getattr(s, "billing_account", None), "is_management": getattr(s, "is_management", False),
                "provider_state": s.provider_state, "onboarding_status": s.onboarding_status, "monitoring_enabled": s.monitoring_enabled,
                "authentication": (checks.get("authentication") or {}).get("status") or "unknown",
                "permissions": (checks.get("permissions") or {}).get("status") or "unknown",
                "permission_detail": (checks.get("permissions") or {}).get("detail"),
                "checks": {k: (v or {}).get("status") for k, v in checks.items()},
                "last_seen_at": s.last_seen_at, "last_validated_at": s.last_validated_at,
                "sources": sources, "health": "Healthy" if ok == len(sources) else "Degraded" if ok else "Not connected",
                "coverage": {"resources": counts["resources"].get(s.external_id, 0), "activity_events_24h": counts["events_24h"].get(s.external_id, 0),
                             "last_cost_day": counts["last_cost_day"].get(s.external_id), "access_assignments": counts["assignments"].get(s.external_id, 0),
                             "security_findings": counts["findings"].get(s.external_id, 0)},
            })
    totals = defaultdict(lambda: defaultdict(int))
    for it in items:
        totals[it["provider"]]["scopes"] += 1
        totals[it["provider"]][it["health"]] += 1
    return {"items": items, "totals": {k: dict(v) for k, v in totals.items()}, "sources": {k: v[0] for k, v in SOURCES.items()},
            "tenants": sorted({s.tenant_id for s in db.scalars(select(CloudSubscription)) if s.tenant_id})}


def run_connection_health(ctx: JobContext, settings: Settings) -> JobResult:
    """Alert once when a scope's authentication or permission check turns to fail, or a data source starts failing."""
    from app.services.vuln.notify import notify
    db = ctx.db
    reg = registry(db)
    prev = dict(ctx.job.checkpoint or {})
    state, alerts, failures = {}, 0, []
    for it in reg["items"]:
        bad = [k for k, v in it["sources"].items() if v["state"] == "FAILING"]
        if it["authentication"] == "fail":
            bad.insert(0, "authentication")
        key = f"{it['provider']}:{it['external_id']}"
        state[key] = sorted(bad)
        newly = sorted(set(bad) - set(prev.get(key, [])))
        if newly:
            reasons = "; ".join(f"{k}: {it['sources'][k]['failure_reason'] or 'failing'}" for k in newly if k in it["sources"])
            if notify(db, "connection_failure", f"{key}:{','.join(newly)}:{datetime.now(UTC).date()}",
                      f"[LV NEXUS] Connection problem: {it['provider'].upper()} {it['name'] or it['external_id']}",
                      f"Failing since the last check: {', '.join(newly)}. {reasons}. See Cloud Connections."):
                alerts += 1
        if bad:
            failures.append({"provider": it["provider"], "scope": it["external_id"], "reason": ", ".join(bad)})
    ctx.job.checkpoint = state
    db.commit()
    summary = {"scopes": len(reg["items"]), "totals": reg["totals"], "alerts": alerts}
    status = JobStatus.SUCCESS if not failures else JobStatus.PARTIAL
    return JobResult(status, len(reg["items"]), len(failures), summary, failures)
