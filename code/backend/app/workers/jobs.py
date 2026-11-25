"""Job definitions. Each function is run through the job engine (lock, history, honest status)."""
from __future__ import annotations

from collections.abc import Callable

from sqlalchemy import select

from app.core.config import Settings, get_settings
from app.database.session import get_session_factory
from app.models import JobStatus, NotificationLog
from app.scheduler.engine import JobContext, JobResult, run_job
from app.services.registry import build_connectors


def _connectors(settings: Settings) -> dict:
    return {c.provider: c for c in build_connectors(settings)}


# ---- collection jobs -------------------------------------------------------------------------
def account_discovery(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.onboarding.engine import run_discovery
    return run_discovery(ctx, build_connectors(settings))


def security_events(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.soc.collectors import AwsAuditCollector, AzureAuditCollector, GcpAuditCollector
    from app.services.soc.engine import run_security_events

    classes = {"aws": AwsAuditCollector, "gcp": GcpAuditCollector, "azure": AzureAuditCollector}
    return run_security_events(ctx, settings, [classes[p](settings, c) for p, c in _connectors(settings).items()])


def billing_refresh(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.finops.collectors import AwsBillingCollector, AzureBillingCollector, GcpBillingCollector
    from app.services.finops.engine import run_billing_refresh

    classes = {"aws": AwsBillingCollector, "gcp": GcpBillingCollector, "azure": AzureBillingCollector}
    return run_billing_refresh(ctx, settings, [classes[p](settings, c) for p, c in _connectors(settings).items()])


def vm_metrics(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.monitoring.collectors import AwsVmCollector, AzureVmCollector, GcpVmCollector
    from app.services.monitoring.engine import run_vm_metrics

    classes = {"aws": AwsVmCollector, "gcp": GcpVmCollector, "azure": AzureVmCollector}
    return run_vm_metrics(ctx, settings, [classes[p](settings, c) for p, c in _connectors(settings).items()])


def resource_inventory(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.inventory import AwsResourceCollector, AzureResourceCollector, GcpResourceCollector, run_resource_inventory

    conns = _connectors(settings)
    classes = {"azure": AzureResourceCollector, "aws": AwsResourceCollector, "gcp": GcpResourceCollector}
    return run_resource_inventory(ctx, settings, [classes[p](settings, c) for p, c in conns.items()], [])


# ---- Google Sheets ---------------------------------------------------------------------------
_backend_factory: Callable | None = None  # tests can substitute an in-memory backend


def _sheets_backend(ctx: JobContext, settings: Settings):
    if _backend_factory is not None:
        return _backend_factory()
    from app.services.google_sheets.backend import GoogleSheetsBackend

    stored = (ctx.job.checkpoint or {}).get("spreadsheet_id") if ctx.job.name == "sheets_sync" else None
    from app.services.google_sheets.backend import SCOPES
    from app.services.notifications.channels import google_credentials
    backend = GoogleSheetsBackend(settings.sheets_spreadsheet_id or stored, credentials=google_credentials(settings, SCOPES))
    if ctx.job.name == "sheets_sync":
        ctx.job.checkpoint = {**(ctx.job.checkpoint or {}), "spreadsheet_id": backend.spreadsheet_id}
    return backend


def _sync(ctx: JobContext, settings: Settings, tabs: list[str] | None) -> tuple[dict, list[dict]]:
    """Returns (summary, failures). When Sheets is switched off this is recorded, not treated as success of a sync."""
    if not settings.sheets_enabled:
        return {"sheets": "disabled (SHEETS_ENABLED=false)"}, []
    from app.core.logging import safe_error
    from app.services.google_sheets.register import sync_register

    try:
        result = sync_register(ctx.db, settings, _sheets_backend(ctx, settings), tabs)
    except Exception as exc:  # noqa: BLE001
        return {"sheets": "failed"}, [{"provider": "google_sheets", "scope": "*", "reason": safe_error(exc)}]
    failures = [{"provider": "google_sheets", "scope": tab, "reason": err} for tab, err in result["errors"].items()]
    return {"sheets": result["tabs"]}, failures


def sheets_sync(ctx: JobContext, settings: Settings) -> JobResult:
    if not settings.sheets_enabled:
        return JobResult(JobStatus.FAILED, 0, 0, {}, [{"provider": "google_sheets", "scope": "*", "reason": "Google Sheets is not enabled (SHEETS_ENABLED)"}])
    summary, failures = _sync(ctx, settings, None)
    ctx.db.commit()
    tabs = summary["sheets"] if isinstance(summary["sheets"], dict) else {}
    status = JobStatus.SUCCESS if not failures else JobStatus.PARTIAL if tabs else JobStatus.FAILED
    return JobResult(status, len(tabs) + len(failures), len(failures), summary, failures)


def _result(summary: dict, failures: list[dict], units: int = 1) -> JobResult:
    return JobResult(JobStatus.PARTIAL if failures else JobStatus.SUCCESS, units, len(failures), summary, failures)


# ---- daily review jobs (07:00 / 07:30 / 08:00 / 08:30 IST) ----------------------------------------
def soc_daily_review(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.notifications.reports import collection_health

    health = collection_health(ctx.db)
    summary, failures = _sync(ctx, settings, ["SOC_Audit_Logs", "Security_Findings", "Security_Reviews", "Daily_Review_Status",
                                              "Cloud_Inventory", "Account_Onboarding", "Remediation_Tracker"])
    summary["collection"] = health["jobs"]["security_events"]
    if health["jobs"]["security_events"] != "success":
        failures += [f for f in health["failing"] if f["job"] == "security_events"] or [
            {"provider": "*", "scope": "*", "reason": f"security_events collection status in the last 24h: {health['jobs']['security_events']}"}]
    return _result(summary, failures)


def vm_daily_review(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.notifications.reports import collection_health

    health = collection_health(ctx.db)
    summary, failures = _sync(ctx, settings, ["VM_Inventory", "VM_Health", "VM_Alerts"])
    summary["collection"] = health["jobs"]["vm_metrics"]
    if health["jobs"]["vm_metrics"] != "success":
        failures += [f for f in health["failing"] if f["job"] == "vm_metrics"] or [
            {"provider": "*", "scope": "*", "reason": f"vm_metrics collection status in the last 24h: {health['jobs']['vm_metrics']}"}]
    return _result(summary, failures)


def billing_daily_review(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.finops import analysis
    from app.services.notifications.reports import collection_health

    db = ctx.db
    health = collection_health(db)
    alerts = 0
    for b in analysis.budget_status(db):
        if not b["level"]:
            continue
        subject = f"Budget {b['level_label']}: {b['provider'].upper()} {b['scope']} at {b['utilisation_percent']}% ({b['period_start']})"
        marker = f"budget:{b['id']}:{b['level']}:{b['period_start']}"
        if db.scalar(select(NotificationLog.id).where(NotificationLog.category == "budget_alert", NotificationLog.body.like(f"%{marker}%"))) is None:
            db.add(NotificationLog(channel="google_chat", category="budget_alert", subject=subject, execution_id=ctx.execution_id, status="queued",
                                   body=f"Actual {b['actual']} of approved {b['approved']} {b['currency']} (provisional data).\nref {marker}"))
            alerts += 1
    db.commit()
    summary, failures = _sync(ctx, settings, ["AWS_Billing", "GCP_Billing", "Azure_Billing", "Billing_Summary"])
    summary.update(budget_alerts_queued=alerts, collection=health["jobs"]["billing_refresh"])
    if health["jobs"]["billing_refresh"] != "success":
        failures += [f for f in health["failing"] if f["job"] == "billing_refresh"] or [
            {"provider": "*", "scope": "*", "reason": f"billing_refresh collection status in the last 24h: {health['jobs']['billing_refresh']}"}]
    return _result(summary, failures)


def _send_report(ctx: JobContext, settings: Settings, category: str, subject: str, body: str, overall: str, tabs: list[str]) -> JobResult:
    from app.services.notifications.dispatcher import dispatch

    db = ctx.db
    summary, failures = _sync(ctx, settings, tabs)
    for channel in ("email", "google_chat"):
        db.add(NotificationLog(channel=channel, category=category, subject=f"[{overall}] {subject}", body=body, execution_id=ctx.execution_id, status="queued"))
    db.commit()
    sent = dispatch(ctx, settings)
    summary.update(report_status=overall, delivery=sent.summary)
    failures += sent.failures
    return _result(summary, failures, 2)


def consolidated_daily_report(ctx: JobContext, settings: Settings) -> JobResult:
    """Daily Governance Dashboard: HTML e-mail (with plain-text part), a short Google Chat summary and one append-only
    row in the audit register, plus the register tabs refreshed. Delivery is reported only when the channel accepted it."""
    from app.core.logging import safe_error
    from app.services.ai.analysis import executive_summary
    from app.services.ai.provider import build_provider
    from app.services.notifications import governance as gov
    from app.services.notifications.dispatcher import dispatch

    db = ctx.db
    snap = gov.snapshot(db, settings)
    subject, body, page, short = gov.subject(snap, settings), gov.text(snap), gov.html(snap), gov.chat(snap)
    ai = executive_summary(build_provider(settings), body)
    if ai:  # advisory, clearly labelled, generated only from the verified figures above
        body += "\n\nAI-ASSISTED SUMMARY (advisory only, generated from the figures above)\n" + ai
        page = page.replace("</td></tr></table></td></tr></table></body>", '<div style="background:#fff;border:1px dashed #98a2b3;border-radius:10px;padding:14px 18px;margin:0 0 14px 0">'
                            '<div style="font-size:11px;color:#667085">AI insight · advisory only · generated from the figures above</div>'
                            f'<div style="font-size:13px;color:#344054;white-space:pre-wrap">{gov._e(ai)}</div></div></td></tr></table></td></tr></table></body>', 1)
    summary, failures = _sync(ctx, settings, ["Daily_Review_Status", "Automation_Execution_Logs", "Access_Assignments", "Identity_Changes",
                                              "Audit_Anomalies", "Billing_Periods", "Cloud_Security_Findings", "Governance_Daily_Snapshot"])
    if settings.sheets_enabled:
        try:
            from app.services.google_sheets.register import append_governance
            summary["governance_row"] = "appended" if append_governance(_sheets_backend(ctx, settings), gov.register_row(snap)) else "already recorded today"
        except Exception as exc:  # noqa: BLE001
            failures.append({"provider": "google_sheets", "scope": "Governance_Daily_Snapshot", "reason": safe_error(exc)})
    db.add(NotificationLog(channel="email", category="daily_report", subject=subject[:255], body=body, body_html=page, execution_id=ctx.execution_id, status="queued"))
    db.add(NotificationLog(channel="google_chat", category="daily_report", subject=f"LV NEXUS daily governance – {snap['date']}", body=short,
                           execution_id=ctx.execution_id, status="queued"))
    db.commit()
    sent = dispatch(ctx, settings)
    summary.update(report_status=snap["status"], delivery=sent.summary)
    failures += sent.failures
    return _result(summary, failures, 2)


def weekly_reports(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.notifications.reports import weekly_report
    return _send_report(ctx, settings, "weekly_report", *weekly_report(ctx.db, settings), ["Weekly_Review_Status"])


def monthly_reports(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.notifications.reports import monthly_report
    return _send_report(ctx, settings, "monthly_report", *monthly_report(ctx.db, settings), ["Monthly_Review_Status", "Billing_Summary"])


def asset_details_sync(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.assets.collectors import COLLECTORS
    from app.services.assets.sync import run_asset_details
    return run_asset_details(ctx, settings, [COLLECTORS[p](settings, c) for p, c in _connectors(settings).items()])


def asset_activity_review(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.assets.sync import run_activity_review
    return run_activity_review(ctx, settings)


def monthly_audit_reports(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.reports.audit_mail import run_monthly_audit_reports
    return run_monthly_audit_reports(ctx, settings)


def notification_dispatch(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.notifications.dispatcher import dispatch
    result = dispatch(ctx, settings)
    if result.scopes_total == 0:
        return JobResult(JobStatus.SUCCESS, 0, 0, {"sent": 0, "note": "nothing queued"}, [])
    return result


def ai_analysis(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.ai.analysis import run_ai_analysis
    return run_ai_analysis(ctx, settings)


def security_findings_sync(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.vuln.sync import run_security_sync
    return run_security_sync(ctx, settings, trigger=getattr(ctx, "trigger", "schedule"))


def audit_rule_evaluation(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.audit.engine import run_audit_evaluation
    return run_audit_evaluation(ctx, settings)


def security_sla_check(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.vuln.sla_job import run_sla_check
    return run_sla_check(ctx, settings)


def budget_alerts(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.budget.engine import evaluate_alerts
    summary = evaluate_alerts(ctx.db)
    ctx.db.commit()
    return JobResult(status=JobStatus.SUCCESS, scopes_total=summary["budgets_checked"], summary=summary)


def access_inventory(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.access.engine import run_access_inventory
    return run_access_inventory(ctx, settings, _connectors(settings))


def scheduled_reports(ctx: JobContext, settings: Settings) -> JobResult:
    from app.api.routes.reports import run_due_schedules
    summary = run_due_schedules(ctx.db, settings.frontend_url)
    ctx.db.commit()
    status = JobStatus.SUCCESS if not summary["failed"] else (JobStatus.PARTIAL if summary["generated"] else JobStatus.FAILED)
    return JobResult(status=status, scopes_total=summary["generated"] + summary["failed"], scopes_failed=summary["failed"], summary=summary)


def entra_activity(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.soc.entra import EntraActivityCollector, run_entra_activity
    return run_entra_activity(ctx, settings, EntraActivityCollector(settings))


def cost_detail_refresh(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.finops.detail import run_cost_detail
    return run_cost_detail(ctx, settings, _connectors(settings))


def connection_health(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.connections_health import run_connection_health
    return run_connection_health(ctx, settings)


def anomaly_detection(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.audit.anomaly import run_anomaly_detection
    return run_anomaly_detection(ctx, settings)


def compliance_evaluation(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.compliance.engine import run_compliance_job
    return run_compliance_job(ctx, settings)


def preflight(ctx: JobContext, settings: Settings) -> JobResult:
    from app.services.preflight import run_preflight_job
    return run_preflight_job(ctx, settings)


JOB_FUNCTIONS: dict[str, Callable[[JobContext, Settings], JobResult]] = {
    "account_discovery": account_discovery, "monthly_audit_reports": monthly_audit_reports, "asset_details_sync": asset_details_sync,
    "asset_activity_review": asset_activity_review, "security_events": security_events, "billing_refresh": billing_refresh,
    "vm_metrics": vm_metrics, "resource_inventory": resource_inventory, "sheets_sync": sheets_sync, "soc_daily_review": soc_daily_review, "vm_daily_review": vm_daily_review,
    "billing_daily_review": billing_daily_review, "consolidated_daily_report": consolidated_daily_report,
    "weekly_reports": weekly_reports, "monthly_reports": monthly_reports, "notification_dispatch": notification_dispatch,
    "ai_analysis": ai_analysis, "security_findings_sync": security_findings_sync, "audit_rule_evaluation": audit_rule_evaluation,
    "security_sla_check": security_sla_check, "budget_alerts": budget_alerts, "access_inventory": access_inventory, "scheduled_reports": scheduled_reports,
    "entra_activity": entra_activity, "cost_detail_refresh": cost_detail_refresh, "connection_health": connection_health,
    "anomaly_detection": anomaly_detection, "preflight": preflight, "compliance_evaluation": compliance_evaluation,
}


def job_ready(settings: Settings, name: str) -> bool:
    """Whether the scheduler should start a job automatically. Optional integrations stay idle until configured."""
    if name == "sheets_sync":
        return settings.sheets_enabled
    if name == "security_findings_sync":
        return settings.security_sync_enabled and (settings.aws_enabled or settings.azure_enabled or settings.gcp_enabled)
    if name == "entra_activity":
        return settings.azure_enabled
    if name in ("resource_inventory", "connection_health", "cost_detail_refresh", "anomaly_detection", "asset_details_sync"):
        return settings.aws_enabled or settings.azure_enabled or settings.gcp_enabled
    if name == "ai_analysis":
        from app.services.ai.provider import build_provider
        return build_provider(settings) is not None
    if name == "notification_dispatch":
        return bool(settings.chat_webhook_url or settings.notify_email_enabled)
    return True


def execute(name: str, trigger: str = "schedule", triggered_by: str | None = None, session_factory=None):
    from app.services.connections import effective_settings

    base = get_settings()
    fn = JOB_FUNCTIONS[name]
    # Connection settings saved in the dashboard are read at the start of every run, so changes apply without a restart.
    return run_job(session_factory or get_session_factory(), name, lambda ctx: fn(ctx, effective_settings(ctx.db, base)),
                   trigger=trigger, triggered_by=triggered_by,
                   lock_ttl=base.security_sync_lock_ttl_seconds if name == "security_findings_sync" else base.discovery_lock_ttl_seconds)
