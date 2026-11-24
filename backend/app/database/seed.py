"""Idempotent reference data: roles, permissions and the automation job catalogue."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import PERMISSIONS, ROLES
from app.models import AutomationJob, Permission, Role

# name: (description, cron in Asia/Kolkata, implemented)
JOB_CATALOGUE: dict[str, tuple[str, str, bool]] = {
    "account_discovery": ("Discover and validate AWS accounts, GCP projects, Azure subscriptions", "*/15 * * * *", True),
    "resource_inventory": ("Resource inventory: Azure Resource Manager, AWS services per region, GCP Cloud Asset Inventory (VMs come from vm_metrics)", "*/15 * * * *", True),
    "vm_metrics": ("VM inventory, metrics, port exposure and health", "*/15 * * * *", True),
    "security_events": ("Incremental audit event collection and rule-based detection", "*/5 * * * *", True),
    "billing_refresh": ("Billing data refresh and forecasts", "0 * * * *", True),
    "ai_analysis": ("AI-assisted analysis of open findings (advisory)", "*/15 * * * *", True),
    "sheets_sync": ("Sync the Google Sheets control register", "*/30 * * * *", True),
    "notification_dispatch": ("Deliver queued email and Google Chat notifications", "*/5 * * * *", True),
    "soc_daily_review": ("Daily SOC review", "0 7 * * *", True),
    "vm_daily_review": ("Daily VM health review", "30 7 * * *", True),
    "billing_daily_review": ("Daily billing review and budget warnings", "0 8 * * *", True),
    "consolidated_daily_report": ("Consolidated daily report (email + Google Chat)", "30 8 * * *", True),
    "weekly_reports": ("Weekly security and FinOps summary (Monday)", "0 9 * * 1", True),
    "monthly_reports": ("Monthly expenditure, budget and infrastructure report", "0 9 1 * *", True),
    "monthly_audit_reports": ("Monthly Cloud Security & Governance Audit report per account / subscription / project (PDF + CSV) e-mailed to the account SPOC", "30 9 1 * *", True),
    "security_findings_sync": ("Native security findings sync: AWS Security Hub, Azure Advisor, Google SCC (02:00 UTC)", "0 2 * * *", True),
    "audit_rule_evaluation": ("Evaluate new audit events against detection rules; open cases for flagged activity", "*/5 * * * *", True),
    "security_sla_check": ("Remediation SLA, overdue findings, exception expiry and investigation escalation", "15 * * * *", True),
    "access_inventory": ("Identity and access inventory (Entra ID, Azure RBAC + PIM, AWS IAM / Identity Center, GCP IAM incl. org / folder), "
                         "identity lifecycle, effective access and approval reconciliation", "10,25,40,55 * * * *", True),
    "scheduled_reports": ("Generate due scheduled reports into the archive and e-mail recipients", "7,22,37,52 * * * *", True),
    "entra_activity": ("Microsoft Entra ID audit and sign-in logs into the live activity feed", "*/5 * * * *", True),
    "cost_detail_refresh": ("Detailed cost (resource, region, SKU, usage type, tags), provider forecasts and provider budgets", "20 * * * *", True),
    "connection_health": ("Cloud connection registry: authentication, permissions, API capability and data freshness per scope", "*/15 * * * *", True),
    "anomaly_detection": ("Live audit anomaly detection: new IP / country, unusual hours, failure spikes, privilege changes, mass deletions",
                          "*/5 * * * *", True),
    "preflight": ("Pre-flight: credentials, permissions, data sources and integrations per cloud / scope, with the fix for each failure",
                  "40 6 * * *", True),
    "budget_alerts": ("Budget register: status, utilisation and threshold alerts (internal LV NEXUS alerts)", "25 * * * *", True),
    "compliance_evaluation": ("Compliance policy library: CERT-In, DPDP, ISO 27001/27017/27018, NIST CSF 2.0, CIS, SOC 2, CSA CCM, OWASP checks "
                              "over collected cloud data, with scores and evidence", "50 7,19 * * *", True),
}
ADMIN_SCHEDULED = {"security_findings_sync"}
JOB_TIMEZONES = {"security_findings_sync": "UTC", "security_sla_check": "UTC", "budget_alerts": "UTC", "access_inventory": "UTC", "scheduled_reports": "UTC",
                 "entra_activity": "UTC", "cost_detail_refresh": "UTC", "connection_health": "UTC"}


def seed_reference_data(db: Session) -> None:
    perms = {p.name: p for p in db.scalars(select(Permission))}
    for name, desc in PERMISSIONS.items():
        if name not in perms:
            perms[name] = Permission(name=name, description=desc)
            db.add(perms[name])
    roles = {r.name: r for r in db.scalars(select(Role))}
    for name, (desc, perm_names) in ROLES.items():
        role = roles.get(name)
        if role is None:
            role = Role(name=name, description=desc)
            db.add(role)
        role.permissions = [perms[p] for p in perm_names]
    jobs = {j.name: j for j in db.scalars(select(AutomationJob))}
    for name, (desc, cron, implemented) in JOB_CATALOGUE.items():
        job = jobs.get(name)
        if job is None:
            job = AutomationJob(name=name)
            db.add(job)
        if name not in ADMIN_SCHEDULED or job.schedule is None:  # the security sync schedule is set by administrators in the UI
            job.schedule = cron
        job.description, job.implemented = desc, implemented
        if name in JOB_TIMEZONES:
            job.schedule_timezone = JOB_TIMEZONES[name]
    from app.services.vuln.defaults import seed_security_defaults
    seed_security_defaults(db)
    from app.services.budget.engine import seed_budget_defaults
    seed_budget_defaults(db)
    from app.services.access.engine import seed_access_defaults
    seed_access_defaults(db)
    db.commit()
