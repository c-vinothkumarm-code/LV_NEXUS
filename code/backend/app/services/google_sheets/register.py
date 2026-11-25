"""Multi-Cloud-Operations-Control-Register: 23 tabs kept in step with the database (external-audit reference).

Rules: every row has a stable Record Key in column A (no duplicates); history tabs are append-only;
upsert tabs rewrite only the automation-owned columns, so anything a reviewer types to the right of
them (reviewer, notes, evidence links) is never overwritten."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.api.serializers import query_scopes
from app.core.config import Settings
from app.models import AuditEvent, AutomationExecutionLog, BillingRecord, RemediationRecord, SecurityFinding, SecurityReview, VMAlert, VMInventory, VMMetric
from app.services.finops import analysis
from app.services.notifications.governance import REGISTER_HEAD as GOVERNANCE_HEAD

from .backend import SheetsBackend

HUMAN = ["Reviewer", "Reviewer Notes", "Evidence Link"]  # never written by automation


@dataclass
class Tab:
    name: str
    headers: list[str]
    rows: Callable[[Session, Settings], list[list]]
    append_only: bool = False
    human_columns: bool = False


def _t(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ""


def _n(v):
    return "" if v is None else round(float(v), 2)


def _check(row, name: str) -> str:
    return ((row.checks or {}).get(name) or {}).get("status", "n/a")


def _inventory(db, s):
    return [[f"{r.provider}:{r.external_id}", r.provider.upper(), r.external_id, r.name, r.provider_state, r.parent or "", r.environment or "",
             r.onboarding_status, _t(r.first_discovered_at), _t(r.last_seen_at), _t(datetime.now(UTC))] for r in query_scopes(db)]


def _onboarding(db, s):
    return [[f"{r.provider}:{r.external_id}", r.provider.upper(), r.external_id, r.name, r.onboarding_status,
             *[_check(r, c) for c in ("authentication", "permissions", "configuration", "audit_logs", "billing", "monitoring")],
             _t(r.last_validated_at)] for r in query_scopes(db)]


def _audit(db, s):
    since = datetime.now(UTC) - timedelta(days=7)
    q = select(AuditEvent).where(AuditEvent.detection_status == "flagged", AuditEvent.event_timestamp >= since).order_by(AuditEvent.event_timestamp)
    return [[f"{e.provider}:{e.event_id}", e.provider.upper(), e.scope_external_id, e.region or "", _t(e.event_timestamp), e.event_name,
             e.principal or "", e.source_ip or "", e.resource_id or "", e.resource_type or "", e.event_category or "", e.severity or "",
             e.risk_score if e.risk_score is not None else "", e.description or "", "Collected", "Flagged by rule", e.review_status]
            for e in db.scalars(q.limit(20000))]


def _findings(db, s):
    return [[f"finding:{f.id}", f.provider.upper(), f.scope_external_id, f.rule_id, f.title, f.severity, f.risk_score, f.principal or "",
             f.resource_id or "", f.occurrence_count, _t(f.first_seen_at), _t(f.last_seen_at), f.review_status, f.recommended_action or "",
             (f.ai_analysis or "")[:2000], f"{s.dashboard_url.rstrip('/')}/soc" if s.dashboard_url else ""]
            for f in db.scalars(select(SecurityFinding).order_by(SecurityFinding.id))]


def _reviews(db, s):
    return [[f"review:{r.id}", r.finding_id, r.previous_status or "", r.new_status, r.reviewer, r.notes or "", r.evidence_reference or "", _t(r.created_at)]
            for r in db.scalars(select(SecurityReview).order_by(SecurityReview.id))]


def _billing(provider: str):
    def rows(db, s):
        since = datetime.now(UTC).date() - timedelta(days=s.finops_lookback_days)
        provisional = func.sum(case((BillingRecord.is_final.is_(False), 1), else_=0))
        q = (select(BillingRecord.scope_external_id, BillingRecord.usage_date, func.min(BillingRecord.currency_original),
                    func.sum(BillingRecord.cost_original), func.sum(BillingRecord.cost_usd), func.sum(BillingRecord.cost_inr),
                    func.max(BillingRecord.conversion_rate), func.min(BillingRecord.billing_period_start), provisional)
             .where(BillingRecord.provider == provider, BillingRecord.usage_date >= since)
             .group_by(BillingRecord.scope_external_id, BillingRecord.usage_date).order_by(BillingRecord.usage_date, BillingRecord.scope_external_id))
        return [[f"{scope}:{d.isoformat()}", scope, d.isoformat(), cur, _n(orig), _n(usd), _n(inr), _n(rate) if rate else "",
                 bps.isoformat() if bps else "", "Provisional" if prov else "Final"] for scope, d, cur, orig, usd, inr, rate, bps, prov in db.execute(q).all()]
    return rows


def _billing_summary(db, s):
    m = analysis.monthly_summary(db, datetime.now(UTC).date())
    budgets = {(b["provider"], b["scope"]): b for b in analysis.budget_status(db) if b["service"] == "*"}
    start = date.fromisoformat(m["month"] + "-01")
    per = db.execute(select(BillingRecord.provider, BillingRecord.scope_external_id, func.sum(BillingRecord.cost_usd))
                     .where(BillingRecord.usage_date >= start).group_by(BillingRecord.provider, BillingRecord.scope_external_id)).all()
    out = []
    for p, scope, mtd in per:
        b = budgets.get((p, scope), {})
        out.append([f"{p}:{scope}:{m['month']}", p.upper(), scope, m["month"], _n(mtd), b.get("approved", ""), b.get("utilisation_percent", ""),
                    b.get("level_label", "No budget"), b.get("forecast", "") or "", b.get("remaining", ""), "Provisional (not a final invoice)"])
    return out


def _vm_inventory(db, s):
    return [[f"{v.provider}:{v.instance_id}", v.provider.upper(), v.scope_external_id, v.name or "", v.region or "", v.instance_type or "",
             v.power_state or "", v.public_ip or "", v.private_ip or "", ", ".join(v.exposed_ports or []), v.health_status, _t(v.launched_at),
             _t(v.last_seen_at), "Deleted" if v.deleted_at else "Present"] for v in db.scalars(select(VMInventory).order_by(VMInventory.id))]


def _vm_health(db, s):
    latest = select(VMMetric.vm_id, func.max(VMMetric.id).label("mid")).group_by(VMMetric.vm_id).subquery()
    q = select(VMMetric, VMInventory).join(latest, VMMetric.id == latest.c.mid).join(VMInventory, VMInventory.id == VMMetric.vm_id)
    return [[f"{v.provider}:{v.instance_id}:{m.collected_at:%Y%m%d%H%M}", v.provider.upper(), v.scope_external_id, v.name or "", _t(m.collected_at),
             _n(m.cpu_percent), _n(m.memory_percent), _n(m.disk_percent), _n(m.network_in_bytes), _n(m.network_out_bytes),
             ", ".join(m.missing_metrics or []) or "none", v.health_status] for m, v in db.execute(q).all()]


def _vm_alerts(db, s):
    q = select(VMAlert, VMInventory).join(VMInventory, VMInventory.id == VMAlert.vm_id).order_by(VMAlert.id)
    return [[f"alert:{a.id}", v.provider.upper(), v.scope_external_id, v.name or "", a.alert_type, a.severity, a.message or "", a.status,
             _t(a.created_at), _t(a.resolved_at)] for a, v in db.execute(q).all()]


def _review_status(period: str, days: int):
    """One row per scope per period: what automation collected. Review status starts as pending and is
    only ever completed by a person in the reviewer columns."""
    def rows(db, s):
        now = datetime.now(UTC)
        since = now - timedelta(days=days)
        label = now.strftime("%Y-%m-%d") if period == "daily" else now.strftime("%G-W%V") if period == "weekly" else now.strftime("%Y-%m")
        def grouped(model, ts, *where):
            return {(p, sc): n for p, sc, n in db.execute(select(model.provider, model.scope_external_id, func.count()).where(ts >= since, *where)
                                                         .group_by(model.provider, model.scope_external_id)).all()}
        events = grouped(AuditEvent, AuditEvent.event_timestamp)
        findings = grouped(SecurityFinding, SecurityFinding.last_seen_at)
        pending = grouped(SecurityFinding, SecurityFinding.last_seen_at, SecurityFinding.review_status.in_(["Pending Review", "Under Investigation"]))
        cost = {(p, sc): c for p, sc, c in db.execute(select(BillingRecord.provider, BillingRecord.scope_external_id, func.sum(BillingRecord.cost_usd))
                .where(BillingRecord.usage_date >= since.date()).group_by(BillingRecord.provider, BillingRecord.scope_external_id)).all()}
        out = []
        for r in query_scopes(db):
            k = (r.provider, r.external_id)
            out.append([f"{label}:{r.provider}:{r.external_id}", label, r.provider.upper(), r.external_id, r.name, r.onboarding_status,
                        events.get(k, 0), findings.get(k, 0), pending.get(k, 0), _n(cost.get(k)),
                        "Pending human review" if pending.get(k, 0) else "No open findings from automation", _t(now)])
        return out
    return rows


def _remediation(db, s):
    return [[f"task:{t.id}", t.category, t.provider.upper(), t.scope_external_id, t.title, t.proposed_action or "", t.status, t.decided_by or "",
             _t(t.decided_at), _t(t.created_at), _t(t.resolved_at)] for t in db.scalars(select(RemediationRecord).order_by(RemediationRecord.id))]


def _executions(db, s):
    q = select(AutomationExecutionLog).where(AutomationExecutionLog.finished_at.is_not(None),
                                             AutomationExecutionLog.started_at >= datetime.now(UTC) - timedelta(days=14)).order_by(AutomationExecutionLog.id)
    return [[f"exec:{e.id}", e.job_name, e.trigger, e.status, _t(e.started_at), _t(e.finished_at), e.scopes_total, e.scopes_failed,
             "; ".join(f"{f.get('provider')}/{f.get('scope')}: {f.get('reason')}" for f in (e.failures or [])[:10])[:4000] or (e.error or "")]
            for e in db.scalars(q)]


def _names(db) -> dict:
    from app.services.notifications.governance import scope_names
    return scope_names(db)


def _access_assignments(db, s):
    from app.models.access import AccessAssignment, CloudIdentity
    names = _names(db)
    idents = {(i.provider, i.principal_id): i for i in db.scalars(select(CloudIdentity))}
    out = []
    for a in db.scalars(select(AccessAssignment).order_by(AccessAssignment.id).limit(50000)):
        i = idents.get((a.provider, a.principal_id))
        out.append([f"{a.provider}:{a.source_id_hash}", a.provider.upper(), names.get((a.provider, a.scope_external_id), a.scope_external_id), a.scope_external_id,
                    a.scope_level or "", a.resource_group or "", a.resource_name or "", (i.display_name if i else None) or a.principal_id,
                    (i.sign_in_name if i else None) or "", a.principal_type or "", a.role_name or "", "Yes" if a.privileged else "No", a.pim_state or "active",
                    a.inherited_from or "", _t(a.expires_at), _t(a.first_seen_at), _t(a.last_seen_at), _t(a.removed_at) or "current"])
    return out


def _identity_changes(db, s):
    from app.models.iam import IdentityChangeEvent
    names = _names(db)
    q = select(IdentityChangeEvent).where(IdentityChangeEvent.detected_at >= datetime.now(UTC) - timedelta(days=30)).order_by(IdentityChangeEvent.id)
    return [[f"change:{c.id}", c.provider.upper(), names.get((c.provider, c.scope_external_id), c.scope_external_id or "directory"), c.principal_name or c.principal_id,
             c.principal_type or "", c.change_type, "Yes" if c.privileged else "No", str(c.previous_state or "")[:500], str(c.new_state or "")[:500],
             c.initiated_by or "", c.approval_reference or "", _t(c.detected_at)] for c in db.scalars(q.limit(20000))]


def _anomalies(db, s):
    from app.models.platform import AuditAnomaly
    names = _names(db)
    q = select(AuditAnomaly).where(AuditAnomaly.last_event_at >= datetime.now(UTC) - timedelta(days=90)).order_by(AuditAnomaly.id)
    return [[f"anomaly:{a.dedupe_key}", a.provider.upper(), names.get((a.provider, a.scope_external_id), a.scope_external_id), a.rule, a.severity, a.title,
             a.principal or "", a.event_count, _t(a.first_event_at), _t(a.last_event_at), a.status, a.acknowledged_by or "", _t(a.acknowledged_at), a.note or ""]
            for a in db.scalars(q.limit(20000))]


def _billing_periods(db, s):
    from app.models import BillingPeriod
    names = _names(db)
    return [[f"{b.provider}:{b.scope_external_id}:{b.name}", b.provider.upper(), names.get((b.provider, b.scope_external_id), b.scope_external_id),
             b.scope_external_id, b.name, b.period_start.isoformat(), b.period_end.isoformat(), b.source, _n(b.total_original), b.currency or "",
             _n(b.total_usd), _n(b.total_inr), b.total_source or "", "Final" if b.is_final else "Provisional", _t(b.total_collected_at)]
            for b in db.scalars(select(BillingPeriod).order_by(BillingPeriod.provider, BillingPeriod.scope_external_id, BillingPeriod.period_start))]


def _cloud_findings(db, s):
    from app.models.vuln import CloudSecurityFinding as F
    names = _names(db)
    since = datetime.now(UTC) - timedelta(days=30)
    q = select(F).where(F.is_security.is_(True), (F.internal_status.in_(("OPEN", "UNDER_REVIEW", "REOPENED"))) | (F.resolved_at >= since)).order_by(F.id)
    return [[f"{f.provider}:{f.native_id_hash}", f.provider.upper(), names.get((f.provider, f.scope_external_id), f.scope_external_id), f.source, f.severity,
             f.title, f.resource_name or f.resource_id or "", f.compliance_standard or "", f.control_id or "", f.internal_status, _t(f.sla_due_at),
             _t(f.first_observed_at or f.first_synced_at), _t(f.last_observed_at), _t(f.resolved_at), f.owner or ""] for f in db.scalars(q.limit(30000))]


def _none(db, s):
    return []  # rows are appended by the daily governance report only


_REVIEW_HEAD = ["Record Key", "Period", "Cloud", "Scope ID", "Scope Name", "Onboarding Status", "Events Collected", "Findings", "Pending Review",
                "Cost USD", "Automation Status", "Updated At"]
_BILL_HEAD = ["Record Key", "Scope ID", "Usage Date", "Original Currency", "Cost (Original)", "Cost USD", "Cost INR", "USD/INR Rate",
              "Billing Period Start", "Data Status"]

TABS: list[Tab] = [
    Tab("Cloud_Inventory", ["Record Key", "Cloud", "Scope ID", "Name", "Provider State", "Parent", "Environment", "Onboarding Status",
                            "First Discovered", "Last Seen", "Updated At"], _inventory),
    Tab("Account_Onboarding", ["Record Key", "Cloud", "Scope ID", "Name", "Status", "Authentication", "Permissions", "Configuration", "Audit Logs",
                               "Billing", "Monitoring", "Last Validated"], _onboarding),
    Tab("SOC_Audit_Logs", ["Record Key", "Cloud", "Scope ID", "Region", "Event Timestamp", "Event Name", "Principal", "Source IP", "Resource ID",
                           "Resource Type", "Category", "Severity", "Risk Score", "Description", "Collection Status", "Detection Status",
                           "Review Status"], _audit, append_only=True),
    Tab("Security_Findings", ["Record Key", "Cloud", "Scope ID", "Rule", "Title", "Severity", "Risk Score", "Principal", "Resource", "Occurrences",
                              "First Seen", "Last Seen", "Review Status", "Recommended Action", "AI Analysis", "Dashboard Link"], _findings, human_columns=True),
    Tab("Security_Reviews", ["Record Key", "Finding ID", "Previous Status", "New Status", "Reviewer", "Notes", "Evidence Reference", "Reviewed At"],
        _reviews, append_only=True),
    Tab("AWS_Billing", _BILL_HEAD, _billing("aws")),
    Tab("GCP_Billing", _BILL_HEAD, _billing("gcp")),
    Tab("Azure_Billing", _BILL_HEAD, _billing("azure")),
    Tab("Billing_Summary", ["Record Key", "Cloud", "Scope ID", "Month", "MTD Cost USD", "Approved Budget", "Utilisation %", "Budget Level",
                            "Forecast", "Remaining Budget", "Data Status"], _billing_summary),
    Tab("VM_Inventory", ["Record Key", "Cloud", "Scope ID", "Name", "Region", "Type", "Power State", "Public IP", "Private IP", "Internet-Open Ports",
                         "Health", "Launched", "Last Seen", "Presence"], _vm_inventory),
    Tab("VM_Health", ["Record Key", "Cloud", "Scope ID", "Name", "Collected At", "CPU %", "Memory %", "Disk %", "Network In Bytes", "Network Out Bytes",
                      "Missing Metrics", "Health"], _vm_health, append_only=True),
    Tab("VM_Alerts", ["Record Key", "Cloud", "Scope ID", "VM", "Alert", "Severity", "Message", "Status", "Raised", "Resolved"], _vm_alerts),
    Tab("Daily_Review_Status", _REVIEW_HEAD, _review_status("daily", 1), human_columns=True),
    Tab("Weekly_Review_Status", _REVIEW_HEAD, _review_status("weekly", 7), human_columns=True),
    Tab("Monthly_Review_Status", _REVIEW_HEAD, _review_status("monthly", 31), human_columns=True),
    Tab("Remediation_Tracker", ["Record Key", "Category", "Cloud", "Scope ID", "Title", "Proposed Action", "Status", "Decided By", "Decided At",
                                "Raised", "Resolved"], _remediation, human_columns=True),
    Tab("Automation_Execution_Logs", ["Record Key", "Job", "Trigger", "Status", "Started", "Finished", "Scopes Checked", "Scopes Failed", "Failures"],
        _executions, append_only=True),
    Tab("Governance_Daily_Snapshot", GOVERNANCE_HEAD, _none, append_only=True, human_columns=True),
    Tab("Access_Assignments", ["Record Key", "Cloud", "Subscription / Account", "Scope ID", "Level", "Resource Group", "Resource", "Identity",
                               "Sign-in Name", "Identity Type", "Role", "Privileged", "PIM State", "Inherited From", "Expires", "First Seen",
                               "Last Seen", "Removed"], _access_assignments),
    Tab("Identity_Changes", ["Record Key", "Cloud", "Subscription / Account", "Identity", "Identity Type", "Change", "Privileged", "Before", "After",
                             "Initiated By", "Approval Reference", "Detected"], _identity_changes, append_only=True),
    Tab("Audit_Anomalies", ["Record Key", "Cloud", "Subscription / Account", "Rule", "Severity", "Title", "Principal", "Events", "First Event",
                            "Last Event", "Status", "Acknowledged By", "Acknowledged At", "Note"], _anomalies, human_columns=True),
    Tab("Billing_Periods", ["Record Key", "Cloud", "Subscription / Account", "Scope ID", "Period", "Start", "End", "Dates Source", "Cost (Billing Currency)",
                            "Currency", "Cost USD", "Cost INR", "Total Source", "Data Status", "Collected"], _billing_periods),
    Tab("Cloud_Security_Findings", ["Record Key", "Cloud", "Subscription / Account", "Source", "Severity", "Title", "Resource", "Standard", "Control",
                                    "Status", "SLA Due", "First Observed", "Last Observed", "Resolved", "Owner"], _cloud_findings, human_columns=True),
]
TAB_NAMES = [t.name for t in TABS]


def sync_register(db: Session, settings: Settings, backend: SheetsBackend, only: list[str] | None = None) -> dict:
    """Idempotent sync. Returns per-tab counts and per-tab errors (a failing tab does not stop the others)."""
    tabs = [t for t in TABS if only is None or t.name in only]
    backend.ensure_tabs({t.name: t.headers + (HUMAN if t.human_columns else []) for t in tabs})
    result: dict = {"tabs": {}, "errors": {}}
    for tab in tabs:
        try:
            rows = tab.rows(db, settings)
            index = {}
            for n, key in enumerate(backend.read_keys(tab.name), start=2):
                index.setdefault(key, n)
            new = [r for r in rows if r[0] not in index]
            seen, deduped = set(), []
            for r in new:  # also guard against duplicate keys inside one batch
                if r[0] not in seen:
                    seen.add(r[0])
                    deduped.append(r)
            updates = {} if tab.append_only else {index[r[0]]: r for r in rows if r[0] in index}
            if updates:
                backend.update_rows(tab.name, updates, len(tab.headers))
            if deduped:
                backend.append_rows(tab.name, deduped)
            result["tabs"][tab.name] = {"appended": len(deduped), "updated": len(updates)}
        except Exception as exc:  # noqa: BLE001 - recorded as a failure for this tab
            from app.core.logging import safe_error
            result["errors"][tab.name] = safe_error(exc)
    return result


def append_governance(backend: SheetsBackend, row: list) -> bool:
    """Append today's governance snapshot once (the Record Key is the date). Returns False when it was already there."""
    tab = next(t for t in TABS if t.name == "Governance_Daily_Snapshot")
    backend.ensure_tabs({tab.name: tab.headers + HUMAN})
    if row[0] in set(backend.read_keys(tab.name)):
        return False
    backend.append_rows(tab.name, [row])
    return True
