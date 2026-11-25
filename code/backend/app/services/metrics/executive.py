"""Executive Overview metrics: every number with its definition, source, calculation, timestamp, scope and availability.

Rules
- Values come only from data LV NEXUS collected. Nothing is estimated or filled in.
- "No data" is never 0: a metric whose source was never collected has value None and availability "not_collected";
  a source whose latest collection failed is "failed" (last stored value kept); older than its freshness window is "stale".
- Only metrics the caller's role may see are returned (the same permissions as the pages behind them).
"""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from statistics import median

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.serializers import iso
from app.core.config import Settings
from app.models import (
    SCOPE_MODELS,
    AccessAssignment,
    AuditEvent,
    AuditInvestigation,
    AutomationExecutionLog,
    BillingForecast,
    BillingRecord,
    CloudResource,
    CloudSecurityFinding,
    ComplianceResult,
    FindingException,
    IdentityChangeEvent,
    JobStatus,
    SyncCheckpoint,
    VMInventory,
    VMMetric,
)

PROVIDERS = ("aws", "azure", "gcp")
NOUN = {"aws": "AWS accounts", "azure": "Azure subscriptions", "gcp": "GCP projects"}
NAME = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
OK_STATES = (JobStatus.SUCCESS.value, JobStatus.PARTIAL.value)
OPEN = ("OPEN", "UNDER_REVIEW", "REOPENED")
RUNNING = ("running", "vm running", "poweredon")
STOPPED = ("stopped", "vm stopped", "vm deallocated", "deallocated", "terminated", "poweredoff", "suspended")

# section -> (jobs that collect it, freshness window, permission(s) needed)
SECTIONS = {
    "connectivity": (["account_discovery"], timedelta(hours=6), "inventory:read"),
    "security": (["security_findings_sync"], timedelta(hours=30), "vuln:read"),
    "infrastructure": (["resource_inventory", "vm_metrics"], timedelta(hours=3), "infra:read|inventory:read"),
    "finops": (["billing_refresh"], timedelta(hours=30), "finops:read"),
    "governance": (["compliance_evaluation"], timedelta(hours=30), "onboarding:read|reports:export"),
    "operations": (["security_events", "entra_activity", "access_inventory"], timedelta(hours=1), "audit:read"),
}
LINKS = {"connectivity": "/accounts", "security": "/vulnerabilities", "infrastructure": "/monitoring", "finops": "/cost/overview",
         "governance": "/compliance", "operations": "/activity"}


def _aware(dt):
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _section_state(db: Session, section: str, has_data: bool, data_time) -> dict:
    jobs, window, _perm = SECTIONS[section]
    last_ok = db.scalar(select(func.max(AutomationExecutionLog.finished_at)).where(
        AutomationExecutionLog.job_name.in_(jobs), AutomationExecutionLog.status.in_(OK_STATES)))
    last = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name.in_(jobs),
                                                          AutomationExecutionLog.status != JobStatus.SKIPPED_OVERLAP.value)
                     .order_by(AutomationExecutionLog.id.desc()).limit(1))
    as_of = _aware(last_ok) or _aware(data_time)
    if not has_data and as_of is None:
        availability = "not_collected"
    elif last is not None and last.status == JobStatus.FAILED.value:
        availability = "failed"
    elif as_of is not None and datetime.now(UTC) - as_of > window:
        availability = "stale"
    else:
        availability = "available"
    reason = None
    if last is not None and last.status in (JobStatus.FAILED.value, JobStatus.PARTIAL.value):
        reason = (last.error or "; ".join(f.get("reason", "") for f in (last.failures or [])[:2]))[:240] or None
    return {"as_of": iso(as_of), "availability": availability, "reason": reason, "jobs": jobs}


class _Builder:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, section: str, state: dict, key: str, label: str, value, unit: str, definition: str, source: str, calculation: str,
            scope: str = "All accounts, subscriptions and projects collected", breakdown: dict | None = None, link: str | None = None,
            tone: str | None = None, availability: str | None = None, note: str | None = None):
        avail = availability or (state["availability"] if value is not None else ("not_collected" if state["availability"] in ("available", "not_collected") else state["availability"]))
        self.items.append({"key": key, "section": section, "label": label, "value": value, "unit": unit, "definition": definition, "source": source,
                           "calculation": calculation, "as_of": state["as_of"], "scope": scope, "availability": avail, "reason": state["reason"],
                           "breakdown": breakdown, "link": link or LINKS[section], "tone": tone, "note": note})


def _can(perms: set[str], need: str) -> bool:
    return any(p in perms for p in need.split("|"))


def executive_metrics(db: Session, settings: Settings, perms: set[str]) -> dict:
    now = datetime.now(UTC)
    today = now.date()
    m0 = today.replace(day=1)
    pm0 = (m0 - timedelta(days=1)).replace(day=1)
    b = _Builder()
    allowed = {s for s, (_j, _w, need) in SECTIONS.items() if _can(perms, need)}

    # ---------------- connectivity
    if "connectivity" in allowed:
        rows = {p: list(db.scalars(select(m))) for p, m in SCOPE_MODELS.items()}
        total = sum(len(r) for r in rows.values())
        seen = [_aware(s.last_seen_at) for r in rows.values() for s in r if getattr(s, "last_seen_at", None)]
        st = _section_state(db, "connectivity", total > 0, max(seen) if seen else None)
        for p in PROVIDERS:
            onboarded = sum(1 for s in rows[p] if s.onboarding_status == "Fully Onboarded")
            b.add("connectivity", st, f"scopes_{p}", NOUN[p], len(rows[p]) if rows[p] or total else None, "count",
                  f"{NOUN[p]} discovered by LV NEXUS through the provider's organization / tenant / resource manager API.",
                  {"aws": "AWS Organizations ListAccounts", "azure": "Azure Resource Manager subscriptions", "gcp": "Cloud Resource Manager projects"}[p],
                  "Count of discovered scopes; 'fully onboarded' = every onboarding check passes.", scope=f"{NAME[p]} organization / tenant",
                  breakdown={"fully_onboarded": onboarded, "discovered": len(rows[p])})
        onboarded_all = sum(1 for r in rows.values() for s in r if s.onboarding_status == "Fully Onboarded")
        b.add("connectivity", st, "account_coverage", "Account coverage", round(100 * onboarded_all / total, 1) if total else None, "percent",
              "Share of discovered accounts / subscriptions / projects where every onboarding check (authentication, permissions, logs, billing, monitoring) passes.",
              "LV NEXUS onboarding validation", "fully onboarded scopes ÷ discovered scopes × 100",
              tone="good" if total and onboarded_all == total else "warning" if total else None)
        runs = list(db.scalars(select(AutomationExecutionLog).where(AutomationExecutionLog.started_at >= now - timedelta(hours=24),
                                                                    AutomationExecutionLog.status != JobStatus.SKIPPED_OVERLAP.value)))
        done = [r for r in runs if r.status in (JobStatus.SUCCESS.value, JobStatus.PARTIAL.value, JobStatus.FAILED.value)]
        ok = sum(1 for r in done if r.status == JobStatus.SUCCESS.value)
        b.add("connectivity", st, "collection_success_rate", "Collection success rate (24 h)", round(100 * ok / len(done), 1) if done else None, "percent",
              "Share of collection job runs in the last 24 hours that completed without any failed account, region or API call.",
              "LV NEXUS job execution log", "successful runs ÷ (successful + partial + failed runs) × 100",
              breakdown=dict(Counter(r.status for r in done)) or None, link="/automation",
              tone=None if not done else "good" if ok == len(done) else "warning")
        cps = list(db.scalars(select(SyncCheckpoint)))
        regions = {(c.provider, c.region) for c in cps if c.region}
        ok_regions = {(c.provider, c.region) for c in cps if c.region and c.state == "OK"}
        b.add("connectivity", st, "region_coverage", "Regions collected (security data)", len(ok_regions) if regions else None, "count",
              "Distinct provider regions where the latest security-data collection succeeded.", "LV NEXUS security collection checkpoints",
              "count of distinct (provider, region) with a checkpoint in state OK", breakdown={"regions_attempted": len(regions), "regions_ok": len(ok_regions)} if regions else None,
              link="/integrations/regions", note=f"{len(regions) - len(ok_regions)} region(s) attempted without success" if len(regions) > len(ok_regions) else None)

    # ---------------- security
    if "security" in allowed:
        q = [CloudSecurityFinding.is_security.is_(True), CloudSecurityFinding.native_state == "ACTIVE", CloudSecurityFinding.internal_status.in_(OPEN)]
        any_findings = db.scalar(select(func.count()).select_from(CloudSecurityFinding)) or 0
        st = _section_state(db, "security", any_findings > 0, db.scalar(select(func.max(CloudSecurityFinding.last_synced_at))))
        sev = dict(db.execute(select(CloudSecurityFinding.severity, func.count()).where(*q).group_by(CloudSecurityFinding.severity)).all())
        by_p = dict(db.execute(select(CloudSecurityFinding.provider, func.count()).where(*q).group_by(CloudSecurityFinding.provider)).all())
        has = any_findings > 0 or st["availability"] != "not_collected"
        src = "AWS Security Hub, Microsoft Defender for Cloud / Advisor, Google Security Command Center"
        total_open = sum(sev.values())
        b.add("security", st, "findings_open", "Open findings", total_open if has else None, "count",
              "Security findings that are active at the provider and open in LV NEXUS (open, under review or reopened).", src,
              "count where native state = ACTIVE and internal status ∈ {OPEN, UNDER_REVIEW, REOPENED}", breakdown=by_p or None)
        for s, tone in (("Critical", "critical"), ("High", "serious"), ("Medium", "warning")):
            b.add("security", st, f"findings_{s.lower()}", f"{s} findings", sev.get(s, 0) if has else None, "count",
                  f"Open findings the provider rates {s}.", src, f"open findings with severity = {s}", tone=tone if sev.get(s) else None,
                  link=f"/vulnerabilities/findings?severity={s}")
        week = now - timedelta(days=7)
        new = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(*q, CloudSecurityFinding.first_observed_at >= week)) or 0
        resolved = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(
            CloudSecurityFinding.is_security.is_(True), CloudSecurityFinding.resolved_at >= now - timedelta(days=30))) or 0
        overdue = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(
            *q, CloudSecurityFinding.sla_due_at.is_not(None), CloudSecurityFinding.sla_due_at < now, CloudSecurityFinding.sla_paused.is_not(True))) or 0
        b.add("security", st, "findings_new_7d", "New findings (7 days)", new if has else None, "count",
              "Open findings first observed by the provider in the last 7 days.", src, "open findings with first_observed_at ≥ now − 7 days")
        b.add("security", st, "findings_resolved_30d", "Resolved findings (30 days)", resolved if has else None, "count",
              "Findings resolved in LV NEXUS or by the provider in the last 30 days.", src, "findings with resolved_at ≥ now − 30 days", tone="good" if resolved else None)
        b.add("security", st, "findings_overdue", "Overdue remediation", overdue if has else None, "count",
              "Open findings past their remediation deadline (SLA by severity); paused SLAs (approved exceptions) are excluded.",
              "LV NEXUS remediation SLA policy", "open findings with sla_due_at < now and SLA not paused", tone="critical" if overdue else None,
              link="/vulnerabilities/sla")

    # ---------------- infrastructure
    if "infrastructure" in allowed:
        res_by_p = dict(db.execute(select(CloudResource.provider, func.count()).where(CloudResource.not_deleted()).group_by(CloudResource.provider)).all())
        vms = list(db.scalars(select(VMInventory).where(VMInventory.deleted_at.is_(None))))
        st = _section_state(db, "infrastructure", bool(res_by_p or vms), db.scalar(select(func.max(CloudResource.last_seen_at))))
        has = bool(res_by_p or vms) or st["availability"] != "not_collected"
        b.add("infrastructure", st, "resources_total", "Cloud resources", sum(res_by_p.values()) if has else None, "count",
              "Resources currently present in the collected inventory (deleted resources excluded).",
              "AWS resource APIs, Azure Resource Graph, Google Cloud Asset Inventory", "count of inventory resources not marked deleted",
              breakdown=res_by_p or None, link="/inventory/explorer")
        cutoff = now - timedelta(hours=2)
        latest = {}
        for vm_id, at, missing in db.execute(select(VMMetric.vm_id, VMMetric.collected_at, VMMetric.missing_metrics)
                                             .where(VMMetric.collected_at >= now - timedelta(hours=24)).order_by(VMMetric.collected_at)).all():
            latest[vm_id] = (_aware(at), missing or [])
        states = Counter()
        for vm in vms:
            power = (vm.power_state or "").lower()
            if power in STOPPED:
                states["stopped"] += 1
            elif power not in RUNNING:
                states["unknown"] += 1
            elif vm.id not in latest or latest[vm.id][0] < cutoff:
                states["unmonitored"] += 1
            elif (vm.health_status or "").lower() in ("unhealthy", "critical", "failed"):
                states["unhealthy"] += 1
            elif (vm.health_status or "").lower() in ("degraded", "warning") or latest[vm.id][1]:
                states["degraded"] += 1
            else:
                states["healthy"] += 1
        running = sum(states[k] for k in ("healthy", "degraded", "unhealthy", "unmonitored"))
        defs = {"healthy": "Running VMs with metrics in the last 2 hours and no health problem reported.",
                "degraded": "Running VMs with a provider warning or some metrics missing.",
                "unhealthy": "Running VMs the provider reports unhealthy.",
                "stopped": "VMs stopped or deallocated at the provider.",
                "unmonitored": "Running VMs with no metrics in the last 2 hours: their health is unknown, never counted as healthy."}
        for k, tone in (("healthy", "good"), ("degraded", "warning"), ("unhealthy", "critical"), ("stopped", None), ("unmonitored", "warning")):
            b.add("infrastructure", st, f"vms_{k}", f"{k.capitalize()} VMs", states[k] if (vms or has) else None, "count", defs[k],
                  "Amazon CloudWatch, Azure Monitor, Google Cloud Monitoring + VM inventory", f"VMs classified as {k} (see definition)",
                  tone=tone if states[k] else None)
        b.add("infrastructure", st, "monitoring_coverage", "Monitoring coverage", round(100 * (running - states["unmonitored"]) / running, 1) if running else None,
              "percent", "Share of running VMs with metrics collected in the last 2 hours.", "VM metrics collection",
              "running VMs with recent metrics ÷ running VMs × 100")

    # ---------------- finops
    if "finops" in allowed:
        any_cost = db.scalar(select(func.count()).select_from(BillingRecord)) or 0
        st = _section_state(db, "finops", any_cost > 0, db.scalar(select(func.max(BillingRecord.collected_at))))
        src = "AWS Cost Explorer, Azure Cost Management, Google Cloud billing export (BigQuery)"
        mtd_by = {p: float(v or 0) for p, v in db.execute(select(BillingRecord.provider, func.sum(BillingRecord.cost_usd))
                                                         .where(BillingRecord.usage_date >= m0, BillingRecord.cost_usd.is_not(None)).group_by(BillingRecord.provider)).all()}
        mtd = sum(mtd_by.values()) if mtd_by else None
        last = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date.between(pm0, m0 - timedelta(days=1)), BillingRecord.cost_usd.is_not(None)))
        scope = f"Calendar month {m0:%b %Y}, USD; Azure subscriptions may bill on a different cycle"
        b.add("finops", st, "spend_mtd", "Month-to-date spend", round(mtd, 2) if mtd is not None else None, "usd",
              "Actual (unblended) cost recorded this calendar month across all collected clouds.", src, "Σ cost_usd for usage dates from the 1st of this month to today",
              scope=scope, breakdown={p: round(v, 2) for p, v in mtd_by.items()} or None, note="Today is partial; providers can revise the last 1–3 days.")
        for p in PROVIDERS:
            b.add("finops", st, f"spend_mtd_{p}", f"{NAME[p]} spend (MTD)", round(mtd_by[p], 2) if p in mtd_by else None, "usd",
                  f"Month-to-date actual cost of {NAME[p]}.", src, f"Σ cost_usd where provider = {p}, usage date this month", scope=scope,
                  link=f"/cost/analysis?provider={p}")
        b.add("finops", st, "spend_last_month", "Previous month spend", round(float(last), 2) if last is not None else None, "usd",
              "Actual cost of the previous calendar month.", src, "Σ cost_usd for the previous calendar month", scope=f"{pm0:%b %Y}, USD")
        fc = [f for f in db.scalars(select(BillingForecast).where(BillingForecast.period_start == m0)) if f.currency == "USD"]
        forecast = None
        if fc:
            by_scope: dict = {}
            for f in fc:
                if f.method.startswith("provider:") or (f.provider, f.scope_external_id) not in by_scope:
                    by_scope[(f.provider, f.scope_external_id)] = f
            mtd_scope = {(p, s): float(v or 0) for p, s, v in db.execute(select(BillingRecord.provider, BillingRecord.scope_external_id, func.sum(BillingRecord.cost_usd))
                                                                         .where(BillingRecord.usage_date >= m0, BillingRecord.cost_usd.is_not(None))
                                                                         .group_by(BillingRecord.provider, BillingRecord.scope_external_id)).all()}
            forecast = sum((mtd_scope.get(k, 0) + float(f.forecast_amount)) if f.method.startswith("provider:") else float(f.forecast_amount) for k, f in by_scope.items())
        b.add("finops", st, "forecast_month", "Forecast (month end)", round(forecast, 2) if forecast is not None else None, "usd",
              "Expected cost for the whole month: provider forecasts where available, otherwise LV NEXUS's run-rate estimate. An estimate, never added to actual cost.",
              "Provider forecast APIs + LV NEXUS run-rate", "per scope: actual MTD + provider forecast for the rest of the month (or run-rate estimate)", scope=scope)
        if _can(perms, "budget:read"):
            from app.api.routes.budgets import budget_summary
            bs = budget_summary(db=db, _=None)
            util = bs.get("utilisation_percent")
            b.add("finops", st, "budget_utilisation", "Budget utilisation", util, "percent",
                  "Actual month-to-date cost of budgeted scopes against their approved monthly budgets (top-level budgets only, no double counting).",
                  "LV NEXUS budget register + billing data", "Σ actual MTD of active root budgets ÷ Σ approved monthly amount × 100",
                  scope=f"{bs.get('root_budgets', 0)} active top-level budget(s)", link="/budgets",
                  availability=None if util is not None else ("not_collected" if not bs.get("root_budgets") else None),
                  tone=None if util is None else "critical" if util > 100 else "warning" if util >= 75 else "good",
                  note="No active budget" if not bs.get("root_budgets") else None)
            approved, fcast = bs.get("approved_monthly_usd"), bs.get("forecast_month_usd")
            b.add("finops", st, "budget_variance", "Budget variance (forecast)", round(fcast - approved, 2) if fcast is not None and approved else None, "usd",
                  "Forecast month-end cost of budgeted scopes minus their approved budget: positive = expected overspend.",
                  "LV NEXUS budget register + forecasts", "Σ forecast of active root budgets − Σ approved monthly amount", link="/budgets",
                  tone=None if fcast is None or not approved else "critical" if fcast > approved else "good")
        from app.services.finops.analysis import anomalies
        try:
            an = anomalies(db, settings) if any_cost else None
        except Exception:  # noqa: BLE001 - shown as unavailable, not as zero
            an = None
        b.add("finops", st, "cost_anomalies", "Cost anomalies (14 days)", len(an) if an is not None else None, "count",
              "Days where a scope's daily cost rose far above its 14-day average (statistical rule: mean + σ multiple and a minimum USD increase).",
              "LV NEXUS cost anomaly rule on collected billing data", "days with cost > mean + k·σ and increase ≥ the configured minimum",
              tone="warning" if an else None, link="/cost/analysis")

    # ---------------- governance
    if "governance" in allowed:
        from app.services.compliance.engine import latest_run
        run = latest_run(db)
        st = _section_state(db, "governance", run is not None, run.finished_at if run else None)
        counts = Counter(s for (s,) in db.execute(select(ComplianceResult.status).where(ComplianceResult.run_id == run.id)).all()) if run else Counter()
        evaluated = sum(counts.values())
        passed, failed = counts.get("PASS", 0), counts.get("FAIL", 0)
        unknown = evaluated - passed - failed
        src = "LV NEXUS policy library evaluated on collected configuration"
        calc_scope = "Latest compliance run; one control = one policy evaluated on one account / subscription / project"
        b.add("governance", st, "controls_evaluated", "Controls evaluated", evaluated if run else None, "count",
              "Policy checks evaluated in the latest compliance run (policy × scope).", src, "count of results in the latest run", scope=calc_scope)
        b.add("governance", st, "controls_passed", "Passed controls", passed if run else None, "count", "Evaluations that passed.", src, "results with status PASS",
              scope=calc_scope, tone="good" if passed else None)
        b.add("governance", st, "controls_failed", "Failed controls", failed if run else None, "count", "Evaluations that failed.", src, "results with status FAIL",
              scope=calc_scope, tone="critical" if failed else None, link="/compliance/policies?status=FAIL")
        b.add("governance", st, "controls_unknown", "Unknown controls", unknown if run else None, "count",
              "Evaluations that could not be assessed (missing data or permission). Never counted as passed.", src, "results not PASS and not FAIL",
              scope=calc_scope, tone="warning" if unknown else None)
        b.add("governance", st, "compliance_percent", "Compliance", round(100 * passed / (passed + failed), 1) if passed + failed else None, "percent",
              "Share of assessed controls that pass. Unknown controls are excluded from the ratio and shown separately.", src,
              "PASS ÷ (PASS + FAIL) × 100", scope=calc_scope)
        if _can(perms, "vuln:read"):
            exc = db.scalar(select(func.count()).select_from(FindingException).where(FindingException.status == "ACTIVE")) or 0
            b.add("governance", st, "exceptions_active", "Active exceptions", exc, "count",
                  "Approved, unexpired risk exceptions on security findings.", "LV NEXUS exception register", "exceptions with status ACTIVE",
                  link="/vulnerabilities/exceptions", availability="available")

    # ---------------- operations (activity, identity)
    if "operations" in allowed:
        any_ev = db.scalar(select(func.count()).select_from(AuditEvent)) or 0
        st = _section_state(db, "operations", any_ev > 0, db.scalar(select(func.max(AuditEvent.collected_at))))
        has = any_ev > 0 or st["availability"] != "not_collected"
        day = now - timedelta(hours=24)
        src = "AWS CloudTrail, Azure Activity Log + Entra ID audit / sign-in logs, Google Cloud Audit Logs"
        ev = dict(db.execute(select(AuditEvent.provider, func.count()).where(AuditEvent.event_timestamp >= day).group_by(AuditEvent.provider)).all())
        b.add("operations", st, "events_24h", "Events (24 h)", sum(ev.values()) if has else None, "count",
              "Cloud control-plane events with an event time in the last 24 hours, as collected so far.", src,
              "count of audit events with event_timestamp ≥ now − 24 h", breakdown=ev or None,
              note="Collected by polling: events appear after the provider's delivery delay plus the polling interval.")
        flagged = db.scalar(select(func.count()).select_from(AuditEvent).join(AuditInvestigation, AuditInvestigation.audit_event_id == AuditEvent.id)
                            .where(AuditEvent.event_timestamp >= day, AuditInvestigation.classification.in_(["SUSPICIOUS", "RULE_VIOLATION"]))) or 0
        b.add("operations", st, "suspicious_24h", "Suspicious activity (24 h)", flagged if has else None, "count",
              "Events a detection rule classified suspicious or a rule violation. A detection, not a confirmed incident.",
              "LV NEXUS detection rules (SOC library)", "events in the last 24 h with classification SUSPICIOUS or RULE_VIOLATION",
              tone="critical" if flagged else None, link="/audit/suspicious")
        failed_runs = db.scalar(select(func.count()).select_from(AutomationExecutionLog).where(
            AutomationExecutionLog.started_at >= day, AutomationExecutionLog.status.in_([JobStatus.FAILED.value, JobStatus.PARTIAL.value]))) or 0
        delays = [(_aware(c) - _aware(e)).total_seconds() / 60 for e, c in db.execute(
            select(AuditEvent.event_timestamp, AuditEvent.collected_at).where(AuditEvent.collected_at >= day, AuditEvent.collected_at.is_not(None))
            .order_by(AuditEvent.collected_at.desc()).limit(2000)).all() if e and c]
        b.add("operations", st, "ingestion_latency", "Event collection delay (median)", round(median(delays), 1) if delays else None, "minutes",
              "Median time between the provider's event time and LV NEXUS collecting the event (provider delivery delay + polling interval).",
              src, "median(collected_at − event_timestamp) over events collected in the last 24 h (up to 2,000)",
              note="Processing time per event is not recorded separately.")
        b.add("operations", st, "failed_collections_24h", "Failed or partial collections (24 h)", failed_runs, "count",
              "Collection job runs in the last 24 hours where at least one cloud API call, account or region failed (reasons in Jobs and collection).",
              "LV NEXUS job execution log", "job runs with status FAILED or PARTIAL started in the last 24 h", link="/automation",
              tone="warning" if failed_runs else None, availability="available")
        if _can(perms, "access:read"):
            priv = db.scalar(select(func.count(func.distinct(AccessAssignment.principal_id))).where(
                AccessAssignment.removed_at.is_(None), AccessAssignment.privileged.is_(True)))
            any_access = db.scalar(select(func.count()).select_from(AccessAssignment)) or 0
            changes = db.scalar(select(func.count()).select_from(IdentityChangeEvent).where(IdentityChangeEvent.detected_at >= now - timedelta(days=7))) or 0
            ast = _section_state(db, "operations", any_access > 0, db.scalar(select(func.max(AccessAssignment.last_seen_at))))
            b.add("operations", ast, "privileged_identities", "Privileged identities", priv if any_access else None, "count",
                  "Distinct identities holding at least one privileged role (Owner / Administrator / equivalent) right now.",
                  "AWS IAM / Identity Center, Azure RBAC + Entra roles, Google Cloud IAM", "distinct principals with an active privileged assignment",
                  link="/access")
            b.add("operations", ast, "identity_changes_7d", "Identity changes (7 days)", changes if any_access else None, "count",
                  "Users, roles and permissions created, removed or changed, detected in the last 7 days.", "LV NEXUS identity change detection",
                  "identity change events with detected_at ≥ now − 7 days", link="/access")

    sections = [{"key": k, "label": {"connectivity": "Cloud connectivity", "security": "Security", "infrastructure": "Infrastructure",
                                     "finops": "FinOps", "governance": "Governance", "operations": "Activity and identity"}[k], "link": LINKS[k]}
                for k in SECTIONS if k in allowed]
    return {"generated_at": iso(now), "sections": sections, "metrics": b.items}
