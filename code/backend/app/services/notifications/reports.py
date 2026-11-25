"""Daily, weekly and monthly report text built only from database records.

The first line of every report states COMPLETE, PARTIAL or FAILED, derived from the collection jobs that
feed it, and lists each failing scope with its reason. A report is never labelled complete when a
collection failed."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.serializers import query_scopes
from app.core.config import Settings
from app.models import AutomationExecutionLog, JobStatus, OnboardingStatus, SecurityFinding, VMAlert, VMInventory
from app.services.finops import analysis

COLLECTION_JOBS = ("account_discovery", "security_events", "billing_refresh", "vm_metrics")
_IST = timedelta(hours=5, minutes=30)


def _money(v) -> str:
    return "n/a" if v is None else f"${v:,.2f}"


def collection_health(db: Session, hours: int = 24) -> dict:
    """Latest run of each collection job in the window, plus every failing scope."""
    since = datetime.now(UTC) - timedelta(hours=hours)
    jobs, failing = {}, []
    for name in COLLECTION_JOBS:
        e = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == name, AutomationExecutionLog.started_at >= since,
                                                           # a run still in progress has no result yet: judge the last finished one
                                                           AutomationExecutionLog.status.not_in((JobStatus.SKIPPED_OVERLAP.value, JobStatus.RUNNING.value)))
                      .order_by(AutomationExecutionLog.started_at.desc()).limit(1))
        jobs[name] = e.status if e else "not_run"
        if e and e.status in (JobStatus.PARTIAL.value, JobStatus.FAILED.value):
            failing += [{"job": name, **f} for f in (e.failures or [])[:15]] or [{"job": name, "provider": "*", "scope": "*", "reason": e.error or "failed"}]
    states = set(jobs.values())
    overall = "COMPLETE" if states == {"success"} else "FAILED" if states <= {"failed", "not_run"} else "PARTIAL"
    return {"overall": overall, "jobs": jobs, "failing": failing}


def _sev_counts(db: Session, since: datetime) -> dict:
    rows = db.execute(select(SecurityFinding.severity, func.count()).where(SecurityFinding.last_seen_at >= since).group_by(SecurityFinding.severity)).all()
    return {k: v for k, v in rows}


def _scope_lines(db: Session) -> list[str]:
    lines = []
    for provider, label in (("aws", "AWS accounts"), ("gcp", "GCP projects"), ("azure", "Azure subscriptions")):
        rows = [r for r in query_scopes(db, provider) if r.onboarding_status != OnboardingStatus.INACTIVE.value]
        ok = sum(1 for r in rows if r.onboarding_status == OnboardingStatus.FULLY_ONBOARDED.value)
        bad = [r for r in rows if r.onboarding_status in (OnboardingStatus.ACCESS_FAILED.value, OnboardingStatus.PENDING_ACCESS.value)]
        lines.append(f"  {label}: {len(rows)} active, {ok} fully onboarded, {len(bad)} with access problems")
        lines += [f"    - {r.name} ({r.external_id}): {r.onboarding_status}" for r in bad[:10]]
    return lines


def _links(settings: Settings) -> list[str]:
    sheet = f"https://docs.google.com/spreadsheets/d/{settings.sheets_spreadsheet_id}" if settings.sheets_spreadsheet_id else "not configured"
    return ["", f"Dashboard: {settings.dashboard_url or 'not configured'}", f"Google Sheets register: {sheet}", "",
            f"-- {settings.app_name}: One Platform. Every Cloud. Complete Visibility."]


def _failure_lines(health: dict) -> list[str]:
    lines = [f"  {job}: {state}" for job, state in health["jobs"].items()]
    if health["failing"]:
        lines.append("  Failing scopes:")
        lines += [f"    - [{f['job']}] {str(f.get('provider', '')).upper()} {f.get('scope', '')}: {f.get('reason', '')}" for f in health["failing"][:30]]
    return lines


def daily_report(db: Session, settings: Settings, ai_summary: str | None = None) -> tuple[str, str, str]:
    now = datetime.now(UTC)
    since = now - timedelta(days=1)
    health = collection_health(db)
    sev = _sev_counts(db, since)
    pending = db.scalar(select(func.count()).select_from(SecurityFinding).where(SecurityFinding.review_status.in_(["Pending Review", "Under Investigation"])))
    fin = analysis.daily_summary(db)
    budgets = [b for b in analysis.budget_status(db) if b["level"]]
    anomalies = analysis.anomalies(db, settings)
    vm = dict(db.execute(select(VMInventory.health_status, func.count()).where(VMInventory.deleted_at.is_(None)).group_by(VMInventory.health_status)).all())
    alerts = db.scalar(select(func.count()).select_from(VMAlert).where(VMAlert.status == "open", VMAlert.severity.in_(["Critical", "High"])))
    subject = f"Daily Multi-Cloud SOC, FinOps & Infrastructure Health Report – {(now + _IST):%d %b %Y}"
    lines = [f"REPORT STATUS: {health['overall']}", "",
             "1. Review status by cloud", *_scope_lines(db), "",
             "2. Security findings (last 24 hours)",
             "  " + ", ".join(f"{s}: {sev.get(s, 0)}" for s in ("Critical", "High", "Medium", "Low", "Informational")),
             f"  Pending investigations (all open): {pending}",
             "  Findings are flagged by rules and stay Pending Review until an analyst records a decision.", "",
             "3. Billing (provisional figures, not a final invoice)",
             f"  Previous day ({fin['date']}): " + (", ".join(f"{p.upper()} {_money(v)}" for p, v in sorted(fin["previous_day"].items())) or "no billing data collected"),
             "  Current period to date: " + (", ".join(f"{p.upper()} {_money(v)}" for p, v in sorted(fin["period_to_date"].items())) or "no billing data collected"),
             "  Day-on-day change: " + (", ".join(f"{p.upper()} {v:+,.2f}" for p, v in sorted(fin["change"].items())) or "n/a")]
    lines += ["  Budget warnings:"] + ([f"    - {b['provider'].upper()} {b['scope']}: {b['utilisation_percent']}% of {_money(b['approved'])} ({b['level_label']})" for b in budgets[:15]] or ["    none"])
    lines += ["  Abnormal cost increases:"] + ([f"    - {a['provider'].upper()} {a['scope']}: {_money(a['cost_usd'])} on {a['date']} vs usual {_money(a['baseline_mean_usd'])}" for a in anomalies[:10]] or ["    none detected"])
    lines += ["", "4. VM health",
              "  " + (", ".join(f"{k}: {v}" for k, v in sorted(vm.items())) or "no VM data collected"),
              f"  Open Critical/High VM alerts: {alerts}",
              "  'partial' and 'unknown' mean metrics are missing; they are not counted as healthy.", "",
              "5. Automation (last 24 hours)", *_failure_lines(health)]
    if ai_summary:
        lines += ["", "6. AI-assisted summary (advisory only, generated from the figures above)", ai_summary]
    return subject, "\n".join(lines + _links(settings)), health["overall"]


def weekly_report(db: Session, settings: Settings) -> tuple[str, str, str]:
    now = datetime.now(UTC)
    health = collection_health(db, hours=24 * 7)
    sev = _sev_counts(db, now - timedelta(days=7))
    w = analysis.weekly_summary(db)
    top_rules = db.execute(select(SecurityFinding.rule_id, func.count()).where(SecurityFinding.last_seen_at >= now - timedelta(days=7))
                           .group_by(SecurityFinding.rule_id).order_by(func.count().desc()).limit(8)).all()
    lines = [f"REPORT STATUS: {health['overall']}", "", "Security (last 7 days)",
             "  " + ", ".join(f"{s}: {sev.get(s, 0)}" for s in ("Critical", "High", "Medium", "Low", "Informational")),
             *[f"    - {r}: {n}" for r, n in top_rules], "", "FinOps (provisional)",
             f"  Current week {_money(w['current_week'])} vs previous week {_money(w['previous_week'])}"
             + (f" ({w['variation_percent']:+}%)" if w["variation_percent"] is not None else " (no comparison available)"),
             "  Top cost-increasing services:",
             *([f"    - {r['service']}: +{_money(r['increase_usd'])}{' (new this week)' if r['new'] else ''}" for r in w["top_increasing_services"]] or ["    none"]),
             "", "Automation (last 7 days)", *_failure_lines(health)]
    return f"Weekly Multi-Cloud Security & FinOps Summary – week ending {(now + _IST):%d %b %Y}", "\n".join(lines + _links(settings)), health["overall"]


def monthly_report(db: Session, settings: Settings) -> tuple[str, str, str]:
    health = collection_health(db, hours=24 * 31)
    m = analysis.monthly_summary(db)
    top = lambda d, n=10: sorted(d.items(), key=lambda kv: -kv[1])[:n]  # noqa: E731
    vm = dict(db.execute(select(VMInventory.health_status, func.count()).where(VMInventory.deleted_at.is_(None)).group_by(VMInventory.health_status)).all())
    lines = [f"REPORT STATUS: {health['overall']}", "", f"Expenditure for {m['month']} ({'final' if m['is_final'] else 'PROVISIONAL - not a final invoice'})",
             f"  Total actual: {_money(m['total_actual'])}", f"  Approved budget: {_money(m['approved_budget'])}",
             f"  Budget variance: {_money(m['budget_variance'])}", f"  Forecast: {_money(m['forecast'])}",
             f"  Previous month: {_money(m['previous_month'])}" + (f" (month-on-month {m['mom_variation_percent']:+}%)" if m["mom_variation_percent"] is not None else ""),
             "  By cloud:", *[f"    - {p.upper()}: {_money(v)}" for p, v in top(m["by_provider"])],
             "  By account / project / subscription:", *[f"    - {k}: {_money(v)}" for k, v in top(m["by_scope"], 15)],
             "  By service:", *[f"    - {k}: {_money(v)}" for k, v in top(m["by_service"])],
             "", "Infrastructure", "  VM health now: " + (", ".join(f"{k}: {v}" for k, v in sorted(vm.items())) or "no VM data collected"),
             "", "Automation (last 31 days)", *_failure_lines(health)]
    return f"Monthly Multi-Cloud Expenditure, Budget & Infrastructure Report – {m['month']}", "\n".join(lines + _links(settings)), health["overall"]
