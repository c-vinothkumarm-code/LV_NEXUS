"""Daily Governance Dashboard: one snapshot of everything the platform monitors, rendered as an HTML e-mail (with a
plain-text part), a short Google Chat summary and one append-only row in the audit register.

Rules: every figure comes from the database at the time of the run; a value that was not collected is shown as
"not collected" with the reason, never as zero; accounts / subscriptions / projects are shown by name."""
from __future__ import annotations

import html as _html
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import SCOPE_MODELS, AuditEvent, AutomationExecutionLog, BillingPeriod, JobStatus, VMAlert, VMInventory
from app.models.access import AccessAssignment, CloudIdentity
from app.models.iam import IdentityChangeEvent
from app.models.platform import AuditAnomaly
from app.models.vuln import CloudSecurityFinding
from app.services.finops import analysis

IST = timedelta(hours=5, minutes=30)
SEVERITIES = ("Critical", "High", "Medium", "Low")
PROVIDERS = {"aws": "AWS", "azure": "Azure", "gcp": "Google Cloud"}
FRESHNESS = [("account_discovery", "Accounts & subscriptions", 1), ("resource_inventory", "Resource inventory", 1), ("vm_metrics", "VM health", 1),
             ("security_events", "Cloud audit logs", 1), ("entra_activity", "Entra ID sign-ins & audit", 1), ("access_inventory", "Access (IAM)", 2),
             ("billing_refresh", "Billing", 3), ("cost_detail_refresh", "Cost detail", 3), ("security_findings_sync", "Security findings", 26),
             ("anomaly_detection", "Anomaly detection", 1)]
OPEN_FINDING = ("OPEN", "UNDER_REVIEW", "REOPENED")
REQUIRED = ("account_discovery", "security_events", "billing_refresh", "vm_metrics")  # same core set as the collection-health check


def _aware(dt):
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _ago(dt, now) -> str:
    if dt is None:
        return "never"
    m = int((now - _aware(dt)).total_seconds() // 60)
    return f"{m} min ago" if m < 60 else f"{m // 60} h ago" if m < 48 * 60 else f"{m // 1440} days ago"


def _usd(v) -> str:
    return "not collected" if v is None else f"${float(v):,.2f}"


def scope_names(db: Session) -> dict[tuple[str, str], str]:
    return {(p, sid): name or sid for p, m in SCOPE_MODELS.items() for sid, name in db.execute(select(m.external_id, m.name)).all()}


def snapshot(db: Session, settings: Settings, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    day = now - timedelta(days=1)
    names = scope_names(db)

    def nm(provider, sid):
        return names.get((provider, sid)) or next((v for (p, s), v in names.items() if s == sid), None) or sid

    # ---- coverage
    coverage = []
    for p, model in SCOPE_MODELS.items():
        rows = list(db.scalars(select(model).where(model.onboarding_status != "Inactive")))
        if not rows:
            continue
        ok = [r for r in rows if r.onboarding_status == "Fully Onboarded"]
        partial = [r for r in rows if r.onboarding_status == "Partially Onboarded"]
        blocked = [r for r in rows if r not in ok and r not in partial]
        reasons = Counter((((r.checks or {}).get("permissions") or {}).get("detail") or r.onboarding_status) for r in blocked)
        coverage.append({"provider": p, "label": PROVIDERS[p], "total": len(rows), "onboarded": len(ok), "partial": len(partial),
                         "blocked": [r.name for r in blocked], "reasons": reasons.most_common(3)})

    # ---- data freshness
    freshness = []
    for job, label, max_h in FRESHNESS:
        last_ok = db.scalar(select(func.max(AutomationExecutionLog.finished_at)).where(AutomationExecutionLog.job_name == job,
                                                                                         AutomationExecutionLog.status == JobStatus.SUCCESS.value))
        latest = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == job,
                                                                AutomationExecutionLog.status.not_in((JobStatus.RUNNING.value, JobStatus.SKIPPED_OVERLAP.value)))
                           .order_by(AutomationExecutionLog.started_at.desc()).limit(1))
        if latest is None:
            if job in REQUIRED:  # a core collector that never ran means the data is missing, not fine
                freshness.append({"job": job, "label": label, "last_success": "never", "latest": "not run", "state": "stale"})
            continue
        stale = last_ok is None or now - _aware(last_ok) > timedelta(hours=max_h)
        freshness.append({"job": job, "label": label, "last_success": _ago(last_ok, now), "latest": latest.status,
                          "state": "stale" if stale else latest.status if latest.status != "success" else "fresh"})

    # ---- vulnerabilities / native security findings
    sev = dict(db.execute(select(CloudSecurityFinding.severity, func.count()).where(CloudSecurityFinding.internal_status.in_(OPEN_FINDING),
                                                                                   CloudSecurityFinding.is_security.is_(True))
                          .group_by(CloudSecurityFinding.severity)).all())
    overdue = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(
        CloudSecurityFinding.internal_status.in_(OPEN_FINDING), CloudSecurityFinding.sla_due_at < now,
        or_(CloudSecurityFinding.sla_paused.is_(False), CloudSecurityFinding.sla_paused.is_(None))))
    new_f = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(CloudSecurityFinding.first_synced_at >= day))
    resolved_f = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(CloudSecurityFinding.resolved_at >= day))
    top_findings = [{"title": f.title, "severity": f.severity, "where": nm(f.provider, f.scope_external_id), "resource": f.resource_name or ""}
                    for f in db.scalars(select(CloudSecurityFinding).where(CloudSecurityFinding.internal_status.in_(OPEN_FINDING),
                                                                           CloudSecurityFinding.severity.in_(("Critical", "High")))
                                        .order_by(CloudSecurityFinding.severity, CloudSecurityFinding.last_observed_at.desc()).limit(5))]
    security_collected = db.scalar(select(func.count()).select_from(CloudSecurityFinding)) > 0

    # ---- audit & anomalies
    events = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.event_timestamp >= day))
    flagged = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.event_timestamp >= day, AuditEvent.detection_status == "flagged"))
    pending_review = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.detection_status == "flagged",
                                                                                  AuditEvent.review_status.in_(("Pending Review", "Under Investigation"))))
    anomalies = list(db.scalars(select(AuditAnomaly).where(AuditAnomaly.status == "OPEN").order_by(AuditAnomaly.last_event_at.desc())))
    an_sev = Counter(a.severity for a in anomalies)
    top_anomalies = [{"title": a.title, "severity": a.severity, "where": nm(a.provider, a.scope_external_id), "when": _ago(a.last_event_at, now)}
                     for a in sorted(anomalies, key=lambda a: SEVERITIES.index(a.severity) if a.severity in SEVERITIES else 9)[:5]]

    # ---- access (IAM)
    live = AccessAssignment.removed_at.is_(None)
    identities = dict(db.execute(select(CloudIdentity.principal_type, func.count()).group_by(CloudIdentity.principal_type)).all())
    assignments = db.scalar(select(func.count()).select_from(AccessAssignment).where(live))
    privileged = db.scalar(select(func.count()).select_from(AccessAssignment).where(live, AccessAssignment.privileged.is_(True)))
    priv_people = db.scalar(select(func.count(func.distinct(AccessAssignment.principal_id))).where(live, AccessAssignment.privileged.is_(True)))
    changes = list(db.scalars(select(IdentityChangeEvent).where(IdentityChangeEvent.detected_at >= day).order_by(IdentityChangeEvent.detected_at.desc())))
    changes_by = Counter(c.change_type for c in changes)
    priv_changes = [{"who": c.principal_name or c.principal_id, "change": c.change_type.replace("_", " ").lower(),
                     "where": nm(c.provider, c.scope_external_id) if c.scope_external_id else "directory"} for c in changes if c.privileged][:8]
    disabled_with_access = db.scalar(select(func.count(func.distinct(AccessAssignment.principal_id))).join(
        CloudIdentity, (CloudIdentity.principal_id == AccessAssignment.principal_id) & (CloudIdentity.provider == AccessAssignment.provider))
        .where(live, CloudIdentity.enabled.is_(False)))
    access_collected = assignments > 0

    # ---- cost
    fin = analysis.daily_summary(db, now.date())
    periods = []
    for bp in db.scalars(select(BillingPeriod).where(BillingPeriod.period_start <= now.date(), BillingPeriod.period_end >= now.date())):
        periods.append({"name": nm(bp.provider, bp.scope_external_id), "from": f"{bp.period_start:%d %b}", "to": f"{bp.period_end:%d %b}",
                        "cost": bp.total_usd, "day": (now.date() - bp.period_start).days + 1, "days": (bp.period_end - bp.period_start).days + 1})
    periods.sort(key=lambda r: -(float(r["cost"]) if r["cost"] is not None else -1))
    budgets = [{"name": nm(b["provider"], b["scope"]), "pct": b["utilisation_percent"], "level": b["level_label"], "approved": b["approved"],
                "currency": b["currency"]} for b in analysis.budget_status(db, now.date()) if b["level"]]
    cost_anoms = [{"name": nm(a["provider"], a["scope"]), "cost": a["cost_usd"], "usual": a["baseline_mean_usd"], "date": a["date"]}
                  for a in analysis.anomalies(db, settings, now.date())][:8]

    # ---- VMs
    vm = dict(db.execute(select(VMInventory.health_status, func.count()).where(VMInventory.deleted_at.is_(None)).group_by(VMInventory.health_status)).all())
    vm_alerts = db.scalar(select(func.count()).select_from(VMAlert).where(VMAlert.status == "open", VMAlert.severity.in_(["Critical", "High"])))

    # ---- automation problems (last 24 h, latest finished run per job)
    problems = []
    for job in db.scalars(select(AutomationExecutionLog.job_name).where(AutomationExecutionLog.started_at >= day).distinct()):
        e = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == job,
                                                           AutomationExecutionLog.status.not_in((JobStatus.RUNNING.value, JobStatus.SKIPPED_OVERLAP.value)))
                      .order_by(AutomationExecutionLog.started_at.desc()).limit(1))
        if e and e.status in (JobStatus.FAILED.value, JobStatus.PARTIAL.value):
            reasons = [(f.get("name") or (nm(f.get("provider"), f.get("scope")) if f.get("scope") not in (None, "*") else "") or "", str(f.get("reason") or "")[:180])
                       for f in (e.failures or [])[:3]]
            problems.append({"job": job, "status": e.status, "reasons": reasons, "more": max(0, len(e.failures or []) - 3)})

    # ---- compliance (latest evaluation of the policy library)
    compliance = None
    try:
        from app.services.compliance import engine as ceng
        from app.services.compliance.library import BY_KEY, FRAMEWORKS
        crun = ceng.latest_run(db)
        if crun is not None:
            from app.models.compliance import ComplianceResult
            fails = defaultdict(list)
            for x in db.scalars(select(ComplianceResult).where(ComplianceResult.run_id == crun.id, ComplianceResult.status == "FAIL")):
                fails[x.policy_key].append(x)
            sev = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
            top = sorted(fails.items(), key=lambda kv: (sev.get(kv[1][0].severity, 9), -len(kv[1])))[:6]
            compliance = {"as_of": _ago(crun.finished_at, now), "scores": [{"key": k, "name": FRAMEWORKS[k]["name"], "obligation": FRAMEWORKS[k]["obligation"],
                                                                              **((crun.scores or {}).get(k) or {})} for k in ("certin", "dpdp", "iso27001", "soc2", "nist_csf", "cis")],
                          "gaps": [{"key": k, "title": BY_KEY[k].title, "severity": v[0].severity, "scopes": [x.scope_name for x in v][:5],
                                    "legal": any(f in ("certin", "dpdp") for f in BY_KEY[k].refs)} for k, v in top]}
    except Exception:  # noqa: BLE001 - the dashboard still goes out without this section
        compliance = None

    # ---- headline: what needs a decision today
    head = []
    if sev.get("Critical"):
        head.append(f"{sev['Critical']} critical security finding(s) open")
    if overdue:
        head.append(f"{overdue} finding(s) past their remediation SLA")
    if an_sev.get("Critical") or an_sev.get("High"):
        head.append(f"{an_sev.get('Critical', 0) + an_sev.get('High', 0)} high-risk audit anomaly(ies) open")
    if priv_changes:
        head.append(f"{len(priv_changes)} privileged access change(s) in 24 h")
    if disabled_with_access:
        head.append(f"{disabled_with_access} disabled identity(ies) still hold cloud access")
    if budgets:
        head.append(f"{len(budgets)} budget(s) at a warning level")
    blocked_total = sum(len(c["blocked"]) for c in coverage)
    if blocked_total:
        head.append(f"{blocked_total} account(s)/subscription(s) not monitored (access missing)")
    stale = [f["label"] for f in freshness if f["state"] == "stale"]
    if stale:
        head.append("Stale data: " + ", ".join(stale))
    if compliance and any(g["legal"] and g["severity"] in ("Critical", "High") for g in compliance["gaps"]):
        head.append(f"{sum(1 for g in compliance['gaps'] if g['legal'])} legal compliance gap(s) (CERT-In / DPDP)")
    status = "DATA INCOMPLETE" if stale or blocked_total else "ACTION NEEDED" if head else "ALL CLEAR"

    return {"generated_at": now, "date": f"{now + IST:%d %b %Y}", "time": f"{now + IST:%H:%M} IST", "status": status, "headline": head,
            "coverage": coverage, "freshness": freshness,
            "security": {"collected": security_collected, "open": {s: sev.get(s, 0) for s in SEVERITIES}, "overdue": overdue, "new": new_f,
                         "resolved": resolved_f, "top": top_findings},
            "audit": {"events": events, "flagged": flagged, "pending_review": pending_review, "anomalies": {s: an_sev.get(s, 0) for s in SEVERITIES},
                      "top": top_anomalies},
            "access": {"collected": access_collected, "identities": identities, "assignments": assignments, "privileged": privileged,
                       "privileged_principals": priv_people, "changes": dict(changes_by), "privileged_changes": priv_changes,
                       "disabled_with_access": disabled_with_access},
            "cost": {"yesterday": fin["previous_day"], "yesterday_date": fin["date"], "period_to_date": fin["period_to_date"], "periods": periods,
                     "budgets": budgets, "anomalies": cost_anoms},
            "vms": {"health": vm, "alerts": vm_alerts},
            "automation": problems, "compliance": compliance,
            "links": {"dashboard": settings.dashboard_url or settings.frontend_url,
                      "register": f"https://docs.google.com/spreadsheets/d/{settings.sheets_spreadsheet_id}" if settings.sheets_spreadsheet_id else None}}


# ------------------------------------------------------------------ renderers
def subject(s: dict, settings: Settings) -> str:
    return f"[{s['status']}] Daily Governance Dashboard – {s['date']} – LV NEXUS"


def text(s: dict) -> str:
    L = [f"LV NEXUS – Daily Governance Dashboard – {s['date']} ({s['time']})", f"STATUS: {s['status']}", ""]
    L += ["NEEDS ATTENTION"] + ([f"  - {h}" for h in s["headline"]] or ["  - nothing requires a decision today"]) + [""]
    L += ["1. COVERAGE"] + [f"  {c['label']}: {c['onboarded']} of {c['total']} fully monitored" + (f"; not monitored: {', '.join(c['blocked'][:12])}" if c["blocked"] else "")
                           for c in s["coverage"]] + [""]
    L += ["2. DATA FRESHNESS"] + [f"  {f['label']}: last success {f['last_success']} ({f['state']})" for f in s["freshness"]] + [""]
    sec = s["security"]
    L += ["3. SECURITY FINDINGS (open)", "  " + (", ".join(f"{k}: {v}" for k, v in sec["open"].items()) if sec["collected"] else "not collected"),
          f"  Past SLA: {sec['overdue']} · new in 24 h: {sec['new']} · resolved in 24 h: {sec['resolved']}"]
    L += [f"  - [{t['severity']}] {t['title']} – {t['where']}" for t in sec["top"]] + [""]
    a = s["audit"]
    L += ["4. AUDIT & ANOMALIES (24 h)", f"  Events collected: {a['events']} · flagged: {a['flagged']} · awaiting review: {a['pending_review']}",
          "  Open anomalies: " + ", ".join(f"{k}: {v}" for k, v in a["anomalies"].items())]
    L += [f"  - [{t['severity']}] {t['title']} – {t['where']} ({t['when']})" for t in a["top"]] + [""]
    ac = s["access"]
    if ac["collected"]:
        L += ["5. ACCESS (IAM)", f"  Role assignments: {ac['assignments']} · privileged: {ac['privileged']} held by {ac['privileged_principals']} identities",
              "  Identities: " + ", ".join(f"{k}: {v}" for k, v in sorted(ac["identities"].items())),
              f"  Changes in 24 h: {sum(ac['changes'].values())} · disabled identities still holding access: {ac['disabled_with_access']}"]
        L += [f"  - privileged: {c['who']} – {c['change']} – {c['where']}" for c in ac["privileged_changes"]] + [""]
    else:
        L += ["5. ACCESS (IAM)", "  not collected", ""]
    c = s["cost"]
    L += ["6. COST (provisional; providers publish usage 8–24 h late)",
          f"  Yesterday ({c['yesterday_date']}): " + (", ".join(f"{PROVIDERS.get(p, p)} {_usd(v)}" for p, v in sorted(c["yesterday"].items())) or "not collected")]
    L += ["  Current billing period by subscription:"] + ([f"    {p['name']}: {_usd(p['cost'])} ({p['from']}–{p['to']}, day {p['day']} of {p['days']})" for p in c["periods"][:20]]
                                                       or ["    not collected yet"])
    L += ["  Budgets at warning level:"] + ([f"    {b['name']}: {b['pct']}% ({b['level']})" for b in c["budgets"]] or ["    none"])
    L += ["  Abnormal daily cost:"] + ([f"    {x['name']}: {_usd(x['cost'])} on {x['date']} vs usual {_usd(x['usual'])}" for x in c["anomalies"]] or ["    none detected"]) + [""]
    v = s["vms"]
    L += ["7. VIRTUAL MACHINES", "  " + (", ".join(f"{k}: {n}" for k, n in sorted(v["health"].items())) or "not collected") + f" · open critical/high alerts: {v['alerts']}", ""]
    L += ["8. AUTOMATION (problems in the last 24 h)"] + ([f"  {p['job']}: {p['status']}" + "".join(f"\n    - {w + ': ' if w else ''}{r}" for w, r in p["reasons"]) for p in s["automation"]]
                                                       or ["  all collection jobs succeeded"])
    cp = s.get("compliance")
    L += ["", "9. COMPLIANCE" + (f" (evaluated {cp['as_of']})" if cp else "")]
    if cp:
        L += [f"  {x['name']}: " + ("not assessed" if x.get("score") is None else f"{x['score']}% (coverage {x.get('coverage', 0)}%)")
              + (" - LEGAL" if x["obligation"] == "legal" else " - legal from 13 May 2027" if x["obligation"] == "legal_upcoming" else "") for x in cp["scores"]]
        L += [f"  - [{g['severity']}] {g['title']}: {', '.join(g['scopes'])}" + (" (legal)" if g["legal"] else "") for g in cp["gaps"]]
    else:
        L += ["  not evaluated yet"]
    L += ["", f"Dashboard: {s['links']['dashboard']}"] + ([f"Audit register (Google Sheets): {s['links']['register']}"] if s["links"]["register"] else [])
    L += ["", "Read-only monitoring report. Figures are as collected at the time above; 'not collected' means unknown, not zero."]
    return "\n".join(L)


def chat(s: dict) -> str:
    sec, a, ac, c = s["security"], s["audit"], s["access"], s["cost"]
    lines = [f"Status: *{s['status']}*"]
    lines += [f"• {h}" for h in s["headline"][:6]] or ["• Nothing requires a decision today"]
    lines += ["", f"Security: {sec['open']['Critical']} critical · {sec['open']['High']} high open · {sec['overdue']} past SLA",
              f"Audit (24 h): {a['events']} events · {a['flagged']} flagged · {sum(a['anomalies'].values())} open anomalies",
              f"Access: {ac['privileged']} privileged assignments · {sum(ac['changes'].values())} changes in 24 h" if ac["collected"] else "Access: not collected",
              "Cost yesterday: " + (", ".join(f"{PROVIDERS.get(p, p)} {_usd(v)}" for p, v in sorted(c["yesterday"].items())) or "not collected"),
              f"Automation: {len(s['automation'])} job(s) with problems" if s["automation"] else "Automation: all jobs succeeded",
              ("Compliance: " + ", ".join(f"{x['name'].split(' ')[0]} {x['score']}%" for x in s["compliance"]["scores"][:2] if x.get("score") is not None))
              if s.get("compliance") else "Compliance: not evaluated yet", "",
              f"Full dashboard: {s['links']['dashboard']}"]
    return "\n".join(lines)


def _e(v) -> str:
    return _html.escape(str(v))


SEV_COLOR = {"Critical": "#b42318", "High": "#c4320a", "Medium": "#b54708", "Low": "#475467"}
STATUS_COLOR = {"ALL CLEAR": "#067647", "ACTION NEEDED": "#b54708", "DATA INCOMPLETE": "#b42318"}


def html(s: dict) -> str:
    """E-mail-safe HTML (tables + inline styles only; renders in Gmail and Outlook)."""
    card = 'style="background:#ffffff;border:1px solid #e4e7ec;border-radius:10px;padding:16px 18px;margin:0 0 14px 0"'
    h2 = 'style="margin:0 0 10px 0;font-size:15px;color:#101828"'
    td = 'style="padding:6px 8px;border-top:1px solid #f2f4f7;font-size:13px;color:#344054;vertical-align:top"'
    th = 'style="padding:6px 8px;font-size:11px;color:#667085;text-align:left;text-transform:uppercase;letter-spacing:.04em"'

    def tile(label, value, note="", color="#101828"):
        return (f'<td style="padding:6px"><div style="border:1px solid #e4e7ec;border-radius:8px;padding:10px 12px;background:#fff">'
                f'<div style="font-size:11px;color:#667085">{_e(label)}</div><div style="font-size:22px;font-weight:700;color:{color}">{_e(value)}</div>'
                f'<div style="font-size:11px;color:#98a2b3">{_e(note)}</div></div></td>')

    def table(head, rows, empty):
        if not rows:
            return f'<p style="font-size:13px;color:#667085;margin:4px 0">{_e(empty)}</p>'
        return ('<table width="100%" cellspacing="0" cellpadding="0" style="border-collapse:collapse"><tr>' + "".join(f"<th {th}>{_e(h)}</th>" for h in head)
                + "</tr>" + "".join("<tr>" + "".join(f"<td {td}>{c}</td>" for c in r) + "</tr>" for r in rows) + "</table>")

    def sevtag(v):
        return f'<span style="color:{SEV_COLOR.get(v, "#344054")};font-weight:600">{_e(v)}</span>'

    sec, a, ac, c, v = s["security"], s["audit"], s["access"], s["cost"], s["vms"]
    color = STATUS_COLOR.get(s["status"], "#344054")
    parts = [f'''<!DOCTYPE html><html><body style="margin:0;background:#f5f7fb;font-family:Segoe UI,Arial,sans-serif">
<table width="100%" cellspacing="0" cellpadding="0"><tr><td align="center" style="padding:20px 10px">
<table width="760" cellspacing="0" cellpadding="0" style="max-width:760px;width:100%">
<tr><td style="background:#0b1b45;border-radius:10px;padding:18px 20px;color:#fff">
<div style="font-size:11px;letter-spacing:.12em;color:#9fb3ff">LATENTVIEW · LV NEXUS</div>
<div style="font-size:20px;font-weight:700;margin-top:4px">Daily Governance Dashboard</div>
<div style="font-size:12px;color:#c7d2fe;margin-top:2px">{_e(s["date"])} · {_e(s["time"])} · read-only monitoring</div></td></tr>
<tr><td style="padding:14px 0 0 0">''']
    parts.append(f'<div {card}><div style="font-size:12px;color:#667085">Overall status</div><div style="font-size:18px;font-weight:700;color:{color}">{_e(s["status"])}</div>'
                 + ('<ul style="margin:8px 0 0 18px;padding:0;font-size:13px;color:#344054">' + "".join(f"<li>{_e(h)}</li>" for h in s["headline"]) + "</ul>"
                    if s["headline"] else '<p style="font-size:13px;color:#067647;margin:6px 0 0 0">Nothing requires a decision today.</p>') + "</div>")
    parts.append('<table width="100%" cellspacing="0" cellpadding="0"><tr>'
                 + tile("Critical / High findings", f"{sec['open']['Critical']} / {sec['open']['High']}" if sec["collected"] else "–", f"{sec['overdue']} past SLA",
                        SEV_COLOR["Critical"] if sec["open"]["Critical"] else "#101828")
                 + tile("Audit events (24 h)", a["events"], f"{a['flagged']} flagged · {a['pending_review']} awaiting review")
                 + tile("Open anomalies", sum(a["anomalies"].values()), f"{a['anomalies']['Critical'] + a['anomalies']['High']} high-risk")
                 + tile("Privileged assignments", ac["privileged"] if ac["collected"] else "–", f"{len(ac['privileged_changes'])} changed in 24 h")
                 + "</tr></table>")
    cov_rows = [[_e(x["label"]), f"{x['onboarded']} of {x['total']}", _e(", ".join(x["blocked"][:15]) + (" …" if len(x["blocked"]) > 15 else "")) or "—",
                 _e("; ".join(f"{r} ({n})" for r, n in x["reasons"])) or "—"] for x in s["coverage"]]
    parts.append(f'<div {card}><h2 {h2}>1 · Coverage</h2>' + table(["Cloud", "Fully monitored", "Not monitored", "Why"], cov_rows, "No cloud connected.") + "</div>")
    fr_rows = [[_e(f["label"]), _e(f["last_success"]), f'<span style="color:{"#b42318" if f["state"] == "stale" else "#b54708" if f["state"] != "fresh" else "#067647"};font-weight:600">{_e(f["state"])}</span>']
               for f in s["freshness"]]
    parts.append(f'<div {card}><h2 {h2}>2 · Data freshness</h2>' + table(["Source", "Last success", "State"], fr_rows, "No collection has run yet.") + "</div>")
    parts.append(f'<div {card}><h2 {h2}>3 · Security findings</h2>'
                 + ('<p style="font-size:13px;color:#344054;margin:0 0 8px 0">Open: ' + " · ".join(f"{sevtag(k)} {n}" for k, n in sec["open"].items())
                    + f' &nbsp;|&nbsp; past SLA <b>{sec["overdue"]}</b> · new 24 h <b>{sec["new"]}</b> · resolved 24 h <b>{sec["resolved"]}</b></p>'
                    + table(["Severity", "Finding", "Where", "Resource"], [[sevtag(t["severity"]), _e(t["title"]), _e(t["where"]), _e(t["resource"])] for t in sec["top"]],
                            "No critical or high findings open.") if sec["collected"] else '<p style="font-size:13px;color:#667085">Not collected.</p>') + "</div>")
    parts.append(f'<div {card}><h2 {h2}>4 · Audit &amp; anomalies (last 24 h)</h2>'
                 f'<p style="font-size:13px;color:#344054;margin:0 0 8px 0">Events <b>{a["events"]}</b> · flagged <b>{a["flagged"]}</b> · awaiting review <b>{a["pending_review"]}</b> · open anomalies '
                 + " · ".join(f"{sevtag(k)} {n}" for k, n in a["anomalies"].items()) + "</p>"
                 + table(["Severity", "Anomaly", "Where", "Last seen"], [[sevtag(t["severity"]), _e(t["title"]), _e(t["where"]), _e(t["when"])] for t in a["top"]],
                         "No open anomalies.") + "</div>")
    if ac["collected"]:
        parts.append(f'<div {card}><h2 {h2}>5 · Access (IAM)</h2><p style="font-size:13px;color:#344054;margin:0 0 8px 0">Role assignments <b>{ac["assignments"]}</b> · privileged <b>{ac["privileged"]}</b> '
                     f'held by <b>{ac["privileged_principals"]}</b> identities · changes in 24 h <b>{sum(ac["changes"].values())}</b> · disabled identities still holding access '
                     f'<b style="color:{"#b42318" if ac["disabled_with_access"] else "#344054"}">{ac["disabled_with_access"]}</b><br/>Identities: '
                     + _e(", ".join(f"{k} {n}" for k, n in sorted(ac["identities"].items()))) + "</p>"
                     + table(["Identity", "Privileged change", "Where"], [[_e(x["who"]), _e(x["change"]), _e(x["where"])] for x in ac["privileged_changes"]],
                             "No privileged access changes in the last 24 hours.") + "</div>")
    else:
        parts.append(f'<div {card}><h2 {h2}>5 · Access (IAM)</h2><p style="font-size:13px;color:#667085">Not collected.</p></div>')
    per_rows = [[_e(p["name"]), _e(f"{p['from']} – {p['to']}"), _e(f"day {p['day']} of {p['days']}"), f'<b>{_e(_usd(p["cost"]))}</b>'] for p in c["periods"][:25]]
    parts.append(f'<div {card}><h2 {h2}>6 · Cost (provisional)</h2><p style="font-size:13px;color:#344054;margin:0 0 8px 0">Yesterday ({_e(c["yesterday_date"])}): '
                 + (_e(", ".join(f"{PROVIDERS.get(p, p)} {_usd(x)}" for p, x in sorted(c["yesterday"].items()))) or "not collected") + "</p>"
                 + table(["Subscription / account", "Billing period", "Progress", "Cost to date"], per_rows, "Billing periods not collected yet.")
                 + ('<p style="font-size:13px;color:#344054;margin:10px 0 4px 0"><b>Budgets at warning level</b></p>'
                    + table(["Budget scope", "Utilisation", "Level"], [[_e(b["name"]), _e(f"{b['pct']}%"), _e(b["level"])] for b in c["budgets"]], "None."))
                 + ('<p style="font-size:13px;color:#344054;margin:10px 0 4px 0"><b>Abnormal daily cost</b></p>'
                    + table(["Scope", "Day", "Cost", "Usual"], [[_e(x["name"]), _e(x["date"]), _e(_usd(x["cost"])), _e(_usd(x["usual"]))] for x in c["anomalies"]], "None detected."))
                 + '<p style="font-size:11px;color:#98a2b3;margin:8px 0 0 0">Providers publish usage 8–24 h late; current-period figures are not an invoice.</p></div>')
    parts.append(f'<div {card}><h2 {h2}>7 · Virtual machines</h2><p style="font-size:13px;color:#344054;margin:0">'
                 + (_e(" · ".join(f"{k}: {n}" for k, n in sorted(v["health"].items()))) or "Not collected") + f' &nbsp;|&nbsp; open critical/high alerts <b>{v["alerts"]}</b></p></div>')
    au_rows = [[_e(p["job"]), _e(p["status"]), "<br/>".join(_e((w + ": " if w else "") + r) for w, r in p["reasons"]) + (f"<br/>and {p['more']} more" if p["more"] else "")]
               for p in s["automation"]]
    parts.append(f'<div {card}><h2 {h2}>8 · Automation (last 24 h)</h2>' + table(["Job", "Result", "Reason"], au_rows, "All collection jobs succeeded.") + "</div>")
    cp = s.get("compliance")
    if cp:
        sc_rows = [[_e(x["name"]), _e({"legal": "Mandatory now", "legal_upcoming": "Mandatory from 13 May 2027"}.get(x["obligation"], "Voluntary")),
                    f'<b>{_e("–" if x.get("score") is None else str(x["score"]) + "%")}</b>', _e(f"{x.get('coverage', 0)}%")] for x in cp["scores"]]
        gp_rows = [[sevtag(g["severity"]), _e(g["title"]), _e(", ".join(g["scopes"])), "Yes" if g["legal"] else ""] for g in cp["gaps"]]
        parts.append(f'<div {card}><h2 {h2}>9 · Compliance (evaluated {_e(cp["as_of"])})</h2>'
                     + table(["Framework", "Obligation", "Score", "Assessed"], sc_rows, "Not evaluated yet.")
                     + '<p style="font-size:13px;color:#344054;margin:10px 0 4px 0"><b>Gaps to fix first</b></p>'
                     + table(["Severity", "Policy", "Where", "Legal"], gp_rows, "No failing policy.")
                     + '<p style="font-size:11px;color:#98a2b3;margin:8px 0 0 0">Automated checks over collected cloud data and attestations; not a certification or legal opinion.</p></div>')
    links = f'<a href="{_e(s["links"]["dashboard"])}" style="color:#1d4ed8">Open the dashboard</a>'
    if s["links"]["register"]:
        links += f' · <a href="{_e(s["links"]["register"])}" style="color:#1d4ed8">Audit register (Google Sheets)</a>'
    parts.append(f'<p style="font-size:12px;color:#667085;text-align:center;margin:6px 0">{links}</p>'
                 '<p style="font-size:11px;color:#98a2b3;text-align:center;margin:4px 0 0 0">Read-only monitoring report generated by LV NEXUS. "Not collected" means unknown, not zero.</p>'
                 "</td></tr></table></td></tr></table></body></html>")
    return "".join(parts)


def register_row(s: dict) -> list:
    """One append-only row per day for the external-audit register."""
    sec, a, ac, c = s["security"], s["audit"], s["access"], s["cost"]
    return [f"governance:{s['date']}", s["date"], s["time"], s["status"], "; ".join(s["headline"]) or "none",
            "; ".join(f"{x['label']} {x['onboarded']}/{x['total']}" for x in s["coverage"]),
            "; ".join(f"{f['label']}: {f['state']}" for f in s["freshness"] if f["state"] != "fresh") or "all fresh",
            sec["open"]["Critical"], sec["open"]["High"], sec["overdue"], a["events"], a["flagged"], a["pending_review"], sum(a["anomalies"].values()),
            ac["assignments"] if ac["collected"] else "", ac["privileged"] if ac["collected"] else "", sum(ac["changes"].values()), ac["disabled_with_access"],
            "; ".join(f"{PROVIDERS.get(p, p)} {float(v):.2f}" for p, v in sorted(c["yesterday"].items())) or "not collected",
            len(c["budgets"]), len(c["anomalies"]), len(s["automation"]), s["generated_at"].strftime("%Y-%m-%d %H:%M:%S UTC")]


REGISTER_HEAD = ["Record Key", "Date", "Generated (IST)", "Status", "Needs Attention", "Coverage", "Stale / Failing Sources", "Critical Findings",
                 "High Findings", "Findings Past SLA", "Audit Events 24h", "Flagged 24h", "Awaiting Review", "Open Anomalies", "Role Assignments",
                 "Privileged Assignments", "Access Changes 24h", "Disabled With Access", "Cost Yesterday (USD)", "Budgets At Warning",
                 "Cost Anomalies", "Automation Problems", "Generated At"]


def preview(db: Session, settings: Settings) -> tuple[str, str, str, str]:
    s = snapshot(db, settings)
    return subject(s, settings), text(s), html(s), chat(s)

