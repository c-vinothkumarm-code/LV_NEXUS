"""Data tools for the LV NEXUS assistant (executive overview, management summary, collection health, pending actions,
trends, unusual activity, in-app help).

Same contract as the other Copilot tools: each returns {"source", "as_of", "facts": [{"fact", "link"?}], "gap"?} built
only from the platform's own stored records. `f["_perms"]` carries the caller's permissions so a tool that spans several
areas leaves out what the role may not see (and says so). Nothing here calls a cloud or changes anything."""
from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent, AutomationExecutionLog, BillingRecord, CloudSecurityFinding, JobStatus
from app.models.platform import AuditAnomaly

OPEN = ("OPEN", "UNDER_REVIEW", "REOPENED")


def _now() -> datetime:
    return datetime.now(UTC)


def _can(f: dict, perm: str) -> bool:
    return perm in (f.get("_perms") or ())


def _scope(db: Session, provider: str | None, sid: str | None) -> str:
    from app.api.serializers import scope_label
    return scope_label(db, provider, sid) or sid or "-"


def _usd(v: float | None) -> str:
    return "not collected" if v is None else f"${v:,.0f}"


def _overview(db: Session) -> dict:
    from app.api.routes.home import overview
    return overview(db=db, _=None)


# ------------------------------------------------------------------ executive overview
def t_executive_overview(db: Session, f: dict) -> dict:
    o = _overview(db)
    facts = []
    for p, label in (("azure", "Azure"), ("aws", "AWS"), ("gcp", "Google Cloud")):
        if f.get("provider") and p != f["provider"]:
            continue
        c = o["clouds"][p]
        if not c["scopes"]:
            facts.append({"fact": f"{label}: not connected", "link": "/system-health"})
            continue
        facts.append({"fact": f"{label}: {c['scopes']} account(s) ({c['healthy_scopes']} fully onboarded), {c['resources'] + c['vms']} resources, "
                              f"cost this month {_usd(c['cost_mtd'])}, open critical / high findings {c['critical']} / {c['high']}", "link": "/accounts"})
    cost = o["cost"]
    if _can(f, "finops:read"):
        line = f"Cloud cost month to date: {_usd(cost['month_to_date'])}"
        if cost["forecast_month"] is not None:
            line += f"; forecast for the month {_usd(cost['forecast_month'])} (estimate)"
        if cost["last_month"] is not None:
            line += f"; last month {_usd(cost['last_month'])}"
        facts.append({"fact": line, "link": "/cost/overview"})
    sev = o["security"]["by_severity"]
    facts.append({"fact": f"Open security findings: {sev.get('Critical', 0)} critical, {sev.get('High', 0)} high, {sev.get('Medium', 0)} medium",
                  "link": "/vulnerabilities"})
    facts.append({"fact": f"Cloud activity last 24 h: {o['audit']['events_24h']} events, {o['audit']['flagged_24h']} flagged as unusual", "link": "/activity"})
    facts.append({"fact": f"Access: {o['access']['identities_with_access']} identities hold access, {o['access']['privileged_assignments']} privileged role "
                          "assignments", "link": "/access"})
    h = o["health"]
    st = Counter(j["status"] for j in h["jobs"].values())
    facts.append({"fact": f"Core data collections ({h['total']}): {st['success']} succeeded, {st['failed'] + st['partial']} failed or partial, "
                          f"{st['never']} not run yet", "link": "/system-health"})
    stale = [k for k in ("accounts", "cost", "security", "audit", "access") if o[k]["status"] in ("stale", "degraded", "never")]
    if stale:
        facts.append({"fact": "Sections that may be out of date: " + ", ".join(f"{k} ({o[k]['status']})" for k in stale), "link": "/system-health"})
    return {"source": "LV NEXUS overview (collected cloud data)", "as_of": o["generated_at"], "facts": facts}


# ------------------------------------------------------------------ collection / API health
def t_collection_health(db: Session, f: dict) -> dict:
    from app.services.preflight import job_overview
    jobs = [j for j in job_overview(db) if j["enabled"]]
    bad = [j for j in jobs if j["last_status"] in ("failed", "partial")]
    ok = sum(1 for j in jobs if j["last_status"] == "success")
    never_n = sum(1 for j in jobs if j["last_status"] == "never")
    facts = [{"fact": f"Scheduled workflows ({len(jobs)}): {ok} succeeded, {len(bad)} failed or partial, {never_n} not run yet", "link": "/system-health"}]
    for j in sorted(bad, key=lambda j: (j["last_status"] != "failed", j["name"]))[: f.get("limit", 6)]:
        why = j["problems"][0] if j["problems"] else {}
        facts.append({"fact": f"{j['name']}: {j['last_status']}"
                              + (f" ({j['scopes_failed']}/{j['scopes_total']} scopes failed)" if j["scopes_failed"] else "")
                              + (f" - {str(why.get('reason') or '')[:160]}" if why else "")
                              + (f". Fix: {str(why.get('fix'))[:180]}" if why.get("fix") else ""),
                      "link": "/system-health"})
    never = [j["name"] for j in jobs if j["last_status"] == "never"]
    if never:
        facts.append({"fact": f"Never run yet: {', '.join(never[:8])}" + (" ..." if len(never) > 8 else ""), "link": "/system-health"})
    return {"source": "Automation run history and pre-flight", "as_of": _now().isoformat(), "facts": facts}


# ------------------------------------------------------------------ pending actions and decisions
def t_pending_actions(db: Session, f: dict) -> dict:
    facts, hidden = [], []
    if _can(f, "vuln:read"):
        overdue = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(
            CloudSecurityFinding.internal_status.in_(OPEN), CloudSecurityFinding.sla_due_at < _now(), CloudSecurityFinding.is_security.is_(True))) or 0
        unassigned = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(
            CloudSecurityFinding.internal_status.in_(OPEN), CloudSecurityFinding.severity == "Critical", CloudSecurityFinding.owner.is_(None),
            CloudSecurityFinding.is_security.is_(True))) or 0
        from app.models import FindingException
        exc = db.scalar(select(func.count()).select_from(FindingException).where(FindingException.status == "PENDING_APPROVAL")) or 0
        facts.append({"fact": f"Security: {unassigned} critical finding(s) without an owner, {overdue} past their remediation date, "
                              f"{exc} risk exception(s) awaiting approval", "link": "/vulnerabilities"})
    else:
        hidden.append("security")
    if _can(f, "budget:read"):
        from app.models.budget import BudgetRequest
        n = db.scalar(select(func.count()).select_from(BudgetRequest).where(BudgetRequest.status.in_(["PENDING", "MORE_INFO"]))) or 0
        facts.append({"fact": f"Budget: {n} budget request(s) awaiting a decision", "link": "/budgets#approvals"})
    else:
        hidden.append("budget")
    if _can(f, "audit:read"):
        a = Counter(r for (r,) in db.execute(select(AuditAnomaly.severity).where(AuditAnomaly.status == "OPEN",
                                                                                AuditAnomaly.last_event_at >= _now() - timedelta(days=7))))
        facts.append({"fact": f"Live audit: {a['Critical']} critical and {a['High']} high unusual-activity alert(s) not yet acknowledged (7 days)",
                      "link": "/activity"})
    else:
        hidden.append("audit")
    if _can(f, "exec:read") or _can(f, "inventory:read"):
        from app.models.platform import ManagementDecision
        rows = list(db.scalars(select(ManagementDecision).where(ManagementDecision.status == "OPEN").order_by(ManagementDecision.due_date).limit(5)))
        facts.append({"fact": f"Management decisions open: {len(rows)}" + ("".join(f"; {d.title} (owner {d.owner}, due {d.due_date})" for d in rows[:3])),
                      "link": "/executive"})
    out = {"source": "Findings, exceptions, budget requests, unusual-activity alerts and management decisions", "as_of": _now().isoformat(),
           "facts": facts}
    if hidden:
        out["gap"] = "Not shown for your role: " + ", ".join(hidden)
    return out


# ------------------------------------------------------------------ trends
def t_trends(db: Session, f: dict) -> dict:
    today = _now().date()
    m0 = today.replace(day=1)
    prev_m0 = (m0 - timedelta(days=1)).replace(day=1)
    days = (today - m0).days + 1
    prev_end = prev_m0 + timedelta(days=days - 1)
    facts = []
    if _can(f, "finops:read"):
        def spend(a, b, p=None):
            q = select(func.sum(BillingRecord.cost_usd)).where(BillingRecord.usage_date.between(a, b), BillingRecord.cost_usd.is_not(None))
            if p:
                q = q.where(BillingRecord.provider == p)
            v = db.scalar(q)
            return float(v) if v is not None else None
        cur, prev = spend(m0, today, f.get("provider")), spend(prev_m0, prev_end, f.get("provider"))
        if cur is None:
            facts.append({"fact": "Cost trend: no billing data collected yet", "link": "/cost/overview"})
        elif not prev:
            facts.append({"fact": f"Cost this month so far {_usd(cur)}; no data for the same days last month to compare", "link": "/cost/overview"})
        else:
            pct = (cur - prev) / prev * 100
            facts.append({"fact": f"Cost: {_usd(cur)} in the first {days} day(s) of this month vs {_usd(prev)} in the same days last month "
                                  f"({pct:+.1f}%)", "link": "/cost/overview"})
    if _can(f, "vuln:read"):
        since = _now() - timedelta(days=30)
        new = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(CloudSecurityFinding.first_synced_at >= since,
                                                                                      CloudSecurityFinding.is_security.is_(True))) or 0
        res = db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(CloudSecurityFinding.resolved_at >= since,
                                                                                      CloudSecurityFinding.is_security.is_(True))) or 0
        facts.append({"fact": f"Security findings, last 30 days: {new} new, {res} resolved ({'backlog growing' if new > res else 'backlog shrinking or flat'})",
                      "link": "/vulnerabilities"})
    if _can(f, "audit:read"):
        w1 = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.event_timestamp >= _now() - timedelta(days=7))) or 0
        w0 = db.scalar(select(func.count()).select_from(AuditEvent).where(AuditEvent.event_timestamp.between(_now() - timedelta(days=14),
                                                                                                         _now() - timedelta(days=7)))) or 0
        facts.append({"fact": f"Cloud activity: {w1} events in the last 7 days vs {w0} in the 7 days before", "link": "/activity"})
    return {"source": "Billing records, security findings and audit events", "as_of": _now().isoformat(), "facts": facts,
            **({} if facts else {"gap": "Your role cannot see cost, findings or activity trends"})}


# ------------------------------------------------------------------ unusual activity
def t_unusual_activity(db: Session, f: dict) -> dict:
    q = select(AuditAnomaly).where(AuditAnomaly.status == "OPEN", AuditAnomaly.last_event_at >= _now() - timedelta(days=7))
    if f.get("provider"):
        q = q.where(AuditAnomaly.provider == f["provider"])
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    rows = sorted(db.scalars(q), key=lambda a: (order.get(a.severity, 9), -a.event_count))[: f.get("limit", 6)]
    run = db.scalar(select(func.max(AutomationExecutionLog.finished_at)).where(AutomationExecutionLog.job_name == "anomaly_detection",
                                                                               AutomationExecutionLog.status == JobStatus.SUCCESS.value))
    return {"source": "Live audit anomaly detection (each principal compared with its own 30-day history)", "as_of": run.isoformat() if run else None,
            "facts": [{"fact": f"{a.severity}: {a.title} - {a.principal or 'unknown principal'} in {a.provider.upper()} {_scope(db, a.provider, a.scope_external_id)}, "
                               f"{a.event_count} event(s)", "link": "/activity"} for a in rows],
            **({} if rows else {"gap": "No unacknowledged unusual activity in the last 7 days"})}


# ------------------------------------------------------------------ executive summary (management review)
def t_executive_summary(db: Session, f: dict) -> dict:
    from app.services.intelligence.engine import t_security_risks
    facts = [{**x, "section": "Position"} for x in t_executive_overview(db, f)["facts"]]
    if _can(f, "vuln:read"):
        facts += [{**x, "section": "Top risks"} for x in t_security_risks(db, {**f, "limit": 3})["facts"]]
    facts += [{**x, "section": "Trends"} for x in t_trends(db, f)["facts"]]
    facts += [{**x, "section": "Pending actions"} for x in t_pending_actions(db, f)["facts"]]
    if _can(f, "automation:read"):
        facts += [{**x, "section": "Platform health"} for x in t_collection_health(db, {**f, "limit": 3})["facts"]]
    if _can(f, "onboarding:read") or _can(f, "reports:export"):
        facts += [{**x, "section": "Compliance"} for x in t_compliance_posture(db, {**f, "limit": 3})["facts"][:4]]
    return {"source": "Combined: overview, security findings, trends, pending actions and platform health", "as_of": _now().isoformat(),
            "facts": facts}


# ------------------------------------------------------------------ compliance
FRAMEWORK_WORDS = {"certin": ("cert-in", "certin", "cert in", "6 hour", "6-hour", "180 day"), "dpdp": ("dpdp", "data protection act", "personal data", "privacy law"),
                   "iso27001": ("27001",), "iso27017": ("27017",), "iso27018": ("27018",), "nist_csf": ("nist", "csf"), "cis": ("cis ", "cis-", "cis controls", "benchmark"),
                   "soc2": ("soc 2", "soc2"), "csa_ccm": ("csa", "ccm", "cloud controls matrix"), "owasp": ("owasp",)}


def _frameworks_in(question: str) -> list[str]:
    q = f" {question.lower()} "
    return [k for k, words in FRAMEWORK_WORDS.items() if any(w in q for w in words)]


def t_compliance_posture(db: Session, f: dict) -> dict:
    from app.services.compliance import engine
    from app.services.compliance.library import FRAMEWORKS
    run = engine.latest_run(db)
    if run is None:
        return {"source": "LV NEXUS compliance policy library", "as_of": None, "facts": [],
                "gap": "No compliance evaluation has run yet (scheduled 07:50 and 19:50 IST, or Governance > Compliance > Run now)"}
    wanted = _frameworks_in(f.get("_question", "")) or list(FRAMEWORKS)
    order = {"legal": 0, "legal_upcoming": 1, "voluntary": 2, "internal": 3}
    facts = []
    for k in sorted(wanted, key=lambda k: order[FRAMEWORKS[k]["obligation"]]):
        sc = (run.scores or {}).get(k) or {}
        label = {"legal": "legal requirement", "legal_upcoming": "legal from 13 May 2027", "voluntary": "voluntary", "internal": "internal policy"}[FRAMEWORKS[k]["obligation"]]
        score = "no assessed results yet" if sc.get("score") is None else f"score {sc['score']}%"
        facts.append({"fact": f"{FRAMEWORKS[k]['name']} ({label}): {score}, coverage {sc.get('coverage', 0)}%, {sc.get('policies_failing', 0)} failing polic(ies)",
                      "link": f"/compliance/policies?framework={k}"})
    return {"source": "LV NEXUS compliance policy library (automated checks over collected cloud data + attestations)",
            "as_of": run.finished_at.isoformat() if run.finished_at else None, "facts": facts[: max(f.get("limit", 12), len(wanted) if len(wanted) < 11 else 12)]}


def t_compliance_gaps(db: Session, f: dict) -> dict:
    from sqlalchemy import select as _select

    from app.models.compliance import ComplianceResult
    from app.services.compliance import engine
    from app.services.compliance.library import BY_KEY
    run = engine.latest_run(db)
    if run is None:
        return {"source": "LV NEXUS compliance policy library", "as_of": None, "facts": [], "gap": "No compliance evaluation has run yet"}
    fw = _frameworks_in(f.get("_question", ""))
    q = _select(ComplianceResult).where(ComplianceResult.run_id == run.id, ComplianceResult.status == "FAIL")
    if f.get("provider"):
        q = q.where(ComplianceResult.provider == f["provider"])
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    rows = [x for x in db.scalars(q) if not fw or any(k in BY_KEY[x.policy_key].refs for k in fw)]
    rows.sort(key=lambda x: (order.get(x.severity, 9), -x.failing))
    facts = []
    for x in rows[: f.get("limit", 8)]:
        p = BY_KEY[x.policy_key]
        refs = "; ".join(f"{k}: {', '.join(v)}" for k, v in p.refs.items() if not fw or k in fw)[:160]
        ev = ", ".join(str(e.get("item")) for e in (x.evidence or [])[:3])
        facts.append({"fact": f"{x.severity} - {p.title} - {x.scope_name} ({x.provider.upper()}): {x.detail}" + (f" [e.g. {ev}]" if ev else "")
                              + f". Fix: {p.remediation} ({refs})", "link": f"/compliance/policies?policy={p.key}"})
    return {"source": "LV NEXUS compliance policy library", "as_of": run.finished_at.isoformat() if run.finished_at else None, "facts": facts,
            **({} if facts else {"gap": "No failing compliance policy in the latest evaluation" + (" for that framework" if fw else "")})}


# ------------------------------------------------------------------ in-app help
HELP = [
    (("compliance", "cert-in", "dpdp", "iso", "soc 2", "audit report", "policy library"), "Compliance: Governance > Compliance library shows a score per "
     "framework (legal requirements first), failing policies with the accounts and evidence, remediation, attestations and the audit-ready report."),
    (("cost", "spend", "budget", "forecast"), "Cost: monthly spend, forecast (kept separate from actuals), budget and top accounts / services / "
     "resources are on Cost. Billing periods, invoices, tags and amortised cost are on More → Cost analysis.", "/cost/overview"),
    (("access", "iam", "who has", "permission", "role"), "Access (IAM) is read-only: pick a subscription / account / project, then a resource group or "
     "service, to see who has access, directly or inherited. Search a person by name at the top.", "/access"),
    (("vulnerab", "finding", "security hub", "defender", "scc"), "Vulnerabilities lists open findings from Security Hub, Defender / Advisor and SCC. "
     "Click a severity to filter, click a finding for details, owner, SLA and exceptions.", "/vulnerabilities"),
    (("audit", "activity", "sign-in", "unusual", "anomal"), "Live audit streams cloud activity and shows unusual-activity alerts at the top. "
     "Acknowledge an alert with a note once someone has checked it.", "/activity"),
    (("account", "subscription", "project", "resource", "inventory"), "Cloud accounts shows one tree per cloud down to resource group / region, "
     "with health, cost and findings at every level.", "/accounts"),
    (("health", "fail", "error", "sync", "pre-flight", "preflight", "job"), "System health runs pre-flight and lists every scheduled workflow with its "
     "last success, next run and the fix for any failure.", "/system-health"),
    (("report", "export", "excel", "csv", "pdf"), "Exports: most tables have an Export button (CSV / Excel); scheduled and on-demand reports are in "
     "More → Reports & Analytics.", "/reports/library"),
    (("executive", "management", "decision"), "Executive review summarises risk, cost and open management decisions; the assistant can draft an "
     "executive summary from the same data.", "/executive"),
]


def t_app_help(db: Session, f: dict) -> dict:
    q = (f.get("_question") or "").lower()
    hits = [(text, link) for words, text, link in HELP if any(w in q for w in words)] or [(text, link) for _, text, link in HELP]
    return {"source": "LV NEXUS user guide", "as_of": None, "facts": [{"fact": t, "link": link} for t, link in hits[:4]]}
