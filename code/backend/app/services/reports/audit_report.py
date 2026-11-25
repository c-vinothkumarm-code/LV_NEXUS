"""Monthly Cloud Security & Governance Audit Report, one per AWS account / Azure subscription / GCP project.

Built only from data LV NEXUS collected for that scope; anything not collected is written as "Not collected" (never 0).
The automated report never claims a human review: domain review status is "Automated check – SPOC review required".
Outputs: the report in the official LatentView Word layout (DOCX, plus a PDF rendered from it – see audit_template),
attachments A Active Users, B Active Services, C Vulnerability List (CSV) and the e-mail text, all from the same data."""
from __future__ import annotations

import base64
import csv
import io
from calendar import monthrange
from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import BillingForecast, BillingRecord, CloudSecurityFinding, ComplianceResult, IamException, SecuritySlaPolicy
from app.services import ownership as OWN

PROVIDER_NAME = {"aws": "Amazon Web Services (AWS)", "azure": "Microsoft Azure", "gcp": "Google Cloud (GCP)"}
PROVIDER_SHORT = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
SCOPE_NOUN = {"aws": "account", "azure": "subscription", "gcp": "project"}
SEVERITIES = ("Critical", "High", "Medium", "Low")
OPEN = ("OPEN", "UNDER_REVIEW", "REOPENED")
NC = "Not collected"


def month_bounds(month: date) -> tuple[date, date]:
    first = month.replace(day=1)
    return first, first.replace(day=monthrange(first.year, first.month)[1])


def previous_month(today: date | None = None) -> date:
    today = today or datetime.now(UTC).date()
    return (today.replace(day=1) - timedelta(days=1)).replace(day=1)


def _is_vuln(f: CloudSecurityFinding) -> bool:
    text = f"{f.category or ''} {f.finding_type or ''} {f.source or ''} {f.title or ''}".lower()
    return any(k in text for k in ("vulnerab", "cve-", "inspector", "software and configuration checks/vulnerabilities", "os vulnerab"))


def _sla_days(db: Session) -> dict:
    d = {p.severity: round(p.target_hours / 24) for p in db.scalars(select(SecuritySlaPolicy))}
    return d or {"Critical": 5, "High": 7, "Medium": 30, "Low": 100}


def build(db: Session, settings: Settings, provider: str, scope: str, month: date) -> dict:
    """Everything the report shows, for one scope and one calendar month."""
    first, last = month_bounds(month)
    start_dt = datetime(first.year, first.month, 1, tzinfo=UTC)
    end_dt = datetime(last.year, last.month, last.day, tzinfo=UTC) + timedelta(days=1)
    name = OWN.scope_name(db, provider, scope) or scope
    own_row = OWN.get(db, provider, scope)
    own = OWN.to_dict(db, provider, scope, own_row)

    # ---- IAM (existing access inventory, with display names and approval status)
    from app.api.routes.access import assignments as list_assignments
    rows = list_assignments(provider=provider, scope=scope, status=None, privileged=None, access_type=None, role=None, q=None,
                            include_removed=True, page=1, size=100000, db=db, _=None)["items"]
    active = [r for r in rows if not r["removed_at"]]
    removed_in_month = [r for r in rows if r["removed_at"] and first.isoformat() <= r["removed_at"][:10] <= last.isoformat()]
    added_in_month = [r for r in active if r["first_seen_at"] and first.isoformat() <= r["first_seen_at"][:10] <= last.isoformat()]
    principals = {r["principal_id"] for r in active}
    privileged = [r for r in active if r["privileged"]]
    dormant = [r for r in active if r.get("last_sign_in") and r["last_sign_in"][:10] < (last - timedelta(days=30)).isoformat()]
    iam_exceptions = list(db.scalars(select(IamException).where(IamException.provider == provider, IamException.status.in_(["OPEN", "open", "ACTIVE"]))
                                     .where(IamException.scope_path.contains(scope)))) if hasattr(IamException, "scope_path") else []

    # ---- findings
    findings = list(db.scalars(select(CloudSecurityFinding).where(CloudSecurityFinding.provider == provider, CloudSecurityFinding.scope_external_id == scope,
                                                                  CloudSecurityFinding.is_security.is_(True))))
    any_findings_collected = bool(findings) or db.scalar(select(func.count()).select_from(CloudSecurityFinding).where(
        CloudSecurityFinding.provider == provider)) > 0
    open_f = [f for f in findings if f.native_state == "ACTIVE" and f.internal_status in OPEN]
    vulns, others = [f for f in open_f if _is_vuln(f)], [f for f in open_f if not _is_vuln(f)]
    fixed = [f for f in findings if f.resolved_at and start_dt <= (f.resolved_at if f.resolved_at.tzinfo else f.resolved_at.replace(tzinfo=UTC)) < end_dt]
    now = datetime.now(UTC)
    overdue = [f for f in open_f if f.sla_due_at and (f.sla_due_at if f.sla_due_at.tzinfo else f.sla_due_at.replace(tzinfo=UTC)) < now and not f.sla_paused]

    # ---- compliance (latest run)
    from app.services.compliance.engine import latest_run
    run = latest_run(db)
    comp = [r for r in db.scalars(select(ComplianceResult).where(ComplianceResult.run_id == run.id, ComplianceResult.provider == provider,
                                                                 ComplianceResult.scope_external_id == scope))] if run else []
    comp_counts = Counter(r.status for r in comp)

    # ---- cost: 12 months up to the report month, report month detail, budget, forecast
    m12 = (first.replace(day=1) - timedelta(days=330)).replace(day=1)
    monthly = defaultdict(float)
    services = defaultdict(float)
    any_cost = False
    for d, svc, v in db.execute(select(BillingRecord.usage_date, BillingRecord.service, BillingRecord.cost_usd).where(
            BillingRecord.provider == provider, BillingRecord.scope_external_id == scope, BillingRecord.usage_date >= m12,
            BillingRecord.usage_date <= last, BillingRecord.cost_usd.is_not(None))).all():
        any_cost = True
        monthly[d.strftime("%Y-%m")] += float(v)
        if first <= d <= last:
            services[svc or "(unspecified)"] += float(v)
    months = []
    cur = m12
    while cur <= first:
        k = cur.strftime("%Y-%m")
        months.append({"month": cur.strftime("%b %Y"), "key": k, "cost_usd": round(monthly[k], 2) if k in monthly else None})
        cur = (cur.replace(day=28) + timedelta(days=4)).replace(day=1)
    month_cost = round(monthly[first.strftime("%Y-%m")], 2) if first.strftime("%Y-%m") in monthly else None
    budget = own["approved_budget"]["monthly_usd"]
    util = round(month_cost / budget * 100, 1) if month_cost is not None and budget else None
    status = None if util is None else "Exceeds budget" if util > 100 else "Near limit" if util >= 90 else "Within budget"
    cm_first = datetime.now(UTC).date().replace(day=1)
    fc = [f for f in db.scalars(select(BillingForecast).where(BillingForecast.provider == provider, BillingForecast.scope_external_id == scope,
                                                             BillingForecast.period_start == cm_first)) if f.currency == "USD"]
    cm_actual = db.scalar(select(func.sum(BillingRecord.cost_usd)).where(BillingRecord.provider == provider, BillingRecord.scope_external_id == scope,
                                                                         BillingRecord.usage_date >= cm_first, BillingRecord.cost_usd.is_not(None)))
    forecast = None
    if fc:
        f0 = next((f for f in fc if f.method.startswith("provider:")), fc[0])
        forecast = round((float(cm_actual or 0) + float(f0.forecast_amount)) if f0.method.startswith("provider:") else float(f0.forecast_amount), 2)

    # ---- optimisation (existing read-only recommendations, this scope only)
    from app.api.routes.cost import optimization
    try:
        recs = [r for r in optimization(db=db, settings=settings, _=None).get("items", []) if r.get("scope") == scope or r.get("scope_external_id") == scope]
    except Exception:  # noqa: BLE001 - recommendations are optional in the report
        recs = []

    def risk(items: list) -> str:
        sev = {f.severity for f in items}
        return "Critical" if "Critical" in sev else "High" if "High" in sev else "Medium" if items else "Low"

    review = "Automated check – SPOC review required"
    domains = [
        {"domain": "Vulnerability management", "status": review if any_findings_collected else NC,
         "risk": risk(vulns) if any_findings_collected else "—",
         "remarks": f"{len(vulns)} open, {sum(1 for f in overdue if _is_vuln(f))} past SLA"},
        {"domain": "Security findings", "status": review if any_findings_collected else NC,
         "risk": risk(others) if any_findings_collected else "—",
         "remarks": f"{len(others)} open configuration / threat findings"},
        {"domain": "Access management", "status": review if rows else NC, "risk": ("High" if len(privileged) > 5 else "Medium" if privileged else "Low") if rows else "—",
         "remarks": f"{len(principals)} identities, {len(privileged)} privileged assignments"},
        {"domain": "Compliance", "status": review if comp else NC, "risk": ("High" if comp_counts.get("FAIL") else "Low") if comp else "—",
         "remarks": f"{comp_counts.get('PASS', 0)} pass, {comp_counts.get('FAIL', 0)} fail, {len(comp) - comp_counts.get('PASS', 0) - comp_counts.get('FAIL', 0)} not assessed" if comp else "no compliance run"},
        {"domain": "Cost management", "status": review if any_cost else NC, "risk": {"Exceeds budget": "High", "Near limit": "Medium", "Within budget": "Low"}.get(status or "", "—"),
         "remarks": status or ("no approved budget" if any_cost and not budget else "")},
    ]
    month_label = first.strftime("%B %Y")
    title = f"Cloud Security & Governance Audit Report – {PROVIDER_SHORT[provider]} {name} ({scope}) – {month_label}"
    return {
        "title": title, "provider": provider, "provider_name": PROVIDER_NAME[provider], "scope": scope, "name": name, "noun": SCOPE_NOUN[provider],
        "month": first.isoformat(), "month_label": month_label, "period": f"{first:%d} – {last:%d %B %Y}", "generated_at": now.isoformat(),
        "ownership": own, "domains": domains, "sla_days": _sla_days(db),
        "iam": {"collected": bool(rows), "identities": len(principals), "assignments": len(active), "privileged": privileged,
                "added": added_in_month, "removed": removed_in_month, "dormant": dormant, "rows": active, "exceptions": len(iam_exceptions),
                "mfa": NC},
        "vulns": {"collected": any_findings_collected, "open": vulns, "by_severity": Counter(f.severity for f in vulns),
                  "fixed_by_severity": Counter(f.severity for f in fixed if _is_vuln(f))},
        "findings": {"open": others, "by_severity": Counter(f.severity for f in others), "fixed": len([f for f in fixed if not _is_vuln(f)])},
        "overdue": overdue,
        "compliance": {"collected": bool(comp), "pass": comp_counts.get("PASS", 0), "fail": comp_counts.get("FAIL", 0),
                       "other": len(comp) - comp_counts.get("PASS", 0) - comp_counts.get("FAIL", 0),
                       "failing": [{"policy": r.policy_key, "severity": r.severity, "detail": (r.detail or "")[:160]} for r in comp if r.status == "FAIL"],
                       "run_at": run.finished_at.isoformat() if run and run.finished_at else None},
        "cost": {"collected": any_cost, "months": months, "month_cost": month_cost, "budget": budget, "utilisation": util, "status": status,
                 "services": sorted(services.items(), key=lambda kv: -kv[1])[:15], "forecast_current_month": forecast,
                 "current_month_label": cm_first.strftime("%B %Y"), "budgets": own["approved_budget"]["budgets"]},
        "recommendations": recs[:15],
    }


# ---------------------------------------------------------------- attachments

def _safe(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s  # spreadsheet formula injection guard


def _csv(head: list[str], rows: list[list]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(head)
    for r in rows:
        w.writerow([_safe(v) for v in r])
    return buf.getvalue()


def attachments_csv(d: dict, t: dict) -> list[dict]:
    """Attachments A, B and C of the report template (CSV, opens in Excel)."""
    p = f"{d['provider']}-{d['scope']}-{d['month'][:7]}"
    users = _csv(["Identity", "Sign-in / e-mail", "Type", "Role", "Privileged", "Scope level", "Scope path", "How granted", "Status", "Last sign-in",
                  "MFA status", "First seen", "Expires"],
                 [[r["display_name"] or r["principal_id"], r["sign_in_name"], r["identity_type"], r["access_details"], "yes" if r["privileged"] else "no",
                   r["scope_level"], r["scope_path"], r["access_type"], r["approval_status"], r["last_sign_in"] or "not collected", "not collected",
                   r["first_seen_at"], r["expires_at"]] for r in d["iam"]["rows"]])
    services = _csv(["Item", "Name", "Resource ID", "Type / service", "Region", "State", "Status (active / inactive)", "Owner (tag)", f"Cost {d['month_label']} (USD)"],
                    [["Resource", r["name"], r["id"], r["type"], r["region"], r["state"], r["status"], r["owner"] or "no owner tag",
                      "per-service only (see Service rows)"] for r in t["resources"]]
                    + [["Service cost", s, "", s, "", "", "", "", f"{v:.2f}"] for s, v in d["cost"]["services"]])
    order = {s: i for i, s in enumerate(SEVERITIES)}
    now = datetime.now(UTC)

    def frow(f):
        due = f.sla_due_at if (f.sla_due_at is None or f.sla_due_at.tzinfo) else f.sla_due_at.replace(tzinfo=UTC)
        return [f.severity, f.title, f.resource_name or f.resource_id, f.resource_type, f.region, f.internal_status,
                f.first_observed_at.isoformat() if f.first_observed_at else "", due.isoformat() if due else "",
                "yes" if due and due < now and not f.sla_paused else "no", "vulnerability" if _is_vuln(f) else "misconfiguration / threat", f.source, f.native_id]
    vul = _csv(["Severity", "Title", "Resource", "Resource type", "Region", "Status", "Identified", "SLA due", "SLA breached", "Kind", "Source", "Native ID"],
               [frow(f) for f in sorted(d["vulns"]["open"] + d["findings"]["open"], key=lambda f: order.get(f.severity, 9))])
    return [{"filename": f"A_Active_Users_List_{p}.csv", "content_type": "text/csv", "text": users},
            {"filename": f"B_Active_Services_List_{p}.csv", "content_type": "text/csv", "text": services},
            {"filename": f"C_Vulnerability_List_{p}.csv", "content_type": "text/csv", "text": vul}]


# ---------------------------------------------------------------- formatting

def _money(v) -> str:
    return NC if v is None else f"${v:,.2f}"


# ---------------------------------------------------------------- e-mail

def email_parts(d: dict) -> tuple[str, str]:
    subject = f"[LV NEXUS] Monthly Cloud Security & Governance Audit – {d['name']} – {d['month_label']}"
    v, c, iam = d["vulns"], d["cost"], d["iam"]
    lines = [f"Dear {d['ownership']['spoc_name'] or 'Account SPOC'},", "",
             f"Please find attached the Cloud Security & Governance Audit Report for the {d['provider_name']} {d['noun']} {d['name']} ({d['scope']}) "
             f"for {d['month_label']}.", "", "Summary (from collected cloud data):",
             f"  - Open vulnerabilities: {len(v['open'])} (Critical {v['by_severity'].get('Critical', 0)}, High {v['by_severity'].get('High', 0)})" if v["collected"] else f"  - Vulnerabilities: {NC}",
             f"  - Findings past SLA: {len(d['overdue'])}",
             f"  - Identities with access: {iam['identities']}, privileged assignments: {len(iam['privileged'])}" if iam["collected"] else f"  - IAM access: {NC}",
             f"  - Cost {d['month_label']}: {_money(c['month_cost'])}" + (f" of {_money(c['budget'])} approved ({c['utilisation']}%, {c['status']})" if c["utilisation"] is not None else ""),
             f"  - Compliance: {d['compliance']['pass']} pass / {d['compliance']['fail']} fail" if d["compliance"]["collected"] else f"  - Compliance: {NC}",
             "", "Action required: review the report, confirm the access list and the open items, and reply with any exceptions.",
             "Attachments: the report (Word and PDF); A Active Users List; B Active Services List; C Vulnerability List.", "",
             "This report was generated automatically by LV NEXUS (read-only towards the cloud). It is not a substitute for your review.",
             "", "Cloud Team – LatentView Analytics"]
    return subject, "\n".join(lines)


def package(db: Session, settings: Settings, provider: str, scope: str, month: date) -> dict:
    """The report in the official LatentView layout (DOCX + PDF rendered from it) and attachments A, B, C."""
    from app.services.reports import audit_template as AT
    d = build(db, settings, provider, scope, month)
    t = AT.collect(db, settings, d)
    docx = AT.docx_bytes(d, t)
    pdf = AT.pdf_from_docx(docx)
    base = f"{PROVIDER_SHORT[provider]}_{d['scope']}_Monthly_Security_Governance_Audit_{d['month'][:7]}"
    subject, body = email_parts(d)
    return {"data": d, "template": t, "pdf": pdf, "pdf_name": f"{base}.pdf", "docx": docx, "docx_name": f"{base}.docx", "subject": subject, "body": body,
            "attachments": [{"filename": f"{base}.pdf", "content_type": "application/pdf", "base64": base64.b64encode(pdf).decode()},
                            {"filename": f"{base}.docx", "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                             "base64": base64.b64encode(docx).decode()}, *attachments_csv(d, t)]}
