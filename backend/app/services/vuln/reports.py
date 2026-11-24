"""Security reports as CSV, Excel or PDF, built from the database at request time (never from cached figures)."""
from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditEvent, AuditInvestigation, CloudSecurityFinding, FindingException, InvestigationCase, SyncCheckpoint, SyncRun

from .lifecycle import is_overdue

F = CloudSecurityFinding
FINDING_HEAD = ["ID", "Cloud", "Source", "Account / subscription / project", "Region", "Severity", "Category", "Title", "Resource",
                "Resource type", "Compliance standard", "Control", "Native state", "Internal status", "Owner", "First observed", "Last observed",
                "SLA due", "Overdue", "Native ID"]


def _fr(f: CloudSecurityFinding) -> list:
    return [f.id, f.provider, f.source, f.scope_external_id, f.region, f.severity, f.category, f.title, f.resource_id, f.resource_type,
            f.compliance_standard, f.control_id, f.native_state, f.internal_status, f.owner, f.first_observed_at, f.last_observed_at,
            f.sla_due_at, "yes" if is_overdue(f) else "", f.native_id]


def _findings(db, *conds):
    return [_fr(f) for f in db.scalars(select(F).where(F.is_security.is_(True), *conds).order_by(F.severity, F.id))]


def _exceptions(db, *conds):
    head = ["Exception", "Finding", "Cloud", "Scope", "Resource", "Status", "Justification", "Risk acceptance", "Business impact",
            "Compensating controls", "Risk owner", "Technical owner", "Requester", "Approver", "Created", "Approved", "Expires"]
    rows = []
    for e, f in db.execute(select(FindingException, F).join(F, F.id == FindingException.finding_id).where(*conds).order_by(FindingException.id)):
        rows.append([e.id, f.id, f.provider, f.scope_external_id, f.resource_id, e.status, e.business_justification, e.risk_acceptance,
                     e.business_impact, e.compensating_controls, e.risk_owner, e.technical_owner, e.requester, e.approver, e.created_at, e.approved_at, e.expires_at])
    return head, rows


def _audit(db, *conds):
    head = ["Event", "Cloud", "Scope", "Region", "Time (UTC)", "Actor", "Source IP", "Operation", "Resource", "Category", "Classification",
            "Rules", "Investigation status", "Investigator", "Authorized by", "Authorization ref", "Closure reason"]
    q = (select(AuditEvent, AuditInvestigation).outerjoin(AuditInvestigation, AuditInvestigation.audit_event_id == AuditEvent.id)
         .where(*conds).order_by(AuditEvent.event_timestamp.desc()).limit(50000))
    return head, [[e.id, e.provider, e.scope_external_id, e.region, e.event_timestamp, e.principal, e.source_ip, e.event_name, e.resource_id,
                   i.category if i else None, i.classification if i else "NOT_EVALUATED", ", ".join(m.get("rule_key", "") for m in (i.matched_rules or [])) if i else "",
                   i.status if i else None, i.investigator if i else None, i.authorized_by if i else None, i.authorization_reference if i else None,
                   i.closure_reason if i else None] for e, i in db.execute(q)]


def _cases(db, *conds):
    head = ["Case", "Title", "Status", "Origin", "Risk", "Actor", "Cloud", "Scope", "Events", "Resources", "Owner", "Outcome", "Created", "Last event"]
    return head, [[c.id, c.title, c.status, c.origin, c.risk, c.actor, c.provider, c.scope_external_id, len(c.event_ids or []),
                   len(c.resources or []), c.owner, c.outcome, c.created_at, c.last_event_at]
                  for c in db.scalars(select(InvestigationCase).where(*conds).order_by(InvestigationCase.id.desc()))]


def _posture(db):
    rows = list(db.scalars(select(F).where(F.is_security.is_(True))))
    head = ["Cloud", "Severity", "Internal status", "Native state", "Findings", "Overdue"]
    c, o = Counter(), Counter()
    for f in rows:
        k = (f.provider, f.severity, f.internal_status, f.native_state)
        c[k] += 1
        o[k] += is_overdue(f)
    out = [[*k, n, o[k]] for k, n in sorted(c.items())]
    std = Counter(s.strip() for f in rows if f.compliance_standard for s in f.compliance_standard.split(","))
    out += [["", "", "", "", "", ""], ["Standards referenced by provider findings (provider control mapping; not a compliance attestation)", "", "", "", "", ""]]
    out += [[s, "", "", "", n, ""] for s, n in std.most_common(50)]
    return head, out


def _sla(db):
    head = ["ID", "Cloud", "Severity", "Title", "Owner", "Internal status", "First observed", "SLA due", "Overdue", "SLA paused (exception)"]
    return head, [[f.id, f.provider, f.severity, f.title, f.owner, f.internal_status, f.first_observed_at, f.sla_due_at, "yes" if is_overdue(f) else "",
                   "yes" if f.sla_paused else ""] for f in db.scalars(select(F).where(F.is_security.is_(True), F.sla_due_at.is_not(None)).order_by(F.sla_due_at))]


def _sync(db):
    head = ["Run", "Trigger", "Mode", "Status", "Started", "Finished", "Retrieved", "New", "Updated", "Resolved", "Reappeared",
            "Permission errors", "Throttling", "Errors"]
    out = []
    for r in db.scalars(select(SyncRun).order_by(SyncRun.id.desc()).limit(500)):
        c = r.counts or {}
        out.append([r.id, r.trigger, r.mode, r.status, r.started_at, r.finished_at, *(c.get(k, 0) for k in
                    ("retrieved", "new", "updated", "resolved", "reappeared", "permission_errors", "throttling_errors")), len(r.errors or [])])
    return head, out


def _health(db):
    head = ["Cloud", "Source", "Scope", "Region", "State", "Last success", "Last full", "Findings seen", "Consecutive failures", "Last error"]
    return head, [[c.provider, c.source, c.scope_external_id, c.region, c.state, c.last_success_at, c.last_full_at, c.findings_seen,
                   c.consecutive_failures, c.last_error] for c in db.scalars(select(SyncCheckpoint).order_by(SyncCheckpoint.provider, SyncCheckpoint.scope_external_id))]


Inv = AuditInvestigation
REPORTS = {
    "posture": ("Overall multi-cloud security posture", _posture),
    "aws-security-hub": ("AWS Security Hub findings", lambda db: (FINDING_HEAD, _findings(db, F.provider == "aws"))),
    "azure-advisor": ("Azure Advisor security findings", lambda db: (FINDING_HEAD, _findings(db, F.provider == "azure"))),
    "gcp-scc": ("Google SCC findings", lambda db: (FINDING_HEAD, _findings(db, F.provider == "gcp"))),
    "critical-high": ("Critical and High findings", lambda db: (FINDING_HEAD, _findings(db, F.severity.in_(["Critical", "High"]), F.native_state == "ACTIVE"))),
    "open-register": ("Open vulnerability register", lambda db: (FINDING_HEAD, _findings(db, F.internal_status.in_(["OPEN", "UNDER_REVIEW", "REOPENED"])))),
    "exceptions": ("Exception register", _exceptions),
    "expired-exceptions": ("Expired exception register", lambda db: _exceptions(db, FindingException.status == "EXPIRED")),
    "sla": ("Remediation SLA report", _sla),
    "audit-activity": ("Audit activity report", _audit),
    "authorized-activity": ("Authorized activity report", lambda db: _audit(db, Inv.classification == "AUTHORIZED")),
    "suspicious-activity": ("Suspicious and rule-violation activity report", lambda db: _audit(db, Inv.classification.in_(["SUSPICIOUS", "RULE_VIOLATION"]))),
    "open-investigations": ("Open investigation report", lambda db: _cases(db, InvestigationCase.status.not_in(["CLOSED", "NO_ACTION_REQUIRED", "DISMISSED", "AUTHORIZED"]))),
    "closed-investigations": ("Closed investigation report", lambda db: _cases(db, InvestigationCase.status.in_(["CLOSED", "NO_ACTION_REQUIRED", "DISMISSED", "AUTHORIZED"]))),
    "sync": ("Daily synchronization report", _sync),
    "integration-health": ("Cloud integration health report", _health),
}


def _cell(v):
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M")
    s = "" if v is None else str(v)
    return f"'{s}" if s[:1] in ("=", "+", "-", "@") else s  # spreadsheet formula injection guard


def render(db: Session, name: str, fmt: str) -> tuple[bytes, str, str]:
    title, build = REPORTS[name]
    head, rows = build(db)
    return render_table(name, title, head, rows, fmt)


def render_table(name: str, title: str, head: list, rows: list, fmt: str, subtitle: str = "") -> tuple[bytes, str, str]:
    """CSV (UTF-8 BOM, formula-injection safe), Excel or PDF of one table."""
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    meta = f"LV NEXUS · LatentView Analytics - {title} - generated {stamp} from synchronized data{(' - ' + subtitle) if subtitle else ''}"
    fname = f"cloudnexus-{name}-{datetime.now(UTC):%Y%m%d}"
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow([meta])
        w.writerow(head)
        w.writerows([[_cell(v) for v in r] for r in rows])
        return buf.getvalue().encode("utf-8-sig"), "text/csv", f"{fname}.csv"
    if fmt == "xlsx":
        from openpyxl import Workbook
        from openpyxl.styles import Font
        wb = Workbook()
        ws = wb.active
        ws.title = title[:31]
        ws.append([meta])
        ws.append(head)
        for cell in ws[2]:
            cell.font = Font(bold=True)
        for r in rows:
            ws.append([_cell(v) for v in r])
        ws.freeze_panes = "A3"
        out = io.BytesIO()
        wb.save(out)
        return out.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", f"{fname}.xlsx"
    if fmt == "pdf":
        from fpdf import FPDF
        pdf = FPDF(orientation="L", unit="mm", format="A4")
        pdf.set_auto_page_break(True, 10)
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(0, 5, meta, new_x="LMARGIN", new_y="NEXT")
        cols = head[:9]
        width = (pdf.w - 20) / len(cols)
        pdf.set_font("Helvetica", "B", 7)
        for h in cols:
            pdf.cell(width, 6, h[:24], border=1)
        pdf.ln()
        pdf.set_font("Helvetica", "", 6.5)
        for r in rows[:2000]:
            for v in r[:9]:
                txt = _cell(v).encode("latin-1", "replace").decode("latin-1")
                pdf.cell(width, 5, txt[: int(width * 0.55)], border=1)
            pdf.ln()
        if len(rows) > 2000 or len(head) > 9:
            pdf.set_font("Helvetica", "I", 7)
            pdf.cell(0, 6, f"PDF shows the first 9 columns and up to 2000 rows of {len(rows)}; use Excel or CSV for the full register.")
        return bytes(pdf.output()), "application/pdf", f"{fname}.pdf"
    raise ValueError("format must be csv, xlsx or pdf")
