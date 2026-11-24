"""SOC incident e-mail: summary, why it was flagged, what to do next, and the original audit events as a CSV attachment.

Recipient policy:
- SOC_ALERT_RECIPIENTS (comma list) - the SOC / security distribution list; falls back to NOTIFY_EMAIL_TO.
- The affected user is added ONLY when SOC_NOTIFY_AFFECTED_USER=true AND their address is in an allowed corporate domain
  (SOC_AFFECTED_USER_DOMAINS, default GOOGLE_ALLOWED_DOMAIN) AND the rule is not an identity-compromise rule (a possibly
  compromised mailbox must not be told about its own investigation). Off by default.
"""
from __future__ import annotations

import csv
import html
import io
import json
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import AuditEvent
from app.models.vuln import DetectionRule, InvestigationCase

PROVIDER = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
_COMPROMISE_CATS = {"A", "B"}  # identity / reconnaissance: never e-mail the identity under investigation
CSV_HEAD = ["Incident ID", "Detection rule ID", "Event ID", "Event time (UTC)", "Cloud provider", "Account / subscription / project ID",
            "Account name", "Principal identity", "Source IP", "API operation", "Resource ID", "Resource type", "Region", "Event outcome",
            "Original event payload (JSON)"]


def incident_id(case: InvestigationCase) -> str:
    return f"INC-{case.id:06d}"


def confidence_for(rule: DetectionRule) -> str:
    if rule.action == "RULE_VIOLATION":
        return "High"
    if (rule.threshold_count or 1) > 1 or rule.action == "SUSPICIOUS":
        return "Medium"
    return "Low"


def summarize(case: InvestigationCase, rule: DetectionRule, e: AuditEvent, account: str) -> str:
    who = e.principal or "an unknown identity"
    where = f"{PROVIDER.get(e.provider, e.provider)} {account}" + (f" ({e.region})" if e.region else "")
    lines = [f"{who} performed {e.event_name} in {where} at {e.event_timestamp:%Y-%m-%d %H:%M} UTC"
             + (f" from {e.source_ip}" if e.source_ip else "") + ".",
             f"Detection rule {rule.rule_key} \"{rule.name}\" matched ({rule.severity}, confidence {case.confidence or confidence_for(rule)}).",
             f"Why: {rule.description or case.risk_assessment or '-'}",
             "This is a detection that needs analyst review. It is not a confirmed incident until an analyst records that conclusion."]
    if rule.mitre:
        lines.append("MITRE ATT&CK: " + ", ".join(f"{m['id']} {m['name']}" for m in rule.mitre))
    return "\n".join(lines)


def evidence_csv(db: Session, case: InvestigationCase, rule: DetectionRule | None, names: dict, limit: int = 500) -> str:
    ids = (case.event_ids or [])[:limit]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_HEAD)
    for e in db.scalars(select(AuditEvent).where(AuditEvent.id.in_(ids)).order_by(AuditEvent.event_timestamp)) if ids else []:
        raw = e.raw or {}
        row = [incident_id(case), rule.rule_key if rule else "", e.event_id, e.event_timestamp.isoformat(), e.provider, e.scope_external_id,
               names.get((e.provider, e.scope_external_id), ""), e.principal, e.source_ip, e.event_name, e.resource_id, e.resource_type,
               e.region, raw.get("outcome") or "success", json.dumps(raw, default=str, sort_keys=True)]
        w.writerow([_cell(v) for v in row])
    return buf.getvalue()


def _cell(v):
    """CSV formula-injection guard: a value starting with = + - @ is prefixed with an apostrophe."""
    if v is None:
        return ""
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def recipients(settings: Settings, rule: DetectionRule, e: AuditEvent) -> list[str]:
    to = list(dict.fromkeys(getattr(settings, "soc_alert_recipients", None) or settings.notify_email_to or []))
    if getattr(settings, "soc_notify_affected_user", False) and rule.soc_category not in _COMPROMISE_CATS:
        m = re.search(r"[\w.+-]+@([\w-]+\.)+[\w-]+", e.principal or "")
        domains = [d.lower() for d in (getattr(settings, "soc_affected_user_domains", None) or
                                       ([settings.google_allowed_domain] if settings.google_allowed_domain else []))]
        if m and m.group(0).split("@", 1)[1].lower() in domains:
            to.append(m.group(0).lower())
    return list(dict.fromkeys(to))


def build(db: Session, settings: Settings, case: InvestigationCase, rule: DetectionRule, e: AuditEvent, names: dict) -> dict:
    account = names.get((e.provider, e.scope_external_id), e.scope_external_id)
    prefix = getattr(settings, "soc_alert_subject_prefix", None) or "LV NEXUS SOC ALERT"
    title = {"RULE_VIOLATION": "Security Rule Violation Detected", "SUSPICIOUS": "Suspicious Cloud Activity Detected"}.get(
        rule.action, "Cloud Activity Needs Review")
    subject = f"[{prefix}] [{rule.severity.upper()}] {title} – {PROVIDER.get(e.provider, e.provider)} – {account}"[:255]
    link = f"{settings.frontend_url.rstrip('/')}/audit/cases?case={case.id}"
    email = re.search(r"[\w.+-]+@([\w-]+\.)+[\w-]+", e.principal or "")
    fields = [("Incident ID", incident_id(case)), ("Incident title", case.title), ("Severity", rule.severity),
              ("Confidence", case.confidence or confidence_for(rule)), ("Status", "Detected – pending analyst review"),
              ("Cloud provider", PROVIDER.get(e.provider, e.provider)), ("Account / subscription / project", f"{account} ({e.scope_external_id})"),
              ("Affected identity", e.principal or "unknown"), ("Identity e-mail", email.group(0) if email else "not available"),
              ("Source IP", e.source_ip or "not available"), ("Event time", f"{e.event_timestamp:%Y-%m-%d %H:%M:%S} UTC"),
              ("Activity", f"{e.event_name}" + (f" on {e.resource_id}" if e.resource_id else "")),
              ("Detection rule", f"{rule.rule_key} – {rule.name}"),
              ("MITRE ATT&CK", ", ".join(f"{m['id']} {m['name']}" for m in (rule.mitre or [])) or "–"),
              ("Events in this incident", str(len(case.event_ids or [])))]
    why = case.risk_assessment or rule.description or ""
    steps = rule.investigation_steps or "Review the raw events and confirm with the identity owner."
    fix = rule.remediation or "Revert the change if it was not approved."
    text = "\n".join([f"{title} ({rule.severity})", "", *(f"{k}: {v}" for k, v in fields), "", "Why it was flagged:", why, "",
                      "Recommended investigation:", steps, "", "Recommended remediation:", fix, "",
                      f"Incident details: {link}", "",
                      "The original audit events are attached as CSV. LV NEXUS is read-only: nothing was changed in the cloud. "
                      "This alert is a detection, not a confirmed incident."])
    e_ = html.escape
    rows = "".join(f'<tr><td style="padding:6px 10px;color:#667085;white-space:nowrap;vertical-align:top">{e_(k)}</td>'
                   f'<td style="padding:6px 10px;color:#101828">{e_(v)}</td></tr>' for k, v in fields)
    tone = {"Critical": "#b42318", "High": "#c4320a", "Medium": "#b54708"}.get(rule.severity, "#475467")
    page = (f'<div style="font-family:Segoe UI,Arial,sans-serif;max-width:760px;margin:auto;background:#f6f8fb;padding:16px">'
            f'<div style="background:#0b1b3f;color:#fff;padding:14px 18px;border-radius:10px 10px 0 0">'
            f'<div style="font-size:11px;letter-spacing:.12em;opacity:.8">LATENTVIEW · LV NEXUS SOC</div>'
            f'<div style="font-size:18px;font-weight:600;margin-top:4px">{e_(title)}</div></div>'
            f'<div style="background:#fff;padding:16px 18px;border-radius:0 0 10px 10px">'
            f'<span style="display:inline-block;background:{tone};color:#fff;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600">'
            f'{e_(rule.severity)}</span> <span style="font-size:12px;color:#475467">{e_(incident_id(case))} · detection pending analyst review</span>'
            f'<table style="border-collapse:collapse;width:100%;margin-top:12px;font-size:13px">{rows}</table>'
            f'<h3 style="font-size:14px;margin:16px 0 6px">Why it was flagged</h3><p style="font-size:13px;color:#344054;margin:0">{e_(why)}</p>'
            f'<h3 style="font-size:14px;margin:16px 0 6px">Recommended investigation</h3><p style="font-size:13px;color:#344054;margin:0">{e_(steps)}</p>'
            f'<h3 style="font-size:14px;margin:16px 0 6px">Recommended remediation</h3><p style="font-size:13px;color:#344054;margin:0">{e_(fix)}</p>'
            f'<p style="margin:18px 0 6px"><a href="{e_(link)}" style="background:#1d4ed8;color:#fff;text-decoration:none;padding:8px 14px;border-radius:8px;font-size:13px">Open the incident</a></p>'
            f'<p style="font-size:11px;color:#98a2b3;margin-top:14px">Original audit events attached as CSV. LV NEXUS is read-only and has not changed anything in the cloud. '
            f'A detection is not a confirmed incident until an analyst records the outcome.</p></div></div>')
    return {"subject": subject, "text": text, "html": page, "recipients": recipients(settings, rule, e),
            "attachment": {"filename": f"{incident_id(case)}-raw-events.csv", "content_type": "text/csv",
                           "text": evidence_csv(db, case, rule, names)}}
