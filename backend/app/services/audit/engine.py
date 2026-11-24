"""Rule evaluation of collected audit events, investigation cases, correlation, and the investigation workflow.

Every audit event is evaluated once. NORMAL and AUTHORIZED events are retained with their classification and never
open a case or send an alert. Only RULE_VIOLATION, SUSPICIOUS and REVIEW_REQUIRED events get an investigation status;
cases are opened for violations and threshold-based suspicious activity. Nothing here labels an activity malicious:
a person decides the outcome. AI and correlation output is a recommendation (PROPOSED) until an analyst validates it.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import (
    AuditClass,
    AuditEvent,
    AuditInvestigation,
    AuditNote,
    AuditStatus,
    AuditStatusHistory,
    AuthorizationRule,
    CloudSecurityFinding,
    DetectionRule,
    InvestigationCase,
    JobStatus,
    User,
)
from app.models.vuln import FLAGGED
from app.scheduler.engine import JobContext, JobResult
from app.services.vuln.lifecycle import WorkflowError
from app.services.vuln.notify import notify

from .rules import EventView, evaluate, in_change_window

RANK = {"RULE_VIOLATION": 3, "SUSPICIOUS": 2, "REVIEW_REQUIRED": 1}
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0}
BATCH = 5000


def _utc(dt):
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _scope_names(db: Session) -> dict:
    from app.services.notifications.governance import scope_names
    return scope_names(db)


def _group_value(rule: DetectionRule, e: AuditEvent) -> str:
    return {"principal": e.principal, "source_ip": e.source_ip, "resource_id": e.resource_id, "scope": e.scope_external_id}.get(rule.group_by) or "-"


def _group_column(rule: DetectionRule):
    return {"principal": AuditEvent.principal, "source_ip": AuditEvent.source_ip, "resource_id": AuditEvent.resource_id,
            "scope": AuditEvent.scope_external_id}.get(rule.group_by, AuditEvent.principal)


def _new_operation_lookup(db: Session):
    def lookup(e: AuditEvent) -> bool:
        since = _utc(e.event_timestamp) - timedelta(days=30)
        return db.scalar(select(AuditEvent.id).where(AuditEvent.principal == e.principal, AuditEvent.event_name == e.event_name,
                                                     AuditEvent.id != e.id, AuditEvent.event_timestamp >= since,
                                                     AuditEvent.event_timestamp < e.event_timestamp).limit(1)) is None
    return lookup


def _authorized_by_rule(rules: list[AuthorizationRule], e: AuditEvent) -> AuthorizationRule | None:
    ts = _utc(e.event_timestamp)
    for r in rules:
        if (r.enabled and (r.actor or "").lower() == (e.principal or "").lower() and (r.operation or "").lower() == (e.event_name or "").lower()
                and (not r.provider or r.provider == e.provider) and (not r.scope_external_id or r.scope_external_id == e.scope_external_id)
                and (not r.resource_prefix or (e.resource_id or "").startswith(r.resource_prefix))
                and _utc(r.valid_from) <= ts <= _utc(r.valid_until)):
            return r
    return None


def match_rule(db: Session, rule: DetectionRule, ev: EventView, lookup=None) -> str | None:
    """Explanation string when the rule fires for this event, else None."""
    if rule.provider and rule.provider != ev.get("provider"):
        return None
    if not evaluate(rule.conditions, ev):
        return None
    if rule.exclusions and evaluate({"any": rule.exclusions}, ev):
        return None  # provider-managed identity or an approved exclusion
    if rule.change_window and in_change_window(rule.change_window, ev.ts):
        return None
    why = f"{rule.rule_key} {rule.name}: {ev.get('operation')} by {ev.get('actor') or 'unknown actor'}"
    if rule.change_window:
        why += " outside the approved change window"
    if (rule.threshold_count or 1) > 1:
        start = ev.ts - timedelta(minutes=rule.threshold_window_minutes or 60)
        col = _group_column(rule)
        group = _group_value(rule, ev.e)
        q = select(AuditEvent).where(col == group, AuditEvent.event_timestamp >= start, AuditEvent.event_timestamp <= ev.e.event_timestamp)
        if rule.provider:
            q = q.where(AuditEvent.provider == rule.provider)
        def counts(other) -> bool:
            v = EventView(other, lookup)
            return evaluate(rule.conditions, v) and not (rule.exclusions and evaluate({"any": rule.exclusions}, v))
        hits = sum(1 for other in db.scalars(q.limit(1000)) if counts(other))
        if hits < rule.threshold_count:
            return None
        why += f" ({hits} matching events by the same {rule.group_by} within {rule.threshold_window_minutes} min; threshold {rule.threshold_count})"
    return why


def classify_event(db: Session, e: AuditEvent, rules: list[DetectionRule], auth_rules: list[AuthorizationRule], lookup=None) -> dict:
    ev = EventView(e, lookup)
    matched = []
    for r in rules:
        why = match_rule(db, r, ev, lookup)
        if why:
            matched.append({"id": r.id, "rule_key": r.rule_key, "name": r.name, "severity": r.severity, "action": r.action,
                            "create_case": r.create_case, "notify": r.notify, "explanation": why})
    auth = _authorized_by_rule(auth_rules, e)
    if auth:
        cls = AuditClass.AUTHORIZED.value
    elif matched:
        cls = max(matched, key=lambda m: RANK.get(m["action"], 0))["action"]
    else:
        cls = AuditClass.NORMAL.value
    top = max(matched, key=lambda m: SEV_RANK.get(m["severity"], 0)) if matched else None
    return {"classification": cls, "category": ev.get("category"), "matched": matched, "severity": top["severity"] if top else None,
            "explanation": (f"Covered by authorization rule #{auth.id} ({auth.approval_reference})" + (f"; also matched {', '.join(m['rule_key'] for m in matched)}" if matched else ""))
            if auth else ("; ".join(m["explanation"] for m in matched) or None), "auth": auth}


def _case_for(db: Session, s: Settings, rule_match: dict, e: AuditEvent, rule: DetectionRule) -> tuple[InvestigationCase, bool]:
    group = _group_value(rule, e)
    since = _utc(e.event_timestamp) - timedelta(hours=s.audit_case_group_hours)
    case = db.scalar(select(InvestigationCase).where(
        InvestigationCase.rule_id == rule.id, InvestigationCase.actor == group,
        InvestigationCase.status.not_in(["CLOSED", "NO_ACTION_REQUIRED", "AUTHORIZED", "DISMISSED"]),
        InvestigationCase.last_event_at >= since).order_by(InvestigationCase.id.desc()))
    created = case is None
    if created:
        from .soc_alert import confidence_for
        case = InvestigationCase(title=f"{rule.rule_key} {rule.name}"[:512], status=AuditStatus.DETECTED.value, origin="detection_rule", rule_id=rule.id,
                                 correlation_key=f"r{rule.id}:{hashlib.sha256(group.encode()).hexdigest()[:16]}:{e.id}", correlation_type=rule.group_by,
                                 actor=group, provider=e.provider, scope_external_id=e.scope_external_id, risk=rule.severity,
                                 risk_assessment=rule_match["explanation"], event_ids=[], resources=[], finding_ids=[], first_event_at=e.event_timestamp,
                                 disposition="suspicious", confidence=confidence_for(rule))
        db.add(case)
        db.flush()
    case.event_ids = sorted({*(case.event_ids or []), e.id})
    if e.resource_id:
        case.resources = sorted({*(case.resources or []), e.resource_id})[:200]
        fids = db.scalars(select(CloudSecurityFinding.id).where(CloudSecurityFinding.resource_id == e.resource_id).limit(20)).all()
        case.finding_ids = sorted({*(case.finding_ids or []), *fids})
    case.last_event_at = e.event_timestamp
    if SEV_RANK.get(rule.severity, 0) > SEV_RANK.get(case.risk, 0):
        case.risk = rule.severity
    return case, created


def run_audit_evaluation(ctx: JobContext, s: Settings, limit: int = BATCH) -> JobResult:
    db = ctx.db
    rules = list(db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True)).order_by(DetectionRule.id)))
    by_id = {r.id: r for r in rules}
    now = datetime.now(UTC)
    auth_rules = list(db.scalars(select(AuthorizationRule).where(AuthorizationRule.enabled.is_(True), AuthorizationRule.valid_until >= now - timedelta(days=90))))
    pending = list(db.scalars(select(AuditEvent).outerjoin(AuditInvestigation, AuditInvestigation.audit_event_id == AuditEvent.id)
                              .where(AuditInvestigation.id.is_(None)).order_by(AuditEvent.event_timestamp, AuditEvent.id).limit(limit)))
    lookup = _new_operation_lookup(db)
    counts: dict = defaultdict(int)
    new_cases: list[InvestigationCase] = []
    names: dict | None = None
    for e in pending:
        r = classify_event(db, e, rules, auth_rules, lookup)
        for m in r["matched"]:
            rule = by_id.get(m["id"])
            if rule is not None:
                rule.match_count = (rule.match_count or 0) + 1
                if rule.last_triggered_at is None or _utc(rule.last_triggered_at) < _utc(e.event_timestamp):
                    rule.last_triggered_at = e.event_timestamp
        cls = r["classification"]
        counts[cls] += 1
        inv = AuditInvestigation(audit_event_id=e.id, classification=cls, category=r["category"], matched_rules=[{k: v for k, v in m.items()} for m in r["matched"]],
                                 severity=r["severity"], explanation=r["explanation"], evaluated_at=now)
        if r["auth"]:
            a = r["auth"]
            inv.authorized_by, inv.authorization_reason, inv.authorization_reference = a.approved_by, a.reason, a.approval_reference
            inv.authorized_until, inv.authorization_rule_id = a.valid_until, a.id
        db.add(inv)
        db.flush()
        if cls in FLAGGED:
            inv.status, inv.detected_at = AuditStatus.DETECTED.value, now
            db.add(AuditStatusHistory(audit_event_id=e.id, previous_status=None, new_status=AuditStatus.DETECTED.value, actor="rule-engine",
                                      reason=r["explanation"], details={"rules": [m["rule_key"] for m in r["matched"]]}))
            if cls != AuditClass.REVIEW_REQUIRED.value:
                for m in r["matched"]:
                    rule = by_id.get(m["id"])
                    if rule and rule.create_case and m["action"] == cls:
                        case, created = _case_for(db, s, m, e, rule)
                        inv.case_id = case.id
                        if created:
                            new_cases.append(case)
                            counts["cases_opened"] += 1
                        if created:
                            from .soc_alert import summarize
                            names = names if names is not None else _scope_names(db)
                            case.summary = summarize(case, rule, e, names.get((e.provider, e.scope_external_id), e.scope_external_id))
                        if rule.notify and rule.severity in ("Critical", "High") and case.notified_at is None:
                            from .soc_alert import build
                            names = names if names is not None else _scope_names(db)
                            db.flush()
                            a = build(db, s, case, rule, e, names)
                            kind = "audit_rule_violation" if cls == AuditClass.RULE_VIOLATION.value else "audit_suspicious"
                            chat = (f"{a['subject']}\n{case.summary or m['explanation']}\n{s.frontend_url.rstrip('/')}/audit/cases?case={case.id}")
                            if notify(db, kind, f"case{case.id}", a["subject"], a["text"], html=a["html"], recipients=a["recipients"] or None,
                                      attachments=[a["attachment"]], chat_body=chat):
                                case.notified_at = now
                        break
    db.commit()
    counts["proposed_correlations"] = correlate(db, s)
    db.commit()
    return JobResult(JobStatus.SUCCESS, scopes_total=len(pending), summary={"evaluated": len(pending), "rules_enabled": len(rules), **counts,
                                                                           "backlog_remaining": len(pending) == limit})


def correlate(db: Session, s: Settings) -> int:
    """Group flagged events of DIFFERENT rules by the same actor, source IP or resource inside the window into a
    PROPOSED case. A proposal is a recommendation; an analyst validates (opens) or dismisses it."""
    since = datetime.now(UTC) - timedelta(hours=s.audit_case_group_hours)
    rows = db.execute(select(AuditInvestigation, AuditEvent).join(AuditEvent, AuditEvent.id == AuditInvestigation.audit_event_id)
                      .where(AuditInvestigation.classification.in_(list(FLAGGED)), AuditEvent.event_timestamp >= since)).all()
    created = 0
    for kind, attr in (("actor", "principal"), ("ip", "source_ip"), ("resource", "resource_id")):
        groups: dict[str, list] = defaultdict(list)
        for inv, ev in rows:
            if getattr(ev, attr):
                groups[getattr(ev, attr)].append((inv, ev))
        for value, items in groups.items():
            rule_keys = {m.get("rule_key") for inv, _ in items for m in inv.matched_rules or []}
            if len(rule_keys) < 2:
                continue
            ids = sorted(ev.id for _, ev in items)
            key = f"corr:{kind}:{hashlib.sha256(value.encode()).hexdigest()[:16]}:{ids[0]}"
            existing = db.scalar(select(InvestigationCase).where(InvestigationCase.correlation_key == key))
            if existing:
                existing.event_ids = sorted({*(existing.event_ids or []), *ids})
                continue
            evs = [ev for _, ev in items]
            db.add(InvestigationCase(title=f"Possible related activity by {kind} {value[:120]}: {', '.join(sorted(k for k in rule_keys if k))}"[:512],
                                     status="PROPOSED", origin="correlation", correlation_key=key, correlation_type=kind, actor=value[:512],
                                     provider=evs[0].provider, scope_external_id=evs[0].scope_external_id,
                                     risk=max((m.get("severity") for inv, _ in items for m in inv.matched_rules or []), key=lambda x: SEV_RANK.get(x, 0), default="Medium"),
                                     risk_assessment=f"{len(ids)} flagged events matching {len(rule_keys)} different rules within {s.audit_case_group_hours} h. "
                                                     "Correlation is a recommendation until an analyst validates it.",
                                     event_ids=ids, resources=sorted({ev.resource_id for ev in evs if ev.resource_id})[:200], finding_ids=[],
                                     first_event_at=min(ev.event_timestamp for ev in evs), last_event_at=max(ev.event_timestamp for ev in evs)))
            created += 1
    return created


# ------------------------------------------------------------------------------------------------- workflow
A = AuditStatus
TRANSITIONS = {
    A.DETECTED: {A.REVIEWING, A.INVESTIGATING, A.AUTHORIZED, A.ESCALATED, A.NO_ACTION_REQUIRED},
    A.REVIEWING: {A.INVESTIGATING, A.AUTHORIZED, A.ESCALATED, A.NO_ACTION_REQUIRED, A.CLOSED},
    A.INVESTIGATING: {A.ESCALATED, A.AUTHORIZED, A.NO_ACTION_REQUIRED, A.CLOSED},
    A.ESCALATED: {A.INVESTIGATING, A.AUTHORIZED, A.NO_ACTION_REQUIRED, A.CLOSED},
    A.AUTHORIZED: {A.CLOSED, A.REOPENED},
    A.NO_ACTION_REQUIRED: {A.CLOSED, A.REOPENED},
    A.CLOSED: {A.REOPENED},
    A.REOPENED: {A.REVIEWING, A.INVESTIGATING, A.ESCALATED, A.AUTHORIZED, A.NO_ACTION_REQUIRED, A.CLOSED},
}
ESCALATION_TARGETS = ("Cloud Security", "Cloud Governance", "CISO")


def _check(cur: str | None, new: str, user: User, data: dict) -> None:
    new_s = AuditStatus(new)
    if cur is None:
        raise WorkflowError("Only flagged activities have an investigation. Use 'Flag for review' first if this activity needs one.")
    if new_s not in TRANSITIONS[AuditStatus(cur)]:
        raise WorkflowError(f"Cannot move from {cur} to {new}")
    if new_s == A.AUTHORIZED:
        if "audit:authorize" not in user.permission_names:
            raise WorkflowError("Authorizing an activity needs the audit:authorize permission")
        if not (data.get("reason") or "").strip() or not (data.get("approval_reference") or "").strip():
            raise WorkflowError("Authorization needs a reason and an approval reference")
    if new_s in (A.CLOSED, A.NO_ACTION_REQUIRED, A.REOPENED) and not (data.get("reason") or "").strip():
        raise WorkflowError(f"A reason is required for {new}")
    if new_s == A.ESCALATED and data.get("escalated_to") not in ESCALATION_TARGETS:
        raise WorkflowError(f"Escalate to one of: {', '.join(ESCALATION_TARGETS)}")


def transition_event(db: Session, inv: AuditInvestigation, new: str, user: User, data: dict) -> None:
    _check(inv.status, new, user, data)
    details = {k: data.get(k) for k in ("approval_reference", "change_ticket", "valid_until", "escalated_to") if data.get(k)}
    db.add(AuditStatusHistory(audit_event_id=inv.audit_event_id, previous_status=inv.status, new_status=new, actor=user.email,
                              reason=data.get("reason"), details=details))
    inv.status = new
    if new == A.AUTHORIZED:  # applies to this event only; future events need an approved authorization rule
        inv.authorized_by, inv.authorization_reason = user.email, data["reason"]
        inv.authorization_reference, inv.change_ticket = data["approval_reference"], data.get("change_ticket")
        inv.authorized_until = _utc(datetime.fromisoformat(data["valid_until"])) if data.get("valid_until") else None
    if new in (A.CLOSED, A.NO_ACTION_REQUIRED):
        inv.closure_reason = data["reason"]
    if new == A.ESCALATED:
        inv.escalated_to = data["escalated_to"]


def flag_for_review(db: Session, inv: AuditInvestigation, user: User, reason: str) -> None:
    """'Mark as suspicious' on an activity the rules did not flag: puts it in the queue without declaring an incident."""
    if inv.status is not None:
        raise WorkflowError("This activity is already in the investigation workflow")
    if not reason.strip():
        raise WorkflowError("A reason is required")
    db.add(AuditStatusHistory(audit_event_id=inv.audit_event_id, previous_status=None, new_status=A.DETECTED.value, actor=user.email,
                              reason=f"Flagged manually: {reason}", details={"previous_classification": inv.classification}))
    inv.classification, inv.status, inv.detected_at = AuditClass.SUSPICIOUS.value, A.DETECTED.value, datetime.now(UTC)
    inv.explanation = f"Flagged manually by {user.email}: {reason}"


def transition_case(db: Session, case: InvestigationCase, new: str, user: User, data: dict) -> None:
    if case.status == "PROPOSED":
        if new not in ("DETECTED", "DISMISSED"):
            raise WorkflowError("A proposed correlation must first be validated (DETECTED) or dismissed")
        if new == "DISMISSED" and not (data.get("reason") or "").strip():
            raise WorkflowError("A reason is required to dismiss a proposal")
        case.validated_by = user.email
    else:
        _check(case.status, new, user, data)
    db.add(AuditNote(subject_type="case", subject_id=case.id, author=user.email,
                     body=f"Status {case.status} -> {new}" + (f": {data['reason']}" if data.get("reason") else "")))
    case.status = new
    if new in ("CLOSED", "NO_ACTION_REQUIRED", "DISMISSED", "AUTHORIZED"):
        case.closure_reason, case.outcome = data.get("reason"), data.get("outcome") or data.get("reason")


def related_events(db: Session, e: AuditEvent, hours: int = 24, limit: int = 50) -> list[AuditEvent]:
    t = _utc(e.event_timestamp)
    conds = [c for c in (AuditEvent.principal == e.principal if e.principal else None,
                         AuditEvent.resource_id == e.resource_id if e.resource_id else None,
                         AuditEvent.source_ip == e.source_ip if e.source_ip else None) if c is not None]
    if not conds:
        return []
    from sqlalchemy import or_
    return list(db.scalars(select(AuditEvent).where(or_(*conds), AuditEvent.id != e.id,
                                                    and_(AuditEvent.event_timestamp >= t - timedelta(hours=hours), AuditEvent.event_timestamp <= t + timedelta(hours=hours)))
                           .order_by(AuditEvent.event_timestamp).limit(limit)))
