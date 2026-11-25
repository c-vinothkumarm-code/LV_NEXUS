"""Cloud audit operations API: activity repository, rule-based classification, investigations, cases and rules."""
from __future__ import annotations

from collections import Counter
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, object_session

from app.api.deps import log_action, require_any
from app.api.serializers import scope_label
from app.core.config import Settings, get_settings
from app.core.security import require
from app.database.session import get_db
from app.models import (
    AuditEvent,
    AuditInvestigation,
    AuditNote,
    AuditStatusHistory,
    AuthorizationRule,
    DetectionRule,
    DetectionRuleHistory,
    InvestigationCase,
    SecurityEvidence,
    User,
)
from app.models.vuln import DISPOSITIONS
from app.services.audit import engine as eng
from app.services.audit.rules import EventView, validate
from app.services.vuln.defaults import rule_snapshot
from app.services.vuln.lifecycle import WorkflowError, add_evidence

router = APIRouter(prefix="/api/v1/audit", tags=["cloud audit operations"])
E, Inv = AuditEvent, AuditInvestigation
OPEN_STATUSES = ["DETECTED", "REVIEWING", "INVESTIGATING", "ESCALATED", "REOPENED"]
VIEWS = {  # named queues used by the UI sub-sections
    "queue": lambda q: q.where(Inv.status.in_(OPEN_STATUSES)),
    "authorized": lambda q: q.where(or_(Inv.classification == "AUTHORIZED", Inv.status == "AUTHORIZED")),
    "suspicious": lambda q: q.where(Inv.classification.in_(["SUSPICIOUS", "RULE_VIOLATION"])),
    "closed": lambda q: q.where(Inv.status.in_(["CLOSED", "NO_ACTION_REQUIRED"])),
    "review": lambda q: q.where(Inv.classification == "REVIEW_REQUIRED"),
    "normal": lambda q: q.where(Inv.classification == "NORMAL"),
    "unevaluated": lambda q: q.where(Inv.id.is_(None)),
}


def _err(exc: Exception):
    raise HTTPException(409, str(exc))


def edict(e: AuditEvent, i: AuditInvestigation | None, full: bool = False) -> dict:
    raw = e.raw or {}
    d = {"id": e.id, "event_id": e.event_id, "provider": e.provider, "scope": e.scope_external_id, "scope_name": scope_label(object_session(e), e.provider, e.scope_external_id), "region": e.region, "time": e.event_timestamp,
         "operation": e.event_name, "actor": e.principal, "source_ip": e.source_ip, "resource_id": e.resource_id, "resource_type": e.resource_type,
         "result": raw.get("outcome") or "success", "classification": i.classification if i else "NOT_EVALUATED", "category": i.category if i else None,
         "severity": i.severity if i else None, "status": i.status if i else None, "investigator": i.investigator if i else None,
         "rules": [m.get("rule_key") for m in (i.matched_rules or [])] if i else [], "case_id": i.case_id if i else None,
         "suspicious": bool(i and i.classification in ("SUSPICIOUS", "RULE_VIOLATION"))}
    if full:
        d |= {"user_agent": raw.get("userAgent"), "error_code": raw.get("error_code") or raw.get("errorCode"), "raw": raw,
              "request": raw.get("requestParameters") or raw.get("request") or raw.get("properties"),
              "response": raw.get("responseElements") or raw.get("response"),
              "authentication": raw.get("userIdentity") or raw.get("authenticationInfo") or raw.get("claims"),
              "investigation": None if i is None else {"matched_rules": i.matched_rules, "explanation": i.explanation, "evaluated_at": i.evaluated_at,
                                                       "detected_at": i.detected_at, "authorized_by": i.authorized_by, "authorization_reason": i.authorization_reason,
                                                       "authorization_reference": i.authorization_reference, "change_ticket": i.change_ticket,
                                                       "authorized_until": i.authorized_until, "authorization_rule_id": i.authorization_rule_id,
                                                       "closure_reason": i.closure_reason, "escalated_to": i.escalated_to, "ai_analysis": i.ai_analysis}}
    return d


def _filters(q, provider, scope, region, classification, status, category, actor, ip, operation, text, date_from, date_to, investigator, rule, view):
    for col, val in ((E.provider, provider), (E.scope_external_id, scope), (E.region, region), (Inv.classification, classification),
                     (Inv.status, status), (Inv.category, category), (E.source_ip, ip), (Inv.investigator, investigator)):
        if val:
            q = q.where(col.in_(val.split(",")))
    if actor:
        q = q.where(E.principal.ilike(f"%{actor}%"))
    if operation:
        q = q.where(E.event_name.ilike(f"%{operation}%"))
    if text:
        like = f"%{text}%"
        q = q.where(or_(E.event_name.ilike(like), E.principal.ilike(like), E.resource_id.ilike(like), E.source_ip.ilike(like), E.event_id.ilike(like)))
    if rule:
        q = q.where(Inv.explanation.ilike(f"%{rule}%"))
    if date_from:
        q = q.where(E.event_timestamp >= datetime.combine(date_from, datetime.min.time(), UTC))
    if date_to:
        q = q.where(E.event_timestamp < datetime.combine(date_to + timedelta(days=1), datetime.min.time(), UTC))
    if view in VIEWS:
        q = VIEWS[view](q)
    return q


@router.get("/events")
def list_events(provider: str | None = None, scope: str | None = None, region: str | None = None, classification: str | None = None,
                status: str | None = None, category: str | None = None, actor: str | None = None, ip: str | None = None, operation: str | None = None,
                q: str | None = None, date_from: date | None = None, date_to: date | None = None, investigator: str | None = None,
                rule: str | None = None, view: str | None = None, sort: str = "time", order: str = "desc",
                page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=500), db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    base = select(E, Inv).outerjoin(Inv, Inv.audit_event_id == E.id)
    base = _filters(base, provider, scope, region, classification, status, category, actor, ip, operation, q, date_from, date_to, investigator, rule, view)
    total = db.scalar(select(func.count()).select_from(base.subquery()))
    col = {"time": E.event_timestamp, "actor": E.principal, "operation": E.event_name, "provider": E.provider, "severity": Inv.severity}.get(sort, E.event_timestamp)
    rows = db.execute(base.order_by(col.desc() if order == "desc" else col.asc(), E.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [edict(e, i) for e, i in rows]}


def _get(db: Session, eid: int) -> tuple[AuditEvent, AuditInvestigation | None]:
    e = db.get(E, eid)
    if e is None:
        raise HTTPException(404, "Audit event not found")
    return e, db.scalar(select(Inv).where(Inv.audit_event_id == eid))


@router.get("/events/{eid}")
def event_detail(eid: int, db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    e, i = _get(db, eid)
    rel = eng.related_events(db, e)
    invs = {x.audit_event_id: x for x in db.scalars(select(Inv).where(Inv.audit_event_id.in_([r.id for r in rel] or [-1])))}
    case = db.get(InvestigationCase, i.case_id) if i and i.case_id else None
    return {"event": edict(e, i, full=True),
            "history": [{"from": h.previous_status, "to": h.new_status, "actor": h.actor, "reason": h.reason, "details": h.details, "at": h.created_at}
                        for h in db.scalars(select(AuditStatusHistory).where(AuditStatusHistory.audit_event_id == eid).order_by(AuditStatusHistory.id))],
            "notes": [{"author": n.author, "body": n.body, "at": n.created_at} for n in db.scalars(
                select(AuditNote).where(AuditNote.subject_type == "audit_event", AuditNote.subject_id == eid).order_by(AuditNote.id))],
            "evidence": [_ev(x) for x in db.scalars(select(SecurityEvidence).where(SecurityEvidence.subject_type == "audit_event", SecurityEvidence.subject_id == eid))],
            "related": [edict(r, invs.get(r.id)) for r in rel],
            "case": None if case is None else {"id": case.id, "title": case.title, "status": case.status, "risk": case.risk}}


def _ev(x: SecurityEvidence) -> dict:
    return {"id": x.id, "kind": x.kind, "name": x.name, "reference": x.reference if x.kind != "file" else None, "sha256": x.sha256,
            "note": x.note, "uploaded_by": x.uploaded_by, "at": x.created_at}


class TransitionIn(BaseModel):
    status: str
    reason: str | None = Field(default=None, max_length=5000)
    approval_reference: str | None = Field(default=None, max_length=255)
    change_ticket: str | None = Field(default=None, max_length=255)
    valid_until: str | None = None
    escalated_to: str | None = None


@router.post("/events/{eid}/status")
def event_status(eid: int, body: TransitionIn, db: Session = Depends(get_db), user: User = Depends(require("audit:investigate"))):
    e, i = _get(db, eid)
    if i is None:
        raise HTTPException(409, "This activity has not been evaluated yet")
    try:
        eng.transition_event(db, i, body.status, user, body.model_dump())
    except (WorkflowError, ValueError) as exc:
        _err(exc)
    log_action(db, user.email, "audit_event.status", str(eid), {"to": body.status})
    db.commit()
    return edict(e, i)


class ReasonIn(BaseModel):
    reason: str = Field(min_length=3, max_length=5000)


@router.post("/events/{eid}/flag")
def flag(eid: int, body: ReasonIn, db: Session = Depends(get_db), user: User = Depends(require("audit:investigate"))):
    e, i = _get(db, eid)
    if i is None:
        raise HTTPException(409, "This activity has not been evaluated yet")
    try:
        eng.flag_for_review(db, i, user, body.reason)
    except WorkflowError as exc:
        _err(exc)
    db.commit()
    return edict(e, i)


class AssignIn(BaseModel):
    investigator: str | None = Field(default=None, max_length=255)


@router.post("/events/{eid}/assign")
def assign(eid: int, body: AssignIn, db: Session = Depends(get_db), user: User = Depends(require("audit:investigate"))):
    e, i = _get(db, eid)
    if i is None or i.status is None:
        raise HTTPException(409, "Only flagged activities have an investigator")
    db.add(AuditStatusHistory(audit_event_id=eid, previous_status=i.status, new_status=i.status, actor=user.email,
                              reason=f"Investigator {i.investigator or '-'} -> {body.investigator or '-'}", details={"investigator": body.investigator}))
    i.investigator = body.investigator
    db.commit()
    return edict(e, i)


class NoteIn(BaseModel):
    body: str = Field(min_length=1, max_length=20000)


@router.post("/events/{eid}/notes", status_code=201)
def note(eid: int, body: NoteIn, db: Session = Depends(get_db), user: User = Depends(require("audit:investigate"))):
    _get(db, eid)
    db.add(AuditNote(subject_type="audit_event", subject_id=eid, author=user.email, body=body.body))
    db.commit()
    return {"ok": True}


class EvidenceIn(BaseModel):
    kind: str
    name: str = Field(max_length=255)
    reference: str | None = None
    content_base64: str | None = None
    content_type: str | None = None
    note: str | None = None


@router.post("/events/{eid}/evidence", status_code=201)
def evidence(eid: int, body: EvidenceIn, db: Session = Depends(get_db), s: Settings = Depends(get_settings), user: User = Depends(require("audit:investigate"))):
    _get(db, eid)
    try:
        ev = add_evidence(db, s, "audit_event", eid, body.model_dump(), user)
    except WorkflowError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return _ev(ev)


@router.post("/events/{eid}/ai")
def ai_event(eid: int, db: Session = Depends(get_db), s: Settings = Depends(get_settings), user: User = Depends(require("audit:investigate"))):
    from app.services.ai.provider import build_provider
    from app.services.vuln.ai import analyse_audit
    provider = build_provider(s)
    if provider is None:
        raise HTTPException(409, "AI analysis is not configured (AI_PROVIDER and key)")
    e, i = _get(db, eid)
    try:
        result = analyse_audit(provider, e, i, eng.related_events(db, e))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"AI analysis failed: {str(exc)[:200]}") from exc
    if i is not None:
        i.ai_analysis = result
    db.add(AuditNote(subject_type="audit_event", subject_id=eid, author=user.email, body="Advisory AI analysis generated (no status changed)."))
    db.commit()
    return result


@router.get("/overview")
def overview(provider: str | None = None, days: int = Query(30, ge=1, le=365), db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    since = datetime.now(UTC) - timedelta(days=days)
    q = select(E, Inv).outerjoin(Inv, Inv.audit_event_id == E.id).where(E.event_timestamp >= since)
    if provider:
        q = q.where(E.provider == provider)
    rows = db.execute(q).all()
    cls, st, cat, prov, rules, trend = Counter(), Counter(), Counter(), Counter(), Counter(), {}
    for e, i in rows:
        c = i.classification if i else "NOT_EVALUATED"
        cls[c] += 1
        prov[e.provider] += 1
        if i:
            cat[i.category] += 1
            if i.status:
                st[i.status] += 1
            for m in i.matched_rules or []:
                rules[f"{m.get('rule_key')} {m.get('name')}"] += 1
        d = e.event_timestamp.date().isoformat()
        trend.setdefault(d, Counter())[c] += 1
    cases = Counter(dict(db.execute(select(InvestigationCase.status, func.count()).group_by(InvestigationCase.status)).all()))
    return {"window_days": days, "total": len(rows), "classification": dict(cls), "status": dict(st), "by_category": cat.most_common(15),
            "by_provider": dict(prov), "top_rules": rules.most_common(10), "cases": dict(cases),
            "trend": [{"date": d, **dict(c)} for d, c in sorted(trend.items())], "generated_at": datetime.now(UTC)}


# ------------------------------------------------------------------------------------------------ cases
def cdict(c: InvestigationCase) -> dict:
    return {"id": c.id, "title": c.title, "status": c.status, "origin": c.origin, "rule_id": c.rule_id, "correlation_type": c.correlation_type,
            "actor": c.actor, "provider": c.provider, "scope": c.scope_external_id, "scope_name": scope_label(object_session(c), c.provider, c.scope_external_id), "risk": c.risk, "risk_assessment": c.risk_assessment, "owner": c.owner,
            "outcome": c.outcome, "closure_reason": c.closure_reason, "validated_by": c.validated_by, "event_ids": c.event_ids, "resources": c.resources,
            "finding_ids": c.finding_ids, "first_event_at": c.first_event_at, "last_event_at": c.last_event_at, "created_at": c.created_at,
            "incident_id": f"INC-{c.id:06d}", "disposition": c.disposition, "disposition_label": DISPOSITIONS.get(c.disposition or "", None),
            "confidence": c.confidence, "summary": c.summary, "notified_at": c.notified_at}


@router.get("/cases")
def cases(status: str | None = None, page: int = Query(1, ge=1), page_size: int = Query(50, le=200), db: Session = Depends(get_db),
          _: User = Depends(require("audit:read"))):
    q = select(InvestigationCase)
    if status:
        q = q.where(InvestigationCase.status.in_(status.split(",")))
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    return {"total": total, "items": [cdict(c) for c in db.scalars(q.order_by(InvestigationCase.id.desc()).offset((page - 1) * page_size).limit(page_size))]}


@router.get("/cases/{cid}")
def case_detail(cid: int, db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    c = db.get(InvestigationCase, cid)
    if c is None:
        raise HTTPException(404, "Case not found")
    evs = db.execute(select(E, Inv).outerjoin(Inv, Inv.audit_event_id == E.id).where(E.id.in_(c.event_ids or [-1])).order_by(E.event_timestamp)).all()
    return {"case": cdict(c), "timeline": [edict(e, i) for e, i in evs],
            "notes": [{"author": n.author, "body": n.body, "at": n.created_at} for n in db.scalars(
                select(AuditNote).where(AuditNote.subject_type == "case", AuditNote.subject_id == cid).order_by(AuditNote.id))],
            "evidence": [_ev(x) for x in db.scalars(select(SecurityEvidence).where(SecurityEvidence.subject_type == "case", SecurityEvidence.subject_id == cid))]}


class CaseIn(TransitionIn):
    outcome: str | None = None


@router.post("/cases/{cid}/status")
def case_status(cid: int, body: CaseIn, db: Session = Depends(get_db), user: User = Depends(require("audit:investigate"))):
    c = db.get(InvestigationCase, cid)
    if c is None:
        raise HTTPException(404, "Case not found")
    try:
        eng.transition_case(db, c, body.status, user, body.model_dump())
    except (WorkflowError, ValueError) as exc:
        _err(exc)
    log_action(db, user.email, "case.status", str(cid), {"to": body.status})
    db.commit()
    return cdict(c)


class DispositionIn(BaseModel):
    disposition: str
    notes: str = Field(min_length=3, max_length=4000)


@router.post("/cases/{cid}/disposition")
def case_disposition(cid: int, body: DispositionIn, db: Session = Depends(get_db), user: User = Depends(require("audit:investigate"))):
    """Analyst conclusion (suspicious / confirmed malicious / legitimate / approved / false positive / insufficient evidence).
    Separate from the workflow status; every change is recorded as a case note with the analyst and the reasoning."""
    c = db.get(InvestigationCase, cid)
    if c is None:
        raise HTTPException(404, "Case not found")
    if body.disposition not in DISPOSITIONS:
        raise HTTPException(422, f"disposition must be one of {', '.join(DISPOSITIONS)}")
    prev = c.disposition
    c.disposition = body.disposition
    db.add(AuditNote(subject_type="case", subject_id=c.id, author=user.email,
                     body=f"Disposition {DISPOSITIONS.get(prev or '', 'not set')} -> {DISPOSITIONS[body.disposition]}: {body.notes}"))
    log_action(db, user.email, "case.disposition", str(cid), {"from": prev, "to": body.disposition})
    db.commit()
    return cdict(c)


@router.get("/cases/{cid}/evidence.csv")
def case_evidence_export(cid: int, db: Session = Depends(get_db), user: User = Depends(require("audit:read"))):
    """The original audit events of an incident (same CSV as the SOC alert attachment). Every download is logged."""
    from fastapi.responses import Response

    from app.services.audit.soc_alert import evidence_csv, incident_id
    from app.services.notifications.governance import scope_names
    c = db.get(InvestigationCase, cid)
    if c is None:
        raise HTTPException(404, "Case not found")
    rule = db.get(DetectionRule, c.rule_id) if c.rule_id else None
    text = evidence_csv(db, c, rule, scope_names(db), limit=5000)
    log_action(db, user.email, "case.evidence_export", str(cid), {"events": len(c.event_ids or [])})
    db.commit()
    return Response(text.encode("utf-8-sig"), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{incident_id(c)}-raw-events.csv"'})


class OwnerIn(BaseModel):
    owner: str | None = Field(default=None, max_length=255)


@router.post("/cases/{cid}/assign")
def case_assign(cid: int, body: OwnerIn, db: Session = Depends(get_db), user: User = Depends(require("audit:investigate"))):
    c = db.get(InvestigationCase, cid)
    if c is None:
        raise HTTPException(404, "Case not found")
    db.add(AuditNote(subject_type="case", subject_id=cid, author=user.email, body=f"Owner {c.owner or '-'} -> {body.owner or '-'}"))
    c.owner = body.owner
    db.commit()
    return cdict(c)


@router.post("/cases/{cid}/notes", status_code=201)
def case_note(cid: int, body: NoteIn, db: Session = Depends(get_db), user: User = Depends(require("audit:investigate"))):
    if db.get(InvestigationCase, cid) is None:
        raise HTTPException(404, "Case not found")
    db.add(AuditNote(subject_type="case", subject_id=cid, author=user.email, body=body.body))
    db.commit()
    return {"ok": True}


@router.post("/cases/{cid}/evidence", status_code=201)
def case_evidence(cid: int, body: EvidenceIn, db: Session = Depends(get_db), s: Settings = Depends(get_settings), user: User = Depends(require("audit:investigate"))):
    if db.get(InvestigationCase, cid) is None:
        raise HTTPException(404, "Case not found")
    try:
        ev = add_evidence(db, s, "case", cid, body.model_dump(), user)
    except WorkflowError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return _ev(ev)


# ------------------------------------------------------------------------------------------------ detection rules
class RuleIn(BaseModel):
    rule_key: str = Field(min_length=2, max_length=64)
    name: str = Field(min_length=3, max_length=255)
    description: str | None = None
    provider: str | None = None
    category: str | None = None
    conditions: dict
    action: str
    severity: str
    threshold_count: int = Field(1, ge=1, le=10000)
    threshold_window_minutes: int = Field(0, ge=0, le=7 * 24 * 60)
    group_by: str = "principal"
    change_window: dict | None = None
    approved_change_reference: str | None = None
    create_case: bool = True
    notify: bool = False
    owner: str | None = None
    enabled: bool = True
    # SOC library metadata: only applied when sent (older clients that omit them keep the stored values)
    soc_category: str | None = None
    mitre: list[str] | None = None
    investigation_steps: str | None = Field(default=None, max_length=4000)
    remediation: str | None = Field(default=None, max_length=4000)
    exclusions: list[dict] | None = None
    data_requirements: list[str] | None = None


_LIBRARY_FIELDS = ("soc_category", "mitre", "investigation_steps", "remediation", "exclusions", "data_requirements")


def _rule_data(b: RuleIn) -> dict:
    from app.services.audit.soc_library import mitre_objects
    data = b.model_dump(exclude=set(_LIBRARY_FIELDS))
    for k in _LIBRARY_FIELDS:
        if k in b.model_fields_set:
            data[k] = mitre_objects(b.mitre or []) if k == "mitre" else getattr(b, k)
    return data


def _validate_rule(b: RuleIn) -> None:
    from app.services.audit.soc_library import MITRE, SOC_CATEGORIES
    if b.soc_category is not None and b.soc_category not in SOC_CATEGORIES:
        raise HTTPException(422, f"soc_category must be one of {', '.join(SOC_CATEGORIES)}")
    if b.mitre and any(m not in MITRE for m in b.mitre):
        raise HTTPException(422, f"Unknown MITRE technique: {', '.join(m for m in b.mitre if m not in MITRE)}")
    for x in b.exclusions or []:
        try:
            validate(x)
        except ValueError as exc:
            raise HTTPException(422, f"Exclusion: {exc}") from exc
    if b.action not in ("RULE_VIOLATION", "SUSPICIOUS", "REVIEW_REQUIRED"):
        raise HTTPException(422, "action must be RULE_VIOLATION, SUSPICIOUS or REVIEW_REQUIRED")
    if b.severity not in ("Critical", "High", "Medium", "Low", "Informational"):
        raise HTTPException(422, "Unknown severity")
    if b.provider not in (None, "", "aws", "azure", "gcp"):
        raise HTTPException(422, "provider must be aws, azure, gcp or empty")
    if b.group_by not in ("principal", "source_ip", "resource_id", "scope"):
        raise HTTPException(422, "group_by must be principal, source_ip, resource_id or scope")
    if b.threshold_count > 1 and not b.threshold_window_minutes:
        raise HTTPException(422, "A frequency threshold needs a time window")
    try:
        validate(b.conditions)
    except ValueError as exc:
        raise HTTPException(422, f"Conditions: {exc}") from exc


def rdict(r: DetectionRule, available: dict | None = None) -> dict:
    from app.services.audit.soc_library import SOC_CATEGORIES, data_available, rule_fields
    available = available if available is not None else data_available(get_settings())
    fields, ops = rule_fields(r.conditions)
    missing = [d for d in (r.data_requirements or []) if not available.get(d, False)]
    return {"id": r.id, **rule_snapshot(r), "version": r.version, "updated_by": r.updated_by, "updated_at": r.updated_at,
            "soc_category_label": SOC_CATEGORIES.get(r.soc_category or ""), "last_triggered_at": r.last_triggered_at,
            "match_count": r.match_count or 0, "required_fields": fields, "event_types": ops,
            "data_status": "disabled" if not r.enabled else ("needs data source" if missing else "active"), "missing_data": missing}


@router.get("/rules")
def rules(db: Session = Depends(get_db), _: User = Depends(require_any("audit:read", "audit:rules"))):
    from app.services.audit.soc_library import MITRE, SOC_CATEGORIES, data_available
    avail = data_available(get_settings())
    items = [rdict(r, avail) for r in db.scalars(select(DetectionRule).order_by(DetectionRule.rule_key))]
    return {"items": items, "categories": SOC_CATEGORIES, "mitre": MITRE, "data_sources": avail,
            "coverage": {k: sum(1 for i in items if i["soc_category"] == k and i["enabled"]) for k in SOC_CATEGORIES}}


@router.post("/rules", status_code=201)
def create_rule(body: RuleIn, db: Session = Depends(get_db), user: User = Depends(require("audit:rules"))):
    _validate_rule(body)
    if db.scalar(select(DetectionRule.id).where(DetectionRule.rule_key == body.rule_key)):
        raise HTTPException(409, "Rule ID already exists")
    r = DetectionRule(**_rule_data(body), updated_by=user.email, version=1, match_count=0)
    r.provider = r.provider or None
    db.add(r)
    db.flush()
    db.add(DetectionRuleHistory(rule_id=r.id, version=1, action="created", actor=user.email, snapshot=rule_snapshot(r)))
    log_action(db, user.email, "audit_rule.create", r.rule_key)
    db.commit()
    return rdict(r)


@router.put("/rules/{rid}")
def update_rule(rid: int, body: RuleIn, db: Session = Depends(get_db), user: User = Depends(require("audit:rules"))):
    r = db.get(DetectionRule, rid)
    if r is None:
        raise HTTPException(404, "Rule not found")
    _validate_rule(body)
    data = _rule_data(body)
    data["provider"] = data["provider"] or None
    action = "updated" if data["enabled"] == r.enabled else ("enabled" if data["enabled"] else "disabled")
    for k, v in data.items():
        setattr(r, k, v)
    r.version, r.updated_by = (r.version or 1) + 1, user.email
    db.add(DetectionRuleHistory(rule_id=r.id, version=r.version, action=action, actor=user.email, snapshot=rule_snapshot(r)))
    log_action(db, user.email, f"audit_rule.{action}", r.rule_key, {"version": r.version})
    db.commit()
    return rdict(r)


@router.get("/rules/{rid}/history")
def rule_history(rid: int, db: Session = Depends(get_db), _: User = Depends(require_any("audit:read", "audit:rules"))):
    return {"items": [{"version": h.version, "action": h.action, "actor": h.actor, "snapshot": h.snapshot, "at": h.created_at}
                      for h in db.scalars(select(DetectionRuleHistory).where(DetectionRuleHistory.rule_id == rid).order_by(DetectionRuleHistory.id.desc()))]}


class TestIn(BaseModel):
    rule: RuleIn
    days: int = Field(7, ge=1, le=90)
    limit: int = Field(5000, ge=1, le=20000)


@router.post("/rules/test")
def test_rule(body: TestIn, db: Session = Depends(get_db), _: User = Depends(require("audit:rules"))):
    """Dry run against stored events. Nothing is saved, flagged or notified."""
    _validate_rule(body.rule)
    r = DetectionRule(**body.rule.model_dump())
    r.id = 0
    since = datetime.now(UTC) - timedelta(days=body.days)
    events = db.scalars(select(E).where(E.event_timestamp >= since).order_by(E.event_timestamp.desc()).limit(body.limit)).all()
    lookup = eng._new_operation_lookup(db)
    hits = []
    for e in events:
        why = eng.match_rule(db, r, EventView(e, lookup), lookup)
        if why:
            hits.append({**edict(e, None), "explanation": why})
    return {"evaluated": len(events), "matches": len(hits), "sample": hits[:50]}


# ------------------------------------------------------------------------------------------------ authorization rules
class AuthRuleIn(BaseModel):
    name: str = Field(min_length=3, max_length=255)
    provider: str | None = None
    scope_external_id: str | None = None
    actor: str = Field(min_length=3, max_length=512)
    operation: str = Field(min_length=2, max_length=255)
    resource_prefix: str | None = None
    reason: str = Field(min_length=10, max_length=5000)
    approval_reference: str = Field(min_length=2, max_length=255)
    valid_until: datetime


def adict(a: AuthorizationRule) -> dict:
    return {"id": a.id, "name": a.name, "provider": a.provider, "scope": a.scope_external_id, "actor": a.actor, "operation": a.operation,
            "resource_prefix": a.resource_prefix, "reason": a.reason, "approval_reference": a.approval_reference, "approved_by": a.approved_by,
            "valid_from": a.valid_from, "valid_until": a.valid_until, "enabled": a.enabled}


@router.get("/authorization-rules")
def auth_rules(db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    return {"items": [adict(a) for a in db.scalars(select(AuthorizationRule).order_by(AuthorizationRule.id.desc()))]}


@router.post("/authorization-rules", status_code=201)
def create_auth_rule(body: AuthRuleIn, db: Session = Depends(get_db), user: User = Depends(require("audit:rules"))):
    if "audit:authorize" not in user.permission_names:
        raise HTTPException(403, "Creating an authorization rule needs audit:authorize as well")
    if any(ch in body.actor + body.operation for ch in "*?"):
        raise HTTPException(422, "Wildcards are not allowed: an authorization rule names one actor and one operation")
    until = body.valid_until if body.valid_until.tzinfo else body.valid_until.replace(tzinfo=UTC)
    if until <= datetime.now(UTC) or until > datetime.now(UTC) + timedelta(days=365):
        raise HTTPException(422, "valid_until must be in the future and within one year")
    a = AuthorizationRule(**body.model_dump(exclude={"valid_until"}), valid_until=until, approved_by=user.email, valid_from=datetime.now(UTC))
    db.add(a)
    db.flush()
    log_action(db, user.email, "authorization_rule.create", str(a.id), {"actor": a.actor, "operation": a.operation, "ref": a.approval_reference})
    db.commit()
    return adict(a)


@router.post("/authorization-rules/{aid}/disable")
def disable_auth_rule(aid: int, db: Session = Depends(get_db), user: User = Depends(require("audit:rules"))):
    a = db.get(AuthorizationRule, aid)
    if a is None:
        raise HTTPException(404, "Rule not found")
    a.enabled = False
    log_action(db, user.email, "authorization_rule.disable", str(aid))
    db.commit()
    return adict(a)
