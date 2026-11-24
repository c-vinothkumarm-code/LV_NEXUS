"""Vulnerability management API: native findings, lifecycle, exceptions, evidence, SLA, notification rules, reports."""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, object_session

from app.api.deps import log_action, require_any
from app.api.serializers import scope_label
from app.core.config import Settings, get_settings
from app.core.security import assigned_scopes, current_user, require
from app.database.session import get_db
from app.models import (
    AuditInvestigation,
    CloudSecurityFinding,
    ExceptionApproval,
    FindingComment,
    FindingException,
    FindingStatusHistory,
    InvestigationCase,
    NotificationRule,
    SecurityEvidence,
    SecuritySlaPolicy,
    User,
)
from app.services.vuln import lifecycle as lc
from app.services.vuln.reports import REPORTS, render

router = APIRouter(prefix="/api/v1/security", tags=["vulnerability management"])
F = CloudSecurityFinding
SORTABLE = {"severity": F.severity, "first_observed_at": F.first_observed_at, "last_observed_at": F.last_observed_at, "sla_due_at": F.sla_due_at,
            "provider": F.provider, "internal_status": F.internal_status, "title": F.title, "id": F.id, "last_synced_at": F.last_synced_at}
SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


def reader(user: User = Depends(require_any("vuln:read", "vuln:read_assigned"))) -> User:
    return user


def _scoped(q, user: User):
    """Cloud engineers (vuln:read_assigned only) see findings assigned to them; Project Owners also see every finding in
    the accounts / subscriptions / projects assigned to them."""
    if "vuln:read" not in user.permission_names:
        pairs = assigned_scopes(user)
        conds = [F.owner == user.email] + [and_(F.provider == p, F.scope_external_id == sc) for p, sc in sorted(pairs)]
        q = q.where(or_(*conds))
    return q


def _finding(db: Session, fid: int, user: User) -> CloudSecurityFinding:
    f = db.get(F, fid)
    visible = f is not None and ("vuln:read" in user.permission_names or f.owner == user.email
                                 or (f.provider, f.scope_external_id) in assigned_scopes(user))
    if not visible:
        raise HTTPException(404, "Finding not found")
    return f


def _err(exc: lc.WorkflowError):
    raise HTTPException(409, str(exc))


def fdict(f: CloudSecurityFinding, brief: bool = True) -> dict:
    d = {"id": f.id, "provider": f.provider, "source": f.source, "is_security": f.is_security, "scope": f.scope_external_id, "scope_name": scope_label(object_session(f), f.provider, f.scope_external_id), "region": f.region,
         "organization_id": f.organization_id, "parent_id": f.parent_id, "resource_id": f.resource_id, "resource_name": f.resource_name,
         "resource_type": f.resource_type, "resource_group": f.resource_group, "title": f.title, "severity": f.severity, "category": f.category,
         "native_state": f.native_state, "internal_status": f.internal_status, "owner": f.owner, "analyst": f.analyst,
         "first_observed_at": f.first_observed_at, "last_observed_at": f.last_observed_at, "last_synced_at": f.last_synced_at,
         "sla_due_at": f.sla_due_at, "sla_paused": f.sla_paused, "overdue": lc.is_overdue(f), "needs_reassessment": f.needs_reassessment,
         "reopen_count": f.reopen_count, "control_id": f.control_id, "compliance_standard": f.compliance_standard}
    if not brief:
        d |= {"native_id": f.native_id, "description": f.description, "finding_type": f.finding_type, "remediation": f.remediation,
              "remediation_url": f.remediation_url, "native_workflow_status": f.native_workflow_status, "native_record_state": f.native_record_state,
              "mute_state": f.mute_state, "native_updated_at": f.native_updated_at, "native_resolved_at": f.native_resolved_at,
              "first_synced_at": f.first_synced_at, "resolved_at": f.resolved_at, "resolved_by": f.resolved_by, "environment": f.environment,
              "ai_analysis": f.ai_analysis, "raw": f.raw}
    return d


def _filters(q, *, provider=None, scope=None, region=None, severity=None, category=None, status=None, owner=None, resource_type=None,
             source=None, q_text=None, org=None, parent=None, environment=None, date_from=None, date_to=None, overdue=None,
             native_state=None, security_only=True, reassess=None):
    if security_only:
        q = q.where(F.is_security.is_(True))
    for col, val in ((F.provider, provider), (F.scope_external_id, scope), (F.region, region), (F.category, category), (F.owner, owner),
                     (F.resource_type, resource_type), (F.source, source), (F.organization_id, org), (F.parent_id, parent),
                     (F.environment, environment), (F.native_state, native_state)):
        if val:
            q = q.where(col.in_(val.split(",")) if "," in val else col == val)
    if severity:
        q = q.where(F.severity.in_(severity.split(",")))
    if status:
        q = q.where(F.internal_status.in_(status.split(",")))
    if q_text:
        like = f"%{q_text.strip()}%"
        q = q.where(or_(F.title.ilike(like), F.resource_id.ilike(like), F.resource_name.ilike(like), F.control_id.ilike(like), F.scope_external_id.ilike(like)))
    if date_from:
        q = q.where(F.first_observed_at >= datetime.combine(date_from, datetime.min.time(), UTC))
    if date_to:
        q = q.where(F.first_observed_at < datetime.combine(date_to + timedelta(days=1), datetime.min.time(), UTC))
    if overdue:
        q = q.where(F.sla_due_at < datetime.now(UTC), F.sla_paused.is_(False), F.internal_status.in_(lc.OPEN_STATES))
    if reassess:
        q = q.where(F.needs_reassessment.is_(True))
    return q


class ListArgs:
    def __init__(self, provider: str | None = None, scope: str | None = None, region: str | None = None, severity: str | None = None,
                 category: str | None = None, status: str | None = None, owner: str | None = None, resource_type: str | None = None,
                 source: str | None = None, q: str | None = None, org: str | None = None, parent: str | None = None, environment: str | None = None,
                 date_from: date | None = None, date_to: date | None = None, overdue: bool | None = None, native_state: str | None = None,
                 security_only: bool = True, reassess: bool | None = None):
        self.kw = dict(provider=provider, scope=scope, region=region, severity=severity, category=category, status=status, owner=owner,
                       resource_type=resource_type, source=source, q_text=q, org=org, parent=parent, environment=environment,
                       date_from=date_from, date_to=date_to, overdue=overdue, native_state=native_state, security_only=security_only, reassess=reassess)


@router.get("/findings")
def list_findings(a: ListArgs = Depends(), sort: str = "severity", order: str = "asc", page: int = Query(1, ge=1),
                  page_size: int = Query(50, ge=1, le=500), db: Session = Depends(get_db), user: User = Depends(reader)):
    q = _scoped(_filters(select(F), **a.kw), user)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    col = SORTABLE.get(sort, F.severity)
    if sort == "severity":
        from sqlalchemy import case
        col = case({k: v for k, v in SEV_ORDER.items()}, value=F.severity, else_=9)
    q = q.order_by(col.desc() if order == "desc" else col.asc(), F.id.desc())
    items = db.scalars(q.offset((page - 1) * page_size).limit(page_size)).all()
    return {"total": total, "page": page, "page_size": page_size, "items": [fdict(f) for f in items]}


@router.get("/findings/facets")
def facets(security_only: bool = True, db: Session = Depends(get_db), user: User = Depends(reader)):
    out = {}
    for name, col in (("provider", F.provider), ("scope", F.scope_external_id), ("region", F.region), ("category", F.category),
                      ("resource_type", F.resource_type), ("owner", F.owner), ("organization", F.organization_id), ("parent", F.parent_id),
                      ("source", F.source), ("environment", F.environment)):
        q = _scoped(select(col, func.count()).where(col.is_not(None)), user)
        if security_only:
            q = q.where(F.is_security.is_(True))
        out[name] = [{"value": v, "count": n} for v, n in db.execute(q.group_by(col).order_by(func.count().desc()).limit(200))]
    return out


@router.get("/findings/{fid}")
def finding_detail(fid: int, db: Session = Depends(get_db), user: User = Depends(reader)):
    f = _finding(db, fid, user)
    exc = db.scalars(select(FindingException).where(FindingException.finding_id == fid).order_by(FindingException.id.desc())).all()
    approvals = db.scalars(select(ExceptionApproval).where(ExceptionApproval.exception_id.in_([e.id for e in exc] or [-1])).order_by(ExceptionApproval.id)).all()
    related = db.scalars(select(F).where(F.resource_id == f.resource_id, F.id != f.id).limit(20)).all() if f.resource_id else []
    cases = db.scalars(select(InvestigationCase).order_by(InvestigationCase.id.desc()).limit(500)).all()
    return {"finding": fdict(f, brief=False),
            "history": [{"id": h.id, "field": h.field, "from": h.previous_value, "to": h.new_value, "actor": h.actor, "reason": h.reason, "at": h.created_at}
                        for h in db.scalars(select(FindingStatusHistory).where(FindingStatusHistory.finding_id == fid).order_by(FindingStatusHistory.id))],
            "comments": [{"id": c.id, "kind": c.kind, "author": c.author, "body": c.body, "at": c.created_at}
                         for c in db.scalars(select(FindingComment).where(FindingComment.finding_id == fid).order_by(FindingComment.id))],
            "evidence": [_ev(e) for e in db.scalars(select(SecurityEvidence).where(SecurityEvidence.subject_type == "finding", SecurityEvidence.subject_id == fid))],
            "exceptions": [_exc(e, f) for e in exc],
            "approvals": [{"exception_id": a.exception_id, "action": a.action, "actor": a.actor, "notes": a.notes, "at": a.created_at} for a in approvals],
            "related_findings": [fdict(r) for r in related],
            "related_cases": [{"id": c.id, "title": c.title, "status": c.status} for c in cases if fid in (c.finding_ids or [])]}


def _ev(e: SecurityEvidence) -> dict:
    return {"id": e.id, "kind": e.kind, "name": e.name, "reference": e.reference if e.kind != "file" else None, "sha256": e.sha256,
            "size_bytes": e.size_bytes, "content_type": e.content_type, "note": e.note, "uploaded_by": e.uploaded_by, "at": e.created_at}


def _exc(e: FindingException, f: CloudSecurityFinding | None = None) -> dict:
    d = {"id": e.id, "finding_id": e.finding_id, "status": e.status, "business_justification": e.business_justification,
         "risk_acceptance": e.risk_acceptance, "business_impact": e.business_impact, "compensating_controls": e.compensating_controls,
         "risk_owner": e.risk_owner, "technical_owner": e.technical_owner, "requester": e.requester, "approver": e.approver,
         "created_at": e.created_at, "approved_at": e.approved_at, "expires_at": e.expires_at, "decision_notes": e.decision_notes}
    if f is not None:
        d |= {"provider": f.provider, "scope": f.scope_external_id, "resource_id": f.resource_id, "title": f.title, "severity": f.severity}
    return d


class StatusIn(BaseModel):
    status: str
    reason: str | None = Field(default=None, max_length=5000)


@router.post("/findings/{fid}/status")
def change_status(fid: int, body: StatusIn, db: Session = Depends(get_db), user: User = Depends(require("vuln:triage"))):
    f = _finding(db, fid, user)
    try:
        lc.set_status(db, f, body.status, user, body.reason)
    except (lc.WorkflowError, ValueError) as exc:
        _err(lc.WorkflowError(str(exc)))
    log_action(db, user.email, "finding.status", str(fid), {"to": body.status})
    db.commit()
    return fdict(f)


class AssignIn(BaseModel):
    field: str = "owner"
    value: str | None = Field(default=None, max_length=255)


@router.post("/findings/{fid}/assign")
def assign(fid: int, body: AssignIn, db: Session = Depends(get_db), user: User = Depends(require("vuln:triage"))):
    f = _finding(db, fid, user)
    try:
        lc.assign(db, f, body.field, (body.value or "").strip() or None, user.email)
    except lc.WorkflowError as exc:
        _err(exc)
    db.commit()
    return fdict(f)


class BulkIn(BaseModel):
    ids: list[int] = Field(min_length=1, max_length=500)
    action: str  # status | assign
    status: str | None = None
    reason: str | None = None
    field: str | None = "owner"
    value: str | None = None


@router.post("/findings/bulk")
def bulk(body: BulkIn, db: Session = Depends(get_db), user: User = Depends(require("vuln:triage"))):
    done, failed = [], []
    for fid in body.ids:
        f = db.get(F, fid)
        try:
            if f is None:
                raise lc.WorkflowError("not found")
            if body.action == "status":
                lc.set_status(db, f, body.status or "", user, body.reason)
            elif body.action == "assign":
                lc.assign(db, f, body.field or "owner", body.value, user.email)
            else:
                raise lc.WorkflowError("unknown action")
            done.append(fid)
        except (lc.WorkflowError, ValueError) as exc:
            failed.append({"id": fid, "reason": str(exc)})
    log_action(db, user.email, f"finding.bulk_{body.action}", ",".join(map(str, done))[:250], {"failed": len(failed)})
    db.commit()
    return {"updated": done, "failed": failed}


class CommentIn(BaseModel):
    kind: str = "comment"
    body: str = Field(min_length=1, max_length=20000)


@router.post("/findings/{fid}/comments", status_code=201)
def add_comment(fid: int, body: CommentIn, db: Session = Depends(get_db), user: User = Depends(require_any("vuln:triage", "vuln:remediate"))):
    f = _finding(db, fid, user)
    try:
        c = lc.comment(db, f, body.kind, body.body, user.email)
    except lc.WorkflowError as exc:
        _err(exc)
    db.commit()
    return {"id": c.id}


class EvidenceIn(BaseModel):
    kind: str
    name: str = Field(max_length=255)
    reference: str | None = Field(default=None, max_length=1024)
    content_base64: str | None = None
    content_type: str | None = None
    note: str | None = Field(default=None, max_length=5000)


@router.post("/findings/{fid}/evidence", status_code=201)
def add_finding_evidence(fid: int, body: EvidenceIn, db: Session = Depends(get_db), s: Settings = Depends(get_settings),
                         user: User = Depends(require_any("vuln:triage", "vuln:remediate"))):
    _finding(db, fid, user)
    try:
        ev = lc.add_evidence(db, s, "finding", fid, body.model_dump(), user)
    except lc.WorkflowError as exc:
        raise HTTPException(422, str(exc)) from exc
    db.commit()
    return _ev(ev)


@router.get("/evidence/{eid}/download")
def download_evidence(eid: int, db: Session = Depends(get_db), s: Settings = Depends(get_settings), user: User = Depends(current_user)):
    ev = db.get(SecurityEvidence, eid)
    if ev is None:
        raise HTTPException(404, "Evidence not found")
    if ev.subject_type == "finding":
        if not {"vuln:read", "vuln:read_assigned"} & user.permission_names:
            raise HTTPException(403, "Forbidden")
        _finding(db, ev.subject_id, user)  # 404 for an engineer who is not the owner
    elif "audit:read" not in user.permission_names:
        raise HTTPException(403, "Forbidden")
    path = lc.evidence_path(s, ev)
    if path is None:
        raise HTTPException(404, "File not available")
    # always served as a download, never rendered inline
    return FileResponse(path, media_type="application/octet-stream", filename=ev.name)


class ExceptionIn(BaseModel):
    business_justification: str = Field(max_length=10000)
    risk_acceptance: str = Field(max_length=10000)
    business_impact: str | None = Field(default=None, max_length=10000)
    compensating_controls: str | None = Field(default=None, max_length=10000)
    risk_owner: str = Field(max_length=255)
    technical_owner: str | None = Field(default=None, max_length=255)
    validity_days: int | None = None


@router.post("/findings/{fid}/exceptions", status_code=201)
def request_exc(fid: int, body: ExceptionIn, db: Session = Depends(get_db), s: Settings = Depends(get_settings),
                user: User = Depends(require("exception:request"))):
    f = _finding(db, fid, user)
    try:
        e = lc.request_exception(db, s, f, body.model_dump(), user)
    except lc.WorkflowError as exc:
        _err(exc)
    db.commit()
    return _exc(e, f)


@router.get("/exceptions")
def list_exceptions(status: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_any("vuln:read", "exception:approve"))):
    q = select(FindingException, F).join(F, F.id == FindingException.finding_id).order_by(FindingException.id.desc())
    if status:
        q = q.where(FindingException.status.in_(status.split(",")))
    return {"items": [_exc(e, f) for e, f in db.execute(q.limit(1000))]}


class DecisionIn(BaseModel):
    approve: bool
    notes: str | None = Field(default=None, max_length=5000)


@router.post("/exceptions/{eid}/decision")
def decide(eid: int, body: DecisionIn, db: Session = Depends(get_db), user: User = Depends(require("exception:approve"))):
    e = db.get(FindingException, eid)
    if e is None:
        raise HTTPException(404, "Exception not found")
    f = db.get(F, e.finding_id)
    try:
        lc.decide_exception(db, e, f, body.approve, user, body.notes)
    except lc.WorkflowError as exc:
        _err(exc)
    log_action(db, user.email, "exception.approve" if body.approve else "exception.reject", str(eid))
    db.commit()
    return _exc(e, f)


class CloseIn(BaseModel):
    notes: str = Field(min_length=3, max_length=5000)


@router.post("/exceptions/{eid}/close")
def close_exc(eid: int, body: CloseIn, db: Session = Depends(get_db), user: User = Depends(require_any("exception:approve", "vuln:triage"))):
    e = db.get(FindingException, eid)
    if e is None:
        raise HTTPException(404, "Exception not found")
    f = db.get(F, e.finding_id)
    try:
        lc.end_exception(db, e, f, "CLOSED", user.email, body.notes)
    except lc.WorkflowError as exc:
        _err(exc)
    log_action(db, user.email, "exception.close", str(eid))
    db.commit()
    return _exc(e, f)


@router.post("/findings/{fid}/ai")
def ai_finding(fid: int, db: Session = Depends(get_db), s: Settings = Depends(get_settings), user: User = Depends(require_any("vuln:triage", "vuln:remediate"))):
    from app.services.ai.provider import build_provider
    from app.services.vuln.ai import analyse_finding
    provider = build_provider(s)
    if provider is None:
        raise HTTPException(409, "AI analysis is not configured (AI_PROVIDER and key)")
    f = _finding(db, fid, user)
    related = db.scalars(select(F).where(F.resource_id == f.resource_id, F.id != f.id).limit(10)).all() if f.resource_id else []
    try:
        f.ai_analysis = analyse_finding(provider, f, related)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"AI analysis failed: {str(exc)[:200]}") from exc
    lc.history(db, f, "ai_analysis", None, "generated", user.email, "Advisory analysis requested")
    db.commit()
    return f.ai_analysis


@router.get("/findings/{fid}/export")
def export_finding(fid: int, db: Session = Depends(get_db), user: User = Depends(reader)):
    data = finding_detail(fid, db, user)
    return Response(json.dumps(data, default=str, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="cloudnexus-finding-{fid}.json"'})


@router.get("/history")
def recent_history(limit: int = Query(200, le=1000), field: str | None = None, db: Session = Depends(get_db), user: User = Depends(require("vuln:read"))):
    q = select(FindingStatusHistory, F.title, F.severity, F.provider).join(F, F.id == FindingStatusHistory.finding_id).order_by(FindingStatusHistory.id.desc())
    if field:
        q = q.where(FindingStatusHistory.field == field)
    return {"items": [{"finding_id": h.finding_id, "title": t, "severity": sv, "provider": p, "field": h.field, "from": h.previous_value,
                       "to": h.new_value, "actor": h.actor, "reason": h.reason, "at": h.created_at} for h, t, sv, p in db.execute(q.limit(limit))]}


@router.get("/overview")
def overview(provider: str | None = None, scope: str | None = None, date_from: date | None = None, date_to: date | None = None,
             db: Session = Depends(get_db), user: User = Depends(reader)):
    q = _scoped(_filters(select(F), provider=provider, scope=scope, date_from=date_from, date_to=date_to), user)
    rows = db.scalars(q).all()
    now = datetime.now(UTC)
    sev, status, by_prov, by_scope, by_region, by_cat, sla = Counter(), Counter(), defaultdict(Counter), Counter(), Counter(), Counter(), Counter()
    active = [f for f in rows if f.native_state == "ACTIVE" or f.internal_status in lc.OPEN_STATES]
    for f in rows:
        status[f.internal_status] += 1
        if f.internal_status in lc.OPEN_STATES or f.internal_status == "EXCEPTION":
            sev[f.severity] += 1
            by_prov[f.provider][f.severity] += 1
            by_scope[f"{f.provider}:{f.scope_external_id}"] += 1
            by_region[f.region or "global"] += 1
            by_cat[f.category or "Uncategorised"] += 1
        if f.sla_due_at:
            if f.internal_status == "RESOLVED" and f.resolved_at:
                sla["met" if lc._aware(f.resolved_at) <= lc._aware(f.sla_due_at) else "missed"] += 1
            elif lc.is_overdue(f, now):
                sla["overdue"] += 1
            elif f.internal_status in lc.OPEN_STATES:
                sla["on_track"] += 1
    days = [(now - timedelta(days=i)).date() for i in range(29, -1, -1)]
    trend = []
    for d in days:
        end = datetime.combine(d + timedelta(days=1), datetime.min.time(), UTC)
        opened = sum(1 for f in rows if lc._aware(f.first_synced_at) < end)
        closed = sum(1 for f in rows if f.resolved_at and lc._aware(f.resolved_at) < end)
        trend.append({"date": d.isoformat(), "detected": sum(1 for f in rows if (lc._aware(f.first_observed_at) or lc._aware(f.first_synced_at)).date() == d),
                      "resolved": sum(1 for f in rows if f.resolved_at and lc._aware(f.resolved_at).date() == d), "open_total": max(0, opened - closed)})
    exc_trend = Counter((e.created_at.date().isoformat(), e.status) for e in db.scalars(select(FindingException).where(FindingException.created_at >= now - timedelta(days=90))))
    out = {"kpis": {"total": len(rows), "critical": sev["Critical"], "high": sev["High"], "medium": sev["Medium"], "low": sev["Low"],
                    "open": status["OPEN"], "under_review": status["UNDER_REVIEW"], "exceptions": status["EXCEPTION"], "resolved": status["RESOLVED"],
                    "reopened": status["REOPENED"], "false_positive": status["FALSE_POSITIVE"], "overdue": sla["overdue"], "active_natively": len(active)},
           "by_provider": {p: dict(c) for p, c in by_prov.items()}, "by_scope": by_scope.most_common(25), "by_region": by_region.most_common(25),
           "by_category": by_cat.most_common(15), "sla": dict(sla), "trend": trend,
           "exception_trend": [{"date": d, "status": s, "count": n} for (d, s), n in sorted(exc_trend.items())],
           "non_security_recommendations": db.scalar(select(func.count()).select_from(F).where(F.is_security.is_(False), F.native_state == "ACTIVE")) or 0,
           "generated_at": now}
    if "audit:read" in user.permission_names:
        cls = Counter(dict(db.execute(select(AuditInvestigation.classification, func.count()).group_by(AuditInvestigation.classification)).all()))
        st = Counter(dict(db.execute(select(AuditInvestigation.status, func.count()).where(AuditInvestigation.status.is_not(None))
                                     .group_by(AuditInvestigation.status)).all()))
        from app.models import AuditEvent
        out["audit"] = {"total_events": db.scalar(select(func.count()).select_from(AuditEvent)) or 0, "evaluated": sum(cls.values()),
                        "authorized": cls["AUTHORIZED"] + st["AUTHORIZED"], "normal": cls["NORMAL"], "suspicious": cls["SUSPICIOUS"],
                        "violations": cls["RULE_VIOLATION"], "review_required": cls["REVIEW_REQUIRED"],
                        "under_investigation": st["DETECTED"] + st["REVIEWING"] + st["INVESTIGATING"] + st["ESCALATED"] + st["REOPENED"],
                        "closed": st["CLOSED"] + st["NO_ACTION_REQUIRED"]}
    return out


SOURCE_LABEL = {"security_hub": "AWS Security Hub", "azure_advisor": "Azure Advisor", "defender": "Microsoft Defender for Cloud",
                "azure_defender": "Microsoft Defender for Cloud", "azure_policy": "Azure Policy", "scc": "Google Security Command Center"}


@router.get("/sources")
def sources(db: Session = Depends(get_db), user: User = Depends(reader)):
    """Per cloud and source: open findings and how much of the estate was actually read. A source that was refused or not
    enabled is reported as such, never as "0 findings"."""
    from app.models import SyncCheckpoint
    open_q = _scoped(select(F.provider, F.source, F.severity, func.count()).where(F.is_security.is_(True), F.internal_status.in_(lc.OPEN_STATES)), user)
    counts: dict = defaultdict(Counter)
    for p, src, sev, n in db.execute(open_q.group_by(F.provider, F.source, F.severity)):
        counts[(p, src)][sev] += n
    cps: dict = defaultdict(list)
    for c in db.scalars(select(SyncCheckpoint)):
        cps[(c.provider, c.source)].append(c)
    out = []
    for key in sorted(set(counts) | set(cps)):
        p, src = key
        rows = cps.get(key, [])
        states = Counter(c.state for c in rows)
        last_ok = max((c.last_success_at for c in rows if c.last_success_at), default=None)
        problems = [{"scope": c.scope_external_id, "region": c.region, "state": c.state, "message": c.last_error}
                    for c in rows if c.state not in ("OK",)][:20]
        sev = counts.get(key, Counter())
        out.append({"provider": p, "source": src, "label": SOURCE_LABEL.get(src, src), "open": sum(sev.values()),
                    "critical": sev["Critical"], "high": sev["High"], "medium": sev["Medium"], "low": sev["Low"],
                    "partitions": len(rows), "ok": states["OK"], "access_denied": states["ACCESS_DENIED"], "not_enabled": states["NOT_ENABLED"],
                    "errors": states["ERROR"] + states["PARTIALLY_CONFIGURED"], "last_success_at": last_ok.isoformat() if last_ok else None, "problems": problems,
                    "status": "never" if not rows else "ok" if states["OK"] == len(rows) else "partial" if states["OK"] else "failed"})
    return {"items": out}


# ---------------------------------------------------------------------------------------------- policies
class SlaIn(BaseModel):
    severity: str
    target_hours: int = Field(ge=1, le=24 * 365)
    pause_on_exception: bool = True


@router.get("/sla-policies")
def sla_list(db: Session = Depends(get_db), _: User = Depends(require_any("vuln:read", "vuln:read_assigned"))):
    return {"items": [{"severity": p.severity, "target_hours": p.target_hours, "pause_on_exception": p.pause_on_exception, "updated_by": p.updated_by,
                       "updated_at": p.updated_at} for p in db.scalars(select(SecuritySlaPolicy))]}


@router.put("/sla-policies")
def sla_update(body: SlaIn, db: Session = Depends(get_db), user: User = Depends(require("security:admin"))):
    p = db.scalar(select(SecuritySlaPolicy).where(SecuritySlaPolicy.severity == body.severity))
    if p is None:
        p = SecuritySlaPolicy(severity=body.severity, target_hours=body.target_hours)
        db.add(p)
    old = p.target_hours
    p.target_hours, p.pause_on_exception, p.updated_by = body.target_hours, body.pause_on_exception, user.email
    db.flush()
    changed = 0
    for f in db.scalars(select(F).where(F.severity == body.severity, F.internal_status.in_(lc.OPEN_STATES))):
        lc.apply_sla(db, f, user.email, f"SLA policy {body.severity} changed {old} h -> {body.target_hours} h")
        changed += 1
    log_action(db, user.email, "sla.update", body.severity, {"from": old, "to": body.target_hours})
    db.commit()
    return {"severity": p.severity, "target_hours": p.target_hours, "findings_recalculated": changed}


class RuleIn(BaseModel):
    enabled: bool
    channels: str = "email,google_chat"


@router.get("/notification-rules")
def nrules(db: Session = Depends(get_db), _: User = Depends(require_any("security:admin", "sync:read"))):
    return {"items": [{"event_type": r.event_type, "description": r.description, "enabled": r.enabled, "channels": r.channels,
                       "updated_by": r.updated_by} for r in db.scalars(select(NotificationRule).order_by(NotificationRule.event_type))]}


@router.put("/notification-rules/{event_type}")
def nrule_update(event_type: str, body: RuleIn, db: Session = Depends(get_db), user: User = Depends(require("security:admin"))):
    r = db.scalar(select(NotificationRule).where(NotificationRule.event_type == event_type))
    if r is None:
        raise HTTPException(404, "Unknown notification rule")
    chans = ",".join(c for c in (x.strip() for x in body.channels.split(",")) if c in ("email", "google_chat"))
    r.enabled, r.channels, r.updated_by = body.enabled, chans, user.email
    log_action(db, user.email, "notification_rule.update", event_type, {"enabled": body.enabled, "channels": chans})
    db.commit()
    return {"event_type": event_type, "enabled": r.enabled, "channels": r.channels}


@router.get("/reports")
def report_list(_: User = Depends(require("reports:export"))):
    return {"items": [{"name": k, "title": v[0]} for k, v in REPORTS.items()], "formats": ["csv", "xlsx", "pdf"]}


@router.get("/reports/{name}")
def report(name: str, format: str = "csv", db: Session = Depends(get_db), user: User = Depends(require("reports:export"))):
    if name not in REPORTS:
        raise HTTPException(404, "Unknown report")
    if name.startswith(("audit", "authorized", "suspicious", "open-inv", "closed-inv")) and "audit:read" not in user.permission_names:
        raise HTTPException(403, "Missing permission: audit:read")
    try:
        content, mime, fname = render(db, name, format)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    log_action(db, user.email, "report.export", name, {"format": format})
    db.commit()
    return Response(content, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{fname}"'})
