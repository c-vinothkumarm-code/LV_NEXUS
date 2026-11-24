"""Live multi-cloud activity: feed, Server-Sent Events stream, investigation answers, freshness and export.

Events come only from provider audit logs collected by the security_events and entra_activity jobs (CloudTrail, Azure
Activity Log, Microsoft Entra audit / sign-in logs, Google Cloud Audit Logs). The stream pushes rows as soon as they are
stored; "provider delay" (event time -> collection) and "ingestion" time are reported separately."""
from __future__ import annotations

import asyncio
import csv
import io
import json
from datetime import UTC, date, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, object_session

from app.api.routes.audit_ops import E, Inv, _filters, edict
from app.api.serializers import scope_label
from app.core.security import require
from app.database.session import get_db, get_session_factory
from app.models import AccessGrant, AccessRequest, AuditEvent, AutomationJob, User
from app.models.access import AccessAssignment, CloudIdentity
from app.services.audit import engine as audit_engine

router = APIRouter(prefix="/api/v1/activity", tags=["live activity"])
SOURCES = {"aws": "AWS CloudTrail (management events; data events where enabled)",
           "azure": "Azure Activity Log; Microsoft Entra audit and sign-in logs",
           "gcp": "Google Cloud Audit Logs (Admin Activity, System Event, Policy Denied; Data Access where enabled)"}
LIMITATIONS = [
    "Collection polls provider APIs (CloudTrail LookupEvents, Azure Monitor, Microsoft Graph, Cloud Logging). EventBridge, Event Hubs, "
    "Pub/Sub log sinks and CloudTrail Lake are not connected yet, so an event appears after the provider delivers it to its API and the "
    "next collection run (every 5 minutes by default).",
    "CloudTrail LookupEvents returns management events only; data events need a trail with CloudTrail Lake or S3 delivery.",
    "Entra sign-in logs need Microsoft Graph AuditLog.Read.All and an Entra ID P1/P2 licence.",
]


def _q(provider, scope, resource, user, severity, category, result, q, start, end, classification):
    base = select(E, Inv).outerjoin(Inv, Inv.audit_event_id == E.id)
    base = _filters(base, provider, scope, None, classification, None, None, user, None, None, q, start, end, None, None, None)
    if resource:
        base = base.where(E.resource_id.ilike(f"%{resource}%"))
    if severity:
        base = base.where(Inv.severity.in_(severity.split(",")))
    if category:
        base = base.where(or_(E.event_category.in_(category.split(",")), Inv.category.in_(category.split(","))))
    if result == "success":
        base = base.where(or_(func.coalesce(E.raw["outcome"].as_string(), "success") == "success"))
    elif result in ("failure", "denied"):
        base = base.where(E.raw["outcome"].as_string().in_(["failure", "denied"]))
    return base


def _row(e: AuditEvent, i) -> dict:
    d = edict(e, i)
    raw = e.raw or {}
    d |= {"event_category": e.event_category, "ingested_at": e.collected_at, "risk_score": e.risk_score,
          "service": raw.get("service"), "resource_group": raw.get("resourceGroup") or _rg(e.resource_id),
          "provider_delay_seconds": int((_aware(e.collected_at) - _aware(e.event_timestamp)).total_seconds()) if e.collected_at else None,
          "principal_type": raw.get("userIdentityType")}
    return d


def _aware(dt):
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def _rg(rid: str | None) -> str | None:
    if rid and "/resourceGroups/" in rid:
        return rid.split("/resourceGroups/")[1].split("/")[0]
    return None


FILTER_ARGS = dict(provider=None, scope=None, resource=None, user=None, severity=None, category=None, result=None, q=None, start=None,
                   end=None, classification=None)


@router.get("/events")
def events(provider: str | None = None, scope: str | None = None, resource: str | None = None, user: str | None = None,
           severity: str | None = None, category: str | None = None, result: str | None = None, q: str | None = None,
           start: date | None = None, end: date | None = None, classification: str | None = None, after_id: int | None = None,
           sort: str = "time", order: str = "desc", page: int = Query(1, ge=1), page_size: int = Query(100, ge=1, le=500),
           db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    base = _q(provider, scope, resource, user, severity, category, result, q, start, end, classification)
    if after_id:
        base = base.where(E.id > after_id)
    total = db.scalar(select(func.count()).select_from(base.subquery()))
    col = {"time": E.event_timestamp, "ingested": E.collected_at, "actor": E.principal, "operation": E.event_name}.get(sort, E.event_timestamp)
    rows = db.execute(base.order_by(col.desc() if order == "desc" else col.asc(), E.id.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    latest = db.scalar(select(func.max(E.id)))
    return {"total": total, "page": page, "page_size": page_size, "latest_id": latest, "items": [_row(e, i) for e, i in rows]}


@router.get("/stream")
async def stream(request: Request, provider: str | None = None, scope: str | None = None, resource: str | None = None, user: str | None = None,
                 severity: str | None = None, category: str | None = None, result: str | None = None, q: str | None = None,
                 classification: str | None = None, after_id: int | None = None, _: User = Depends(require("audit:read"))):
    """Server-Sent Events. Each message is one new event (`id:` is the row id, so the browser resumes after a reconnect)."""
    factory = get_session_factory()
    last = int(request.headers.get("last-event-id") or 0) or after_id
    if not last:
        with factory() as db:
            last = db.scalar(select(func.max(E.id))) or 0

    async def gen():
        nonlocal last
        yield "retry: 5000\n\n"
        started, beat = datetime.now(UTC), datetime.now(UTC)
        while datetime.now(UTC) - started < timedelta(minutes=10):  # the browser reconnects transparently
            if await request.is_disconnected():
                return
            with factory() as db:
                base = _q(provider, scope, resource, user, severity, category, result, q, None, None, classification).where(E.id > last)
                rows = db.execute(base.order_by(E.id).limit(200)).all()
                for e, i in rows:
                    last = max(last, e.id)
                    yield f"id: {e.id}\nevent: activity\ndata: {json.dumps(_row(e, i), default=str)}\n\n"
                # advance past rows that did not match the filters so they are not re-read
                last = max(last, db.scalar(select(func.max(E.id))) or last) if not rows else last
            if datetime.now(UTC) - beat > timedelta(seconds=15):
                beat = datetime.now(UTC)
                yield f": keep-alive {beat.isoformat()}\n\n"
            await asyncio.sleep(3)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/events/{eid}/investigation")
def investigation(eid: int, db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    e = db.get(AuditEvent, eid)
    if e is None:
        raise HTTPException(404, "Event not found")
    i = db.scalar(select(Inv).where(Inv.audit_event_id == eid))
    raw = e.raw or {}
    outcome = raw.get("outcome") or "success"
    principal = (e.principal or "").strip()
    short = principal.rsplit("/", 1)[-1].split(":", 1)[-1].lower()
    ident = None
    if short:
        ident = db.scalars(select(CloudIdentity).where(CloudIdentity.provider == e.provider, or_(
            func.lower(CloudIdentity.sign_in_name) == short, func.lower(CloudIdentity.principal_id) == principal.lower()))).first()
    holds = []
    if ident is not None:
        holds = [f"{a.role_name} at {a.scope_path}" for a in db.scalars(select(AccessAssignment).where(
            AccessAssignment.provider == e.provider, AccessAssignment.principal_id == ident.principal_id, AccessAssignment.removed_at.is_(None),
            or_(AccessAssignment.scope_external_id == e.scope_external_id, AccessAssignment.inherited_from.is_not(None))))]
    t = _aware(e.event_timestamp)
    window = (t - timedelta(days=2), t + timedelta(hours=6))
    approvals = []
    if ident is not None or short:
        names = {short} | ({(ident.sign_in_name or "").lower()} if ident else set())
        for r in db.scalars(select(AccessRequest).where(AccessRequest.status.in_(["APPROVED", "EXECUTED", "VERIFIED"]),
                                                        AccessRequest.updated_at.between(*window))):
            if (r.sign_in_name or "").lower() in names:
                approvals.append(r.request_key)
        for g in db.scalars(select(AccessGrant).where(AccessGrant.state.in_(["ACTIVE", "APPROVED", "PROVISIONED"]))):
            if (g.sign_in_name or "").lower() in names and g.scope_external_id == e.scope_external_id:
                approvals.append(g.grant_key)
    expected = None
    if i is not None:
        expected = {"NORMAL": "Yes: matches no detection rule", "AUTHORIZED": "Yes: covered by an authorization rule or analyst authorization",
                    "REVIEW_REQUIRED": "Unclear: needs review", "SUSPICIOUS": "No: flagged as suspicious",
                    "RULE_VIOLATION": "No: violates a detection rule"}.get(i.classification, i.classification)
    related = audit_engine.related_events(db, e)
    return {
        "answers": [
            {"q": "Who performed the action?", "a": principal or "Not reported by the provider",
             "basis": raw.get("userIdentityType") or e.event_category},
            {"q": "What API operation was executed?", "a": e.event_name, "basis": raw.get("service") or e.provider},
            {"q": "What resource was affected?", "a": e.resource_id or "Not reported", "basis": e.resource_type},
            {"q": "When did it happen?", "a": e.event_timestamp, "basis": f"collected {e.collected_at}"},
            {"q": "From where did it originate?", "a": e.source_ip or "Not reported", "basis": e.region},
            {"q": "Was the operation successful?", "a": {"success": "Yes", "failure": "No (failed)", "denied": "No (access denied)"}.get(outcome, outcome),
             "basis": raw.get("error_code") or raw.get("errorCode")},
            {"q": "Was the action expected?", "a": expected or "Not evaluated yet by the rule engine", "basis": i.explanation if i else None},
            {"q": "Was it associated with an approved request?", "a": ", ".join(sorted(set(approvals))) or "No approved request found for this identity",
             "basis": "Access requests and approval register within 2 days before the event"},
            {"q": "Was the user authorized?", "a": ("Yes: holds " + "; ".join(holds[:5])) if holds else
             ("Identity known, no role assignment found on this scope" if ident else "Identity not in the access inventory (or not collected)"),
             "basis": "Access inventory (actual assignments)"},
            {"q": "Does the event indicate suspicious behaviour?", "a": "Yes" if i and i.classification in ("SUSPICIOUS", "RULE_VIOLATION") else
             "No rule matched" if i else "Not evaluated yet", "basis": ", ".join(m.get("rule_key", "") for m in (i.matched_rules or [])) if i else None},
        ],
        "identity": None if ident is None else {"provider": ident.provider, "principal_id": ident.principal_id, "name": ident.sign_in_name,
                                                "type": ident.principal_type, "lifecycle": ident.lifecycle_status},
        "related": [_row(r, None) for r in related[:20]],
    }


@router.get("/freshness")
def freshness(db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    since = datetime.now(UTC) - timedelta(hours=24)
    out = []
    rows = db.execute(select(E.provider, func.coalesce(E.event_category, ""), func.max(E.event_timestamp), func.max(E.collected_at), func.count())
                      .where(E.collected_at >= since).group_by(E.provider, func.coalesce(E.event_category, ""))).all()
    for p, cat, last_event, last_ingest, n in rows:
        out.append({"provider": p, "category": cat or None, "events_24h": n, "last_event_time": last_event, "last_ingested_at": last_ingest})
    delays = {}
    for p in ("aws", "azure", "gcp"):
        sample = list(db.execute(select(E.event_timestamp, E.collected_at).where(E.provider == p, E.collected_at >= since)
                                 .order_by(E.id.desc()).limit(500)).all())
        secs = sorted((_aware(c) - _aware(t)).total_seconds() for t, c in sample if c and t)
        delays[p] = {"median_seconds": int(secs[len(secs) // 2]) if secs else None, "sample": len(secs)}
    jobs = {j.name: {"last_run_at": j.last_finished_at or j.last_started_at, "last_status": j.last_status, "schedule": j.schedule}
            for j in db.scalars(select(AutomationJob).where(AutomationJob.name.in_(["security_events", "entra_activity", "audit_rule_evaluation"])))}
    return {"sources": SOURCES, "by_source": out, "delay": delays, "jobs": jobs, "limitations": LIMITATIONS,
            "note": "Provider delay = collection time minus event time (provider delivery + polling interval)."}


@router.get("/export")
def export(format: str = "csv", provider: str | None = None, scope: str | None = None, resource: str | None = None, user: str | None = None,
           severity: str | None = None, category: str | None = None, result: str | None = None, q: str | None = None,
           start: date | None = None, end: date | None = None, classification: str | None = None,
           db: Session = Depends(get_db), actor: User = Depends(require("audit:read"))):
    if format not in ("csv", "json"):
        raise HTTPException(422, "format must be csv or json")
    rows = [_row(e, i) for e, i in db.execute(_q(provider, scope, resource, user, severity, category, result, q, start, end, classification)
                                               .order_by(E.event_timestamp.desc()).limit(50_000)).all()]
    from app.api.deps import log_action
    log_action(db, actor.email, "activity.export", None, {"format": format, "rows": len(rows), "provider": provider})
    db.commit()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    if format == "json":
        return Response(json.dumps({"generated_at": stamp, "filters": {"provider": provider, "scope": scope, "start": str(start), "end": str(end)},
                                    "items": rows}, default=str), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="cloudnexus-activity-{stamp}.json"'})
    cols = ["id", "event_id", "provider", "scope_name", "scope", "region", "resource_group", "resource_id", "operation", "event_category", "actor",
            "source_ip", "time", "ingested_at", "provider_delay_seconds", "result", "severity", "risk_score", "classification"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([("'" + str(r.get(c)) if str(r.get(c) or "")[:1] in "=+-@" else r.get(c)) for c in cols])  # CSV-injection safe
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="cloudnexus-activity-{stamp}.csv"'})


# ------------------------------------------------------------------ anomalies (read-only detection; acknowledge = human note)
def _anomaly(a) -> dict:
    return {"id": a.id, "rule": a.rule, "severity": a.severity, "title": a.title, "provider": a.provider, "scope": a.scope_external_id, "scope_name": scope_label(object_session(a), a.provider, a.scope_external_id),
            "principal": a.principal, "detail": a.detail or {}, "event_ids": a.event_ids or [], "event_count": a.event_count,
            "first_event_at": a.first_event_at.isoformat() if a.first_event_at else None,
            "last_event_at": a.last_event_at.isoformat() if a.last_event_at else None, "status": a.status,
            "acknowledged_by": a.acknowledged_by, "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None, "note": a.note}


@router.get("/anomalies")
def anomalies(status: str | None = "OPEN", rule: str | None = None, provider: str | None = None, severity: str | None = None,
              hours: int = Query(168, ge=1, le=24 * 90), limit: int = Query(100, ge=1, le=500),
              db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    from app.models.platform import AuditAnomaly as A
    q = select(A).where(A.last_event_at >= datetime.now(UTC) - timedelta(hours=hours))
    for col, val in ((A.status, status), (A.rule, rule), (A.provider, provider), (A.severity, severity)):
        if val:
            q = q.where(col == val)
    rows = list(db.scalars(q.order_by(A.last_event_at.desc()).limit(limit)))
    counts = dict(db.execute(select(A.rule, func.count()).where(A.status == "OPEN", A.last_event_at >= datetime.now(UTC) - timedelta(hours=hours))
                             .group_by(A.rule)).all())
    run = db.scalar(select(AutomationJob).where(AutomationJob.name == "anomaly_detection"))
    return {"items": [_anomaly(a) for a in rows], "open_by_rule": counts,
            "last_run_at": run.last_finished_at.isoformat() if run and getattr(run, "last_finished_at", None) else None}


class AckIn(BaseModel):
    note: str = Field(min_length=3, max_length=2000)


@router.post("/anomalies/{aid}/acknowledge")
def acknowledge(aid: int, body: AckIn, db: Session = Depends(get_db), actor: User = Depends(require("audit:investigate"))):
    """Records that a person reviewed the anomaly, with their note. Nothing is changed in any cloud."""
    from app.api.deps import log_action
    from app.models.platform import AuditAnomaly as A
    a = db.get(A, aid)
    if a is None:
        raise HTTPException(404, "Anomaly not found")
    a.status, a.acknowledged_by, a.acknowledged_at, a.note = "ACKNOWLEDGED", actor.email, datetime.now(UTC), body.note
    log_action(db, actor.email, "audit_anomaly.acknowledge", str(aid), {"rule": a.rule})
    db.commit()
    return _anomaly(a)
