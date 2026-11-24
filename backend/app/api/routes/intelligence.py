"""AI Intelligence Center API: Copilot, agents, recommendations and the human action workflow
(recommendation -> human review -> authorized approval -> execution by a person -> verification -> audit)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import log_action
from app.api.serializers import iso
from app.core.config import Settings, get_settings
from app.core.security import require
from app.database.session import get_db
from app.models import User
from app.models.ai import AIActionEvent, AIAgentRun, AIConversation, AIRecommendation
from app.services.ai.provider import build_provider
from app.services.intelligence import engine as I

router = APIRouter(prefix="/api/v1/ai", tags=["ai intelligence center"])


class AskBody(BaseModel):
    question: str = Field(min_length=2, max_length=2000)
    follow_up: bool | None = None  # None: detected from the wording ("and for AWS?", "why?")


@router.get("/status")
def status(settings: Settings = Depends(get_settings), user: User = Depends(require("ai:use"))):
    p = build_provider(settings)
    return {"model_configured": p is not None, "model": getattr(p, "model", None) if p else None,
            "tools": [{"name": t.name, "description": t.description, "available": t.permission in user.permission_names} for t in I.TOOLS],
            "agents": [{"key": k, "name": n, "available": perm in user.permission_names} for k, (n, perm) in I.AGENTS.items()],
            "policy": "The AI reads the platform's own records through permission-checked tools. It never changes any cloud resource, access or "
                      "budget; recommendations need human review, approval, execution by a person and verification."}


@router.post("/ask")
def ask(body: AskBody, db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(require("ai:use"))):
    out = I.ask(db, settings, user, body.question, body.follow_up)
    log_action(db, user.email, "ai.ask", str(out["id"]), {"tools": [r["tool"] for r in out["results"]], "denied": out["denied"],
                                                          "source": out["answer_source"]})
    db.commit()
    return out


@router.get("/conversations")
def conversations(db: Session = Depends(get_db), user: User = Depends(require("ai:use"))):
    rows = db.scalars(select(AIConversation).where(AIConversation.user_email == user.email).order_by(AIConversation.id.desc()).limit(50))
    return {"items": [{"id": c.id, "question": c.question, "answer": c.answer, "answer_source": c.answer_source, "tools": c.tools,
                       "at": iso(c.created_at)} for c in rows]}


@router.post("/agents/{agent}/run")
def run(agent: str, db: Session = Depends(get_db), user: User = Depends(require("ai:use"))):
    if agent not in I.AGENTS:
        raise HTTPException(404, "Unknown agent")
    name, perm = I.AGENTS[agent]
    if perm not in user.permission_names:
        raise HTTPException(403, f"{name} needs the {perm} permission")
    r = I.run_agent(db, agent, user)
    log_action(db, user.email, "ai.agent_run", agent, {"recommendations": r.recommendations})
    db.commit()
    return {"id": r.id, "agent": agent, "summary": r.summary, "recommendations": r.recommendations, "at": iso(r.created_at)}


@router.get("/runs")
def runs(db: Session = Depends(get_db), _: User = Depends(require("ai:use"))):
    return {"items": [{"id": r.id, "agent": r.agent, "started_by": r.started_by, "status": r.status, "summary": r.summary,
                       "recommendations": r.recommendations, "at": iso(r.created_at)} for r in db.scalars(select(AIAgentRun).order_by(AIAgentRun.id.desc()).limit(50))]}


def _rec(r: AIRecommendation) -> dict:
    return {"id": r.id, "agent": r.agent, "agent_name": I.AGENTS[r.agent][0], "title": r.title, "category": r.category, "priority": r.priority,
            "rationale": r.rationale, "evidence": r.evidence, "recommended_action": r.recommended_action, "action_type": r.action_type,
            "required_permission": r.required_permission, "confidence": r.confidence, "status": r.status, "reviewed_by": r.reviewed_by,
            "approved_by": r.approved_by, "executed_by": r.executed_by, "verification": r.verification, "created_at": iso(r.created_at)}


@router.get("/recommendations")
def recommendations(status: str | None = None, agent: str | None = None, db: Session = Depends(get_db), user: User = Depends(require("ai:use"))):
    stmt = select(AIRecommendation)
    if status:
        stmt = stmt.where(AIRecommendation.status == status)
    if agent:
        stmt = stmt.where(AIRecommendation.agent == agent)
    visible = {k for k, (_, perm) in I.AGENTS.items() if perm in user.permission_names}
    rows = [r for r in db.scalars(stmt.order_by(AIRecommendation.id.desc()).limit(500)) if r.agent in visible]
    return {"items": [_rec(r) for r in rows]}


@router.get("/recommendations/{rid}")
def recommendation(rid: int, db: Session = Depends(get_db), user: User = Depends(require("ai:use"))):
    r = _get(db, rid, user)
    hist = db.scalars(select(AIActionEvent).where(AIActionEvent.recommendation_id == r.id).order_by(AIActionEvent.id))
    return {**_rec(r), "history": [{"action": e.action, "actor": e.actor, "notes": e.notes, "at": iso(e.created_at)} for e in hist]}


def _get(db: Session, rid: int, user: User) -> AIRecommendation:
    r = db.get(AIRecommendation, rid)
    if r is None or I.AGENTS[r.agent][1] not in user.permission_names:
        raise HTTPException(404, "Recommendation not found")
    return r


class StepBody(BaseModel):
    action: str
    notes: str | None = Field(default=None, max_length=4000)


TRANSITIONS = {
    "dismiss": ("PROPOSED", "DISMISSED"), "accept": ("PROPOSED", "ACCEPTED"), "request_approval": ("PROPOSED", "APPROVAL_REQUESTED"),
    "approve": ("APPROVAL_REQUESTED", "APPROVED"), "reject": ("APPROVAL_REQUESTED", "REJECTED"), "executed": ("APPROVED", "EXECUTED"),
}


@router.post("/recommendations/{rid}/step")
def step(rid: int, body: StepBody, db: Session = Depends(get_db), user: User = Depends(require("ai:use"))):
    """Human steps only. 'executed' records that a person made the change outside LV NEXUS; it is then verified."""
    r = _get(db, rid, user)
    if body.action == "verify":
        if r.status != "EXECUTED":
            raise HTTPException(409, "Only executed recommendations can be verified")
        still = {x["dedup_key"] for x in I.generate(db, r.agent)[0]}
        r.status = "NOT_VERIFIED" if r.dedup_key in still else "VERIFIED"
        r.verification = ("The condition is still present in the latest data." if r.status == "NOT_VERIFIED"
                          else "The condition is no longer present in the latest synchronized data.")
        db.add(AIActionEvent(recommendation_id=r.id, action=r.status.lower(), actor=user.email, notes=r.verification))
        db.commit()
        return _rec(r)
    if body.action not in TRANSITIONS:
        raise HTTPException(422, f"action must be one of {', '.join([*TRANSITIONS, 'verify'])}")
    frm, to = TRANSITIONS[body.action]
    if r.status != frm:
        raise HTTPException(409, f"Recommendation is {r.status.lower()}")
    needs = r.required_permission
    if body.action in ("dismiss", "reject") and not (body.notes or "").strip():
        raise HTTPException(422, "A reason is required")
    if body.action == "accept" and needs:
        raise HTTPException(409, "This recommendation implies a change: request approval instead")
    if body.action == "request_approval" and not needs:
        raise HTTPException(409, "No change is implied; accept or dismiss it")
    if body.action in ("approve", "reject"):
        if needs not in user.permission_names:
            raise HTTPException(403, f"Approval needs the {needs} permission")
        if user.email == r.reviewed_by:
            raise HTTPException(403, "The reviewer who requested approval cannot approve it")
        r.approved_by = user.email
    if body.action == "executed":
        if needs and needs not in user.permission_names:
            raise HTTPException(403, f"Recording execution needs the {needs} permission")
        if not (body.notes or "").strip():
            raise HTTPException(422, "Describe the change that was made, where, and its change reference")
        r.executed_by = user.email
    if body.action in ("dismiss", "accept", "request_approval"):
        r.reviewed_by = user.email
    r.status = to
    db.add(AIActionEvent(recommendation_id=r.id, action=body.action, actor=user.email, notes=body.notes))
    log_action(db, user.email, f"ai.recommendation.{body.action}", str(r.id))
    db.commit()
    return _rec(r)
