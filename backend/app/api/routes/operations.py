"""Analyst and FinOps actions: security review decisions and budget management."""
from __future__ import annotations

from datetime import date
from decimal import Decimal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.serializers import iso
from app.core.config import Settings, get_settings
from app.core.security import audit, require
from app.database.session import get_db
from app.models import BillingBudget, ReviewStatus, SecurityFinding, SecurityReview, User
from app.services import connections
from app.services.finops import analysis
from app.services.insights import AUDIT_SOURCE
from app.services.soc.engine import record_review

router = APIRouter(prefix="/api/v1", tags=["operations"])


class ReviewBody(BaseModel):
    status: ReviewStatus
    notes: str | None = Field(default=None, max_length=4000)
    evidence_reference: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def _needs_notes(self):
        decisive = {ReviewStatus.CONFIRMED_LEGITIMATE, ReviewStatus.CONFIRMED_SUSPICIOUS, ReviewStatus.CLOSED}
        if self.status in decisive and not (self.notes or "").strip():
            raise ValueError("Notes are required when confirming or closing a finding")
        return self


class BudgetBody(BaseModel):
    provider: str = Field(pattern="^(aws|gcp|azure)$")
    scope_external_id: str = Field(default="*", max_length=128)
    service: str = Field(default="*", max_length=255)
    period_start: date
    period_end: date
    amount: Decimal = Field(gt=0)
    currency: str = Field(default="USD", pattern="^(USD|INR)$")
    threshold_info: int = Field(default=70, ge=1, le=1000)
    threshold_warning: int = Field(default=80, ge=1, le=1000)
    threshold_high: int = Field(default=90, ge=1, le=1000)
    threshold_exceeded: int = Field(default=100, ge=1, le=1000)

    @model_validator(mode="after")
    def _ordered(self):
        if self.period_end < self.period_start:
            raise ValueError("period_end is before period_start")
        if not self.threshold_info <= self.threshold_warning <= self.threshold_high <= self.threshold_exceeded:
            raise ValueError("Thresholds must be in ascending order")
        return self


@router.get("/soc/findings/{finding_id}")
def finding_detail(finding_id: int, db: Session = Depends(get_db), _: User = Depends(require("soc:read"))):
    f = db.get(SecurityFinding, finding_id)
    if f is None:
        raise HTTPException(404, "Finding not found")
    reviews = db.scalars(select(SecurityReview).where(SecurityReview.finding_id == f.id).order_by(SecurityReview.id)).all()
    return {"id": f.id, "provider": f.provider, "scope": f.scope_external_id, "rule_id": f.rule_id, "title": f.title, "severity": f.severity,
            "risk_score": f.risk_score, "principal": f.principal, "resource_id": f.resource_id, "evidence": f.evidence,
            "ai_analysis": f.ai_analysis, "recommended_action": f.recommended_action, "review_status": f.review_status,
            "occurrence_count": f.occurrence_count, "first_seen_at": iso(f.first_seen_at), "last_seen_at": iso(f.last_seen_at),
            "updated_at": iso(f.updated_at), "source": AUDIT_SOURCE.get(f.provider),
            "reviews": [{"id": r.id, "previous_status": r.previous_status, "new_status": r.new_status, "reviewer": r.reviewer, "notes": r.notes,
                         "evidence_reference": r.evidence_reference, "created_at": iso(r.created_at)} for r in reviews]}


@router.post("/soc/findings/{finding_id}/review")
def review_finding(finding_id: int, body: ReviewBody, db: Session = Depends(get_db), user: User = Depends(require("soc:review"))):
    """Records an analyst's decision. This is the only way a finding's review status changes."""
    f = db.get(SecurityFinding, finding_id)
    if f is None:
        raise HTTPException(404, "Finding not found")
    record_review(db, f, body.status, user.email, body.notes, body.evidence_reference)
    audit(db, user.email, "finding.review", f"finding:{f.id}", status=body.status.value)
    db.commit()
    return {"id": f.id, "review_status": f.review_status}


@router.get("/finops/budgets")
def list_budgets(db: Session = Depends(get_db), _: User = Depends(require("finops:read"))):
    return {"items": analysis.budget_status(db)}


@router.post("/finops/budgets", status_code=201)
def upsert_budget(body: BudgetBody, db: Session = Depends(get_db), user: User = Depends(require("finops:manage"))):
    b = db.scalar(select(BillingBudget).where(BillingBudget.provider == body.provider, BillingBudget.scope_external_id == body.scope_external_id,
                                              BillingBudget.service == body.service, BillingBudget.period_start == body.period_start))
    if b is None:
        b = BillingBudget(provider=body.provider, scope_external_id=body.scope_external_id, service=body.service, period_start=body.period_start)
        db.add(b)
    for k, v in body.model_dump().items():
        setattr(b, k, v)
    b.approved_by = user.email
    audit(db, user.email, "budget.upsert", f"{body.provider}:{body.scope_external_id}:{body.service}", amount=str(body.amount), currency=body.currency)
    db.commit()
    return {"id": b.id}


class ConnectionBody(BaseModel):
    enabled: bool = False
    config: dict[str, str | list[str] | None] = Field(default_factory=dict)


def _provider(provider: str) -> str:
    if provider not in connections.FIELDS:
        raise HTTPException(404, "Unknown cloud provider")
    return provider


@router.get("/connections")
def list_connections(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), _: User = Depends(require("onboarding:read"))):
    return {"providers": connections.describe(db, settings)}


@router.put("/connections/{provider}")
def save_connection(provider: str, body: ConnectionBody, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                    user: User = Depends(require("connections:manage"))):
    """Saves identifiers for one cloud. No credential is accepted here, and nothing is changed in the cloud."""
    provider = _provider(provider)
    try:
        conn = connections.save(db, provider, body.enabled, body.config, keep_sensitive=True, actor=user.email)
    except connections.ConnectionError_ as exc:
        raise HTTPException(422, str(exc)) from None
    audit(db, user.email, "connection.save", provider, enabled=body.enabled, fields=sorted(conn.config))
    db.commit()
    return next(p for p in connections.describe(db, settings) if p["provider"] == provider)


@router.post("/connections/{provider}/test")
def test_connection(provider: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings),
                    user: User = Depends(require("connections:manage"))):
    provider = _provider(provider)
    result = connections.test_connection(db, provider, settings)
    audit(db, user.email, "connection.test", provider, ok=result["ok"])
    db.commit()
    return result
