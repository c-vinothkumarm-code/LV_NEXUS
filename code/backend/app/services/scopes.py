"""Scopes that scheduled collectors work on: only those validated as onboarded."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import SCOPE_MODELS
from app.services.onboarding.status import AUTOMATION_ELIGIBLE


def eligible_scopes(db: Session, provider: str) -> list:
    model = SCOPE_MODELS[provider]
    return list(db.scalars(select(model).where(model.onboarding_status.in_(AUTOMATION_ELIGIBLE),
                                               model.monitoring_enabled.is_(True)).order_by(model.external_id)))


def check_passed(row, check: str) -> bool:
    return ((row.checks or {}).get(check) or {}).get("status") == "pass"
