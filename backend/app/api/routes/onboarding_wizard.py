"""Onboard a cloud: guided, read-only onboarding of AWS, Azure and Google Cloud (see services/onboarding/wizard.py).

Nothing here changes anything in a cloud. Generated scripts and templates are deployed by a cloud administrator;
LV NEXUS then verifies the result with read-only calls and is switched on only after a verification without failures."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.security import audit, require
from app.database.session import get_db
from app.models import User
from app.services import connections
from app.services.onboarding import wizard

router = APIRouter(prefix="/api/v1/onboarding/wizard", tags=["onboarding wizard"])
MANAGE = "connections:manage"


def _provider(provider: str) -> str:
    if provider not in wizard.PROVIDERS:
        raise HTTPException(404, "Unknown cloud provider")
    return provider


class InputsBody(BaseModel):
    config: dict[str, str | list[str] | None] = Field(default_factory=dict)
    inputs: dict[str, str | None] = Field(default_factory=dict)


class ExternalIdBody(BaseModel):
    rotate: bool = False


@router.get("")
def overview(db: Session = Depends(get_db), settings: Settings = Depends(get_settings), _: User = Depends(require("onboarding:read"))):
    return {"providers": wizard.overview(db, settings)}


@router.get("/{provider}")
def get_kit(provider: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(require("onboarding:read"))):
    try:
        return wizard.kit(db, _provider(provider), settings, can_manage=MANAGE in user.permission_names)
    except wizard.WizardError as exc:
        raise HTTPException(422, str(exc)) from None


@router.put("/{provider}/inputs")
def save_inputs(provider: str, body: InputsBody, db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(require(MANAGE))):
    provider = _provider(provider)
    try:
        wizard.save_inputs(db, provider, body.config, {k: v or "" for k, v in body.inputs.items()}, user.email)
    except (wizard.WizardError, connections.ConnectionError_) as exc:
        raise HTTPException(422, str(exc)) from None
    audit(db, user.email, "onboarding.inputs", provider, fields=sorted([*body.config, *body.inputs]))
    db.commit()
    return wizard.kit(db, provider, settings, can_manage=True)


@router.post("/aws/external-id")
def external_id(body: ExternalIdBody, db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(require(MANAGE))):
    """Creates the AWS external ID (kept if one is already in use). rotate=true replaces it: every member role must then be
    updated through the StackSet, otherwise AWS collection stops until it is."""
    _value, created = wizard.ensure_external_id(db, settings, user.email, rotate=body.rotate)
    audit(db, user.email, "onboarding.external_id", "aws", created=created, rotated=body.rotate)  # the value itself is never logged
    db.commit()
    return {"created": created, "rotated": body.rotate and created}


@router.get("/{provider}/files/{name}")
def download(provider: str, name: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(require(MANAGE))):
    provider = _provider(provider)
    try:
        text = wizard.render_file(db, provider, name, settings)
    except wizard.WizardError as exc:
        raise HTTPException(404, str(exc)) from None
    audit(db, user.email, "onboarding.download", f"{provider}:{name}")
    db.commit()
    return PlainTextResponse(text, headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


@router.post("/{provider}/verify")
def verify(provider: str, db: Session = Depends(get_db), settings: Settings = Depends(get_settings), user: User = Depends(require(MANAGE))):
    provider = _provider(provider)
    try:
        result = wizard.verify(db, provider, settings, user.email)
    except wizard.WizardError as exc:
        raise HTTPException(409, str(exc)) from None
    audit(db, user.email, "onboarding.verify", provider, status=result["status"])
    db.commit()
    return result


@router.post("/{provider}/activate")
def activate(provider: str, background: BackgroundTasks, db: Session = Depends(get_db), user: User = Depends(require(MANAGE))):
    provider = _provider(provider)
    try:
        wizard.activate(db, provider, user.email)
    except wizard.WizardError as exc:
        raise HTTPException(409, str(exc)) from None
    audit(db, user.email, "onboarding.activate", provider)
    db.commit()
    from app.workers.run import JOBS
    if "account_discovery" in JOBS:  # first discovery now instead of waiting for the schedule
        background.add_task(JOBS["account_discovery"], "manual", user.email)
    return {"provider": provider, "enabled": True, "discovery": "started"}
