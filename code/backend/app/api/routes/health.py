from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.logging import safe_error
from app.database.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health")
def health(settings: Settings = Depends(get_settings)):
    return {"status": "ok", "service": settings.app_name, "environment": settings.app_env}


@router.get("/health/ready")
def ready(response: Response, db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        tables = db.execute(text("SELECT count(*) FROM automation_jobs")).scalar()
        return {"status": "ready", "database": "ok", "job_catalogue": tables}
    except Exception as exc:  # noqa: BLE001
        response.status_code = 503
        return {"status": "not_ready", "database": safe_error(exc, 200)}
