from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.core.security import audit, require
from app.database.session import get_db
from app.models import User
from app.workers.run import JOBS

router = APIRouter(prefix="/api/v1", tags=["jobs"])
log = logging.getLogger(__name__)


@router.post("/jobs/{job_name}/run", status_code=202)
def run_job_now(job_name: str, background: BackgroundTasks, db: Session = Depends(get_db),
                user: User = Depends(require("automation:run"))):
    if job_name not in JOBS:
        raise HTTPException(404, "Job is not implemented yet")
    audit(db, user.email, "job.run", job_name)
    db.commit()
    background.add_task(JOBS[job_name], "manual", user.email)
    return {"status": "accepted", "job": job_name}


@router.post("/events/pubsub", status_code=202)
def pubsub_push(request: Request, background: BackgroundTasks, settings: Settings = Depends(get_settings)):
    """Event-driven discovery: a Pub/Sub push subscription (e.g. fed by an org-level log sink for
    project/account/subscription creation) triggers an immediate discovery run. The push request must
    carry a Google-signed OIDC token for the configured audience and service account."""
    if not settings.pubsub_push_audience:
        raise HTTPException(503, "Pub/Sub push is not configured")
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(401, "Missing bearer token")
    import google.auth.transport.requests
    from google.oauth2 import id_token

    try:
        claims = id_token.verify_oauth2_token(auth[7:], google.auth.transport.requests.Request(),
                                              settings.pubsub_push_audience)
    except Exception:  # noqa: BLE001
        raise HTTPException(401, "Invalid token") from None
    if settings.pubsub_push_service_account and claims.get("email") != settings.pubsub_push_service_account:
        raise HTTPException(403, "Unexpected caller")
    background.add_task(JOBS["account_discovery"], "event", "pubsub")
    return {"status": "accepted"}
