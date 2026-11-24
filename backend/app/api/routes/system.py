"""System health: is every workflow working, and if not, what exactly to fix. Read-only except for starting a pre-flight
run (which itself only reads)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import log_action, require_any
from app.core.security import require
from app.database.session import get_db
from app.models import AutomationExecutionLog, User
from app.services.connections_health import registry
from app.services.preflight import job_overview

router = APIRouter(prefix="/api/v1/system", tags=["system health"])


def _last_preflight(db: Session) -> dict | None:
    run = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == "preflight",
                                                         AutomationExecutionLog.status != "running").order_by(AutomationExecutionLog.id.desc()).limit(1))
    if run is None:
        return None
    rep = (run.summary or {}).get("preflight")
    if rep is None:  # the run itself crashed
        return {"verdict": "FAIL", "counts": {"PASS": 0, "WARN": 0, "FAIL": 1}, "generated_at": (run.finished_at or run.started_at).isoformat(),
                "checks": [{"area": "platform", "cloud": None, "scope": None, "check": "Pre-flight run", "status": "FAIL",
                            "message": run.error or "The pre-flight run did not finish", "fix": "Check the worker log for this run."}]}
    return rep


@router.get("/health")
def health(db: Session = Depends(get_db), _: User = Depends(require_any("automation:read", "inventory:read"))):
    jobs = job_overview(db)
    reg = registry(db)
    pre = _last_preflight(db)
    active = [j for j in jobs if j["enabled"]]
    failing = [j for j in active if j["last_status"] in ("failed", "partial")]
    verdict = "FAIL" if any(j["last_status"] == "failed" for j in active) or (pre and pre["verdict"] == "FAIL") else \
              "WARN" if failing or pre is None else "PASS"
    return {"verdict": verdict, "jobs": jobs, "jobs_failing": len(failing), "jobs_active": len(active),
            "clouds": reg["totals"], "scopes": [{k: it[k] for k in ("provider", "external_id", "name", "health", "authentication", "permissions")}
                                                | {"sources": {s: v["state"] for s, v in it["sources"].items()}} for it in reg["items"]],
            "preflight": pre}


@router.get("/preflight")
def preflight_result(db: Session = Depends(get_db), _: User = Depends(require_any("automation:read", "inventory:read"))):
    return _last_preflight(db) or {"verdict": "NOT_RUN", "counts": {}, "checks": [], "generated_at": None}


@router.post("/preflight")
async def preflight_run(db: Session = Depends(get_db), actor: User = Depends(require("automation:run"))):
    """Runs pre-flight now (read-only checks) and returns the result; the run is recorded like any other job run."""
    from app.workers.jobs import execute
    log_action(db, actor.email, "system.preflight", "preflight")
    db.commit()
    entry = await run_in_threadpool(execute, "preflight", "manual", actor.email)
    db.expire_all()
    return _last_preflight(db) or {"verdict": "FAIL", "checks": [], "counts": {}, "message": getattr(entry, "error", None)}
