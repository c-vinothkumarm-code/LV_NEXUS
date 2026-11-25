"""Integration and synchronization API: status, history, coverage, failures, retry, manual run, schedule, permissions."""
from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from croniter import croniter
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import log_action
from app.core.config import Settings, get_settings
from app.core.security import require
from app.database.session import get_db
from app.models import SCOPE_MODELS, AutomationJob, SyncCheckpoint, SyncRun, SyncStatus, User

router = APIRouter(prefix="/api/v1/sync", tags=["integration & synchronization"])
JOB = "security_findings_sync"
SOURCES = {"aws": ("security_hub", "AWS Security Hub CSPM"), "azure": ("azure_advisor", "Azure Advisor"), "gcp": ("scc", "Google Security Command Center")}
REQUIRED_PERMISSIONS = {
    "aws": ["securityhub:GetFindings, securityhub:DescribeHub, securityhub:ListMembers, securityhub:ListFindingAggregators, "
            "securityhub:GetFindingAggregator (administrator / aggregation account)",
            "sts:AssumeRole into each member account's read-only role (per-account mode)", "organizations:ListAccounts (discovery)",
            "ec2:DescribeRegions", "cloudtrail:LookupEvents (audit activity)"],
    "azure": ["Reader on each subscription (Azure Advisor recommendations are readable with Reader)",
              "Microsoft.ResourceGraph/resources/read (Resource Graph, management-group mapping)",
              "Management Group Reader at the tenant root group (optional: management-group names)",
              "Reader / Monitoring Reader for the Activity Log (audit activity)"],
    "gcp": ["roles/securitycenter.findingsViewer at the organization (or on each project when no organization access)",
            "roles/resourcemanager.organizationViewer and roles/browser (discovery)", "roles/logging.viewer (Cloud Audit Logs)",
            "Security Command Center API enabled; Premium/Enterprise tier for threat and vulnerability sources"],
}


def _iso(dt):
    return dt.isoformat() if dt else None


def rundict(r: SyncRun) -> dict:
    dur = ((r.finished_at if r.finished_at.tzinfo else r.finished_at.replace(tzinfo=UTC)) -
           (r.started_at if r.started_at.tzinfo else r.started_at.replace(tzinfo=UTC))).total_seconds() if r.finished_at else None
    return {"id": r.id, "trigger": r.trigger, "triggered_by": r.triggered_by, "mode": r.mode, "status": r.status, "started_at": r.started_at,
            "finished_at": r.finished_at, "duration_seconds": dur, "counts": r.counts or {}, "errors": r.errors or [], "execution_id": r.execution_id}


def _next_run(job: AutomationJob | None) -> str | None:
    if not job or not job.schedule or not job.enabled:
        return None
    tz = ZoneInfo(job.schedule_timezone or "UTC")
    return croniter(job.schedule, datetime.now(tz)).get_next(datetime).astimezone(UTC).isoformat()


@router.get("/status")
def status(db: Session = Depends(get_db), s: Settings = Depends(get_settings), _: User = Depends(require("sync:read"))):
    from app.services.connections import effective_settings
    eff = effective_settings(db, s)
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == JOB))
    last = db.scalar(select(SyncRun).order_by(SyncRun.id.desc()).limit(1))
    ok = db.scalar(select(SyncRun).where(SyncRun.status.in_([SyncStatus.COMPLETED.value, SyncStatus.PARTIALLY_COMPLETED.value])).order_by(SyncRun.id.desc()).limit(1))
    full_ok = db.scalar(select(SyncRun).where(SyncRun.status == SyncStatus.COMPLETED.value).order_by(SyncRun.id.desc()).limit(1))
    now = datetime.now(UTC)
    running = bool(job and job.lock_expires_at and (job.lock_expires_at if job.lock_expires_at.tzinfo else job.lock_expires_at.replace(tzinfo=UTC)) > now)
    integrations = []
    for p, (src, label) in SOURCES.items():
        enabled = getattr(eff, f"{p}_enabled")
        cps = db.scalars(select(SyncCheckpoint).where(SyncCheckpoint.provider == p, SyncCheckpoint.source == src)).all()
        states = {}
        for c in cps:
            states[c.state] = states.get(c.state, 0) + 1
        scopes = db.scalar(select(func.count()).select_from(SCOPE_MODELS[p])) or 0
        health = ("NOT_CONFIGURED" if not enabled else "NOT_YET_SYNCED" if not cps else "ACCESS_DENIED" if states.get("ACCESS_DENIED") and not states.get("OK")
                  else "PARTIALLY_CONFIGURED" if any(k != "OK" for k in states) else "OK")
        integrations.append({"provider": p, "source": src, "label": label, "enabled": enabled, "health": health, "checkpoint_states": states,
                             "scopes_in_inventory": scopes, "last_success_at": _iso(max((c.last_success_at for c in cps if c.last_success_at), default=None))})
    return {"schedule": {"cron": job.schedule if job else None, "timezone": job.schedule_timezone if job else "UTC", "enabled": bool(job and job.enabled)},
            "next_run_at": _next_run(job), "running": running, "last_run": rundict(last) if last else None,
            "last_successful_run": rundict(ok) if ok else None, "last_fully_successful_run": rundict(full_ok) if full_ok else None,
            "integrations": integrations}


@router.get("/history")
def history(page: int = Query(1, ge=1), page_size: int = Query(25, le=200), status: str | None = None, db: Session = Depends(get_db),
            _: User = Depends(require("sync:read"))):
    q = select(SyncRun)
    if status:
        q = q.where(SyncRun.status.in_(status.split(",")))
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    return {"total": total, "items": [rundict(r) for r in db.scalars(q.order_by(SyncRun.id.desc()).offset((page - 1) * page_size).limit(page_size))]}


@router.get("/runs/{rid}")
def run_detail(rid: int, db: Session = Depends(get_db), _: User = Depends(require("sync:read"))):
    r = db.get(SyncRun, rid)
    if r is None:
        raise HTTPException(404, "Run not found")
    return rundict(r)


def cpdict(c: SyncCheckpoint) -> dict:
    return {"provider": c.provider, "source": c.source, "scope": c.scope_external_id, "region": c.region, "state": c.state,
            "last_attempt_at": c.last_attempt_at, "last_success_at": c.last_success_at, "last_full_at": c.last_full_at, "watermark": c.watermark,
            "findings_seen": c.findings_seen, "consecutive_failures": c.consecutive_failures, "last_error": c.last_error}


@router.get("/coverage")
def coverage(provider: str | None = None, db: Session = Depends(get_db), _: User = Depends(require("sync:read"))):
    q = select(SyncCheckpoint).order_by(SyncCheckpoint.provider, SyncCheckpoint.scope_external_id, SyncCheckpoint.region)
    if provider:
        q = q.where(SyncCheckpoint.provider == provider)
    cps = db.scalars(q).all()
    covered = {(c.provider, c.scope_external_id) for c in cps}
    missing = []
    for p, model in SCOPE_MODELS.items():
        if provider and p != provider:
            continue
        for sc in db.scalars(select(model)):
            if (p, sc.external_id) not in covered and sc.onboarding_status != "Inactive":
                missing.append({"provider": p, "scope": sc.external_id, "name": sc.name, "onboarding_status": sc.onboarding_status,
                                "monitoring_enabled": sc.monitoring_enabled,
                                "reason": "Not eligible (onboarding incomplete or monitoring disabled)" if sc.onboarding_status not in ("Fully Onboarded", "Partially Onboarded") or not sc.monitoring_enabled
                                else "Covered through an aggregation / organization-level read, or not synced yet"})
    return {"checkpoints": [cpdict(c) for c in cps], "scopes_without_checkpoint": missing}


@router.get("/failed")
def failed(db: Session = Depends(get_db), _: User = Depends(require("sync:read"))):
    cps = db.scalars(select(SyncCheckpoint).where(SyncCheckpoint.state.not_in(["OK", "PENDING"])).order_by(SyncCheckpoint.consecutive_failures.desc())).all()
    runs = db.scalars(select(SyncRun).where(SyncRun.status.in_([SyncStatus.FAILED.value, SyncStatus.PARTIALLY_COMPLETED.value])).order_by(SyncRun.id.desc()).limit(20)).all()
    return {"failing_partitions": [cpdict(c) for c in cps], "runs": [rundict(r) for r in runs]}


@router.get("/permissions")
def permissions(db: Session = Depends(get_db), _: User = Depends(require("sync:read"))):
    out = []
    for p, perms in REQUIRED_PERMISSIONS.items():
        denied = db.scalars(select(SyncCheckpoint).where(SyncCheckpoint.provider == p, SyncCheckpoint.state == "ACCESS_DENIED")).all()
        not_enabled = db.scalars(select(SyncCheckpoint).where(SyncCheckpoint.provider == p, SyncCheckpoint.state.in_(["NOT_ENABLED", "PARTIALLY_CONFIGURED"]))).all()
        out.append({"provider": p, "label": SOURCES[p][1], "required": perms, "access_denied": [cpdict(c) for c in denied],
                    "not_enabled_or_partial": [cpdict(c) for c in not_enabled]})
    return {"items": out, "note": "All collection is read-only. Remediation permissions are never requested or used."}


def _start(db: Session, s: Settings, user: User, only: list[dict] | None, full: bool, background: BackgroundTasks) -> dict:
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == JOB))
    now = datetime.now(UTC)
    if job and job.lock_expires_at and (job.lock_expires_at if job.lock_expires_at.tzinfo else job.lock_expires_at.replace(tzinfo=UTC)) > now:
        raise HTTPException(409, "A security synchronization is already running; no second run was started")
    from app.database.session import get_session_factory
    from app.scheduler.engine import run_job
    from app.services.connections import effective_settings
    from app.services.vuln.sync import run_security_sync

    def go():
        run_job(get_session_factory(), JOB, lambda ctx: run_security_sync(ctx, effective_settings(ctx.db, s), trigger="manual", triggered_by=user.email,
                                                                        only=only, force_full=full),
                trigger="manual", triggered_by=user.email, lock_ttl=s.security_sync_lock_ttl_seconds)
    log_action(db, user.email, "sync.retry" if only else "sync.run", JOB, {"full": full, "partitions": len(only or [])})
    db.commit()
    background.add_task(go)
    return {"status": "accepted", "retry_partitions": len(only or []), "full": full}


class RunIn(BaseModel):
    full: bool = False


@router.post("/run", status_code=202)
def run_now(body: RunIn, background: BackgroundTasks, db: Session = Depends(get_db), s: Settings = Depends(get_settings),
            user: User = Depends(require("sync:run"))):
    return _start(db, s, user, None, body.full, background)


@router.post("/retry", status_code=202)
def retry(background: BackgroundTasks, db: Session = Depends(get_db), s: Settings = Depends(get_settings), user: User = Depends(require("sync:run"))):
    cps = db.scalars(select(SyncCheckpoint).where(SyncCheckpoint.state.in_(["ERROR", "ACCESS_DENIED"]))).all()
    if not cps:
        raise HTTPException(409, "Nothing to retry: no failed partitions")
    only = [{"provider": c.provider, "scope": "*" if c.scope_external_id == "integration" else c.scope_external_id,
             "region": None if c.region in ("global", "*") else c.region} for c in cps]
    return _start(db, s, user, only, False, background)


class ScheduleIn(BaseModel):
    cron: str
    enabled: bool = True


@router.put("/schedule")
def schedule(body: ScheduleIn, db: Session = Depends(get_db), user: User = Depends(require("security:admin"))):
    if not croniter.is_valid(body.cron):
        raise HTTPException(422, "Invalid cron expression")
    job = db.scalar(select(AutomationJob).where(AutomationJob.name == JOB))
    old = job.schedule
    job.schedule, job.enabled, job.schedule_timezone = body.cron, body.enabled, "UTC"
    log_action(db, user.email, "sync.schedule", JOB, {"from": old, "to": body.cron, "enabled": body.enabled})
    db.commit()
    return {"cron": job.schedule, "timezone": "UTC", "enabled": job.enabled, "next_run_at": _next_run(job)}
