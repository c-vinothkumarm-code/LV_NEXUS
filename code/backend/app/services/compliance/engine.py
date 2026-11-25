"""Run the compliance policy library, store results, compute scores.

Score of a framework = severity-weighted share of assessed (policy, scope) results that pass, over the policies mapped
to that framework. NOT_ASSESSED results never count as passing: they lower the coverage figure shown next to the
score instead. A check that crashes is recorded as NOT_ASSESSED with the error, so one bad check cannot hide the rest."""
from __future__ import annotations

import logging
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import JobStatus, utcnow
from app.models.compliance import CompliancePolicySetting, ComplianceResult, ComplianceRun
from app.scheduler.engine import JobContext, JobResult

from . import checks as C
from .library import FRAMEWORKS, POLICIES, SEVERITY_WEIGHT

log = logging.getLogger(__name__)


def settings_map(db: Session) -> dict[str, CompliancePolicySetting]:
    return {s.policy_key: s for s in db.scalars(select(CompliancePolicySetting))}


def effective(policy, setting: CompliancePolicySetting | None) -> dict:
    return {"enabled": setting.enabled if setting else True, "severity": (setting.severity if setting and setting.severity else policy.severity),
            "params": {**policy.params, **((setting.params or {}) if setting else {})}}


def evaluate(db: Session, settings: Settings, trigger: str = "schedule", triggered_by: str | None = None) -> ComplianceRun:
    run = ComplianceRun(trigger=trigger, triggered_by=triggered_by, started_at=utcnow())
    db.add(run)
    db.flush()
    ctx = C.Ctx(db, settings)
    sets = settings_map(db)
    totals = defaultdict(int)
    for pol in POLICIES:
        eff = effective(pol, sets.get(pol.key))
        if not eff["enabled"]:
            continue
        try:
            if pol.check == "attestation":
                rows = C.attestation(ctx, pol, eff["params"], sets.get(pol.key))
            else:
                rows = C.CHECKS[pol.check](ctx, pol, eff["params"])
        except Exception as exc:  # noqa: BLE001 - recorded, never hidden
            log.exception("compliance check %s failed", pol.key)
            from app.core.logging import safe_error
            rows = [C.r("platform", "platform", C.NA, f"Check could not run: {safe_error(exc)[:300]}", basis="error")]
        for x in rows:
            totals[x["status"]] += 1
            db.add(ComplianceResult(run_id=run.id, policy_key=pol.key, provider=x["provider"], scope_external_id=str(x["scope"])[:128],
                                    scope_name=ctx.name(x["provider"], x["scope"])[:255] if x["scope"] != "*" else "all scopes",
                                    status=x["status"], severity=eff["severity"], failing=x["failing"], assessed=x["assessed"],
                                    detail=x["detail"], evidence=x["evidence"], basis=x["basis"]))
    db.flush()
    run.totals = dict(totals)
    run.scores = scores(db, run.id)
    run.finished_at = utcnow()
    return run


def policy_status(rows: list) -> str:
    st = {r.status for r in rows}
    return "FAIL" if "FAIL" in st else "PASS" if "PASS" in st else "NOT_ASSESSED"


def scores(db: Session, run_id: int) -> dict:
    by_policy = defaultdict(list)
    for r in db.scalars(select(ComplianceResult).where(ComplianceResult.run_id == run_id)):
        by_policy[r.policy_key].append(r)
    out = {}
    for fk in FRAMEWORKS:
        mapped = [p for p in POLICIES if fk in p.refs and p.key in by_policy]
        got = possible = 0
        passed = failed = na = 0
        for p in mapped:
            for r in by_policy[p.key]:
                w = SEVERITY_WEIGHT.get(r.severity, 1)
                if r.status == "NOT_ASSESSED":
                    na += 1
                    continue
                possible += w
                if r.status == "PASS":
                    got += w
                    passed += 1
                else:
                    failed += 1
        total = passed + failed + na
        out[fk] = {"score": round(100 * got / possible, 1) if possible else None, "coverage": round(100 * (passed + failed) / total, 1) if total else 0.0,
                   "policies": len(mapped), "results_pass": passed, "results_fail": failed, "results_not_assessed": na,
                   "policies_failing": sum(1 for p in mapped if policy_status(by_policy[p.key]) == "FAIL")}
    return out


def latest_run(db: Session) -> ComplianceRun | None:
    return db.scalar(select(ComplianceRun).where(ComplianceRun.finished_at.is_not(None)).order_by(ComplianceRun.id.desc()).limit(1))


def run_compliance_job(ctx: JobContext, settings: Settings) -> JobResult:
    run = evaluate(ctx.db, settings, "schedule")
    ctx.db.commit()
    errors = [r for r in ctx.db.scalars(select(ComplianceResult).where(ComplianceResult.run_id == run.id, ComplianceResult.basis == "error"))]
    failures = [{"provider": "platform", "scope": r.policy_key, "reason": r.detail} for r in errors]
    summary = {"run_id": run.id, "totals": run.totals, "scores": {k: v["score"] for k, v in (run.scores or {}).items()}}
    return JobResult(JobStatus.PARTIAL if failures else JobStatus.SUCCESS, len(POLICIES), len(failures), summary, failures)

