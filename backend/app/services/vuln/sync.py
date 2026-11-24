"""Daily native security findings synchronization (AWS Security Hub, Azure Advisor, Google SCC).

Rules this module enforces:
  * internal_status, owner, analyst, comments, evidence, exceptions and history are never overwritten by a sync;
    the only internal change a sync can make is the recorded reappearance rule (RESOLVED -> REOPENED);
  * a failed or denied call is recorded as an error and never read as "zero findings";
  * a finding missing from one response is not deleted; it is marked natively resolved only by the provider's own
    state or by an authoritative full listing (Azure Advisor);
  * one failing account / subscription / project / region does not stop the run; progress is committed per partition.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import CloudProject, CloudSecurityFinding, JobStatus, SyncCheckpoint, SyncRun, SyncStatus
from app.scheduler.engine import JobContext, JobResult
from app.services.scopes import eligible_scopes

from .common import Coverage, NormalizedFinding, Partition, classify, id_hash
from .lifecycle import apply_sla, history
from .notify import notify

log = logging.getLogger(__name__)
NATIVE_FIELDS = ("source", "is_security", "scope_external_id", "organization_id", "parent_id", "region", "resource_id", "resource_name",
                 "resource_type", "resource_group", "title", "description", "severity", "category", "finding_type", "compliance_standard",
                 "control_id", "remediation", "remediation_url", "native_workflow_status", "native_record_state", "mute_state",
                 "last_observed_at", "native_updated_at")
STATE_FOR_KIND = {"permission": "ACCESS_DENIED", "not_enabled": "NOT_ENABLED", "throttle": "ERROR", "error": "ERROR"}
REAPPEAR_GRACE = timedelta(hours=24)


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(dt):
    return dt.replace(tzinfo=UTC) if dt is not None and dt.tzinfo is None else dt


def build_collectors(db: Session, s: Settings) -> list:
    from .collectors import AzureAdvisorCollector, SccCollector, SecurityHubCollector
    out: list = []
    if s.aws_enabled:
        from app.services.aws.connector import AwsConnector
        out.append(SecurityHubCollector(s, AwsConnector(s)))
    if s.azure_enabled:
        from app.services.azure.rest import AzureRest

        from .azure_extra import AzurePolicyCollector, DefenderAlertCollector, DefenderAssessmentCollector, advisor_pairs
        rest = AzureRest(s)
        out += [AzureAdvisorCollector(s), DefenderAssessmentCollector(s, rest, advisor_pairs(db)), DefenderAlertCollector(s, rest),
                AzurePolicyCollector(s, rest)]
    if s.gcp_enabled:
        numbers = {p.project_number: p.external_id for p in db.scalars(select(CloudProject)) if p.project_number}
        out.append(SccCollector(s, project_numbers=numbers))
    return out


class _Run:
    def __init__(self):
        self.c = defaultdict(int)
        self.by_provider: dict = defaultdict(lambda: defaultdict(set))
        self.new_crit_high: list[CloudSecurityFinding] = []
        self.errors: list[dict] = []
        self.ok_partitions = 0


def _checkpoint(db: Session, provider: str, source: str, scope: str, region: str) -> SyncCheckpoint:
    cp = db.scalar(select(SyncCheckpoint).where(SyncCheckpoint.provider == provider, SyncCheckpoint.source == source,
                                                SyncCheckpoint.scope_external_id == scope, SyncCheckpoint.region == region))
    if cp is None:
        cp = SyncCheckpoint(provider=provider, source=source, scope_external_id=scope, region=region, state="PENDING")
        db.add(cp)
        db.flush()
    return cp


def upsert(db: Session, s: Settings, nf: NormalizedFinding, run: _Run) -> CloudSecurityFinding | None:
    h = id_hash(nf.native_id)
    row = db.scalar(select(CloudSecurityFinding).where(CloudSecurityFinding.provider == nf.provider, CloudSecurityFinding.native_id_hash == h))
    t = _now()
    run.c["retrieved"] += 1
    if nf.region:
        run.by_provider[nf.provider]["locations"].add(nf.region)
    if nf.scope_external_id:
        run.by_provider[nf.provider]["scopes_with_findings"].add(nf.scope_external_id)
    if row is None:
        if nf.native_state != "ACTIVE":
            run.c["skipped_inactive"] += 1  # already fixed / suppressed before we ever saw it: nothing to track
            return None
        row = CloudSecurityFinding(provider=nf.provider, native_id=nf.native_id, native_id_hash=h, native_state="ACTIVE", raw=nf.raw,
                                   first_observed_at=nf.first_observed_at, first_synced_at=t, last_synced_at=t,
                                   internal_status="OPEN", **{f: getattr(nf, f) for f in NATIVE_FIELDS})
        db.add(row)
        db.flush()
        history(db, row, "internal_status", None, "OPEN", "sync", f"Imported from {nf.source}")
        if row.is_security:
            apply_sla(db, row)
        run.c["new"] += 1
        if row.is_security and row.severity in ("Critical", "High"):
            run.new_crit_high.append(row)
            notify(db, "new_critical_finding" if row.severity == "Critical" else "new_high_finding", f"f{row.id}",
                   f"[LV NEXUS] New {row.severity} finding: {row.title[:150]}",
                   f"{row.provider.upper()} {row.scope_external_id} {row.region or ''}\nResource: {row.resource_id or '-'}\n"
                   f"Source: {row.source}\nRemediation: {(row.remediation or '-')[:800]}")
        return row

    changed = False
    old_sev, old_state = row.severity, row.native_state
    for f in NATIVE_FIELDS:
        v = getattr(nf, f)
        if v is not None and getattr(row, f) != v:
            setattr(row, f, v)
            changed = True
    if nf.first_observed_at and not row.first_observed_at:
        row.first_observed_at = nf.first_observed_at
    row.raw, row.last_synced_at = nf.raw, t
    if row.severity != old_sev:
        history(db, row, "severity", old_sev, row.severity, "sync", "Severity changed by the provider")
        apply_sla(db, row, reason="Severity changed by the provider")
    if nf.native_state != old_state:
        changed = True
        row.native_state = nf.native_state
        history(db, row, "native_state", old_state, nf.native_state, "sync", f"Reported by {nf.source}")
        if nf.native_state == "RESOLVED":
            row.native_resolved_at = t
            run.c["resolved"] += 1
        elif nf.native_state == "ACTIVE" and old_state == "RESOLVED":
            row.native_resolved_at = None
            run.c["reappeared"] += 1
            _reappeared(db, s, row, "The provider reports the issue as active again")
    elif (nf.native_state == "ACTIVE" and row.internal_status == "RESOLVED" and row.resolved_at and nf.last_observed_at
          and _aware(nf.last_observed_at) > _aware(row.resolved_at) + REAPPEAR_GRACE):
        run.c["reappeared"] += 1
        _reappeared(db, s, row, "Still observed by the provider more than 24 hours after it was marked resolved")
    if changed:
        run.c["updated"] += 1
    return row


def _reappeared(db: Session, s: Settings, row: CloudSecurityFinding, reason: str) -> None:
    row.needs_reassessment = True
    if row.internal_status == "RESOLVED" and s.security_reopen_on_reappear:
        history(db, row, "internal_status", "RESOLVED", "REOPENED", "sync", f"Reconciliation rule: {reason}")
        row.internal_status, row.reopen_count = "REOPENED", (row.reopen_count or 0) + 1
        notify(db, "finding_reappeared", f"f{row.id}-r{row.reopen_count}", f"[LV NEXUS] Resolved finding reappeared: {row.title[:150]}",
               f"Finding #{row.id} ({row.severity}) on {row.provider.upper()} {row.scope_external_id} was reopened.\n{reason}\n"
               f"Owner: {row.owner or 'unassigned'}")


def _resolve_absent(db: Session, provider: str, source: str, scope: str, seen: set[str], run: _Run) -> None:
    """Only for providers whose complete listing is authoritative (Advisor deletes fixed recommendations)."""
    q = select(CloudSecurityFinding).where(CloudSecurityFinding.provider == provider, CloudSecurityFinding.source == source,
                                           CloudSecurityFinding.scope_external_id == scope, CloudSecurityFinding.native_state == "ACTIVE")
    for row in db.scalars(q):
        if row.native_id_hash not in seen:
            history(db, row, "native_state", "ACTIVE", "RESOLVED", "sync", "No longer returned by a complete, successful provider listing")
            row.native_state, row.native_resolved_at = "RESOLVED", _now()
            run.c["resolved"] += 1


def _record_error(db, run: _Run, cp: SyncCheckpoint, provider: str, exc: Exception) -> None:
    kind, msg = classify(exc)
    cp.state, cp.last_error, cp.last_attempt_at = STATE_FOR_KIND[kind], msg, _now()
    cp.consecutive_failures = (cp.consecutive_failures or 0) + 1
    run.errors.append({"provider": provider, "source": cp.source, "scope": cp.scope_external_id, "region": cp.region, "kind": kind, "message": msg})
    run.by_provider[provider]["failed_scopes"].add(cp.scope_external_id)
    run.by_provider[provider]["failed_regions"].add(f"{cp.scope_external_id}/{cp.region}")
    log.warning("security sync %s %s/%s: %s", provider, cp.scope_external_id, cp.region, msg)


def _run_partition(db: Session, s: Settings, collector, part: Partition, run: _Run, force_full: bool) -> None:
    cp = _checkpoint(db, collector.provider, collector.source, part.scope, part.region)
    full_due = cp.last_full_at is None or _aware(cp.last_full_at) < _now() - timedelta(days=s.security_sync_full_every_days)
    full = force_full or full_due or cp.watermark is None or part.absence_resolves
    since = None if full else _aware(cp.watermark) - timedelta(minutes=s.security_sync_overlap_minutes)
    started, seen, n = _now(), set(), 0
    from app.services import reliability as rel
    try:
        skip = rel.scope_gate(collector.provider)
        if skip:
            raise rel.CircuitOpen(collector.provider, skip)
        for nf in part.fetch(since):
            upsert(db, s, nf, run)
            seen.add(id_hash(nf.native_id))
            n += 1
            if n % 500 == 0:
                db.commit()  # long listings: keep progress, release locks
    except Exception as exc:  # noqa: BLE001 - recorded, run continues with the next partition
        db.rollback()
        cp = _checkpoint(db, collector.provider, collector.source, part.scope, part.region)
        rel.scope_failed(collector.provider, exc)
        _record_error(db, run, cp, collector.provider, exc)
        db.commit()
        return
    rel.scope_ok(collector.provider)
    if part.absence_resolves:
        _resolve_absent(db, collector.provider, collector.source, part.scope, seen, run)
    cp.state, cp.last_error, cp.consecutive_failures = "OK", None, 0
    cp.last_attempt_at = cp.last_success_at = _now()
    cp.watermark, cp.findings_seen = started, n
    if full:
        cp.last_full_at = started
    run.ok_partitions += 1
    run.by_provider[collector.provider]["scopes_ok"].add(part.scope)
    run.by_provider[collector.provider]["regions_ok"].add(f"{part.scope}/{part.region}")
    db.commit()


def _apply_coverage(db: Session, collector, facts: list[Coverage], run: _Run) -> None:
    for c in facts:
        cp = _checkpoint(db, collector.provider, collector.source, c.scope, c.region)
        cp.state, cp.last_attempt_at = c.state, _now()
        cp.last_error = None if c.state == "OK" else c.message
        if c.state == "OK":
            run.by_provider[collector.provider]["scopes_ok"].add(c.scope)
        else:
            run.by_provider[collector.provider]["coverage_gaps"].add(f"{c.scope}: {c.message}")
            if c.state == "ACCESS_DENIED":
                run.errors.append({"provider": collector.provider, "source": collector.source, "scope": c.scope, "region": c.region,
                                   "kind": "permission", "message": c.message})


def run_security_sync(ctx: JobContext, s: Settings, collectors: list | None = None, *, trigger: str = "schedule",
                      triggered_by: str | None = None, only: list[dict] | None = None, force_full: bool = False) -> JobResult:
    db = ctx.db
    for stale in db.scalars(select(SyncRun).where(SyncRun.status.in_([SyncStatus.RUNNING.value, SyncStatus.RETRYING.value]))):
        stale.status, stale.finished_at = SyncStatus.FAILED.value, _now()
        stale.errors = [*(stale.errors or []), {"kind": "error", "message": "Abandoned: the process stopped before the run finished"}]
    sync = SyncRun(execution_id=ctx.execution_id, trigger="retry" if only else trigger, triggered_by=triggered_by,
                   mode="retry" if only else ("full" if force_full else "incremental"),
                   status=SyncStatus.RETRYING.value if only else SyncStatus.RUNNING.value, started_at=_now())
    db.add(sync)
    db.commit()
    collectors = build_collectors(db, s) if collectors is None else collectors
    run = _Run()
    if not collectors:
        sync.status, sync.finished_at = SyncStatus.FAILED.value, _now()
        sync.errors = [{"kind": "not_configured", "message": "No security integration is enabled (AWS_ENABLED / AZURE_ENABLED / GCP_ENABLED)"}]
        db.commit()
        return JobResult(JobStatus.FAILED, summary={"sync_run": sync.id}, failures=[{"provider": "*", "scope": "*", "reason": sync.errors[0]["message"]}])
    wanted = {(o["provider"], o["scope"], o.get("region")) for o in only or []}
    for col in collectors:
        scopes = eligible_scopes(db, col.provider)
        if only:
            scopes = [x for x in scopes if any(p == col.provider and sc in (x.external_id, "*") for p, sc, _ in wanted)] or scopes
        by_id = {x.external_id: x for x in scopes}
        run.by_provider[col.provider]["scopes_total"] |= set(by_id)
        try:
            parts, facts = col.plan(scopes)
        except Exception as exc:  # noqa: BLE001 - whole integration unreachable
            db.rollback()
            cp = _checkpoint(db, col.provider, col.source, "integration", "global")
            _record_error(db, run, cp, col.provider, exc)
            db.commit()
            continue
        _apply_coverage(db, col, facts, run)
        db.commit()
        for part in parts:
            if part.fetch is None and part.region == "*":  # per-account Security Hub: expand into enabled regions
                try:
                    expanded = col.expand(part, by_id[part.scope])
                except Exception as exc:  # noqa: BLE001 - e.g. role cannot be assumed
                    db.rollback()
                    _record_error(db, run, _checkpoint(db, col.provider, col.source, part.scope, "global"), col.provider, exc)
                    db.commit()
                    continue
            else:
                expanded = [part]
            for p in expanded:
                if only and not any(pv == col.provider and sc in (p.scope, "*") and rg in (None, p.region) for pv, sc, rg in wanted):
                    continue
                _run_partition(db, s, col, p, run, force_full)

    total_parts = run.ok_partitions + len({(e["provider"], e["scope"], e["region"]) for e in run.errors if e["kind"] != "permission" or e["region"]})
    status = (SyncStatus.COMPLETED if not run.errors else SyncStatus.FAILED if run.ok_partitions == 0 else SyncStatus.PARTIALLY_COMPLETED)
    per = {}
    for prov, d in run.by_provider.items():
        per[prov] = {"scopes_total": len(d["scopes_total"]), "scopes_processed": len(d["scopes_ok"] - d["failed_scopes"]),
                     "scopes_failed": sorted(d["failed_scopes"]), "regions_processed": len(d["regions_ok"]), "regions_failed": sorted(d["failed_regions"]),
                     "locations_seen": sorted(d["locations"]), "coverage_gaps": sorted(d["coverage_gaps"])}
    kinds = defaultdict(int)
    for e in run.errors:
        kinds[e["kind"]] += 1
    base = {k: 0 for k in ("retrieved", "new", "updated", "resolved", "reappeared", "skipped_inactive")}
    sync.counts = {**base, **dict(run.c), "providers": per, "permission_errors": kinds["permission"], "throttling_errors": kinds["throttle"],
                   "not_enabled": kinds["not_enabled"], "other_errors": kinds["error"], "partitions_ok": run.ok_partitions,
                   "new_critical_high": len(run.new_crit_high)}
    sync.errors, sync.status, sync.finished_at = run.errors, status.value, _now()
    db.commit()
    _summary_notifications(db, sync)
    db.commit()
    job_status = {SyncStatus.COMPLETED: JobStatus.SUCCESS, SyncStatus.PARTIALLY_COMPLETED: JobStatus.PARTIAL}.get(status, JobStatus.FAILED)
    return JobResult(job_status, scopes_total=total_parts, scopes_failed=len(run.errors), summary={"sync_run": sync.id, **sync.counts},
                     failures=[{"provider": e["provider"], "scope": f"{e['scope']}/{e['region']}", "reason": f"{e['kind']}: {e['message']}"} for e in run.errors])


def _summary_notifications(db: Session, sync: SyncRun) -> None:
    c = sync.counts or {}
    dur = (_aware(sync.finished_at) - _aware(sync.started_at)).total_seconds() if sync.finished_at else 0
    lines = [f"SYNC STATUS: {sync.status}", f"Started {sync.started_at:%Y-%m-%d %H:%M} UTC, duration {dur / 60:.1f} min", ""]
    for prov, d in (c.get("providers") or {}).items():
        lines.append(f"{prov.upper()}: {d['scopes_processed']}/{d['scopes_total']} scopes, {d['regions_processed']} regions/locations OK"
                     + (f", FAILED: {', '.join(d['regions_failed'][:10])}" if d["regions_failed"] else "")
                     + (f"; gaps: {'; '.join(d['coverage_gaps'][:5])}" if d["coverage_gaps"] else ""))
    lines += ["", f"Findings retrieved {c.get('retrieved', 0)}, new {c.get('new', 0)} (Critical/High {c.get('new_critical_high', 0)}), "
                  f"updated {c.get('updated', 0)}, natively resolved {c.get('resolved', 0)}, reappeared {c.get('reappeared', 0)}",
              f"Permission errors {c.get('permission_errors', 0)}, throttling {c.get('throttling_errors', 0)}, not enabled {c.get('not_enabled', 0)}, "
              f"other {c.get('other_errors', 0)}", "Next scheduled run: 02:00 UTC"]
    for e in (sync.errors or [])[:20]:
        lines.append(f"- {e.get('provider', '')} {e.get('scope', '')} {e.get('region', '')}: {e.get('kind')}: {e.get('message', '')[:200]}")
    body = "\n".join(lines)
    notify(db, "sync_completed", f"run{sync.id}", f"[LV NEXUS] Security sync {sync.status}: {c.get('new', 0)} new findings", body, sync.execution_id)
    if sync.status != SyncStatus.COMPLETED.value:
        notify(db, "sync_failed", f"run{sync.id}", f"[LV NEXUS] Security sync {sync.status}: {len(sync.errors or [])} problem(s)", body, sync.execution_id)
