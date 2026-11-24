"""SOC pipeline: collect -> store unified events -> detect -> findings. Human review is separate.

Collection status lives in automation_execution_logs, detection status on each audit event,
review status on each finding. None of them is ever set as a side effect of another."""
from __future__ import annotations

import hashlib
import json
import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models import AuditEvent, JobStatus, NotificationLog, RemediationRecord, ReviewStatus, SecurityFinding, SecurityReview, Severity, utcnow
from app.scheduler.engine import JobContext, JobResult
from app.services import reliability as rel  # noqa: E402
from app.services.scopes import check_passed, eligible_scopes

from .rules import AGGREGATE_RULES, BASE_SCORE, evaluate, is_untrusted_ip

log = logging.getLogger(__name__)
_RAW_LIMIT = 20_000
_EVENT_COLUMNS = ("provider", "scope_external_id", "event_id", "event_timestamp", "event_name", "region", "principal",
                  "source_ip", "resource_id", "resource_type", "event_category")
_BASELINE_DAYS, _BASELINE_MIN_DAYS = 30, 7


def _safe_raw(event: dict) -> dict:
    raw = {**(event.get("raw") or {}), "outcome": event.get("outcome"), "error_code": event.get("error_code"),
           "service": event.get("service"), "read_only": event.get("read_only")}
    text = json.dumps(raw, default=str)
    return json.loads(text) if len(text) <= _RAW_LIMIT else {"truncated": True, "outcome": event.get("outcome"),
                                                             "error_code": event.get("error_code"), "service": event.get("service")}


def _key(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


def _upsert_finding(db: Session, cache: dict, *, rule_id: str, title: str, severity: Severity, recommendation: str,
                    event: dict, count: int = 1, extra: dict | None = None) -> SecurityFinding:
    day = event["event_timestamp"].date().isoformat()
    key = _key(rule_id, event["provider"], event["scope_external_id"], event.get("principal"), event.get("resource_id"), day)
    f = cache.get(key) or db.scalar(select(SecurityFinding).where(SecurityFinding.dedupe_key == key))
    sample = {"event_id": event["event_id"], "event_name": event["event_name"], "source_ip": event.get("source_ip"),
              "time": event["event_timestamp"].isoformat(), "outcome": event.get("outcome"), "region": event.get("region")}
    if f is None:
        f = SecurityFinding(dedupe_key=key, provider=event["provider"], scope_external_id=event["scope_external_id"], rule_id=rule_id,
                            title=title, severity=severity.value, risk_score=BASE_SCORE[severity], principal=event.get("principal"),
                            resource_id=event.get("resource_id"), recommended_action=recommendation,
                            evidence={"events": [sample], **(extra or {})}, first_seen_at=event["event_timestamp"],
                            last_seen_at=event["event_timestamp"], occurrence_count=count,
                            review_status=ReviewStatus.PENDING_REVIEW.value)
        db.add(f)
        f._is_new = True
    else:  # duplicate of an existing finding: count it and keep evidence, never touch the review status
        ev = dict(f.evidence or {})
        events = list(ev.get("events", []))
        if sample["event_id"] not in {x["event_id"] for x in events} and len(events) < 20:
            events.append(sample)
        f.evidence = {**ev, "events": events, **(extra or {})}
        f.occurrence_count += count
        f.last_seen_at = max(f.last_seen_at, event["event_timestamp"])
        order = [s.value for s in (Severity.INFORMATIONAL, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
        if order.index(severity.value) > order.index(f.severity):
            f.severity, f.risk_score = severity.value, max(f.risk_score, BASE_SCORE[severity])
    cache[key] = f
    return f


def _known_pairs(db: Session, provider: str, scope: str, now: datetime) -> set | None:
    """(principal, event_name) pairs seen in the baseline window; None when there is not enough history."""
    oldest = db.scalar(select(func.min(AuditEvent.event_timestamp)).where(AuditEvent.provider == provider,
                                                                         AuditEvent.scope_external_id == scope))
    if oldest is None or now - oldest < timedelta(days=_BASELINE_MIN_DAYS):
        return None
    rows = db.execute(select(AuditEvent.principal, AuditEvent.event_name).where(
        AuditEvent.provider == provider, AuditEvent.scope_external_id == scope,
        AuditEvent.event_timestamp >= now - timedelta(days=_BASELINE_DAYS)).distinct())
    return {(p, n) for p, n in rows}


def detect(db: Session, settings: Settings, events: list[dict], baseline: set | None) -> list[SecurityFinding]:
    """Run every rule over newly stored events. Returns findings created or updated."""
    cache: dict[str, SecurityFinding] = {}
    failed_auth, denied, data_reads = defaultdict(list), defaultdict(list), defaultdict(list)
    for e in events:
        for rule, severity in evaluate(e):
            _upsert_finding(db, cache, rule_id=rule.id, title=rule.title, severity=severity, recommendation=rule.recommendation, event=e)
            if rule.id == "failed_authentication":
                failed_auth[e.get("principal")].append(e)
            if rule.id == "unauthorized_access":
                denied[e.get("principal")].append(e)
        if e.get("event_category") == "data_access":
            data_reads[e.get("principal")].append(e)
        if not e.get("read_only") and is_untrusted_ip(e.get("source_ip"), settings.soc_trusted_cidrs):
            t, sev, _, rec = AGGREGATE_RULES["unexpected_source_ip"]
            _upsert_finding(db, cache, rule_id="unexpected_source_ip", title=t, severity=sev, recommendation=rec, event=e)
        if baseline is not None and not e.get("read_only") and e.get("outcome") == "success" \
                and (e.get("principal"), e["event_name"]) not in baseline:
            baseline.add((e.get("principal"), e["event_name"]))
            t, sev, _, rec = AGGREGATE_RULES["unusual_api_call"]
            _upsert_finding(db, cache, rule_id="unusual_api_call", title=t, severity=sev, recommendation=rec, event=e)
    for rule_id, groups, threshold in (("repeated_failed_authentication", failed_auth, settings.soc_failed_auth_threshold),
                                       ("repeated_permission_denied", denied, settings.soc_denied_threshold),
                                       ("abnormal_data_access", data_reads, settings.soc_data_access_threshold)):
        t, sev, _, rec = AGGREGATE_RULES[rule_id]
        for evs in groups.values():
            if len(evs) >= threshold:
                _upsert_finding(db, cache, rule_id=rule_id, title=t, severity=sev, recommendation=rec, event=evs[-1], count=len(evs),
                                extra={"window_count": len(evs), "distinct_ips": sorted({x.get("source_ip") or "" for x in evs})[:10]})
    # Correlation: several different rules for one principal in the same batch raise the risk score.
    by_principal = defaultdict(set)
    for f in cache.values():
        by_principal[(f.provider, f.scope_external_id, f.principal)].add(f.rule_id)
    for f in cache.values():
        related = by_principal[(f.provider, f.scope_external_id, f.principal)] - {f.rule_id}
        if related and f.principal:
            f.evidence = {**(f.evidence or {}), "related_rules": sorted(related)}
            f.risk_score = min(100, max(f.risk_score, BASE_SCORE[Severity(f.severity)] + 5 * len(related)))
    return list(cache.values())


def _store(db: Session, events: list[dict]) -> list[dict]:
    """Insert events that are not stored yet (idempotent on provider + event_id)."""
    new, seen = [], set()
    for i in range(0, len(events), 500):
        chunk = events[i:i + 500]
        existing = set(db.scalars(select(AuditEvent.event_id).where(
            AuditEvent.provider == chunk[0]["provider"], AuditEvent.event_id.in_([e["event_id"] for e in chunk]))))
        for e in chunk:
            if e["event_id"] in existing or e["event_id"] in seen:
                continue
            seen.add(e["event_id"])
            matched = evaluate(e)
            top = max((s for _, s in matched), key=lambda s: BASE_SCORE[s], default=None)
            db.add(AuditEvent(**{k: e[k] for k in _EVENT_COLUMNS}, raw=_safe_raw(e),
                              description=f"{e['event_name']} by {e.get('principal') or 'unknown'} ({e.get('outcome')})"[:1000],
                              detection_status="flagged" if matched else "evaluated_no_match",
                              severity=top.value if top else None, risk_score=BASE_SCORE[top] if top else None,
                              review_status=ReviewStatus.PENDING_REVIEW.value))
            new.append(e)
    return new


def run_security_events(ctx: JobContext, settings: Settings, collectors: list) -> JobResult:
    db, job = ctx.db, ctx.job
    checkpoint = dict(job.checkpoint or {})
    now = utcnow()
    failures, summary = [], {"events_stored": 0, "findings_touched": 0, "new_findings": 0, "by_provider": {}}
    total = failed = 0
    urgent: list[SecurityFinding] = []
    for collector in collectors:
        p = collector.provider
        stats = summary["by_provider"].setdefault(p, {"scopes": 0, "events": 0, "skipped_no_audit_access": 0})
        for scope in eligible_scopes(db, p):
            if not check_passed(scope, "audit_logs"):
                stats["skipped_no_audit_access"] += 1  # tracked as an onboarding gap, not silently dropped
                failures.append({"provider": p, "scope": scope.external_id, "name": scope.name,
                                 "reason": "Audit log access not validated (see onboarding checks)"})
                total, failed = total + 1, failed + 1
                continue
            total += 1
            _skip = rel.scope_gate(p)
            if _skip:
                failed += 1
                failures.append({"provider": p, "scope": scope.external_id, "name": scope.name, "reason": _skip})
                continue
            stats["scopes"] += 1
            ck = f"{p}:{scope.external_id}"
            since = (datetime.fromisoformat(checkpoint[ck]) - timedelta(minutes=settings.soc_overlap_minutes) if ck in checkpoint
                     else now - timedelta(hours=settings.soc_initial_lookback_hours))
            try:
                events, capped = [], False
                for ev in collector.collect(scope, since, now):
                    events.append(ev)
                    if len(events) >= settings.soc_max_events_per_scope:
                        capped = True
                        break
                baseline = _known_pairs(db, p, scope.external_id, now)
                new = _store(db, events)
                findings = detect(db, settings, new, baseline)
                # Advance only as far as data was actually read, so nothing is skipped after a capped run.
                checkpoint[ck] = (max(e["event_timestamp"] for e in events) if capped else now).isoformat()
                job.checkpoint = dict(checkpoint)
                db.commit()
                rel.scope_ok(p)
                stats["events"] += len(new)
                summary["events_stored"] += len(new)
                summary["findings_touched"] += len(findings)
                fresh = [f for f in findings if getattr(f, "_is_new", False)]
                summary["new_findings"] += len(fresh)
                urgent += [f for f in fresh if f.severity in (Severity.CRITICAL.value, Severity.HIGH.value)]
                if capped:
                    failures.append({"provider": p, "scope": scope.external_id, "name": scope.name,
                                     "reason": f"Event cap of {settings.soc_max_events_per_scope} reached; remainder is collected next run"})
            except Exception as exc:  # noqa: BLE001 - one scope must not stop the others, and must be reported
                db.rollback()
                log.exception("audit collection failed for %s %s", p, scope.external_id)
                failed += 1
                failures.append({"provider": p, "scope": scope.external_id, "name": scope.name, "reason": rel.scope_failed(p, exc)})
    if urgent:
        lines = [f"- [{f.severity}] {f.provider.upper()} {f.scope_external_id}: {f.title} ({f.principal or 'unknown principal'})" for f in urgent[:25]]
        db.add(NotificationLog(channel="google_chat", category="soc_verification_request", execution_id=ctx.execution_id,
                               subject=f"{len(urgent)} new Critical/High finding(s) need analyst verification",
                               body="\n".join(lines) + "\nStatus: Pending Review. Not confirmed.", status="queued"))
        db.commit()
    if not collectors:
        failures.append({"provider": "*", "scope": "*", "reason": "No cloud provider is enabled"})
        return JobResult(JobStatus.FAILED, 0, 0, summary, failures)
    if total == 0:
        failures.append({"provider": "*", "scope": "*", "reason": "No onboarded scopes yet. Run account discovery first."})
        return JobResult(JobStatus.FAILED, 0, 0, summary, failures)
    status = JobStatus.SUCCESS if not failures else JobStatus.FAILED if failed == total else JobStatus.PARTIAL
    return JobResult(status, total, failed, summary, failures)


def record_review(db: Session, finding: SecurityFinding, new_status: ReviewStatus, reviewer: str,
                  notes: str | None, evidence_reference: str | None) -> SecurityFinding:
    """A person's decision. Appends to the immutable review history; confirmed suspicious opens an incident."""
    previous = finding.review_status
    db.add(SecurityReview(finding_id=finding.id, previous_status=previous, new_status=new_status.value, reviewer=reviewer,
                          notes=notes, evidence_reference=evidence_reference))
    finding.review_status = new_status.value
    if new_status == ReviewStatus.CONFIRMED_SUSPICIOUS and previous != new_status.value:
        key = f"incident:finding:{finding.id}"
        if db.scalar(select(RemediationRecord).where(RemediationRecord.dedupe_key == key)) is None:
            db.add(RemediationRecord(dedupe_key=key, category="incident", provider=finding.provider,
                                     scope_external_id=finding.scope_external_id, finding_id=finding.id,
                                     title=f"Incident: {finding.title}", description=notes,
                                     proposed_action=finding.recommended_action, status="pending_approval"))
        for channel in ("google_chat", "email"):
            db.add(NotificationLog(channel=channel, category="soc_confirmed_incident",
                                   subject=f"[{finding.severity}] Confirmed suspicious activity: {finding.title}",
                                   body=(f"Cloud: {finding.provider.upper()}\nScope: {finding.scope_external_id}\n"
                                         f"Principal: {finding.principal or 'unknown'}\nResource: {finding.resource_id or 'n/a'}\n"
                                         f"Confirmed by: {reviewer}\nRecommended action: {finding.recommended_action or 'n/a'}\n"
                                         "No automatic action has been taken."), status="queued"))
    return finding


def event_counts_by_rule(findings: list[SecurityFinding]) -> dict[str, int]:
    return dict(Counter(f.rule_id for f in findings))
