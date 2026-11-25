"""Live audit anomaly detection across AWS CloudTrail, Azure Activity Log / Entra ID and GCP Cloud Audit Logs.

Each principal is compared with its OWN recent history (the baseline), so normal behaviour of automation accounts does
not raise alerts. Rules:

- new_source_ip     a principal with enough history calls from a public IP it has not used in the baseline window
- new_country       a successful Entra ID sign-in from a country the user has not signed in from in the baseline window
- unusual_hours     write activity in an hour that holds (almost) none of the principal's history (local time zone)
- failure_spike     many failed / denied calls by one principal within a short window
- privilege_change  role, policy, key or group-membership changes that grant access (always flagged)
- mass_deletion     many successful delete / terminate calls by one principal within a short window

Detection is read-only: it reads stored events and records anomalies. It never changes cloud access or resources and
never closes anything on its own. Nothing is inferred when history is missing: principals without a baseline only get
the threshold rules (failure spike, privilege change, mass deletion)."""
from __future__ import annotations

import hashlib
import ipaddress
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.logging import mask
from app.models import AuditEvent, AutomationExecutionLog, JobStatus
from app.models.platform import AuditAnomaly
from app.scheduler.engine import JobContext, JobResult

BATCH = 20_000
FIRST_RUN_LOOKBACK = timedelta(hours=24)
SEVERITY = {"new_source_ip": "Medium", "new_country": "High", "unusual_hours": "Medium", "failure_spike": "High",
            "privilege_change": "High", "mass_deletion": "Critical"}
TITLE = {"new_source_ip": "Activity from a new IP address", "new_country": "Sign-in from a new country", "unusual_hours": "Activity at unusual hours",
         "failure_spike": "Spike in failed or denied calls", "privilege_change": "Privilege or access change", "mass_deletion": "Mass deletion"}

PRIV_AWS = {"attachuserpolicy", "attachrolepolicy", "attachgrouppolicy", "putuserpolicy", "putrolepolicy", "putgrouppolicy", "createaccesskey",
            "addusertogroup", "updateassumerolepolicy", "createpolicyversion", "setdefaultpolicyversion", "createloginprofile",
            "updateloginprofile", "createuser", "createrole"}
PRIV_AZURE = ("microsoft.authorization/roleassignments/write", "microsoft.authorization/roledefinitions/write",
              "microsoft.authorization/elevateaccess/action", "add member to role", "add eligible member to role", "add app role assignment",
              "add owner to application", "add owner to service principal", "certificates and secrets management", "add service principal credentials")
PRIV_GCP = ("setiampolicy", "createserviceaccountkey", "createserviceaccount", "createrole", "updaterole")


def _raw(e: AuditEvent) -> dict:
    return e.raw or {}


def _ok(e: AuditEvent) -> bool:
    return (_raw(e).get("outcome") or "success") == "success"


def _failed(e: AuditEvent) -> bool:
    return (_raw(e).get("outcome") or "success") in ("failure", "denied")


def _write(e: AuditEvent) -> bool:
    if _raw(e).get("read_only"):
        return False
    n = e.event_name.lower()
    return not (n.startswith(("get", "list", "describe", "lookup", "head")) or n.endswith(("/read", ".get", ".list")) or n == "sign-in")


def is_privilege(e: AuditEvent) -> bool:
    n = e.event_name.lower()
    if e.provider == "aws":
        return n in PRIV_AWS
    if e.provider == "gcp":
        return n.endswith(PRIV_GCP)
    return any(s in n for s in PRIV_AZURE)


def is_delete(e: AuditEvent) -> bool:
    n = e.event_name.lower()
    if e.provider == "aws":
        return n.startswith(("delete", "terminate"))
    if e.provider == "gcp":
        return ".delete" in n or n.endswith("delete")
    return n.endswith("/delete") or n.startswith("delete ")


def public_ip(v: str | None) -> bool:
    try:
        ip = ipaddress.ip_address((v or "").strip())
    except ValueError:
        return False  # AWS service host names, "AWS Internal", empty
    return ip.is_global


class Baseline:
    def __init__(self):
        self.events = 0
        self.ips: set[str] = set()
        self.countries: set[str] = set()
        self.signins = 0
        self.hours: Counter = Counter()


def _baselines(db: Session, principals: set[str], before_id: int, since: datetime, tz: ZoneInfo) -> dict[str, Baseline]:
    out: dict[str, Baseline] = defaultdict(Baseline)
    if not principals:
        return out
    q = select(AuditEvent.principal, AuditEvent.source_ip, AuditEvent.region, AuditEvent.event_category, AuditEvent.event_timestamp, AuditEvent.raw).where(
        AuditEvent.principal.in_(principals), AuditEvent.id <= before_id, AuditEvent.event_timestamp >= since)
    for p, ip, region, cat, ts, raw in db.execute(q):
        b = out[p]
        b.events += 1
        if ip:
            b.ips.add(ip)
        if cat == "EntraSignIn" and (raw or {}).get("outcome", "success") == "success":
            b.signins += 1
            if region:
                b.countries.add(region)
        t = ts if ts.tzinfo else ts.replace(tzinfo=UTC)
        b.hours[t.astimezone(tz).hour] += 1
    return out


def _key(*parts) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()


class Collector:
    def __init__(self):
        self.items: dict[str, dict] = {}

    def add(self, rule: str, e: AuditEvent, key_parts: tuple, detail: dict) -> None:
        k = _key(rule, e.provider, e.scope_external_id, e.principal, *key_parts)
        a = self.items.get(k)
        ts = e.event_timestamp if e.event_timestamp.tzinfo else e.event_timestamp.replace(tzinfo=UTC)
        if a is None:
            self.items[k] = a = {"rule": rule, "provider": e.provider, "scope": e.scope_external_id, "principal": e.principal, "detail": detail,
                                 "ids": [], "count": 0, "first": ts, "last": ts}
        a["count"] += 1
        a["first"], a["last"] = min(a["first"], ts), max(a["last"], ts)
        if len(a["ids"]) < 50:
            a["ids"].append(e.id)
        for dk, dv in detail.items():
            if isinstance(dv, list):
                a["detail"][dk] = sorted(set(a["detail"].get(dk, [])) | set(dv))[:25]
            elif dk == "max_in_window":
                a["detail"][dk] = max(a["detail"].get(dk, 0), dv)


def _windows(db: Session, events: list[AuditEvent], pred, minutes: int, threshold: int) -> list[tuple[AuditEvent, int, datetime]]:
    """Events where `pred` reached `threshold` within `minutes` for the same principal (counting stored history too)."""
    hits = []
    by_p: dict[str, list[AuditEvent]] = defaultdict(list)
    for e in events:
        if e.principal and pred(e):
            by_p[e.principal].append(e)
    win = timedelta(minutes=minutes)
    for p, evs in by_p.items():
        mine = {x.id for x in evs}
        start = min(x.event_timestamp for x in evs) - win
        ctx = [x for x in db.scalars(select(AuditEvent).where(AuditEvent.principal == p, AuditEvent.event_timestamp >= start,
                                                              AuditEvent.event_timestamp <= max(x.event_timestamp for x in evs))) if pred(x)]
        ctx.sort(key=lambda x: x.event_timestamp)
        lo = 0
        for hi, x in enumerate(ctx):
            while x.event_timestamp - ctx[lo].event_timestamp > win:
                lo += 1
            n = hi - lo + 1
            if n >= threshold and x.id in mine:
                bucket = ctx[lo].event_timestamp.replace(second=0, microsecond=0)
                bucket = bucket - timedelta(minutes=bucket.minute % minutes)
                hits.append((x, n, bucket))
    return hits


def detect(db: Session, settings: Settings, events: list[AuditEvent], before_id: int, now: datetime | None = None) -> Collector:
    now = now or datetime.now(UTC)
    tz = ZoneInfo(settings.anomaly_timezone)
    base = _baselines(db, {e.principal for e in events if e.principal}, before_id, now - timedelta(days=settings.anomaly_baseline_days), tz)
    out = Collector()
    min_events = settings.anomaly_min_baseline_events
    for e in events:
        b = base.get(e.principal) if e.principal else None
        ts = e.event_timestamp if e.event_timestamp.tzinfo else e.event_timestamp.replace(tzinfo=UTC)
        if b and b.events >= min_events and _ok(e) and public_ip(e.source_ip) and e.source_ip not in b.ips:
            out.add("new_source_ip", e, (e.source_ip,), {"source_ips": [e.source_ip], "baseline_events": b.events, "known_ips": len(b.ips)})
        if e.event_category == "EntraSignIn" and _ok(e) and e.region and b and b.signins >= 5 and e.region not in b.countries:
            out.add("new_country", e, (e.region,), {"countries": [e.region], "known_countries": sorted(b.countries)[:10], "baseline_signins": b.signins})
        if b and b.events >= min_events and _ok(e) and _write(e):
            hour = ts.astimezone(tz).hour
            if b.hours[hour] / b.events < settings.anomaly_rare_hour_share:
                out.add("unusual_hours", e, (ts.astimezone(tz).date().isoformat(), hour),
                        {"local_hours": [hour], "timezone": settings.anomaly_timezone, "share_of_history_pct": round(100 * b.hours[hour] / b.events, 2),
                         "operations": [e.event_name]})
        if _ok(e) and is_privilege(e):
            out.add("privilege_change", e, (e.id,), {"operations": [e.event_name], "resources": [e.resource_id] if e.resource_id else []})
    for e, n, bucket in _windows(db, events, _failed, settings.anomaly_failure_window_minutes, settings.anomaly_failure_threshold):
        out.add("failure_spike", e, (bucket.isoformat(),), {"window_minutes": settings.anomaly_failure_window_minutes, "max_in_window": n,
                                                             "operations": [e.event_name]})
    for e, n, bucket in _windows(db, events, lambda x: _ok(x) and is_delete(x), settings.anomaly_mass_delete_window_minutes,
                                 settings.anomaly_mass_delete_threshold):
        out.add("mass_deletion", e, (bucket.isoformat(),), {"window_minutes": settings.anomaly_mass_delete_window_minutes, "max_in_window": n,
                                                             "operations": [e.event_name]})
    return out


def store(db: Session, found: Collector) -> list[AuditAnomaly]:
    new = []
    for k, a in found.items.items():
        row = db.scalar(select(AuditAnomaly).where(AuditAnomaly.dedupe_key == k))
        if row is None:
            row = AuditAnomaly(dedupe_key=k, rule=a["rule"], severity=SEVERITY[a["rule"]], provider=a["provider"], scope_external_id=a["scope"],
                               principal=(a["principal"] or "")[:512] or None, title=TITLE[a["rule"]], detail=a["detail"], event_ids=a["ids"],
                               event_count=a["count"], first_event_at=a["first"], last_event_at=a["last"])
            db.add(row)
            new.append(row)
        else:
            row.event_count += a["count"]
            row.event_ids = (list(row.event_ids or []) + a["ids"])[:50]
            row.last_event_at = max(row.last_event_at if row.last_event_at.tzinfo else row.last_event_at.replace(tzinfo=UTC), a["last"])
            merged = dict(row.detail or {})
            for dk, dv in a["detail"].items():
                merged[dk] = (sorted(set(merged.get(dk, [])) | set(dv))[:25] if isinstance(dv, list)
                              else max(merged.get(dk, 0), dv) if dk == "max_in_window" else dv)
            row.detail = merged
    db.flush()
    return new


def _watermark(db: Session) -> int | None:
    run = db.scalar(select(AutomationExecutionLog).where(AutomationExecutionLog.job_name == "anomaly_detection",
                                                         AutomationExecutionLog.status.in_([JobStatus.SUCCESS.value, JobStatus.PARTIAL.value]))
                    .order_by(AutomationExecutionLog.id.desc()).limit(1))
    v = ((run.summary or {}).get("last_event_id")) if run else None
    return int(v) if v is not None else None


def run_anomaly_detection(ctx: JobContext, settings: Settings, now: datetime | None = None) -> JobResult:
    from app.services.vuln.notify import notify
    db = ctx.db
    now = now or datetime.now(UTC)
    mark = _watermark(db)
    q = select(AuditEvent).order_by(AuditEvent.id).limit(BATCH)
    if mark is None:
        before = db.scalar(select(func.max(AuditEvent.id)).where(AuditEvent.event_timestamp < now - FIRST_RUN_LOOKBACK)) or 0
        q = q.where(AuditEvent.id > before)
    else:
        before = mark
        q = q.where(AuditEvent.id > mark)
    events = list(db.scalars(q))
    if not events:
        return JobResult(JobStatus.SUCCESS, 0, 0, {"events": 0, "anomalies": 0, "last_event_id": before})
    found = detect(db, settings, events, before, now)
    new = store(db, found)
    alerted = 0
    for a in new:
        if a.severity in ("High", "Critical"):
            who = mask(a.principal or "unknown principal")
            ok = notify(db, "audit_anomaly", a.dedupe_key, f"[{a.severity}] {a.title}: {who} ({a.provider} {a.scope_external_id})",
                        mask(f"{a.title} for {a.principal or 'unknown principal'} in {a.provider} {a.scope_external_id}: {a.event_count} event(s) "
                             f"between {a.first_event_at:%Y-%m-%d %H:%M} and {a.last_event_at:%H:%M} UTC. Evidence: {a.detail}. "
                             "Review it on the Live audit page. LV NEXUS has not changed anything."))
            alerted += int(ok)
    db.commit()
    summary = {"events": len(events), "anomalies": len(found.items), "new": len(new), "alerts": alerted, "last_event_id": events[-1].id,
               "by_rule": dict(Counter(a.rule for a in new)), "backlog": len(events) == BATCH}
    return JobResult(JobStatus.SUCCESS, len(events), 0, summary)
