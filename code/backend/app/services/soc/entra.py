"""Microsoft Entra ID audit and sign-in logs (Microsoft Graph, read-only).

Directory audits need AuditLog.Read.All; sign-in logs additionally need an Entra ID P1/P2 licence. When either is not
available the job reports it as a coverage gap (never as "no activity"). Events are stored in the same unified
audit_events table as Azure Activity Log, CloudTrail and Cloud Audit Logs, with the tenant as the scope."""
from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import datetime, timedelta

from app.core.config import Settings
from app.models import JobStatus
from app.scheduler.engine import JobContext, JobResult
from app.services.azure.rest import GRAPH, AzureRest
from app.services.soc.normalize import _event

log = logging.getLogger(__name__)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_directory_audit(a: dict, tenant: str) -> dict:
    by = a.get("initiatedBy") or {}
    who = (by.get("user") or {}).get("userPrincipalName") or (by.get("app") or {}).get("displayName") or (by.get("app") or {}).get("servicePrincipalId")
    ip = (by.get("user") or {}).get("ipAddress")
    target = (a.get("targetResources") or [{}])[0]
    result = (a.get("result") or "success").lower()
    return _event("azure", tenant, f"entra-audit:{a['id']}", a["activityDateTime"], a.get("activityDisplayName") or "unknown",
                  principal=who, source_ip=ip, resource_id=target.get("id"), resource_type=target.get("type"),
                  category="EntraAudit:" + (a.get("category") or "Directory"), outcome="success" if result == "success" else "failure",
                  error_code=a.get("resultReason") if result != "success" else None, service="Microsoft Entra ID",
                  raw={"targetResources": a.get("targetResources"), "loggedByService": a.get("loggedByService"),
                       "operationType": a.get("operationType"), "correlationId": a.get("correlationId"),
                       "targetName": target.get("userPrincipalName") or target.get("displayName")})


def normalize_sign_in(s: dict, tenant: str) -> dict:
    status = s.get("status") or {}
    code = status.get("errorCode") or 0
    loc = s.get("location") or {}
    return _event("azure", tenant, f"entra-signin:{s['id']}", s["createdDateTime"], "Sign-in", region=loc.get("countryOrRegion"),
                  principal=s.get("userPrincipalName"), source_ip=s.get("ipAddress"), resource_id=s.get("resourceDisplayName"),
                  resource_type="SignIn", category="EntraSignIn", outcome="success" if code == 0 else "failure",
                  error_code=str(code) if code else None, read_only=True, service=s.get("appDisplayName"),
                  raw={"clientApp": s.get("clientAppUsed"), "conditionalAccessStatus": s.get("conditionalAccessStatus"),
                       "riskLevel": s.get("riskLevelDuringSignIn"), "riskState": s.get("riskState"), "failureReason": status.get("failureReason"),
                       "city": loc.get("city"), "isInteractive": s.get("isInteractive")})


class EntraActivityCollector:
    provider = "azure"

    def __init__(self, settings: Settings, rest: AzureRest | None = None):
        self.settings = settings
        self.rest = rest or AzureRest(settings)
        self.tenant = settings.azure_tenant_id or "tenant"

    def audits(self, since: datetime, until: datetime) -> Iterator[dict]:
        flt = f"activityDateTime ge {_iso(since)} and activityDateTime le {_iso(until)}"
        for a in self.rest.pages(f"{GRAPH}/auditLogs/directoryAudits", {"$filter": flt, "$top": "999"}):
            yield normalize_directory_audit(a, self.tenant)

    def sign_ins(self, since: datetime, until: datetime) -> Iterator[dict]:
        flt = f"createdDateTime ge {_iso(since)} and createdDateTime le {_iso(until)}"
        for s in self.rest.pages(f"{GRAPH}/auditLogs/signIns", {"$filter": flt, "$top": "999"}):
            yield normalize_sign_in(s, self.tenant)


def run_entra_activity(ctx: JobContext, settings: Settings, collector: EntraActivityCollector) -> JobResult:
    from app.models.base import utcnow
    from app.services.soc.engine import _known_pairs, _store, detect

    db, job = ctx.db, ctx.job
    checkpoint = dict(job.checkpoint or {})
    now = utcnow()
    summary: dict = {"tenant": collector.tenant, "sources": {}}
    failures: list[dict] = []
    for name, fn in (("directory_audits", collector.audits), ("sign_ins", collector.sign_ins)):
        since = (datetime.fromisoformat(checkpoint[name]) - timedelta(minutes=settings.soc_overlap_minutes) if name in checkpoint
                 else now - timedelta(hours=settings.soc_initial_lookback_hours))
        try:
            events = []
            for ev in fn(since, now):
                events.append(ev)
                if len(events) >= settings.soc_max_events_per_scope:
                    break
            capped = len(events) >= settings.soc_max_events_per_scope
            baseline = _known_pairs(db, "azure", collector.tenant, now)
            new = _store(db, events) if events else []
            detect(db, settings, new, baseline)
            checkpoint[name] = (max(e["event_timestamp"] for e in events) if capped else now).isoformat()
            job.checkpoint = dict(checkpoint)
            db.commit()
            summary["sources"][name] = {"read": len(events), "stored": len(new), "capped": capped}
            if capped:
                failures.append({"provider": "azure", "scope": collector.tenant, "reason": f"{name}: event cap reached; the rest is read next run"})
        except Exception as exc:  # noqa: BLE001 - reported per source
            db.rollback()
            from app.services.reliability import classify
            kind, msg = classify(exc)
            from app.services.azure.permissions import graph_fix, is_licence_error, licence_note
            if is_licence_error(f"{exc} {msg}"):  # tenant has no Entra ID P1/P2: the source does not exist here
                summary["sources"][name] = {"unavailable": "licence", "note": licence_note(name)}
            elif kind == "permission":  # configuration gap: the source is unavailable, the job itself works
                fix = graph_fix(settings, name)
                failures.append({"provider": "azure", "scope": collector.tenant, "reason": f"{name}: unavailable – missing permission. Fix: {fix}"})
                summary["sources"][name] = {"unavailable": "missing permission", "fix": fix}
            else:
                failures.append({"provider": "azure", "scope": collector.tenant, "reason": f"{name}: [{kind}] {msg}"})
                summary["sources"][name] = {"error": msg[:300], "kind": kind}
    errored = sum(1 for v in summary["sources"].values() if "error" in v)
    # FAILED only for unexpected errors on every source; missing permissions are reported as degraded with the fix
    status = JobStatus.SUCCESS if not failures else JobStatus.FAILED if errored == 2 else JobStatus.PARTIAL
    return JobResult(status, 2, len(failures), summary, failures)
