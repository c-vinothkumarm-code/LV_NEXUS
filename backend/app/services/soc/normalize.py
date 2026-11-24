"""Normalise provider audit records into the unified audit event schema.

Everything read from a log is untrusted data: values are truncated and stored, never interpreted."""
from __future__ import annotations

import json
from datetime import UTC, datetime

_DENIED_CODES = ("accessdenied", "unauthorized", "forbidden", "authfailure", "notauthorized")


def _clip(value, n: int) -> str | None:
    return None if value in (None, "") else str(value)[:n]


def _ts(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _event(provider, scope, event_id, ts, name, **kw) -> dict:
    return {"provider": provider, "scope_external_id": scope, "event_id": str(event_id)[:255], "event_timestamp": _ts(ts),
            "event_name": str(name)[:255], "region": _clip(kw.get("region"), 64), "principal": _clip(kw.get("principal"), 512),
            "source_ip": _clip(kw.get("source_ip"), 64), "resource_id": _clip(kw.get("resource_id"), 1024),
            "resource_type": _clip(kw.get("resource_type"), 128), "event_category": _clip(kw.get("category"), 64),
            "outcome": kw.get("outcome", "success"), "error_code": _clip(kw.get("error_code"), 128),
            "read_only": bool(kw.get("read_only", False)), "service": _clip(kw.get("service"), 128), "raw": kw.get("raw") or {}}


def normalize_cloudtrail(record: dict, account_id: str) -> dict:
    """`record` is one item from cloudtrail.lookup_events (CloudTrailEvent holds the full JSON document)."""
    detail = record.get("CloudTrailEvent")
    detail = json.loads(detail) if isinstance(detail, str) else (detail or {})
    ident = detail.get("userIdentity") or {}
    principal = ident.get("arn") or ident.get("userName") or record.get("Username") or ident.get("type")
    error = detail.get("errorCode")
    login_failed = (detail.get("responseElements") or {}).get("ConsoleLogin") == "Failure"
    outcome = "success"
    if error or login_failed:
        outcome = "denied" if error and any(c in error.lower() for c in _DENIED_CODES) else "failure"
    resources = record.get("Resources") or []
    res = resources[0] if resources else {}
    return _event("aws", account_id, record.get("EventId") or detail.get("eventID"), record.get("EventTime") or detail.get("eventTime"),
                  record.get("EventName") or detail.get("eventName"), region=detail.get("awsRegion"), principal=principal,
                  source_ip=detail.get("sourceIPAddress"), resource_id=res.get("ResourceName"), resource_type=res.get("ResourceType"),
                  category=detail.get("eventCategory", "Management"), outcome=outcome, error_code=error,
                  read_only=str(detail.get("readOnly", record.get("ReadOnly", "false"))).lower() == "true",
                  service=detail.get("eventSource") or record.get("EventSource"),
                  raw={"userIdentityType": ident.get("type"), "requestParameters": detail.get("requestParameters"),
                       "responseElements": detail.get("responseElements"), "additionalEventData": detail.get("additionalEventData"),
                       "errorMessage": detail.get("errorMessage"), "userAgent": detail.get("userAgent")})


def normalize_gcp(entry: dict, project_id: str) -> dict:
    """`entry` is a LogEntry in REST (JSON) form with a protoPayload of type AuditLog."""
    p = entry.get("protoPayload") or {}
    status = p.get("status") or {}
    code = status.get("code", 0)
    log_name = entry.get("logName", "")
    category = ("data_access" if "data_access" in log_name else "system_event" if "system_event" in log_name
                else "policy_denied" if "policy" in log_name else "admin_activity")
    outcome = "success" if not code else "denied" if code in (7, 16) or category == "policy_denied" else "failure"
    labels = (entry.get("resource") or {}).get("labels") or {}
    return _event("gcp", project_id, entry.get("insertId"), entry.get("timestamp"), p.get("methodName") or "unknown",
                  region=labels.get("location") or labels.get("zone") or labels.get("region"),
                  principal=(p.get("authenticationInfo") or {}).get("principalEmail"),
                  source_ip=(p.get("requestMetadata") or {}).get("callerIp"), resource_id=p.get("resourceName"),
                  resource_type=(entry.get("resource") or {}).get("type"), category=category, outcome=outcome,
                  error_code=str(code) if code else None, read_only=category == "data_access", service=p.get("serviceName"),
                  raw={"request": p.get("request"), "serviceData": p.get("serviceData"), "statusMessage": status.get("message"),
                       "authorizationInfo": p.get("authorizationInfo"), "metadata": p.get("metadata")})


def _val(obj, attr="value"):
    """Azure SDK LocalizableString / enum / plain string -> string."""
    if obj is None:
        return None
    return getattr(obj, attr, None) or (obj.get(attr) if isinstance(obj, dict) else None) or str(obj)


def normalize_azure(ev, subscription_id: str) -> dict | None:
    """`ev` is an azure.mgmt.monitor EventData (or a dict with the same attribute names). In-flight
    records (Started / Accepted) are skipped so each operation is stored once with its final result."""
    get = ev.get if isinstance(ev, dict) else (lambda k: getattr(ev, k, None))
    status = _val(get("status")) or ""
    if status in ("Started", "Accepted", "Running"):
        return None
    sub_status = _val(get("sub_status")) or ""
    outcome = "success"
    if status == "Failed":
        outcome = "denied" if any(c in sub_status.lower() for c in ("forbidden", "unauthorized")) else "failure"
    http = get("http_request")
    ip = getattr(http, "client_ip_address", None) if http is not None and not isinstance(http, dict) else (http or {}).get("client_ip_address")
    op = _val(get("operation_name")) or "unknown"
    return _event("azure", subscription_id, get("event_data_id") or get("id"), get("event_timestamp"), op,
                  principal=get("caller"), source_ip=ip, resource_id=get("resource_id"), resource_type=_val(get("resource_type")),
                  category=_val(get("category")), outcome=outcome, error_code=sub_status or None,
                  read_only=op.lower().endswith("/read"), service=_val(get("resource_provider_name")),
                  raw={"level": str(get("level")), "resourceGroup": get("resource_group_name"), "properties": get("properties"),
                       "correlationId": get("correlation_id")})
