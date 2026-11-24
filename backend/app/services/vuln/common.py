"""Shared pieces for native security collectors: the normalized finding, error classification and retry with back-off."""
from __future__ import annotations

import hashlib
import logging
import random
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

_JITTER = random.SystemRandom()  # retry jitter only; OS randomness

log = logging.getLogger(__name__)

SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")


def sev(label: str | None) -> str:
    v = (label or "").strip().lower()
    return {"critical": "Critical", "high": "High", "medium": "Medium", "moderate": "Medium", "low": "Low"}.get(v, "Informational")


def parse_ts(value) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    s = str(value).replace("Z", "+00:00")
    if "." in s:  # trim nanoseconds (SCC) to microseconds
        head, _, tail = s.partition(".")
        frac = "".join(ch for ch in tail if ch.isdigit())
        tz = tail[len(frac):]
        s = f"{head}.{frac[:6]}{tz}"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def id_hash(native_id: str) -> str:
    return hashlib.sha256(native_id.encode()).hexdigest()


@dataclass
class NormalizedFinding:
    provider: str
    source: str
    native_id: str
    scope_external_id: str
    title: str
    severity: str
    native_state: str
    is_security: bool = True
    organization_id: str | None = None
    parent_id: str | None = None
    region: str | None = None
    resource_id: str | None = None
    resource_name: str | None = None
    resource_type: str | None = None
    resource_group: str | None = None
    description: str | None = None
    category: str | None = None
    finding_type: str | None = None
    compliance_standard: str | None = None
    control_id: str | None = None
    remediation: str | None = None
    remediation_url: str | None = None
    native_workflow_status: str | None = None
    native_record_state: str | None = None
    mute_state: str | None = None
    first_observed_at: datetime | None = None
    last_observed_at: datetime | None = None
    native_updated_at: datetime | None = None
    raw: dict = field(default_factory=dict)


@dataclass
class Partition:
    """One unit of collection with its own checkpoint: (scope, region/location) for one source."""
    scope: str
    region: str
    fetch: Callable[[datetime | None], Iterator[NormalizedFinding]]
    # True when a complete, successful full listing is authoritative: a stored ACTIVE finding that is absent was resolved
    absence_resolves: bool = False


@dataclass
class Coverage:
    """A coverage fact that is not a fetch: e.g. an account that is not a Security Hub member, a region not enabled."""
    scope: str
    region: str
    state: str  # OK | PARTIALLY_CONFIGURED | ACCESS_DENIED | NOT_ENABLED | ERROR
    message: str


class HttpError(Exception):
    def __init__(self, status: int, body: str = "", retry_after: float | None = None):
        super().__init__(f"HTTP {status}: {body[:300]}")
        self.status, self.body, self.retry_after = status, body, retry_after


_PERMISSION = ("accessdenied", "unauthorizedoperation", "authorizationfailed", "permission_denied", "forbidden",
               "invalidauthenticationtoken", "authenticationfailed", "not authorized", "does not have authorization")
_THROTTLE = ("throttl", "toomanyrequests", "rate exceeded", "resource_exhausted", "requestlimitexceeded", "slowdown")
_NOT_ENABLED = ("invalidaccessexception", "not subscribed", "service_disabled", "has not been used", "is not enabled",
                "subscriptionnotregistered", "not registered")


def classify(exc: Exception) -> tuple[str, str]:
    """('permission' | 'throttle' | 'not_enabled' | 'error', short message). Never reveals credentials."""
    code = ""
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):  # botocore ClientError
        code = str((resp.get("Error") or {}).get("Code") or "")
    status = getattr(exc, "status", None)
    text = f"{code} {exc}".lower()
    msg = (f"{code}: " if code else "") + str(exc).splitlines()[0][:300]
    if any(k in text for k in _NOT_ENABLED):
        return "not_enabled", msg
    if status == 429 or any(k in text for k in _THROTTLE):
        return "throttle", msg
    if status in (401, 403) or any(k in text for k in _PERMISSION):
        return "permission", msg
    return "error", msg


def with_retry(fn: Callable, *, attempts: int = 4, base_delay: float = 1.0, sleep: Callable[[float], None] = time.sleep):
    """Run fn(); on throttling or transient (5xx) errors back off exponentially with jitter, honouring Retry-After."""
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            kind, _ = classify(exc)
            transient = kind == "throttle" or getattr(exc, "status", 0) in (500, 502, 503, 504)
            if not transient or attempt == attempts:
                raise
            delay = getattr(exc, "retry_after", None) or base_delay * (2 ** (attempt - 1)) * (1 + _JITTER.random() * 0.25)
            log.info("transient error (%s); retry %d/%d in %.1fs", kind, attempt, attempts - 1, delay)
            sleep(min(delay, 60))
    return None  # pragma: no cover
