"""Shared reliability layer for every cloud API call.

- `call()`      : explicit retry with exponential backoff + jitter for throttling (429), server errors (5xx) and timeouts,
                  honouring Retry-After; per-key rate limiting; metrics and a structured log line per failure.
- RateLimiter   : token bucket per API family (e.g. Azure Cost Management is throttled per scope and minute).
- ProviderGuard : circuit breaker per provider per run. Transient failures (timeouts, 5xx, throttling after retries,
                  unexpected errors) across scopes open it; invalid / expired credentials open it at once. Permission
                  and "API not enabled" errors never open it: they are scope configuration, not provider health.
                  When open, the remaining scopes of that provider are skipped and reported as "provider unavailable",
                  and the other clouds continue.
- RunContext    : run ID, job, guards and metrics for the current job run (a context variable, so concurrent jobs in
                  threads never share state). Stored on the run log at the end of the run.

Nothing here talks to a cloud by itself; it wraps the calls the collectors already make (all read-only)."""
from __future__ import annotations

import contextvars
import logging
import random
import threading
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from app.core.logging import safe_error

_JITTER = random.SystemRandom()  # retry jitter only; OS randomness

log = logging.getLogger("cloudnexus.calls")

TRANSIENT = ("throttle", "server", "timeout")
GCP_TIMEOUT = 60.0      # seconds, every Google API call
BQ_TIMEOUT = 300.0      # seconds, BigQuery billing queries
AZURE_CLIENT_OPTIONS = {"connection_timeout": 10, "read_timeout": 60, "retry_total": 4}  # every Azure SDK client
CONFIG_KINDS = ("permission", "not_enabled", "not_found")

# calls per second, burst. Conservative defaults below published quotas.
RATE_LIMITS: dict[str, tuple[float, int]] = {
    "azure_cost": (0.1, 1),      # Cost Management query / forecast: strict per-scope limits (QPU); one query every 10 s
    "azure_graph": (8.0, 8),
    "azure_arm": (10.0, 10),
    "aws_ce": (2.0, 2),          # Cost Explorer: low TPS, billed per call
    "aws": (10.0, 10),
    "gcp": (10.0, 10),
    "gcp_bigquery": (1.0, 1),
}

_TIMEOUT_WORDS = ("timed out", "timeout", "readtimeout", "connecttimeout", "deadline exceeded", "deadline_exceeded")
_AUTH_WORDS = ("expiredtoken", "invalidclienttokenid", "token has expired", "invalid_grant", "aadsts7000222", "aadsts700082",
               "refreshtoken", "credentialunavailable", "defaultcredentialserror", "unable to locate credentials",
               "nocredentialserror", "invalidauthenticationtokentenant", "authentication failed")


def classify(exc: BaseException) -> tuple[str, str]:
    """(kind, message). kind: throttle | server | timeout | auth_expired | permission | not_enabled | not_found | error."""
    from app.services.vuln.common import classify as base_classify
    text = f"{type(exc).__name__} {exc}".lower()
    status = getattr(exc, "status", None) or getattr(exc, "status_code", None)
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        status = status or (resp.get("ResponseMetadata") or {}).get("HTTPStatusCode")
    msg = safe_error(exc, 300)
    if status == 429 or any(w in text for w in ("too many requests", "toomanyrequests", "throttl", "rate exceeded", "ratelimit")):
        return "throttle", msg
    if isinstance(exc, TimeoutError) or any(w in text for w in _TIMEOUT_WORDS):
        return "timeout", msg
    from app.services.vuln.common import _NOT_ENABLED
    if any(w in text for w in _NOT_ENABLED):
        # e.g. Security Hub answers HTTP 401 InvalidAccessException when it is simply not enabled in that account:
        # a per-scope configuration gap, never a provider-wide credential failure.
        return "not_enabled", msg
    if any(w in text for w in _AUTH_WORDS) or status == 401:
        return "auth_expired", msg
    kind, _ = base_classify(exc) if isinstance(exc, Exception) else ("error", msg)
    if kind != "error":
        return kind, msg
    if status in (500, 502, 503, 504) or any(w in text for w in ("internalerror", "serviceunavailable", "bad gateway", "internal server error")):
        return "server", msg
    if status == 404 or "notfound" in text.replace(" ", ""):
        return "not_found", msg
    return "error", msg


FIX_HINTS = {
    "permission": "Grant the read permission named in the message to the LV NEXUS identity on this scope (see System Health).",
    "not_enabled": "Enable the API / service named in the message for this scope.",
    "auth_expired": "Credentials are invalid or expired: sign in again (az login / aws sso login / gcloud auth) or rotate the secret.",
    "throttle": "The provider throttled the requests after all retries; the next run retries automatically.",
    "timeout": "The provider did not answer in time after all retries; the next run retries automatically.",
    "server": "The provider returned server errors after all retries; the next run retries automatically.",
}


class CircuitOpen(RuntimeError):
    def __init__(self, provider: str, reason: str):
        super().__init__(f"{provider} unavailable for the rest of this run: {reason}")
        self.provider, self.reason = provider, reason


class RateLimiter:
    def __init__(self, rate: float, burst: int, clock=time.monotonic, sleep=time.sleep):
        self.rate, self.burst, self.clock, self.sleep = rate, burst, clock, sleep
        self.tokens, self.last = float(burst), clock()
        self.lock = threading.Lock()

    def acquire(self) -> float:
        with self.lock:
            now = self.clock()
            self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= 1:
                self.tokens -= 1
                return 0.0
            wait = (1 - self.tokens) / self.rate
            self.tokens = 0.0
            self.last = now + wait
        self.sleep(wait)
        return wait


_limiters: dict[str, RateLimiter] = {}
_limiters_lock = threading.Lock()


def limiter(key: str) -> RateLimiter | None:
    if key not in RATE_LIMITS:
        return None
    with _limiters_lock:
        if key not in _limiters:
            _limiters[key] = RateLimiter(*RATE_LIMITS[key])
        return _limiters[key]


@dataclass
class ProviderGuard:
    provider: str
    threshold: int = 4
    consecutive: int = 0
    open_reason: str | None = None
    failures: int = 0
    successes: int = 0

    @property
    def is_open(self) -> bool:
        return self.open_reason is not None

    def success(self) -> None:
        self.consecutive, self.successes = 0, self.successes + 1

    def failure(self, kind: str, message: str) -> None:
        self.failures += 1
        if kind in CONFIG_KINDS:
            return  # a missing permission on one scope says nothing about the provider's availability
        if kind == "auth_expired":
            self.open_reason = f"credentials invalid or expired ({message[:160]})"
            return
        self.consecutive += 1
        if self.consecutive >= self.threshold and not self.is_open:
            self.open_reason = f"{self.consecutive} consecutive failures, last: {message[:160]}"
            log.warning('{"event": "circuit_open", "provider": "%s"}', self.provider)


@dataclass
class ApiStats:
    calls: int = 0
    errors: int = 0
    retries: int = 0
    duration_ms: int = 0
    by_kind: dict = field(default_factory=lambda: defaultdict(int))


@dataclass
class RunContext:
    job: str
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started: float = field(default_factory=time.monotonic)
    guards: dict = field(default_factory=dict)
    stats: dict = field(default_factory=lambda: defaultdict(ApiStats))
    dry_run: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)

    def guard(self, provider: str) -> ProviderGuard:
        with self.lock:
            if provider not in self.guards:
                self.guards[provider] = ProviderGuard(provider)
            return self.guards[provider]

    def report(self) -> dict:
        return {"run_id": self.run_id, "duration_ms": int((time.monotonic() - self.started) * 1000), "dry_run": self.dry_run,
                "providers": {p: {"status": "Unavailable" if g.is_open else ("Degraded" if g.failures else "Healthy"),
                                  "reason": g.open_reason, "scope_failures": g.failures, "scope_successes": g.successes}
                              for p, g in self.guards.items()},
                "api": {k: {"calls": s.calls, "errors": s.errors, "retries": s.retries, "duration_ms": s.duration_ms,
                            "errors_by_kind": dict(s.by_kind)} for k, s in sorted(self.stats.items())},
                "api_errors": sum(s.errors for s in self.stats.values()), "retries": sum(s.retries for s in self.stats.values())}


_current: contextvars.ContextVar[RunContext | None] = contextvars.ContextVar("cloudnexus_run", default=None)


def current() -> RunContext | None:
    return _current.get()


def start_run(job: str, dry_run: bool = False) -> tuple[RunContext, contextvars.Token]:
    ctx = RunContext(job=job, dry_run=dry_run)
    return ctx, _current.set(ctx)


def end_run(token: contextvars.Token) -> None:
    _current.reset(token)


def call(provider: str, api: str, fn: Callable, *, scope: str | None = None, rate_key: str | None = None, attempts: int = 4,
         base_delay: float = 1.0, max_delay: float = 60.0, sleep: Callable[[float], None] = time.sleep):
    """Run one provider API call with rate limiting, retries and metrics. Raises the final error (classified by callers)."""
    ctx = current()
    if ctx is not None and ctx.guard(provider).is_open:
        raise CircuitOpen(provider, ctx.guard(provider).open_reason or "")
    lim = limiter(rate_key or provider)
    stats = ctx.stats[f"{provider}:{api}"] if ctx is not None else ApiStats()
    for attempt in range(1, attempts + 1):
        if lim is not None:
            lim.acquire()
        t0 = time.monotonic()
        try:
            out = fn()
            stats.calls += 1
            stats.duration_ms += int((time.monotonic() - t0) * 1000)
            return out
        except Exception as exc:  # noqa: BLE001 - classified, retried or re-raised
            stats.calls += 1
            stats.duration_ms += int((time.monotonic() - t0) * 1000)
            kind, msg = classify(exc)
            if kind not in TRANSIENT or attempt == attempts:
                stats.errors += 1
                stats.by_kind[kind] += 1
                log.warning('{"event": "api_error", "provider": "%s", "api": "%s", "scope": "%s", "kind": "%s", "attempts": %d}',
                            provider, api, scope or "-", kind, attempt)
                raise
            stats.retries += 1
            ra = getattr(exc, "retry_after", None) or _header_retry_after(exc)
            delay = min(max_delay, float(ra) if ra else base_delay * (2 ** (attempt - 1)) * (1 + _JITTER.random() * 0.5))
            sleep(delay)
    return None  # pragma: no cover


def _header_retry_after(exc: BaseException) -> float | None:
    """Seconds to wait from an HTTP error's headers (Retry-After, Azure Cost Management QPU / entity retry headers)."""
    resp = getattr(exc, "response", None)
    headers = getattr(resp, "headers", None)
    if not headers:
        return None
    best = None
    for k, v in dict(headers).items():
        key = str(k).lower()
        if key == "retry-after" or (key.startswith("x-ms-ratelimit-") and key.endswith("retry-after")):
            try:
                best = max(best or 0.0, float(v))
            except (TypeError, ValueError):
                continue
    return best


# ---------------------------------------------------------------- per-scope gate used by every collector loop
def scope_gate(provider: str) -> str | None:
    """Reason to skip the next scope of `provider` in this run (circuit open), or None."""
    ctx = current()
    if ctx is not None and ctx.guard(provider).is_open:
        return f"Skipped: {provider.upper()} unavailable for this run ({ctx.guard(provider).open_reason})"
    return None


def scope_ok(provider: str) -> None:
    ctx = current()
    if ctx is not None:
        ctx.guard(provider).success()


def scope_failed(provider: str, exc: BaseException) -> str:
    """Record a failed scope; returns a readable reason that includes the fix."""
    kind, msg = classify(exc)
    ctx = current()
    if ctx is not None and not isinstance(exc, CircuitOpen):
        ctx.guard(provider).failure(kind, msg)
    if isinstance(exc, CircuitOpen):
        return str(exc)
    hint = FIX_HINTS.get(kind)
    return f"[{kind}] {msg}" + (f" Fix: {hint}" if hint else "")
