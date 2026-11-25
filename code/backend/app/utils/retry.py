"""Exponential backoff with jitter for cloud API calls that hit rate limits."""
from __future__ import annotations

import random
import time
from collections.abc import Callable
from typing import TypeVar

_JITTER = random.SystemRandom()  # retry jitter only; OS randomness

T = TypeVar("T")

_THROTTLE_CODES = {
    "Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded",
    "ServiceUnavailable", "InternalFailure", "InternalError",
}


def is_retryable(exc: BaseException) -> bool:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict) and resp.get("Error", {}).get("Code") in _THROTTLE_CODES:
        return True
    status = getattr(exc, "status_code", None)
    if status is None:
        code = getattr(exc, "code", None)  # google.api_core exceptions expose an int/enum code
        status = getattr(code, "value", code) if not callable(code) else None
    return status in (429, 500, 502, 503, 504)


def with_backoff(fn: Callable[[], T], *, attempts: int = 5, base: float = 0.5, cap: float = 20.0,
                 sleep: Callable[[float], None] = time.sleep) -> T:
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - classified below
            if attempt == attempts or not is_retryable(exc):
                raise
            sleep(min(cap, base * 2 ** (attempt - 1)) * (0.5 + _JITTER.random() / 2))
    raise RuntimeError("unreachable")
