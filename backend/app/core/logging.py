"""Logging with secret redaction so credentials never reach log output."""
from __future__ import annotations

import logging
import re

_PATTERNS = [
    re.compile(r"(?i)(authorization|x-amz-security-token|client_secret|secret|password|token|api[_-]?key)(\"?\s*[:=]\s*\"?)([^\s\",;&]+)"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
    re.compile(r"\bya29\.[A-Za-z0-9_.-]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]


_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b")
_KEY_ID = re.compile(r"\b(A[KS]IA)[0-9A-Z]{12}([0-9A-Z]{4})\b")


def mask(text: str) -> str:
    """Mask personal / identifying values (e-mails, IPv4 addresses, AWS access key IDs) for logs and LLM prompts.
    a.person@corp.com -> a***@corp.com, 203.0.113.7 -> 203.0.x.x, AKIA...WXYZ -> AKIA****WXYZ."""
    text = _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)
    text = _IPV4.sub(lambda m: f"{m.group(1)}.{m.group(2)}.x.x", text)
    return _KEY_ID.sub(lambda m: f"{m.group(1)}****{m.group(2)}", text)


def redact(text: str) -> str:
    out = _PATTERNS[0].sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]", text)
    out = _KEY_ID.sub(lambda m: f"{m.group(1)}****{m.group(2)}", out)  # access key IDs are identifiers: keep a masked hint
    for p in _PATTERNS[1:]:
        out = p.sub("[REDACTED]", out)
    return out


def safe_error(exc: BaseException, limit: int = 400) -> str:
    """Compact, redacted description of an exception, safe to store and display."""
    code = None
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):  # botocore ClientError
        code = resp.get("Error", {}).get("Code")
    code = code or getattr(exc, "error_code", None) or getattr(exc, "reason", None)
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    parts = [type(exc).__name__]
    if code and isinstance(code, str):
        parts.append(code)
    elif status is not None and not callable(status):
        parts.append(str(status))
    msg = redact(str(exc)).replace("\n", " ")
    return (" / ".join(parts) + ": " + msg)[:limit]


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = mask(redact(record.getMessage()))
        record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: time, level, logger, message, plus run_id / job of the current job run."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import UTC, datetime
        msg = record.getMessage()
        out = {"ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"), "level": record.levelname,
               "logger": record.name}
        try:  # structured messages (e.g. api_error events) are merged as fields
            parsed = json.loads(msg) if msg.startswith("{") else None
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            out.update(parsed)
        else:
            out["message"] = msg
        try:
            from app.services.reliability import current
            ctx = current()
            if ctx is not None:
                out.setdefault("run_id", ctx.run_id)
                out.setdefault("job", ctx.job)
        except Exception:  # noqa: BLE001,S110 - logging must never fail
            pass
        if record.exc_info:
            out["error"] = mask(redact(self.formatException(record.exc_info)))[-2000:]
        return json.dumps(out, default=str)


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if fmt == "json" else logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # Cloud SDKs log every HTTP request and token fetch at INFO; keep their warnings and errors only.
    # LV NEXUS's own api_error / job_finished events are unaffected.
    for noisy in ("azure.core.pipeline.policies.http_logging_policy", "azure.identity", "azure.mgmt", "msal",
                  "httpx", "httpcore", "urllib3", "botocore", "google.auth", "googleapiclient.discovery_cache"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
