# Module 1 – Shared reliability layer (done)

## What changed and why

| File | Change |
|---|---|
| `backend/app/services/reliability.py` (new) | One layer for every cloud call: `call()` (retries with exponential backoff + jitter for 429 / 5xx / timeouts, honours Retry-After, metrics), token-bucket `RateLimiter` per API family (Azure Cost Management one query per 2.5 s, Graph 8/s, ARM 10/s, AWS Cost Explorer 2/s, BigQuery 1/s), `ProviderGuard` circuit breaker per provider per run, `classify()` (throttle, server, timeout, auth_expired, permission, not_enabled, not_found), fix hints, explicit timeout constants. |
| `backend/app/core/logging.py` | JSON log formatter (one object per line, with `run_id` and `job`), `mask()` for e-mails, IPv4 addresses and AWS access-key IDs applied to every log line. |
| `backend/app/scheduler/engine.py` | Every job run gets a run context: run ID, provider health, per-API calls / errors / retries / duration; stored on the run log (`summary.run`) and logged as a `job_finished` JSON event. |
| `backend/app/services/{soc,finops,monitoring,access,vuln}/…`, `inventory.py`, `finops/detail.py` | Per-scope gate: when a provider's circuit is open the remaining scopes are skipped and reported as "provider unavailable"; failures are recorded with kind and fix text; other clouds continue. |
| `backend/app/services/azure/rest.py` | All Graph / ARM / Cost Management REST calls go through `call()` with rate limits (6 attempts for Cost Management) and a 10 s connect / 60 s read timeout. |
| `backend/app/services/azure/connector.py`, `monitoring/collectors.py` | Every Azure SDK client created with 10 s connect / 60 s read timeouts and 4 retries. |
| GCP call sites (discovery, IAM, monitoring, billing) | Explicit 60 s timeout on every Google API call; BigQuery 300 s. |
| `backend/app/services/finops/detail.py` | **Fix for your failing `cost_detail_refresh`**: Cost Management queries are paced, and each breakdown is isolated: one failing query keeps the previous data of that breakdown and the rest are stored; status becomes partial with the reason instead of failed. |
| `backend/app/services/soc/entra.py` | **Fix for your failing `entra_activity`**: a missing Graph permission is reported as "unavailable – missing permission. Fix: grant AuditLog.Read.All…" (degraded), not as a job failure. |
| `backend/app/services/ai/provider.py` | Everything sent to Gemini / OpenAI is masked (e-mails, IPs, key IDs) and redacted. |
| `backend/app/core/config.py` | `LOG_FORMAT` (json), `DRY_RUN` (used by module 2), `CIRCUIT_BREAKER_THRESHOLD` (4). |

## Behaviour rules

- A missing permission or a disabled API never opens the circuit (it is one scope's configuration, not provider health).
- Invalid or expired credentials open it at once: the other scopes of that cloud are skipped with "credentials invalid or expired" and the fix.
- Four consecutive transient failures (after retries) open it for the rest of that run only; the next run starts closed.
- Nothing is retried that could change anything: every call remains read-only.

## Tests

15 new tests (`tests/unit/test_reliability.py`): 429 with Retry-After, 5xx, timeouts, 403 / 404 / expired credentials /
API disabled (no retry), give-up after N attempts, circuit breaker per provider, reset on success, rate limiter pacing,
masking, JSON log fields, run report on the execution log, 2,401 items across 25 pages after a 429, 403 raised (never an
empty list), cost-detail breakdown isolation, Entra missing permission → degraded with the fix.
Full suite: 257 passed on SQLite and on MySQL 8.
