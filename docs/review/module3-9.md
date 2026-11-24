# Modules 3–9 — changes, endpoints, migrations, tests

## Module 3 — Cloud accounts
- `GET /api/v1/accounts/tree?provider=` — per cloud: group (MG / OU / folder) → scope → resource group (Azure) or region (AWS, GCP), each with resources, VMs, unhealthy VMs, critical / high / all open findings, cost MTD (null = not collected).
- `GET /api/v1/accounts/node?provider&scope&child&q&page&size` — resources (with findings and cost), VMs, top 50 findings.
- Fix: resources with a NULL `state` were excluded by `state != 'deleted'` in SQL.
- Page `/accounts` (tree + detail). Tests: `tests/integration/test_accounts.py`.

## Module 4 — Cost
- Page `/cost/overview` over the existing `/api/v1/cost/analysis` (no backend change). Actual and forecast never mixed; unknown shown as "—".

## Module 5 — Access (IAM), read-only
- `GET /api/v1/access/tree`, `GET /api/v1/access/who?provider&scope&child&resource&q`, `GET /api/v1/access/search?q`.
- New read-only collectors (`app/services/access/resource_iam.py`): AWS S3 bucket + customer-managed KMS key policies; GCP resource-level IAM via Cloud Asset `searchAllIamPolicies`; GCP transitive group membership via Cloud Identity. Stored under their own sources so a failure never removes account-level rows.
- Azure RG / resource-level assignments already come from the Authorization API (same data as Resource Graph `authorizationresources`).
- Legacy workflow endpoints (register, requests, approvals, reconciliation, reviews, history, revocation plans, shared flag) return 404 unless `ACCESS_WORKFLOWS_ENABLED=true`; UI pages removed; tables kept.
- Tests: `test_access_view.py`, `tests/unit/test_resource_iam.py`.

## Module 6 — Vulnerabilities
- `GET /api/v1/security/sources` — open findings and read coverage per cloud and source (OK / access denied / not enabled / error).
- Page `/vulnerabilities` (previous overview moved to `/vulnerabilities/overview`). Test: `test_vuln_api.py::test_sources_report_coverage_not_zero`.

## Module 7 — Live audit anomalies
- Migration **0008** (`audit_anomalies`, new table only). Job `anomaly_detection` (*/5, incremental watermark).
- Rules: new_source_ip, new_country (Entra sign-ins), unusual_hours, failure_spike, privilege_change, mass_deletion; thresholds in settings (`ANOMALY_*`).
- `GET /api/v1/activity/anomalies`, `POST /api/v1/activity/anomalies/{id}/acknowledge` (note only). Alerts via rule `audit_anomaly`, masked.
- Tests: `test_anomaly.py`.

## Module 8 — System health, pre-flight, dry run, alerts, Key Vault
- `GET /api/v1/system/health`, `GET|POST /api/v1/system/preflight`; job `preflight` daily 06:40 IST.
- `alert_run_problem` in the job engine: one `job_run_problem` alert per workflow / status / day (security sync keeps its own alert).
- `python -m app.demo_check` — pre-flight + dry run into a throw-away SQLite DB, notifications off, single PASS / FAIL, report file.
- `app/core/secrets.py` — Key Vault via REST + DefaultAzureCredential; secret source tracked for pre-flight.
- Page `/system-health` (not `/health`: that path is the API liveness probe and would be served instead of the page on refresh).
- Tests: `test_system_health.py`.

## Module 9 — Results
- `ruff` clean; **281 passed, 1 skipped** on SQLite; full suite passes on MySQL 8; `alembic upgrade head` + `alembic check` clean on an empty MySQL database; `tsc` + `vite build` clean.
- Job catalogue: 25 jobs. README and `docs/management-summary.md` updated.

## Deployment (existing installation, data kept)
1. Copy the changed files over the CLOUD NEXUS folder (the list is in the delivery message).
2. `cd backend` → `.venv\Scripts\activate` → `alembic upgrade head` (adds `audit_anomalies` only).
3. `python -m app.demo_check --preflight-only`, fix FAILs, then `python -m app.demo_check`.
4. `cd ..\frontend` → `npm run build` (or `npm run dev`), restart the API and worker.

## Hardening after the first live Azure runs (2026-11-18/19)
- Azure Cost Management 429: classified as throttling; waits for the longest `Retry-After` / `x-ms-ratelimit-*-retry-after`
  header; paced to one query per 10 s; up to 7 retries. Validation probe retried, so a throttle no longer marks billing
  as "not validated". `cost_detail_refresh` explains why nothing was processed.
- Entra / Graph refusals: fix text matches the identity in use (`az login` user → Entra role Global Reader; app
  registration → Graph application permission + admin consent). Management groups → Reader on Tenant Root Group.
- No Entra ID P1/P2 licence: sign-in logs reported as "not available in this tenant" (pre-flight WARN), not as a failure.
- Pre-flight now has tenant-level checks (Entra directory, management groups, Entra audit / sign-in logs), so a Graph
  refusal can no longer hide behind subscription-level PASS results. Per-subscription label is "Azure RBAC role assignments".
- Tests: 284 passed / 1 skipped (SQLite), 283 / 2 (MySQL 8); ruff clean; tsc + build clean; pip-audit and npm audit clean;
  security lint findings reviewed (false positives: own `extra()` method, validated BigQuery identifiers, fixed subprocess args).
