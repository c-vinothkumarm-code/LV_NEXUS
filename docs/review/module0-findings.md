# Module 0 – Codebase review: external calls, workflows, findings and plan

Reviewed: commit `HEAD` of CloudNexus (backend 23 jobs, ~60 API route groups, frontend ~60 pages). Nothing was changed
in this module. Severity: **High** = can make a demo run fail or show wrong data; **Medium** = degrades reliability or
violates a stated requirement; **Low** = polish.

## 1. Inventory

### 1.1 Workflows (scheduled jobs)

| Job | Default schedule | What it calls |
|---|---|---|
| account_discovery | every 15 min | AWS Organizations, STS AssumeRole; Azure subscriptions; GCP Resource Manager (org, folders, projects); per-scope validation (IAM test calls, CloudTrail, Cost Explorer, Monitoring, Service Usage, Billing) |
| resource_inventory | every 15 min | Azure Resource Manager resources.list; AWS EC2/EBS/VPC/SG/S3/ELBv2/RDS/EKS/Lambda/Backup per region; GCP Cloud Asset searchAllResources |
| vm_metrics | every 15 min | AWS EC2 describe_instances + CloudWatch GetMetricData; Azure Compute + Monitor metrics; GCP Compute + Cloud Monitoring list_time_series |
| security_events | every 5 min | AWS CloudTrail LookupEvents (every region); Azure Activity Log; GCP Cloud Logging list_entries |
| entra_activity | every 5 min | Microsoft Graph auditLogs/directoryAudits, auditLogs/signIns |
| billing_refresh | hourly | AWS Cost Explorer GetCostAndUsage; Azure Cost Management Query; GCP BigQuery billing export |
| cost_detail_refresh | hourly | Azure Cost Management Query (4–6 queries / subscription), Forecast, Consumption Budgets; AWS GetCostAndUsage (3+ / account), GetCostForecast, Budgets; GCP BigQuery |
| access_inventory | every 15 min | Azure Authorization (role definitions / assignments), Graph (users, SPs, groups, apps, directory roles, PIM), ARM management groups, PIM eligibility; AWS IAM (users, roles, policies, keys), Identity Center, Identity Store; GCP getIamPolicy (org, folders, projects), IAM service accounts + keys |
| security_findings_sync | admin-set (02:00 UTC) | AWS Security Hub GetFindings; Azure Advisor, Defender assessments/alerts, Policy states, Resource Graph; GCP SCC findings |
| connection_health | every 15 min | none (database only) |
| audit_rule_evaluation, security_sla_check, budget_alerts, ai_analysis | 5–60 min | database; ai_analysis calls Gemini / OpenAI when configured |
| sheets_sync, *_daily_review, weekly/monthly_reports, consolidated_daily_report, scheduled_reports, notification_dispatch | various | Google Sheets API, Gmail API, Google Chat webhook |

### 1.2 External API calls by provider (distinct operations)

- **AWS (boto3)**: organizations (describe_organization, list_accounts, list_parents, describe_organizational_unit), sts (assume_role, get_caller_identity), cloudtrail lookup_events, ce (get_cost_and_usage, get_cost_and_usage_with_resources, get_cost_forecast), budgets describe_budgets, ec2 (describe_instances, describe_security_groups, describe_volumes/vpcs/subnets, describe_regions), cloudwatch get_metric_data, s3 list_buckets, elbv2, rds, eks, lambda, backup, iam (list_users/roles/groups, list_*_policies, get_user, list_access_keys, get_access_key_last_used), sso-admin, identitystore, securityhub (get_findings, aggregators).
- **Azure (SDK + REST)**: subscriptions.list, resources.list, authorization role_definitions/role_assignments, monitor activity_logs/metrics, costmanagement query (SDK) + query/forecast (REST), consumption budgets, Advisor, Security assessments/alerts, PolicyInsights, Resource Graph, management groups, PIM schedule instances, Microsoft Graph (users, servicePrincipals, groups/transitiveMembers, applications, roleManagement, auditLogs).
- **GCP**: resourcemanager v3 (projects, folders, organizations, get_iam_policy, test_iam_permissions), service usage, billing, logging, monitoring, BigQuery, Cloud Asset searchAllResources, IAM service accounts/keys (REST), SCC (REST).
- **Google Workspace / other**: Sheets, Gmail, Chat webhook, Cloud Identity groups (sign-in), Gemini/OpenAI (optional).

## 2. Findings

| # | Sev | Finding | Evidence |
|---|---|---|---|
| F1 | High | **Retry/timeout handling is inconsistent.** A shared `with_retry` (backoff + jitter, honours Retry-After) exists but is used in only 7 modules. Discovery, billing, VM metrics, audit-log, Entra and Sheets paths rely on SDK defaults. AWS has an explicit botocore config (adaptive, 8 attempts, 10 s/30 s timeouts); Azure SDK and GCP gRPC calls have **no explicit timeouts** (Azure defaults allow multi-minute hangs). | `grep with_retry` → 7 files; 13 cloud-calling modules without it |
| F2 | High | **No circuit breaker.** When a provider is down or credentials are invalid, every scope is still attempted with full retries (e.g. 12 subscriptions × 4 attempts × timeout), so one bad cloud makes the whole run slow and noisy. | scheduler/engine.py, every run_* loop |
| F3 | High | **No per-provider rate limiting.** `cost_detail_refresh` issues 4–6 Cost Management queries per subscription back to back; Azure Cost Management throttles per scope (429 / QPU). Most likely cause of the `cost_detail_refresh` failure on your machine. | finops/detail.py |
| F4 | High | **Isolation too coarse inside some jobs.** In cost_detail_refresh one failing breakdown (e.g. a tag query) aborts the remaining breakdowns of that subscription; in entra_activity a 403 marks the job FAILED instead of "source unavailable: missing AuditLog.Read.All". | detail.py `run()`, soc/entra.py |
| F5 | High | **Permission gaps surface as job failures, not as a pre-flight result.** Your current state: entra_activity FAILED (Graph 403), access_inventory PARTIAL (Graph 403 ×6, management groups 403), cost_detail_refresh FAILED, connection_health/report jobs PARTIAL as a consequence. A demo would show red statuses for configuration, not defects. | your Jobs page |
| F6 | Medium | Pre-flight exists (`python -m app.validation preflight`, `azure`) but covers platform + Azure only: no per-scope read probe for every API, no AWS/GCP API-enablement check, no Sheets/Gmail/Chat reachability, no UI page, no single PASS/FAIL. | validation/preflight.py |
| F7 | Medium | Logs are plain text with secret redaction; no JSON, run ID, per-API duration or per-API error counters. Run logs record scopes total/failed but not discovered/retried/API error counts/duration per API. | core/logging.py, AutomationExecutionLog |
| F8 | Medium | No generic alert when a run fails or a scope could not be scanned (only feature-specific alerts). | notifications |
| F9 | Medium | No dry-run mode (every run writes to DB / Sheets and can send messages). | – |
| F10 | Medium | Secrets come from `.env` (Azure client secret, Gemini key, webhook). No secret-manager integration. | core/config.py |
| F11 | Medium | Masking covers tokens and AWS key patterns, **not e-mails or IPs**. The AI analysis and Copilot send principal e-mails and source IPs to the LLM unmasked. | ai/analysis.sanitize, intelligence/structured.py |
| F12 | Medium | Last-good data: most pages read stored data (good), but "Last updated" labels are inconsistent and some panels show "not collected" when only the latest run failed. | various pages |
| F13 | Medium | **Access management is over-built for the requirement**: ~3,400 lines, 17 tabs, write workflows (requests, approvals, reviews, revocation plans, exceptions). Data sources also differ from the requested ones: Azure per-subscription RBAC (not Resource Graph `authorizationresources`), GCP per-project/folder getIamPolicy (not `searchAllIamPolicies`, so no resource-level GCP IAM), AWS without S3/KMS resource policies, no Cloud Identity group expansion. | access/*, platform.py, 2 pages |
| F14 | Medium | Scheduler runs inside the API process on a laptop: sleep/hibernate = missed runs, and the "running" lock is released only after timeout. For the demo use an always-on host or run the dry-run/manual run just before. | scheduler |
| F15 | Low | The application surface is much larger than the demo scope (vulnerability management, budgets workflow, governance, AI agents, 15 reports). More menu items = more places that show "not collected" during a demo. | AppLayout SECTIONS (13 sections) |
| F16 | Low | Athena/CUR is not used for AWS cost (Cost Explorer is). Correct for accounts without CUR; listed so the pre-flight does not require Athena. | finops |

Already in good shape (kept): idempotent upserts for every store (stable keys; Sheets record keys; audit events de-duplicated by provider + event ID; cost windows replaced, not appended); per-scope try/except in every collector loop; partial listings never mark resources/assignments deleted; AWS role sessions refreshed per run; read-only cloud access everywhere (no write API is called).

## 3. Proposed modules (implemented one at a time, each with tests, waiting for your confirmation)

1. **Shared cloud client layer** – one `call()` wrapper for every provider call: explicit timeouts, retries with exponential backoff + jitter (429 / 5xx / timeouts), Retry-After, per-provider token-bucket rate limiter, per-provider circuit breaker (opens after N consecutive failures → provider "Unavailable" for the rest of the run), classified errors (throttle / permission / not enabled / auth expired / timeout), credential refresh, JSON structured logging (run_id, provider, scope, api, duration_ms, result, attempts), per-run API metrics stored on the run log. All collectors moved onto it.
2. **Run status model + alerts + dry run** – statuses SUCCESS / DEGRADED / FAILED with per-scope outcome (scanned / skipped-permission / failed); Run_Log fields (discovered, scanned, failed, retried, API errors, duration); one alert (e-mail + Chat) when a run fails or any scope was not scanned; `DRY_RUN` mode (no DB/Sheet writes, no messages).
3. **Pre-flight + System Health page** – per cloud, per scope, per API read probe (credentials, permissions, API enabled), Sheets/Gmail/Chat reachability; pass/fail table with the exact fix text; on-demand from the UI and automatically before each scan.
4. **Collector hardening** – fix F3/F4 (paced Cost Management queries, per-breakdown isolation), permission gaps reported as "unavailable – missing X" (not job failure), "Last updated" on every dashboard section from the last successful run.
5. **Access page rewrite** – single read-only page: tree (cloud → MG/org/OU → subscription/project/account → RG/folder → resource) + identity table; sources: Azure Resource Graph `authorizationresources` + Graph names, GCP `searchAllIamPolicies` + Cloud Identity members, AWS Identity Center + IAM + S3/KMS policies; daily cached snapshot; per-node "unavailable – missing permission". Old access workflows removed from UI and API.
6. **Security** – secret-manager loader (Azure Key Vault / GCP Secret Manager; `.env` only when APP_ENV=local), e-mail/IP/key-ID masking in logs and in everything sent to an LLM.
7. **Tests + demo readiness** – mocked tests for success, 429, 5xx, timeout, 403, expired credentials, empty, large pagination for every collector; `python -m app.demo_check` (pre-flight + full dry run → single PASS/FAIL).
8. **README + one-page management summary** (coverage and success rate from real run data).
