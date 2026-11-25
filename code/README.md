# LatentView CloudNexus

**One Platform. Every Cloud. Complete Visibility.** Unified multi-cloud operations, security and FinOps platform for
AWS, Microsoft Azure and Google Cloud: automatic discovery and onboarding, SOC audit-log review, FinOps, VM monitoring,
governance, reports, a Google Sheets control register, Google Chat and email reports, and optional AI-assisted analysis.
Read-only towards every cloud.

**Start here: [docs/LOCAL_SETUP_VSCODE.md](docs/LOCAL_SETUP_VSCODE.md)** - step-by-step setup in VS Code with MySQL.
UI design system and screen map: [docs/ui-phase12.md](docs/ui-phase12.md).
Vulnerability management, audit operations and security sync: [docs/security-operations.md](docs/security-operations.md).
Assessment and roadmap for the enterprise platform: [docs/assessment-and-plan.md](docs/assessment-and-plan.md).
Google Workspace sign-in, access registry and roles: [docs/google-workspace-sso.md](docs/google-workspace-sso.md).
Cloud Budget Management: [docs/budget-management.md](docs/budget-management.md).
Control plane v2 (identity governance, live activity, cost analysis, connections): [docs/control-plane-v2.md](docs/control-plane-v2.md).

## Workspace (v3: production reliability and simplified pages)

Seven pages cover what management asks about; everything else is under **More**.

| Page | Route | What it shows (AWS, Azure and Google Cloud) |
|---|---|---|
| Overview | `/` | Per-cloud cards and cost / vulnerabilities / live audit / access sections, each with its own "last updated" chip |
| Cloud accounts | `/accounts` | One tree per cloud: Azure tenant / management group → subscription → resource group; AWS organization / OU → account → region; GCP organization / folder → project → region. Resources, VMs, unhealthy VMs, critical / high findings and month-to-date cost at every level |
| Cost | `/cost/overview` | Actual, previous period, forecast (always separate) and budget; daily cost by cloud; top accounts, services, resource groups / regions and resources. Advanced slicing stays on `/cost/analysis` |
| Access (IAM) | `/access` | **Read-only.** Who has access at subscription / account / project, resource group / service and resource level, direct vs inherited, groups expanded to members, search by person. A scope that could not be read shows `Access data unavailable – missing permission: <permission>` for that node only |
| Vulnerabilities | `/vulnerabilities` | Open findings from Security Hub, Defender for Cloud / Advisor and SCC; per-source coverage so a refused source is never shown as "0 findings" |
| Live audit | `/activity` | Streaming CloudTrail / Activity Log / Entra / Cloud Audit Logs feed plus anomaly detection: new IP, new country, unusual hours, failure spike, privilege change, mass deletion |
| System health | `/system-health` | Pre-flight PASS / WARN / FAIL per cloud, scope and data source with the fix; every scheduled workflow with last success, next run and the reason it failed |

Reliability: every provider call goes through one layer with timeouts, retries with backoff and `Retry-After`, per-API
rate limits and a per-cloud circuit breaker; one failing scope never stops the others and never erases earlier data.
Logs are JSON with a run ID; e-mails, IPs and key IDs are masked in logs, alerts and anything sent to an LLM. A failed
or partial run raises one `job_run_problem` alert per workflow per day. Review notes per module: `docs/review/`.

### Demo readiness in one command

```
cd backend
python -m app.demo_check            # pre-flight + dry run of every collection workflow -> RESULT: PASS / FAIL
python -m app.demo_check --preflight-only
```

The dry run calls the real (read-only) cloud APIs but writes into a throw-away SQLite copy of the scope list with all
notifications off, so the production database is untouched and nobody is messaged. A partial run counts as FAIL unless
`--allow-partial` is given. The report (no secrets, masked) is written to `demo_check_report.md`.

### Secrets

Set `AZURE_KEY_VAULT_URL=https://<vault>.vault.azure.net` and give the app identity **Key Vault Secrets User**. Secret
names: `cloudnexus-database-url`, `cloudnexus-session-secret`, `cloudnexus-google-client-secret`,
`cloudnexus-entra-client-secret`, `cloudnexus-azure-client-secret`, `cloudnexus-chat-webhook-url`,
`cloudnexus-gemini-api-key`, `cloudnexus-openai-api-key`. With `APP_ENV=local` a `.env` file is fine; in production
pre-flight reports FAIL for any secret read from `.env` or when Key Vault is not configured.

### Legacy access workflows

Access requests, approvals, the approval register, reviews and revocation plans are removed from the UI. Their API is
switched off (`404`) unless `ACCESS_WORKFLOWS_ENABLED=true`; the tables and history are kept untouched.

## Current implementation status

All phases are built and covered by automated tests (304 passed, 1 skipped on SQLite; 303 passed, 2 skipped on MySQL 8; 89/89 end-to-end UI checks). v4 release notes: [docs/review/v4-executive-release.md](docs/review/v4-executive-release.md). Dependency audits (pip-audit, npm audit): no known vulnerabilities. **No phase has
been validated against a live cloud yet**: cloud calls are verified with SDK stubs. The Azure end-to-end validation plan
(preflight, reconciliation R1-R7, 24-hour soak, evidence pack) is the next task.

| Phase | Scope | Built | Validated live |
|---|---|---|---|
| 1-2 | Foundation, auth + RBAC, job engine; discovery and onboarding for AWS, GCP, Azure | Yes | No |
| 3 | SOC: CloudTrail, GCP Audit Logs, Azure Activity Log, rules, review workflow | Yes | No |
| 4 | FinOps: Cost Explorer, BigQuery billing export, Azure Cost Management, budgets, forecast, anomalies | Yes | No |
| 5 | VM monitoring and Azure resource inventory | Yes | No |
| 6-8 | Dashboard, Google Chat + Gmail reports, AI analysis (advisory) | Yes | No |
| 9-10 | Microsoft Entra ID sign-in, validation tooling (`python -m app.validation`), unattended Windows operation | Yes | No |
| 11 | CloudNexus branding, design tokens, animated sign-in, accessibility | Yes | Chromium only |
| 13 | Vulnerability management (AWS Security Hub, Azure Advisor, Google SCC), daily 02:00 UTC security sync, exceptions, SLA, audit rule engine and investigations, 16 reports | Yes | No (simulated provider APIs) |
| 12 | Reference-style UI: navy top navigation, KPI / analytics / floating panels / provider cards on every module; new Dashboard, Governance, Reports, Notifications pages | Yes | Chromium only, test data |
| 16 | Unified Cloud Inventory explorer (hierarchy OU / folder / tenant → scope → resource group, categories, resource detail with tags, findings, VM health) and Cloud Budget Management (register, revisions, configurable approval chains, additional-budget and new-service requests, internal threshold alerts) | Yes | No (test data only) |
| 14 | Enterprise foundation: Google Workspace SSO (PKCE, nonce, `hd` + verified e-mail), access registry, server-side sessions, 16 roles incl. Project Owner scope assignments, 13-section left navigation, global search | Yes | No (Google endpoints simulated in tests) |
| 17-20 | Cloud Access Management (actual assignments vs approval register, request / extension / revocation chains with provider-side verification, reviews), Executive Command Center v2 (21 KPIs, risk & decision centre), cost explorer + optimisation, governance frameworks / controls / evidence / onboarding workflow, AI Intelligence Center (Copilot, 6 agents, governed recommendations), 15 reports with schedules and archive, rate limiting. See [docs/access-governance-ai-reports.md](docs/access-governance-ai-reports.md) | Yes | No (test data only) |
| 21 | Control plane v2: cloud connection registry, live activity feed (SSE) with Entra audit / sign-in logs and investigation, cost analysis (12 billing periods, resource / region / SKU / tag grouping, amortized, provider forecasts and budgets), identity directory and lifecycle (Entra, PIM, management groups, AWS inline / keys / trust, GCP org + folder IAM, service accounts), effective access, revocation plans, access exceptions, Defender for Cloud + Azure Policy, AWS / GCP resource inventory, structured AI analysis, hash-chained central audit trail, management decisions. See [docs/control-plane-v2.md](docs/control-plane-v2.md) | Yes | No (simulated provider APIs, test data) |

Database: **MySQL 8 now**; database-neutral for a later move to **Azure SQL**
([docs/deployment/azure-sql-migration.md](docs/deployment/azure-sql-migration.md)) - planned, not yet tested.

## What each module does

- **Discovery / onboarding** - finds every account, project (including nested folders) and subscription with no IDs in code;
  validates authentication, permissions, audit logs, billing and monitoring; eight onboarding statuses; gaps become
  approval tasks. Nothing is changed in any cloud.
- **Cloud connections** - each cloud's identifiers are entered and tested on the Account Onboarding page (or in `.env`);
  no credential is entered or stored in the application.
- **SOC** - incremental collection with a checkpoint per scope into one unified event schema; rule-based detection with
  severity, risk score, duplicate folding and correlation by principal; findings stay *Pending Review* until an analyst
  records a decision (append-only history); *Confirmed Suspicious* opens an incident and queues an alert.
- **FinOps** - daily cost per scope and service, original currency + USD + INR with the rate and timestamp stored,
  provisional/final flag, AWS and GCP by calendar month and Azure by each subscription's own billing period, budgets with
  70/80/90/100% levels, run-rate forecast, anomaly detection, daily/weekly/monthly summaries.
- **VM monitoring** - inventory, power state, platform metrics, guest metrics where an agent exists, internet-open ports,
  create/delete/resize records. Missing metrics give *Partial data* or *Unknown*, never *Healthy*.
- **Google Sheets** - 17 tabs, stable record keys (no duplicates), append-only history tabs, reviewer columns never overwritten.
- **Notifications** - a message is marked sent only after the provider accepts it; every report starts with
  `REPORT STATUS: COMPLETE | PARTIAL | FAILED` and names failing scopes.
- **AI** - optional and advisory: evidence, affected resource, risk, confidence, suggested action. Log content is treated
  as untrusted data. AI cannot change a review status; with no AI configured, rule detection is unaffected.
- **Automation** - 25 runnable jobs (incl. `anomaly_detection` every 5 min and a daily `preflight`) with overlap locks, execution history and a local cron scheduler (Asia/Kolkata).

## Configuration requirements

All settings are in `.env.example`. Locally you sign in with `aws sso login`, `gcloud auth application-default login`
and `az login`; no access keys or key files are stored.

- **AWS**: read-only role in every member account (`AWS_MEMBER_ROLE_NAME`, external ID); management identity with
  Organizations read, `sts:AssumeRole`, Cost Explorer read.
- **GCP**: `GCP_ORGANIZATION_ID`; org-level Browser, Folder Viewer, Logs Viewer, Monitoring Viewer, Compute Viewer,
  Service Usage Viewer, Billing Viewer; BigQuery read on the billing export (`GCP_BILLING_EXPORT_TABLE`).
- **Azure**: Reader, Monitoring Reader, Cost Management Reader on each subscription; `AZURE_TENANT_ID`, `AZURE_PRINCIPAL_OBJECT_ID`.
  For the Access page and live audit: Reader at the Tenant Root Group (management-group inheritance) and Microsoft Graph
  application permissions with admin consent: `User.Read.All`, `Group.Read.All`, `Application.Read.All`,
  `RoleManagement.Read.Directory`, `AuditLog.Read.All`.
- **AWS (Access page, resource level)**: `s3:ListAllMyBuckets`, `s3:GetBucketPolicy`, `kms:ListKeys`, `kms:DescribeKey`,
  `kms:GetKeyPolicy` in the member role; `sso:List*` / `identitystore:List*` in the management account for Identity Center.
- **GCP (Access page, resource level)**: Cloud Asset Viewer (`cloudasset.assets.searchAllIamPolicies`) with the Cloud
  Asset API enabled; Groups Reader in Google Workspace plus the Cloud Identity API for group membership.
- **Optional**: Google Sheet shared with the platform identity; Google Chat webhook; Gmail service account with
  domain-wide delegation; Gemini or OpenAI key and model name; USD/INR rate.

## Known limitations

- No live cloud validation yet (see status table). Azure SQL is untested.
- AWS guest metrics use a CloudWatch `SEARCH` expression over the `CWAgent` namespace; confirm it against your agent configuration.
- Azure memory and disk utilisation are not collected (needs VM Insights / guest agent); Azure NSG exposure reads NIC-level NSGs only, not subnet-level.
- Azure billing-period start is taken from the first usage day of the subscription's billing month; the period end date is not stored.
- GCP billing reads the standard export by usage date in UTC; a large export table is scanned for the 35-day window on every hourly run.
- Rules for "configuration drift", "unusual resource creation" and "unusual API calls" are covered by change-event rules and a
  first-seen-API baseline (needs 7 days of history); there is no configuration snapshot comparison.
- `resource_inventory` covers Azure (all resources), AWS (main services per region) and GCP (Cloud Asset Inventory). Listening-port (guest-level) monitoring is not built; exposure is from firewall rules.
- Forecasts: AWS Cost Explorer and Azure Cost Management forecasts where collected; GCP uses a run-rate estimate (no API).
- Sign-in: Microsoft Entra ID or Google (OpenID Connect). Local development uses `AUTH_MODE=dev`, refused in production. HTTPS is required before any shared deployment.
- Not collected (shown as "not collected" in the UI, never as zero): AWS Config / GCP Org Policy as separate sources (they arrive through Security Hub / SCC), provider rightsizing advice and savings estimates. See docs/control-plane-v2.md section 7.
- UI tested in Chromium only (Edge uses the same engine); Firefox and Safari untested. Official LatentView logo and brand colours not supplied: slots and proposed tokens are in `frontend/public/brand/` and `frontend/src/theme/tokens.css`.
- `Dockerfile`, `docker-compose.yml` and `infrastructure/terraform/main.tf` were not built or applied; Terraform targets Google Cloud and is a draft.
- Tests and migrations live under `backend/` rather than top-level `tests/` and `database/`.

## Tests

`cd backend && python -m pytest -W ignore` (SQLite) or set `TEST_DATABASE_URL` to a MySQL URL. Results: `docs/integration-test-report.md`.
UI checks (screenshots, accessibility, console errors): `node scripts/validation/ui-check.cjs` against a running instance.

## Next development task

Run `python -m app.demo_check` against the live Azure tenant, fix every FAIL it lists, then AWS and GCP. After that, live validation one cloud at a time, following Part B of the VS Code guide: discovery, then `security_events`,
`billing_refresh`, `vm_metrics`; record each fix in `docs/troubleshooting/troubleshooting.md`. Then the Azure SQL test cycle.

## Layout

```
backend/app/{api,core,database,models,schemas,scheduler,workers,utils}
backend/app/services/{aws,gcp,azure,onboarding,soc,finops,monitoring,google_sheets,notifications,ai}
backend/migrations   backend/tests/{unit,integration,security}
frontend/src/{pages,components,layouts,hooks,services,auth}
.vscode/   infrastructure/   scripts/   docs/
```
