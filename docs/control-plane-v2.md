# CloudNexus control plane v2: identity governance, live activity, cost analysis, connections

This document covers the assessment (Phase 0), what was built for Phases 1-8 of the master prompt, the API, the
migration, the cloud permissions each feature needs, and the live validation still to be done. **Built** = implemented and
tested (242 tests, SQLite and MySQL 8). **Validated live** = checked against your clouds: nothing in this document is
validated live yet.

## 1. Phase 0 assessment (summary)

| Area | Before this release | Gap closed |
|---|---|---|
| Stack | FastAPI, SQLAlchemy, Alembic, MySQL 8, React/TS/Tailwind, in-process scheduler | Kept (no PostgreSQL / Redis / Celery switch: decision recorded with you) |
| Auth / RBAC | Google Workspace SSO, server-side sessions, 16 roles, permission checks on every endpoint | Unchanged; new endpoints use the same permission model |
| Discovery | AWS Organizations, Azure subscriptions, GCP org / folders / projects; onboarding checks | New **Cloud connections** registry per scope and per data source |
| Activity | CloudTrail, Azure Activity Log, GCP Audit Logs every 5 min; rule engine, cases | **Live feed (Server-Sent Events)**, Entra audit + sign-in logs, investigation answers, delay vs ingestion, CSV/JSON export |
| Cost | Daily cost per scope and service; explorer; run-rate forecast | **Cost detail** (resource, resource group, region, SKU, usage type, tags, amortized), provider forecasts and budgets, 12 billing periods, 12 groupings, charts |
| IAM | Azure RBAC (subscription), AWS IAM managed policies + Identity Center, GCP project IAM | Entra users / groups / SPs / managed identities, directory roles, PIM eligibility, management groups, AWS inline policies / boundaries / trust / access keys, GCP org + folder IAM (inherited), service accounts + keys, effective access via groups |
| Lifecycle | None | New / disabled / deleted detection, 30-day NEW badge, change trail linked to provider events, revocation plans with verification |
| Reconciliation | Approved vs actual statuses | Exceptions with ID, owner, risk, evidence, resolution (8 categories) |
| Inventory | All Azure resources; VMs on AWS / GCP | AWS EC2 volumes, VPC, subnets, SGs, S3, ELB, RDS, EKS, Lambda, Backup; GCP via Cloud Asset Inventory |
| Security | Security Hub, Azure Advisor, SCC | + Defender for Cloud assessments and alerts, Azure Policy non-compliance (de-duplicated against Advisor) |
| AI | Copilot, agents, governed recommendations | Structured analysis (summary, evidence, risk, impact, confidence, action, event IDs, resources) with validation against the facts |
| Audit | Per-module append-only tables | **Central audit trail** with SHA-256 hash chain + DB triggers, verify endpoint |
| Executive | 21 KPIs, risk centre, decision tracker | Per-cloud health, identity KPIs, management decision register (owner, due date, impact) |

Existing modules, routes and tables were kept. The admin users page stays at `/admin/access`.

## 2. New and changed jobs

| Job | Schedule (UTC) | Purpose |
|---|---|---|
| `access_inventory` | 10,25,40,55 * * * * (was hourly) | RBAC / IAM + directory, lifecycle, effective access, exceptions, revocation verification, alerts |
| `entra_activity` | */5 | Entra directory audits and sign-ins into the activity feed |
| `cost_detail_refresh` | 20 * * * * | Cost detail, provider forecasts, provider budgets |
| `connection_health` | */15 | Connection registry check; alerts when auth or a data source starts failing |
| `resource_inventory` | */15 | Now AWS and GCP too; a partial listing never marks resources deleted |
| `security_findings_sync` | administrator-set (default 02:00) | Now includes Defender for Cloud and Azure Policy. Set it to every 15-30 min in Integrations > Schedule if you want near-real-time findings |

Total job catalogue: 23.

## 3. API (all under `/api/v1`, permission in brackets)

- `GET /connections/registry` (sync:read | onboarding:read | inventory:read)
- `GET /activity/events`, `/activity/stream` (SSE), `/activity/events/{id}/investigation`, `/activity/freshness`, `/activity/export?format=csv|json` (audit:read)
- `GET /cost/analysis?period&group_by&cost_type&provider&scope&service&region&resource_group&start&end&fy` (finops:read)
- `GET /iam/identities`, `/iam/identities/{id}`, `/iam/effective`, `/iam/privileged`, `/iam/changes`, `/iam/exceptions`, `/iam/revocations`, `/iam/revocations/{id}` (access:read)
- `POST /iam/identities/{id}/revocation-plan`, `/iam/identities/{id}/shared`, `PATCH /iam/exceptions/{id}` (access:manage)
- `POST /iam/revocations/{id}/step` actions request_approval / approve (access:approve, not the creator) / reject / executed / verify / cancel / skip_item
- `POST /ai/analyze`, `GET /ai/analyses` (ai:use + the subject's read permission)
- `GET /audit-trail`, `/audit-trail/verify` (audit:read | admin:users)
- `GET|POST /executive/decisions`, `PATCH /executive/decisions/{id}`, `GET /executive/operations-health`

## 4. Database migration `0007`

12 new tables (identity_group_members, iam_credentials, iam_effective_access, identity_change_events, access_revocation_plans,
access_revocation_items, iam_exceptions, cost_detail_records, provider_budgets, audit_trail, ai_analysis_results,
management_decisions); new nullable columns on cloud_identities and access_assignments (`lifecycle_status` defaults to
Active). Append-only triggers on identity_change_events, audit_trail, ai_analysis_results. Tested upgrade / downgrade /
upgrade on MySQL 8. Back up the database first; no existing data is changed.

One behaviour change: Azure assignments inherited from a management group are now stored once **per subscription**
(key includes the subscription). This fixes a unique-key error with more than one subscription under a management group.
On the first run after upgrading, old inherited rows are marked removed and re-added; change detection ignores this
because it compares principal + role + scope, not row IDs.

## 5. Cloud permissions to add (read-only)

| Feature | Azure | AWS | GCP |
|---|---|---|---|
| Directory / lifecycle | Microsoft Graph application permissions: User.Read.All, Group.Read.All (or GroupMember.Read.All), Application.Read.All, RoleManagement.Read.Directory | iam:Get*, iam:List*, identitystore:List*, sso:List* | iam.serviceAccounts.list, iam.serviceAccountKeys.list (Security Reviewer or IAM Reviewer) |
| Hierarchy IAM | Reader at the tenant root management group (covers management groups and PIM eligibility read) | - | resourcemanager.organizations.getIamPolicy, folders.getIamPolicy (Organization Viewer + Folder Viewer + Security Reviewer) |
| Activity | Monitoring Reader; Graph AuditLog.Read.All; sign-in logs need Entra ID P1/P2 | cloudtrail:LookupEvents | Logs Viewer |
| Cost detail | Cost Management Reader | ce:GetCostAndUsage, ce:GetCostForecast, budgets:ViewBudget (+ opt-in for resource-level data) | BigQuery read on the export (and the detailed export for resource level) |
| Security | Security Reader (Defender), Reader (Policy states) | Security Hub read | Security Center Findings Viewer |
| Inventory | Reader | ec2/s3/elasticloadbalancing/rds/eks/lambda/backup Describe/List (ReadOnlyAccess) | Cloud Asset Viewer |

Missing permissions appear on **Cloud connections** and in job failures as "access denied", never as zero.

## 6. Settings (`.env`)

`COST_DETAIL_DAYS` (35), `COST_TAG_KEYS` (environment,cost-center,business-entity), `COST_INCLUDE_AMORTIZED` (true),
`AWS_RESOURCE_COST_ENABLED` (false), `GCP_BILLING_DETAILED_EXPORT_TABLE`, `FINANCIAL_YEAR_START_MONTH` (4).

## 7. Known limitations (documented, shown in the UI)

- Activity is polled every 5 minutes; EventBridge, Event Hubs, Pub/Sub sinks and CloudTrail Lake are not connected.
  CloudTrail LookupEvents has management events only.
- Invoice documents are not read: "last invoice" periods use billing months.
- Effective access expands Entra groups (transitive) and AWS IAM groups. GCP group membership needs Cloud Identity and is
  not expanded; Azure deny assignments, AWS SCPs and resource policies are not evaluated.
- Revocation is never executed by CloudNexus (your decision): an administrator removes access in the provider and the
  plan is verified against the next complete inventory; after 48 hours without that it becomes VERIFICATION_FAILED.
- GCP has no forecast API (run-rate estimate) and GCP billing budgets are not read.
- The hash chain detects alteration; it is not an external notarisation. Keep database backups and restrict DB admin access.

## 8. Live validation runbook (do in order, Azure first)

1. Back up MySQL, unzip, `alembic upgrade head` (expect 0007), rebuild the frontend, restart.
2. Grant the Graph permissions above to the CloudNexus app registration (admin consent). Run `access_inventory`.
   Compare **Actual access** with Subscription > IAM > Role assignments, including resource-group and inherited ones.
3. Compare **New users & identities** (All) with Entra ID > Users; disable a test user, run the job, confirm **Deleted / disabled**.
4. Run `entra_activity` and `security_events`; open **Live cloud activity**, make a test change in the portal, confirm it
   appears without refreshing after the next run, and that the investigation answers are right.
5. Run `cost_detail_refresh`; compare **Cost analysis** (resource group, region, amortized) with Azure Cost analysis for the same dates.
6. Run `security_findings_sync`; compare Defender recommendations with **Security findings** (no duplicates with Advisor).
7. Repeat 2-6 for AWS, then GCP. Record every difference in `docs/troubleshooting/troubleshooting.md`.
