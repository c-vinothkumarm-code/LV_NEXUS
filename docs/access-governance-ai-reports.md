# Phases 5–8: Access Management, Executive v2, Cost Intelligence, Governance, AI, Reports

Status words follow the README: **Built** = implemented with automated tests (SQLite and MySQL 8); **Validated live** =
checked against your real clouds. None of these modules has been validated live yet.

## Cloud Access Management (`/access`, API `/api/v1/access/*`)

Two records are kept apart on purpose:

| Record | Source | Table |
|---|---|---|
| **Actual assignment** — who really holds a role | `access_inventory` job reading the providers | `access_assignments`, `cloud_identities` |
| **Approval record** — what the business approved | requests approved in CloudNexus, or the imported register (CSV) | `access_grants`, `access_requests`, `access_approvals` |

`reconcile()` compares them and sets each assignment's status: approved, unapproved, expired still active,
approved not provisioned. A grant or revocation request goes through a configurable chain (manager → IT manager →
governance for privileged roles), is then **executed by an administrator in the provider console**, and becomes
VERIFIED only when the next inventory shows the change. After 48 hours without it, the request becomes
VERIFICATION_FAILED. CloudNexus never grants or removes access.

Provider coverage and limitations:

| Provider | Collected | Not collected |
|---|---|---|
| Azure | RBAC role assignments at management group, subscription, resource group and resource scope | Entra sign-in activity, PIM eligible assignments (need Microsoft Graph / PIM read) |
| AWS | IAM users, groups, roles with attached managed policies; IAM Identity Center permission-set assignments | Inline policies, SCPs, permission boundaries, resource policies (not an effective-permission calculation) |
| GCP | Project-level IAM bindings incl. conditions | Organization / folder bindings inherited by the project; resource-level IAM |

Read permissions needed: Azure `Microsoft.Authorization/roleAssignments/read` + `roleDefinitions/read` (Reader covers
both); AWS `iam:List*`, `iam:Get*`, `sso:List*`, `identitystore:Describe*`; GCP `resourcemanager.projects.getIamPolicy`.

## Executive Command Center v2 (`/`, API `/api/v1/executive/summary`)

21 KPIs, each with a link to its source page. A value that is not collected, or not visible to the role, shows "—"
with the reason, never 0. Risk & decision centre groups: immediate (Critical), high priority, financial, access,
compliance. Decision tracker lists pending budget, access and onboarding decisions with who acts next.

## Cost intelligence (`/cost`, `/cost/optimization`)

Periods: last 30 days, 12 weeks, this month, quarter, year, custom. Drilldown cloud → account → service, with the
billing records behind every figure (exportable). Definitions shown on the page: AWS UnblendedCost, Azure ActualCost,
GCP net of credits; currency converted at collection with the stored rate. Actual and forecast are labelled separately.
Optimisation lists only what the collected data supports (idle VMs from metrics, stopped VMs still billed, unused
budgets, new services); everything else is listed as "not detected".

## Governance & Compliance (`/governance/compliance`, `/governance/onboarding`)

Native frameworks come from the compliance standards on findings (CIS, AWS FSBP, etc.); others (ISO 27001, SOC 2,
internal) are imported by CSV with your control text. Control status: FAIL when mapped findings are open, PASS when
mapped findings are all passing, otherwise NOT ASSESSED; a manual status needs evidence. Pass rates are **not** a
certification.

Onboarding workflow: requirement → manager → cost estimate → Finance → governance → architecture & security → setup
(link the real account) → deployment → VAPT (evidence required) → production. Internet-facing requests add WAF, DAST,
domain, TLS, exposure and logging checks. Production approval is blocked while the linked scope has open Critical or
High findings without an approved exception.

## AI Intelligence Center (`/ai`, API `/api/v1/ai/*`)

The Copilot routes a question to permission-checked tools that read CloudNexus records (findings, budgets, access,
exposure, cost, idle VMs). Without a configured model (`AI_PROVIDER=none`) the answer is assembled from the facts;
with Gemini or OpenAI the model writes the answer from the same facts only. Six agents (Security, FinOps, Access,
Infrastructure, Governance, Executive) create recommendations. Lifecycle: proposed → accepted / approval requested →
approved → executed **by a person outside CloudNexus** → verified against the next synchronization. Every step is in
the append-only `ai_action_events` table.

## Reports (`/reports/library`, API `/api/v1/reports/*`)

15 reports in CSV, Excel and PDF, each gated by the permission of its data. Schedules (daily / weekly / monthly, UTC)
run in the `scheduled_reports` job; each file is archived (`report_archive`) and e-mailed through the Gmail channel.
A failed delivery is recorded as failed. Rate limiting: `RATE_LIMIT_PER_MINUTE`, `AUTH_RATE_LIMIT_PER_MINUTE`.

## Migration

`20261118_0006_access_governance_ai_reporting` adds 19 tables and `notification_logs.recipients`; append-only tables
get database triggers. Backward compatible; tested up / down / up on MySQL 8.

## Live validation checklist (to do with your estate)

1. Run `access_inventory` for the Azure subscription that works today; compare counts with the portal's Access control (IAM) blade.
2. Import your business access register CSV; review unapproved and expired-still-active results with the Access Administrator.
3. Compare `/cost` month to date with Azure Cost Management (ActualCost) for the same subscription and dates.
4. Raise one test access request end to end; grant it manually in Azure; confirm it reaches VERIFIED after the next inventory run.
5. Schedule one report to yourself; confirm the e-mail arrives and the archive entry exists.
