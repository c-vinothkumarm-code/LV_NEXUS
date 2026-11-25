# CloudNexus: existing-system assessment and implementation plan

Assessed 17 Nov 2026 against the master prompt "Complete Enterprise Multi-Cloud Intelligence, Security, Access
Governance & FinOps Platform". Status words: **Built** = implemented with automated tests; **Validated live** = checked
against a real cloud; **Not built** = absent.

## 1. Architecture map

```
Browser (React 19 + TypeScript + Tailwind 4 + Recharts)        HttpOnly session cookie, CSRF header, no tokens in storage
   |  /api/v1/*  (Vite proxy locally; API serves the built SPA in production)
FastAPI (Python 3.13)
   ├─ api/routes: auth, admin, inventory(+search), dashboard, operations, security, audit_ops, sync, jobs, health
   ├─ core: settings (.env / Secret Manager), RBAC + sessions (security.py)
   ├─ services: aws | azure | gcp connectors, onboarding, soc, audit (rule engine), vuln (Security Hub, Advisor, SCC),
   │            finops, monitoring, notifications (Chat, Gmail), google_sheets, ai (advisory), identity (Google groups)
   ├─ scheduler + workers: 17 jobs, DB lock per job, execution history, local cron (per-job timezone)
   └─ validation: preflight, Azure reconciliation R1-R7, evidence pack
SQLAlchemy 2 + Alembic 0001-0004  ->  MySQL 8 (now); database-neutral for Azure SQL / PostgreSQL
Append-only history tables enforced by ORM guard + database triggers
```

## 2. Integration status

| Provider | Discovery | Inventory / VMs | Audit logs | Billing | Security findings | Live status |
|---|---|---|---|---|---|---|
| Azure | Subscriptions via service principal (Reader) | Resource inventory, VM metrics (platform) | Activity Log | Cost Management | Azure Advisor (Security category) | **Working on your machine for 1 subscription** (connection configured; scale-out to ~12 subscriptions pending) |
| AWS | Organizations + STS AssumeRole into member accounts | EC2 + CloudWatch | CloudTrail | Cost Explorer | Security Hub | Built, not validated live |
| GCP | Org/folder/project traversal | Compute + Monitoring | Cloud Audit Logs | BigQuery billing export | Security Command Center | Built, not validated live |

Not integrated yet (prompt section 9.1/10.1/12): Microsoft Defender for Cloud (excluded at your request; Advisor is used),
AWS Config / Inspector / GuardDuty / Access Analyzer / Trusted Advisor as separate sources (they arrive through Security
Hub when enabled there), Azure Policy, GCP Organization Policy, AWS Budgets / Azure Budgets / GCP Budgets APIs, all
identity and IAM inventories (needed for Access Management).

## 3. Module coverage against the prompt

| Prompt module | Today | Gap |
|---|---|---|
| 4 SSO + RBAC | **Built this phase**: Google Workspace SSO, registry, sessions, 16 roles, scope assignments | Resource-level permissions beyond scope (resource group) |
| 5 UI/UX | **Built this phase**: 13-section left navigation (built modules only), top bar search + global filters, light/dark | Environment and billing-period selectors are page-specific today; AI Copilot entry waits for Phase 7 |
| 6 Executive Command Center | Overview page (scopes, resources, findings, MTD cost, budget use, VM health, alerts, freshness) | Access KPIs, budget approvals, risk & decision centre, YTD, forecast KPIs |
| 7 AI | Advisory AI for findings and audit events (OpenAI/Gemini optional) | Copilot, agents, action-approval workflow |
| 8 Inventory | Scopes, resources, VMs, metrics, exposure | Organisation hierarchy drilldown (OU / management group / folder), resource detail page, OS / vCPU / memory size, backup status |
| 9 Security & audit | Unified findings, lifecycle, exceptions, SLA, audit rule engine, cases, 16 reports | Lifecycle states differ from the prompt list (mapping needed); configurable severity mapping UI |
| 10 Cost intelligence | Daily cost per scope/service, USD/INR, provisional flag, forecasts, anomalies | Amortized vs unblended vs credits, quarterly/yearly views, resource-level cost, optimisation (idle VMs, unattached disks) |
| 11 Budget management | Simple budgets with thresholds (70/80/90/100) | Budget register fields, revisions, additional-budget and new-service workflows, Finance approvals |
| 12 Access management | Not built | Whole module |
| 13 Governance | Onboarding status per scope, exceptions | Frameworks, controls, evidence, onboarding governance workflow |
| 14 Cloud operations | Audit activities, jobs | Service health, change tracking views, SIEM export |
| 15 Notifications | Chat + Gmail reports, alert rules, in-app alerts | Templates, escalation, approval e-mail evidence |
| 16 Reports | 16 security reports + daily/weekly/monthly | Budget, access, inventory, cost-optimisation reports; scheduling UI |

## 4. Defects and technical debt found (and fixed this phase)

| Issue | Fix |
|---|---|
| Lint: ambiguous names (`I`) in audit routes and reports; loop variable captured in a lambda in the Security Hub collector | Renamed; bound the loop variable (behaviour unchanged) |
| Import ordering inconsistencies (13 files) | `ruff --fix` |
| Floating hero panels overlapped neighbouring cards (prompt forbids overlap) | Panels now sit side by side |
| Sign-in accepted any verified e-mail of an allowed domain and auto-provisioned new users | Google Workspace `hd` + verified e-mail + domain + registry required; auto-provision off by default |
| Stateless session tokens could not be revoked before expiry | Server-side sessions; logout / suspension take effect immediately |

Open items (not fixed yet): Azure memory/disk metrics need VM Insights; the GCP billing query rescans 35 days hourly;
`resource_inventory` lists only VMs for AWS and GCP; no live validation of AWS and GCP.

## 5. Implementation plan

| Phase | Content | Status |
|---|---|---|
| 1 | Assessment (this document) | Done |
| 2 | Foundation: SSO, registry, sessions, roles (Access Administrator, Governance Manager, Finance Approver, Executive / CISO, Project Owner), scope-based access, left navigation, global search, lint fixes | **Done this turn** |
| 3 | Cloud inventory: organisation hierarchy, resource detail drawer, VM detail, categories | **Done** (OS / vCPU / memory size / backup / resource cost still not collected) |
| 4 | Cloud Budget Management: register, revisions, alerts, configurable approval chains, additional-budget and new-service requests, Finance approvals | **Done** (native provider budgets not read yet) |
| 5 | Cloud Access Management: Azure RBAC, AWS IAM + Identity Center, GCP IAM inventories; access register (+ CSV import); request / extension / revocation with provider-side verification; reviews; approval-vs-actual comparison | **Done** (Entra sign-in activity, PIM eligibility, inherited org/folder IAM not collected) |
| 6 | Executive Command Center v2 + cost explorer (definitions, periods, drilldown, records) + optimisation + governance frameworks, controls, evidence, onboarding workflow | **Done** (amortized cost, resource-level cost not collected) |
| 7 | AI Intelligence Center: Copilot over internal APIs with RBAC, 6 agents, recommendation → review → approval → execution by a person → verification → audit | **Done** (the AI never executes changes) |
| 8 | 15 reports (CSV / Excel / PDF), scheduled reports with archive and Gmail delivery, rate limiting | **Built**; live validation with your estate still to do |

Each phase keeps existing working functionality, adds migrations that are backward compatible, and is delivered with
tests on SQLite and MySQL.
