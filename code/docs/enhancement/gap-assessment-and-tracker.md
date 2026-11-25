# LV NEXUS – enhancement gap assessment and completion tracker (24 Nov 2026)

Scope: the "existing application enhancement" master prompt (sections 1–15) plus the "Daily cloud monitoring & Google
Sheets audit automation" addendum. The existing application (FastAPI + MySQL + React, 28 routers, 27 scheduled jobs) is
extended in place: no new application, no replaced module, no mock data. Product name stays **LV NEXUS** (existing
branding; the prompt's "LV NUXUS" is read as the same product).

Reference sample: the uploaded "AWS – LV Data Services – Security & Governance Audit Report" (structure used for the
monthly report; its account ID and names are not stored anywhere in code or tests).

Status legend: **Working** (implemented, tests pass) · **Improve** (works, gaps listed) · **Partial** · **Not implemented** ·
**Failing** (integration error on the live PC) · **Needs permission** (cloud grant missing). "Live" = verified against real
cloud APIs on the PC; everything here was verified with automated tests and fictional demo data only.

## 1. Gap assessment (inspection of the current code)

| Area | Existing | Status | Gap / next step |
|---|---|---|---|
| Executive / account / security / IAM / activity / vulnerability / cost / compliance dashboards | All exist with freshness, filters, drill-down, CSV export (redesign phases A–I) | Working | Historical comparison on every dashboard; live verification |
| Azure IAM: management group, subscription, resource group, resource levels | `access/collectors.py` reads RBAC at all four levels; direct vs inherited (`access_type`) | Working (not live-verified) | Custom role flag + role-definition view; managed identity type label |
| Azure users, groups, service principals, PIM eligible / active | `access/directory.py` (Graph users/groups, PIM eligible for Entra + Azure RBAC) | Working (live: needs Graph consent) | Needs permission: Graph application permissions + admin consent |
| AWS / GCP IAM | Identity Center / IAM / GCP IAM collectors | Working | — |
| AI GUARD (Azure OpenAI, Vertex AI, API keys, OAuth apps, token usage, cost) | Only the LV NEXUS AI assistant provider | **Not implemented** | New module: collectors (Cognitive Services accounts + deployments, Azure Monitor token metrics; Vertex endpoints + Monitoring; GCP API Keys API; OAuth apps), registry, alerts |
| FinOps filters (provider, period incl. 12 months / custom, daily / monthly, actual / amortized / forecast / budget, group by account / service / region / resource / SKU) | Cost analysis page has billing period, group-by, actual / amortized, forecast | Improve | Add: last 3/6/12 months presets, monthly granularity, usage quantity, entity / cost-centre grouping (now possible via ownership) |
| FinOps AI advisor | Rule-based recommendations (`/cost/optimization`, idle VMs, unattached disks) | Partial | AI explanation + savings / confidence / owner / approval workflow; AI-model cost rules after AI GUARD |
| Account ownership (SPOC, owner, entity, lead, admin, FinOps SPOC, cost centre, budget) | — | **Done in this round** | — |
| Monthly per-account audit report (PDF + attachments) | Only a consolidated monthly e-mail | **Done** – now in the official LatentView Word layout (DOCX + PDF) | Live data verification |
| Monthly e-mail on the 1st (TO SPOC, CC lead / owner / admin / FinOps) with delivery log + retry | Notification queue with retry existed | **Done in this round** | SMTP / Gmail credentials on the server |
| Daily governance e-mail + Google Chat | `notifications/governance.py`, `reports.py` daily report, Chat channel, dedup keys | Working | Add AI-usage and credential-expiry sections after AI GUARD; Sheets link |
| Immediate critical security / budget alerts, dedup | `vuln/notify.py` rules + NotificationKey | Working | — |
| Security enhancements (identity threat, privileged monitoring, exposure, drift, compliance, exceptions) | SOC library A–G (79 rules), privileged change alerts, exposure findings, compliance library (36 policies: CIS / NIST / ISO mapping), exceptions | Working / Improve | Secret & credential expiry (needs AI GUARD key inventory), container vulnerability view, drift baseline |
| Google Sheets register | `google_sheets/register.py`: 20+ tabs incl. Daily / Weekly / Monthly review status with human columns, remediation tracker, execution logs | Working (needs Sheets credentials) | Rename / map to the FY 2026-27 tracker tabs; engineer activity tab |
| Engineer activity tracking + Daily Operations page | Review status rows with human columns; SOC analyst identity on case actions | Partial | Engineer assignment registry, human validation records (identity + time + comment), Daily Operations & Engineer Activity page |

## 1a. Cloud Services & Asset Management (Modules 1, 2, 7 of the asset / access enhancement) – increment 1 done

See [cloud-services-asset-management.md](cloud-services-asset-management.md). Increment 2 (resource-level access governance,
expiry reminders 15/7/3/0 days, extension and revocation workflow – approve in the app, the cloud admin executes, LV NEXUS
verifies read-only; no response → escalate to the Reporting Manager, then a revocation task that still needs approval) and
increment 3 (daily Google Sheets governance log, append-only) are next.

## 1b. Round 2 – report in the official Word layout

- Template `services/reports/templates/monthly_audit_report.docx`: the approved report format with every account-specific
  value removed (checked by `test_shipped_template_has_no_account_data`). Logo, styles, header/footer and all 13 sections kept.
- `services/reports/audit_template.py` fills it per AWS account / Azure subscription / GCP project: cover table, attachments
  table, 7 audit domains, tools per provider, access counts, fiscal-quarter spend vs budget (FY April–March), exceeded budget,
  findings-by-region image (drawn from collected findings), monthly/quarterly mitigation tracker, Critical/High and SLA-breach
  exceptions, key rotation, network exposure, VM counts. Azure and GCP get their native service names.
- Not collected by LV NEXUS and shown as such: MFA status, root / break-glass password rotation, "Additional budget" approvals.
  Review status is always "Need to Review with SPOC"; the sign-off table is left for the signatories.
- The PDF is rendered from the filled DOCX, so both carry the same content. Attachments: A Active Users List, B Active Services
  List, C Vulnerability List (CSV). Download: `format=pdf|docx|zip`. Cover values: AUDIT_REPORT_PREPARED_BY / _REVIEWED_BY / _VERSION.
- Tests: `tests/integration/test_audit_template.py` (4) + updated `test_account_audit.py`.

## 2. Implemented in this round (Steps 8–10 of the prompt, tied to the uploaded sample report)

- **Account ownership** – tables `account_ownership` + `account_ownership_history` (migration **0013**, new tables only).
  `GET /api/v1/accounts/ownership`, `GET|PUT /api/v1/accounts/ownership/{provider}/{scope}`. Editing needs
  `connections:manage`; every changed field gets a history row (who, old, new, when). Approved budget is read live from the
  budget tracker (active budgets covering the scope), never typed in twice. UI: Cloud Accounts → select an account →
  Ownership panel (edit, history).
- **Monthly Cloud Security & Governance Audit report** – `services/reports/audit_report.py`. Title
  "Cloud Security & Governance Audit Report – [Provider] [Name] ([ID]) – [Month Year]". Sections 1–13 of the prompt plus
  sign-off; uses the existing IAM inventory, findings (vulnerabilities vs other findings), compliance results, billing,
  budgets, forecasts and optimisation recommendations for that scope only. Missing data = "Not collected". Domain review
  status is always "Automated check – SPOC review required" (never claims a human review). PDF + CSV attachments
  A IAM access · B vulnerabilities · C security findings · D cost breakdown (formula-injection safe).
  `GET /api/v1/reports/audit/{provider}/{scope}?month=YYYY-MM&format=pdf|zip` (needs reports:export + access:read +
  vuln:read + finops:read).
- **Monthly e-mail** – job `monthly_audit_reports` (catalogue, 1st of the month 09:30) for the previous month; TO SPOC, CC entity
  lead / owner / cloud admin / FinOps SPOC; subject "[LV NEXUS] Monthly Cloud Security & Governance Audit – [Name] – [Month]";
  queued once per scope and month (dedup key), retried by the existing dispatcher, logged (`GET /api/v1/reports/audit/deliveries`).
  A scope without SPOC e-mail is reported in the job run as not sent with the reason (never silent). Manual send:
  `POST /api/v1/reports/audit/{provider}/{scope}/send` (automation:run). Email channel now supports Cc.

## 3. Completion tracker

| Feature | Existing status | Enhancement | Test result | Final status |
|---|---|---|---|---|
| Account ownership + history | Not implemented | Tables, API, UI, history, RBAC | `test_account_audit.py`: save, history, validation, unknown fields, viewer 403 – pass | Done (demo data) |
| Approved budget from budget tracker | Budget tracker existed | Live mapping per scope | budget 750 USD mapped from BUD fixture – pass | Done |
| Monthly audit report PDF + 4 CSV | Not implemented | Builder, PDF, CSV, ZIP | title format, sections, vuln/finding split, "not collected" months, PDF/ZIP endpoints – pass; PDF rendered and inspected | Done (demo data) |
| Monthly e-mail TO/CC, dedup, delivery log, missing SPOC | Partial (consolidated mail) | Per-scope job, Cc, log | recipients, Cc header, PDF attachment, second run no duplicate, missing-SPOC reported – pass | Done (not sent through real SMTP here) |
| Regression | – | – | backend 379 passed / 1 skipped; ruff clean; tsc, build, oxlint 0 errors | Pass |
| Azure advanced IAM | Working (4 scope levels, PIM eligible) | Custom-role / managed-identity labels | not changed this round | Pending verification on live tenant |
| AI GUARD + OAuth / API key governance | Not implemented | — | — | Next increment |
| FinOps filters 3/6/12 months, monthly granularity, entity / cost centre | Improve | — | — | Next increment |
| FinOps AI advisor | Partial | — | — | Next increment |
| Daily e-mail / Chat additions (AI usage, credential expiry, Sheets link) | Working | — | — | After AI GUARD + Sheets tracker |
| Security enhancements (credential expiry, drift, container) | Partial | — | — | Next increment |
| Google Sheets FY 2026-27 tracker + engineer activity + Daily Operations page | Partial | — | — | Next increment |

## 4. What the user must do on the PC
1. `alembic upgrade head` (0012 → **0013**), restart API and scheduler.
2. Fill ownership for each account (Cloud Accounts → account → Ownership → Edit).
3. E-mail transport configured (SMTP or Gmail API) for real delivery; check `/api/v1/reports/audit/deliveries` after the 1st.
