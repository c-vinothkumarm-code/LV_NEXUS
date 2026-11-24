# Cloud Budget Management

The authoritative internal record of Finance-approved cloud budgets (sidebar: Cloud Budget Management).

## Register

Fields: ID, name, level (organization / provider / environment / account / business entity / project / service),
parent (for allocations), ENV, cloud provider, account name and ID (from the discovered inventory), project /
application, business entity, service, approved monthly and annual amount **in the original currency**, the exchange
rate to USD and its date (required for non-USD budgets), USD equivalents, time line (start / end), project team /
Finance / internal approval (from the approval workflow, with approver and date), e-mail subject, native cloud budget
alert name, owner, status (Draft, Pending, Approved, Active, Expired, Rejected), created and last-updated dates.

- A budget is created as **Draft**, submitted for approval (**Pending**), becomes **Approved** after the last step and
  **Active** from its start date; it becomes **Expired** after its end date.
- An approved budget **cannot be edited**. Its original amount is kept for ever; increases and decreases are approved
  **revisions** (append-only, with previous and revised amounts, effective date, reason, every approver, e-mail
  reference and evidence).
- **Consolidated totals count top-level budgets only.** An allocation (a budget with a parent) is part of its parent's
  amount and is not added again.

## Spend, forecast and utilisation

- **Actual** = collected billing records in USD for the budget's scope (account; provider; environment = accounts
  labelled with it; organisation = all), optionally one service, for the current month. Provisional (not final) billing
  is flagged.
- If no billing record covers the budget's scope in the period, actual is **not collected** — never shown as 0.
- **Forecast** = run-rate over complete days only (today is partial), labelled an estimate.
- Utilisation = actual / current approved monthly amount.

## Thresholds and alerts

Default thresholds 50% (Informational), 75% (Warning), 90% (High warning), 100% (Budget reached); above 100% is always
"Budget exceeded". Administrators (budget:configure) change the global list; a budget can carry its own list.

The `budget_alerts` job (hourly at :25 UTC, or "Evaluate now") raises one alert per budget, month and threshold, with
approved, actual, forecast, remaining, utilisation, owner, required action and notification history. Alerts at 90% and
above are queued to e-mail / Google Chat through the existing notification channels. Every alert is labelled a
**CloudNexus alert**; the provider's own budget alert is only referenced by name. **No alert stops, deletes or changes
any cloud resource.**

## Requests and approval chains

| Request | Default chain |
|---|---|
| New budget (submitted from the register) | Project team → Finance → Internal governance |
| Additional budget | Project team → Finance → Internal governance → Final |
| Budget decrease | Finance |
| New cloud service | Project team → Entity lead → Finance → Internal governance |

Step permissions: project team and entity lead `budget:manage`; Finance and final `budget:approve`; internal governance
`governance:manage`. Rules enforced by the server: the requester cannot approve; one person cannot approve two steps of
the same request; rejecting or asking for information needs notes; the requester answers information requests or
withdraws. Chains are configurable per request type and **from a monthly amount** (the chain with the highest minimum
not above the request amount applies).

Additional-budget requests record the existing budget, month-to-date actual and forecast at submission, the amount,
proposed budget, justification, team, effective date, e-mail subject and reference, and supporting documents. New
service requests also record business purpose, provider, scope, service, technical requirements and estimated monthly
/ annual cost; approval means **approved for provisioning by an authorized administrator** — CloudNexus does not
provision anything.

An e-mail subject is stored as a reference only; approval is the recorded workflow decision.

## Compatibility with existing FinOps budgets

Active account- and provider-level register budgets are mirrored into the existing FinOps budget table for the current
month (marked `register:<budget ID>`), so the Command Center and Cost pages show register amounts. A budget entered
directly in FinOps for the same scope and month is left untouched and the register does not overwrite it.

## Roles

| Role | Can |
|---|---|
| FinOps Analyst | Register budgets, submit, request changes and new services, acknowledge alerts, approve project-team / entity-lead steps of others' requests |
| Finance Approver | Finance and final approval steps |
| Governance Manager | Internal governance step; thresholds and approval chains |
| Executive / CISO, Auditor | Read the register, requests and alerts |
| Super Admin | Everything |

## Known limitations

- Native provider budgets (AWS Budgets, Azure Budgets, GCP Budgets API) are not read yet; only their names are recorded.
- Business-entity and project-level budgets count spend only when accounts are attached (`scopes`) or the budget is
  account-level; tag-based cost allocation is not collected yet.
- Amortized / unblended / credit distinctions depend on the billing collectors (Cost Intelligence phase).
- Budget reports are exported from the register, requests and alerts pages (CSV); scheduled budget reports come with
  the reporting phase.

API: `/api/v1/budgets`, `/budgets/summary`, `/budgets/{id}`, `/budgets/{id}/submit`, `/budget-requests`,
`/budget-requests/{id}/decision|respond|withdraw`, `/budget-alerts`, `/budget-alerts/{id}/acknowledge`,
`/budget-alerts/evaluate`, `/budget-settings`, `/budget-settings/thresholds`, `/budget-settings/workflows`.
Tests: `backend/tests/integration/test_budgets.py`.
