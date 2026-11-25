# Target architecture

```
Scheduler (local scheduler today; cloud cron later) ──► python -m app.workers.run <job>
Org log sink ─► Pub/Sub ─► push ─► Cloud Run service (FastAPI + React dashboard)
                                        │
        ┌───────────────────────────────┼────────────────────────────────┐
        ▼                               ▼                                ▼
  AWS (STS AssumeRole,           GCP (service identity,           Azure (service principal,
  read-only member roles)        read-only OAuth scopes)          Reader roles)
                                        │
                     MySQL 8 today -> Azure SQL later (operational + append-only history)
                     BigQuery (read: GCP billing export)
                     Secret store (Key Vault / Secret Manager)
                                        │
            Google Sheets register · Gmail · Google Chat · Gemini (Phases 3, 7, 8)
```

## Principles

1. **Read-only.** Connectors call only list/get/describe APIs. Remediation is a task for a person.
2. **Three separate states.** Collection status (job runs), detection status (rules), human review status never imply one another.
3. **Unknown is not healthy.** A failed or unavailable check is stored as `unknown`/`fail`; dashboards show "not collected" rather than zero.
4. **No silent skips.** A job run lists every failing provider or scope with its reason and is `partial` or `failed`.
5. **Dynamic scopes.** Inventory is rebuilt from the provider every 15 minutes; code holds no scope IDs.

## Connector contract

`app/services/connector.py` defines `CloudConnector`: `missing_configuration()`, `discover()`, `validate(scope)`.
The onboarding engine (`app/services/onboarding/engine.py`) is provider-neutral, so later collectors (audit logs,
billing, VMs) iterate the same inventory filtered by `AUTOMATION_ELIGIBLE` statuses.

## Onboarding status rules

| Condition (first match wins) | Status |
|---|---|
| Provider reports the scope closed/suspended/deleted, or stops returning it | Inactive |
| Monitoring switched off in the app | Monitoring Disabled |
| Not validated yet | Discovered |
| Authentication check not passed | Access Failed |
| Permission check not passed | Pending Access |
| Audit, billing, monitoring (and required APIs) all pass | Fully Onboarded |
| None of audit, billing, monitoring pass | Pending Configuration |
| Otherwise | Partially Onboarded |

## Module map

| Module | Code | Job(s) |
|---|---|---|
| A Discovery and onboarding | `services/aws|gcp|azure/connector.py`, `services/onboarding` | `account_discovery` |
| B SOC | `services/soc` (collectors, normalize, rules, engine) | `security_events`, `soc_daily_review` |
| C FinOps | `services/finops` (collectors, engine, analysis) | `billing_refresh`, `billing_daily_review` |
| D VM monitoring | `services/monitoring` (collectors, health, engine) | `vm_metrics`, `vm_daily_review` |
| E Google Sheets | `services/google_sheets` (backend, register) | `sheets_sync` and the review jobs |
| G Notifications | `services/notifications` (channels, dispatcher, reports) | `notification_dispatch`, daily/weekly/monthly reports |
| H AI | `services/ai` (provider, analysis) | `ai_analysis` |
| I Scheduler | `scheduler/engine.py`, `workers/jobs.py`, `workers/local_scheduler.py` | all |

Every collector reads the inventory through `services/scopes.py`, so only scopes validated as onboarded are collected,
and a scope whose specific check (audit, billing, monitoring) has not passed is reported in the run rather than skipped silently.
