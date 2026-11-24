# CloudNexus — management summary (v3)

**What it is.** One read-only platform for AWS, Microsoft Azure and Google Cloud that shows every account, what it
costs, who has access, which vulnerabilities are open and what is happening right now — with a health page that says
plainly when something could not be collected and how to fix it.

## What management sees (7 pages)

| Question | Page | Answer it gives |
|---|---|---|
| What do we run, and is it healthy? | Cloud accounts | Every subscription / account / project in one tree per cloud, down to resource group or region, with resources, VM health, open critical/high findings and month-to-date cost at each level |
| What do we spend? | Cost | Actual vs previous period, forecast (kept separate from actual), budget, daily trend by cloud, top accounts / services / resource groups / resources |
| Who has access to what? | Access (IAM) | Read-only list of every person, group and service identity per subscription, resource group and resource; inherited vs direct; groups expanded to people |
| Are we exposed? | Vulnerabilities | Open findings from AWS Security Hub, Microsoft Defender / Advisor and Google SCC, by severity and source, with SLA status |
| Is anything unusual happening? | Live audit | Live activity feed plus automatic flags: sign-in from a new country, new IP, unusual hours, failure spikes, privilege changes, mass deletions |
| Can we trust the numbers today? | System health | PASS / WARN / FAIL per cloud, scope and data source, with the exact fix |

## Why it is safe

- **Read-only towards every cloud.** No create, change or delete calls exist in the code; access management actions were removed from the product.
- **Secrets in Azure Key Vault**, never in code, logs, the UI or alerts. E-mails, IPs and key IDs are masked in logs, alerts and anything sent to AI.
- **No silent gaps.** A permission error is shown as "data unavailable – missing permission: …", never as zero. Incomplete API responses never delete earlier data.
- **No false success.** A failed or partial collection raises an alert once per workflow per day; the demo check returns FAIL if any workflow is incomplete.

## Why it does not fail

Every provider call has timeouts, automatic retries with back-off, per-API rate limits and a per-cloud circuit
breaker. One failing account never stops the others. All runs are logged with a run ID.

## Readiness before a demo

`python -m app.demo_check` runs pre-flight and a dry run of every workflow and prints a single **PASS** or **FAIL**
with the fix for each failure. The dry run uses the real cloud APIs (read-only) but writes nothing to the production
database and sends no messages.

## Status and evidence

| Item | Status |
|---|---|
| Automated tests | 284 passed, 1 skipped (SQLite); 283 passed, 2 skipped (MySQL 8); pip-audit and npm audit: no known vulnerabilities |
| Pages and APIs | Built; checked in Chromium with sample data |
| Live coverage per cloud (scopes read / total, per data source) | **From the first live `demo_check` run** — figures are taken from that report, not estimated here |
| Known gaps | AWS effective permissions (SCPs, permission boundaries) are not combined; Azure deny assignments and conditional access not evaluated; Graph permissions need tenant admin consent |

**Next step:** run `demo_check` on the live Azure tenant, close every FAIL (mainly Microsoft Graph consent and Reader at
the Tenant Root Group), then repeat for AWS and GCP and attach the report to this summary.
