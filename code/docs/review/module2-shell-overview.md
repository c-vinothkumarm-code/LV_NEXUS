# Module 2 – Enterprise shell and Overview (done)

| File | Change |
|---|---|
| `frontend/src/layouts/AppLayout.tsx` | New navigation: a **Workspace** list with only Overview, Cloud accounts, Cost, Access (IAM), Vulnerabilities, Live audit, System health. All other modules stay reachable under a collapsible **More** (opens automatically when you are on one of those pages). The old Command Center moved to `/executive`. |
| `frontend/src/index.css` | Sidebar section label and compact "More" items. |
| `frontend/src/components/shell.tsx` (new) | `FreshnessChip` ("Updated 5 min ago", stale / last run failed / not collected yet, with the reason on hover), `SectionCard`, `Metric` (unknown values show "—", never 0). |
| `frontend/src/pages/home/Overview.tsx` (new) | The new home page: one card per cloud (scopes onboarded, resources, cost this month, critical/high, VMs running, activity and flagged events, privileged roles), four headline cards (cost, vulnerabilities, live audit, access), 30-day cost trend, severity breakdown with top findings, unusual activity, inventory. Every section has its own "Updated …" chip. |
| `frontend/src/App.tsx` | `/` = Overview, `/executive` = Command Center, `/accounts` and `/health` routes (they open the current inventory explorer and connection registry until modules 3 and 8 replace them). |
| `backend/app/api/routes/home.py` (new), `main.py` | `GET /api/v1/home`: one call for the whole page. Each section returns `updated_at` (last successful run, or the stored data's own time), `status` (fresh / stale / degraded / never) and the failure reason; a failed latest run never blanks a section. |
| `backend/tests/integration/test_home.py` (new) | Unknown vs zero, data-time fallback, failed run → degraded with last data kept, RBAC. |

Tests: 259 passed.
