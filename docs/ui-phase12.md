# Phase 12 - Reference-style UI for LatentView CloudNexus

**One Platform. Every Cloud. Complete Visibility.**

The UI follows the visual language of the supplied reference (dark navy top navigation, light-blue gradient page,
white rounded cards with soft shadows, a large central chart, floating donut and trend panels, provider cards with a
dark pill action). It is CloudNexus's own design in that style: no logo, name, person or figure from the reference is
used. Every number comes from the existing API; anything the platform does not collect says so instead of showing zero.

## Design system

| Item | Value | Where |
|---|---|---|
| Typeface | Inter (variable, self-hosted via `@fontsource-variable/inter`, OFL licence), one family everywhere | `src/index.css`, `--font-ui` |
| Page | light-blue gradient `#d6e4fc -> #f3f7fe` (dark theme: deep navy) | `--page-gradient` |
| Navigation | navy `#11162e` / `#1a2142`, pill active state | `--nav`, `--nav-2`, `.cn-topnav` |
| Cards | white, 20 px radius, 1 px `#e4e9f2` border, soft blue-tinted shadow; floating panels use `--shadow-2` | `.cn-card`, `.cn-float` |
| Buttons, inputs, segmented controls | fully rounded; dark pill for primary card actions | `.cn-btn-dark`, `.cn-seg` |
| Comparison series | current `#2f4fae`, previous `#9fb4ea` | `--compare-current`, `--compare-previous` |
| Provider series | Azure `#2f55c9`, AWS `#0f97a8`, GCP `#8a63d8` (dark: `#4f7cf0`, `#119fb2`, `#9277e8`) - validated for colour-blind separation and 3:1 contrast | `--series-*` |
| Change chips | red-tinted for increases in cost or findings, green-tinted for decreases | `.cn-delta-*` |
| Motion | card lift on hover, floating-panel entrance, count-up KPIs, chart draw-in, notification badge pop; all off with reduced motion | `index.css` |

Provider badges show initials (Az, AWS, GCP) on a darkened provider colour; third-party logos are not drawn.

## Shared layout kit (`src/components/hero.tsx`)

`HeroLayout` places, on wide screens: KPI cards (left) - large analytics card (centre) - floating trend panel (right,
overlapping) - floating distribution donut (left, lifted) - provider cards (bottom). Below 1280 px it stacks.
Components: `KpiCard`, `Panel`, `ComparisonChart` (Columns/Line switch, hover card, "View as table"), `ArcDonut`,
`TrendArea` (hatched area with a callout and change against a comparison value), `ProviderCard`, `Segmented`,
`SubTabs`, `Delta`, `ProviderBadge`. The existing `Card` and `StatTile` were restyled so every lower section matches.

## Navigation and routes

| Item | Route | Permission | Notes |
|---|---|---|---|
| Overview | `/` | inventory:read | |
| Dashboard | `/dashboard` | finops:read | new: cost dashboard |
| Cloud Inventory | `/inventory` | onboarding:read | was `/onboarding` (redirects) |
| FinOps | `/finops` | finops:read | |
| Security Operations | `/soc` | soc:read | |
| Monitoring | `/monitoring` + `/automation` | infra:read / automation:read | was `/infrastructure` (redirects); sub-tabs |
| Governance | `/governance` | onboarding:read | new |
| Reports | `/reports` | automation:read | new |
| Notifications | bell + `/notifications` | inventory:read | new page |
| Profile menu | Access control (`/access`, admin), Sign out | | |

Items a role cannot use are hidden; the API enforces the same permissions.

## Data mapping (no new endpoints, no schema change)

| Screen | Component | API |
|---|---|---|
| Dashboard | KPIs, daily current-vs-previous month, by-cloud and monthly views, cumulative trend, donut, provider cards | `/dashboard/finops?date_from=<1st of last month>`, `/dashboard/overview` (budget), `/dashboard/infrastructure` (CPU) |
| Overview | KPIs, daily spend by cloud, daily total trend, open findings donut, provider health cards | `/dashboard/overview` |
| Cloud Inventory | status by cloud, integration gaps, scopes by cloud, provider cards | `/onboarding/summary`, `/inventory/scopes`, `/onboarding/tasks`, `/onboarding/records` |
| FinOps | KPIs, daily expenditure, monthly trend, distribution, budget-vs-actual provider cards, optimisation candidates | `/dashboard/finops`, `/dashboard/infrastructure` |
| Security Operations | KPIs, daily / severity / by-cloud findings, detection trend, severity donut, posture cards | `/dashboard/soc` |
| Monitoring | KPIs, CPU by VM / regions / by cloud, utilisation, health donut, provider cards | `/dashboard/infrastructure` |
| Automation | KPIs, runs per day, scheduler | `/dashboard/automation` |
| Governance | control status by check, review status, onboarding-status donut, provider cards, configuration matrix, exceptions, access review | `/inventory/scopes`, `/onboarding/summary`, `/onboarding/tasks`, `/dashboard/soc`, `/admin/users` (admin only) |
| Reports | report runs, upcoming runs, delivery donut, report cards with Run now, CSV exports | `/dashboard/automation`, `/dashboard/soc`, `/dashboard/finops`, `POST /jobs/{name}/run` |
| Notifications | active alerts, delivery counts | `/dashboard/overview`, `/dashboard/automation` |

Rules applied in the calculations (`src/lib/cost.ts`):

- Month-over-month compares month-to-date with **the same days** of the previous month, up to the last day that has
  current-month billing data (billing lags 1-2 days), so a partial month is never compared with a full one.
- Budget utilisation per provider uses approved USD budgets whose period covers today.
- "Optimisation candidates" are running VMs below 10% CPU at the latest collected sample. They are review candidates;
  no saving is estimated, and provider rightsizing advice is not collected.

## Shown as "not collected" (no invented values)

Resource-group cost; cloud policy compliance (Azure Policy, AWS Config, GCP Organization Policy); provider rightsizing
advice and savings; memory and disk where no guest agent reports. Each needs a new read-only collector and approval.

## Test results (test-only database, Chromium headless, 17 Nov 2026)

| Test | Result |
|---|---|
| axe-core WCAG 2 A/AA, 11 pages x light and dark (22 scans) + sign-in | 0 violations (one contrast defect on provider badges found and fixed) |
| Console / page errors | 0 |
| Page load to settled screen | 1.8-2.2 s (includes a fixed 1.1 s settle wait) |
| Every navigation route, plus `/infrastructure` and `/onboarding` redirects | all resolve, no "Page not found" |
| Sign out, sign in, notifications popover, profile menu | working |
| Chart hover card, Daily / By cloud / Monthly, Columns / Line | working |
| Reduced motion | KPI values render final numbers immediately; background animation static |
| Phone 390 px / tablet 768 px | no horizontal overflow; drawer navigation; stacked panels |
| Viewer role (Phase 11 check) | only permitted items; SOC API and Run now return 403 |
| Backend regression | 147 passed, 1 skipped (SQLite and MySQL 8) |
| Bundle | one JS chunk ~800 KB uncompressed; per-page code splitting is a follow-up |

Screenshots used test data, so they are layout evidence only. Re-run `node scripts/validation/ui-check.cjs` against
the live environment for CISO evidence. Firefox and Safari have not been tested.

## Files changed

New: `components/hero.tsx`, `lib/cost.ts`, `pages/Dashboard.tsx`, `pages/Governance.tsx`, `pages/Reports.tsx`,
`pages/Notifications.tsx`. Changed: `layouts/AppLayout.tsx` (top navigation), `App.tsx` (routes and redirects),
`theme/tokens.css`, `theme/brand.ts` (tagline), `index.css`, `components/ui.tsx`, every page under `pages/`, the
sign-in page, `package.json` (Inter font). Backend: email report footer tagline only.
