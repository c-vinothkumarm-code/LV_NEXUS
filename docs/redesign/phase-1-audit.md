# LV NEXUS redesign – Phase 1: audit and implementation inventory

Date: 24 Nov 2026 · Source audited: `Documents\LV NEXUS` (backend v16 + frontend), synced copy verified by checksum.
Backup taken before any redesign change: `release\backup-before-redesign-2026-11-24.zip`.

## 1. Stack and foundations (what exists today)

| Area | Today | Impact on the redesign |
|---|---|---|
| Frontend | React 19, TypeScript 7, Vite 8, Tailwind CSS 4, React Router 7, Recharts 3, lucide-react icons, Inter (self-hosted) | Keep. 3D needs **three** (+ optionally @react-three/fiber, drei): new dependencies, lazy-loaded only |
| Backend | FastAPI, SQLAlchemy 2 + Alembic (head 0012), MySQL 8.4; 27 routers, ~230 endpoints under `/api/v1` | No API is removed; new metrics only through existing or additive endpoints |
| Authentication | SSO only: Google Workspace (PKCE) and Microsoft Entra ID; HttpOnly session cookie; CSRF header; dev mode for local | **No password sign-in exists**: no password field, "remember me" or "forgot password" will be added (they would be fake). MFA is enforced by Google / Entra, not by LV NEXUS |
| Authorisation | Backend RBAC: `require(perm)` on every endpoint; roles admin / viewer / … with ~40 permissions; scope assignments per user | Frontend hides what the backend forbids; backend checks stay the source of truth |
| Design tokens | `src/theme/tokens.css`: light + dark (`data-theme`), proposed brand values, status and colour-blind-safe chart palettes, radius / motion tokens, reduced-motion handling | Replace values with the palette in the brief; keep the token names so every page follows |
| Branding | Original LV NEXUS product mark (`components/brand/Brand.tsx`); slots `public/brand/latentview-logo.svg` and `-white.svg` | **Official LatentView and LV NEXUS logo files are not in the project** (only README.txt). Needed before the final logo composition |
| Login | Split screen, 2D canvas network animation (≤70 nodes, paused when hidden, still frame for reduced motion), SSO buttons, progress text | Replace the left side with the 3D "Connected Intelligence" scene; keep the SSO logic unchanged |
| Shell | Top bar + sidebar with 9 workspace pages and a "More" section (11 groups); breadcrumbs; theme toggle; notifications; assistant | Re-organise into the 12 sections of the brief without dropping any route |
| Tests | Backend 371 passed / 1 skipped; frontend: type check + build + oxlint (0 errors); no frontend unit tests | Add route smoke tests (Playwright) and visual checks per phase |

## 2. Implementation inventory (target section → what exists → what changes)

| Target section (brief) | Existing routes | Existing APIs | Data source | Redesign | Main component changes | Tests |
|---|---|---|---|---|---|---|
| 1 Executive Overview | `/`, `/executive`, `/dashboard`, `/operations` | `home/brief`, `command_center/summary`, `dashboard/overview`, `system/health` | DB aggregates of all collectors | One executive page: connectivity, security, infrastructure, FinOps, governance, operations KPIs with definition / source / timestamp / scope / availability | New `MetricCard` (count-up only on real change), `MetricInfo` popover, freshness chips | Each KPI equals its API value; "no data" ≠ 0; stale state shown |
| 2 Cloud Accounts | `/accounts`, `/inventory`, `/connections`, `/connections/onboard` | `accounts/tree`, `accounts/node`, `inventory/scopes`, `connections/registry`, `onboarding/wizard` | AWS Organizations, Azure management groups / subscriptions, GCP Resource Manager | Hierarchy tree + optional 3D topology from the same tree data | `TopologyScene` (lazy, WebGL fallback = tree) | Counts match `accounts/tree`; fallback without WebGL |
| 3 Security Center | `/vulnerabilities/*` (10 routes) | `security/findings`, `findings/facets`, `findings/{id}`, status, SLA, exceptions | Security Hub, Defender for Cloud / Advisor, SCC | Overview, findings, posture, remediation; evidence link per finding; potential risk vs confirmed incident labels | Finding drawer restyle; relationship view only where resource / identity links exist | Severity totals = facets; evidence link present |
| 4 Live Cloud Activity / SOC | `/activity`, `/soc`, `/audit/*` (11 routes) | `activity/events`, `activity/stream` (SSE), `activity/freshness`, `audit_ops/*` (25) | CloudTrail, Azure Activity Log + Entra audit / sign-in, GCP Audit Logs (polled) | Timeline animates only new events; event / collected / processed times shown separately; "polled every N min" stated | Timeline, volume, outcome and source-IP charts | No animation without new events; times displayed separately |
| 5 Identity & Access | `/access`, `/access/*`, `/admin/access` | `access/*` (21), `access_view/*`, `platform/iam/*` | IAM, Entra, Azure RBAC, GCP IAM | KPIs + relationship graph identity → group → role → permission → resource + table | `RelationGraph` (2D first; 3D optional) | Graph nodes = API records; MFA shown only where collected |
| 6 Cloud Resources | `/inventory/explorer` | `explorer/summary`, `tree`, `resources`, `resources/{pk}` | AWS Config / describe calls, Azure Resource Graph, GCP Cloud Asset | Unified explorer with the category / filter set of the brief | Filter bar, card layout on mobile | Filters change API query; totals match |
| 7 Infrastructure Health | `/monitoring`, `/infrastructure` | `dashboard/infrastructure`, VM metrics endpoints | CloudWatch, Azure Monitor, Cloud Monitoring | States Healthy / Degraded / Unhealthy / Stopped / Unmonitored / Unknown; missing metrics ≠ healthy | Line charts with thresholds | Unmonitored never counted as healthy |
| 8 FinOps | `/cost/*` (5), `/budgets/*` (4), `/finops` | `cost/explorer`, `records`, `optimization`, `budgets/*` (18), `dashboard/finops` | Cost Explorer, Azure Cost Management, BigQuery billing export | Spend, budget, forecast, anomalies with currency / period / collected-at / source limits | Budget progress, provider comparison | Totals match records; forecast labelled as provider forecast |
| 9 Governance & Compliance | `/governance`, `/compliance`, `/compliance/policies` | `governance/*` (11), `compliance/*` (7) | Policy evaluations from collected config | Controls with scope / evidence / timestamp / owner / status; unknown ≠ passed | Control table + drawer | Unknown controls counted separately |
| 10 Reports & Alerts | `/reports`, `/reports/library`, `/notifications` | `reports/*` (8), notification log | Report generators, NotificationLog | Branded report catalogue, schedules, delivery status (submitted vs delivered kept distinct) | Report cards, delivery history table | Exports work; delivery states honest |
| 11 Integrations | `/integrations/*` (7), `/system-health` | `sync/*` (9), `system/preflight`, `connections/*` | Collector runs, preflight | Status per provider: auth, API health, last success / failure, coverage, delay | Integration cards | Failures visible; no credentials shown |
| 12 Administration | `/admin/access`, `/automation`, `/ai`, `/audit/trail` | `admin/*`, `jobs/*`, `intelligence/*` | App DB | Users, roles, audit log, settings, retention, notifications, jobs | Admin tabs | RBAC: viewer cannot reach admin actions |

## 3. Data the brief asks for that is NOT collected today (shown as "not available", never invented)

- Identity MFA status per user (Entra / Google admin data not collected); last sign-in per identity is partial.
- Event ingestion latency as a metric: event time and collection time exist; processing time is not stored per event.
- Agent health for VMs (beyond "metrics present / missing").
- Business impact text for findings: only where the provider supplies it.
- Optimisation savings: only provider recommendations (AWS Cost Optimization Hub / Advisor / Recommender) where collected.
- Geographic resource locations for a globe: regions only (no coordinates are fabricated; the topology is a network, not a geo map).

## 4. Dependencies before the branded phases

1. **Official logo files** (LatentView Analytics and LV NEXUS): SVG, or transparent PNG ≥ 1024 px, for light and dark backgrounds, into `frontend/public/brand/`.
2. Brand guide (colours, clear space, minimum size). Without it the palette from the brief is used.
3. Approval to add `three` (+ `@react-three/fiber`, `@react-three/drei`) as front-end dependencies (lazy-loaded, login and topology only).

## 5. Delivery plan (each phase: implement → build → test → fix → document)

| Phase | Content | Needs |
|---|---|---|
| A | Design tokens from the brief (light / dark), component library pass, shell with the 12 sections, theme persistence + system default | — |
| B | 3D "Connected Intelligence" login (WebGL with fallback, reduced motion, mobile simplified) with the official logos | Logos, three.js approval |
| C | Executive Overview with metric definitions / sources / timestamps | — |
| D | Cloud Accounts topology (tree + 3D) | three.js approval |
| E | Security Center + SOC | — |
| F | Identity graph + Resource explorer | — |
| G | Infrastructure Health + FinOps | — |
| H | Governance + Reports + Integrations + Administration | — |
| I | Responsive / accessibility pass, Playwright route sweep, performance budget, regression report | — |
