# LV NEXUS v4 — executive release: issues, fixes, validation and how to run it

Prepared for the Cisco and LatentView senior-management review. Every result below was produced by tests that were
actually executed; the generated evidence is in `docs/review/api-sweep-report.md` and `docs/review/e2e-report.md`.

## 1. What was inspected

| Area | Scope |
|---|---|
| Backend API | All 203 endpoints (119 GET, 69 POST, 9 PUT, 5 PATCH, 1 DELETE) across 24 modules |
| Frontend | 63 routes, workspace navigation, "More" sections, sub-tabs, header actions |
| Data | Same figures compared across Overview, Executive review, Cloud accounts and the assistant |
| Security | Authentication on every endpoint, role restrictions on write endpoints, CSRF, headers, dependency audits |
| AI | Existing Copilot tools, routing, permissions, audit trail, model handling |

## 2. Issues found and fixed (root causes, not hidden)

| # | Issue | Root cause | Fix |
|---|---|---|---|
| 1 | Executive page showed **0 cloud resources** while Cloud accounts showed them | `state != 'deleted'` in SQL silently drops rows with no state (many Azure resources) — in 8 queries | One shared filter `CloudResource.not_deleted()` used everywhere; regression test compares all views |
| 2 | Executive page showed **"Unapproved access assignments"** | Counted against the approval register, which is switched off (read-only Access page) | Replaced by facts: identities with access, privileged role assignments, scopes with unreadable access data; access risks list privileged assignments to review |
| 3 | **Six cost pages** with the same daily chart; two audit-review pages; four "overview" pages | Pages added over several phases, never consolidated | Cost overview + Cost analysis + Optimisation + Budgets; `/dashboard`, `/cost`, `/finops`, `/soc`, `/operations` redirect to their replacement (old links keep working); 4 dead page files removed |
| 4 | Two old pages **contradicted** newer ones ("No cloud inventory collected", "No audit log data") | Legacy pipelines superseded by v2 collectors | Redirected to the current pages (Executive review, Cloud audit) |
| 5 | No Back button or breadcrumbs | — | Back (returns to the previous page with its filters, or to the parent page when opened directly) and breadcrumbs on every page |
| 6 | Plain "Page not found" / "no access" text | — | Full-page states with Go back and Home |
| 7 | "1 of 9 collections succeeded" vs "22 of 25 healthy" in the same brief | Never-run jobs counted as healthy in one place and failed in another | Both now say: succeeded / failed or partial / not run yet |
| 8 | Assistant only answered security / cost / access questions; no follow-ups; only reachable on its own page | Limited tool set | 7 new data tools, follow-up context, chat panel on every page (see §4) |
| 9 | Missing `Permissions-Policy` and `Cross-Origin-Opener-Policy` headers | — | Added; CSP on app pages kept (and `object-src 'none'` added) |
| 10 | Sub-tab labels wrapped onto two lines | Fixed-width tab bar | Tabs never wrap; the bar scrolls on narrow screens |

Earlier fixes from the live Azure runs (Cost Management throttling, billing validation retry, identity-aware permission
fixes, tenant-level pre-flight checks, P1/P2 licence handling) remain in place — see `module3-9.md`.

## 3. UI / UX changes

- **Workspace navigation (8 items):** Overview, Executive review, Cloud accounts, Cost, Access (IAM), Vulnerabilities,
  Live audit, System health. Specialist pages stay under **More**, without duplicates.
- **Executive review:** new *Executive brief* (Position, Top risks, Trends, Pending actions, Platform health — every line
  verified and linked to its page) with a *Draft management summary* button; KPIs grouped into Footprint, Cost and
  budget, Security, Access instead of one 21-tile wall.
- **Back + breadcrumbs** on every page; proper 404 / no-access pages; consistent page headers.
- **Assistant panel** (header button or Ctrl+J), available everywhere, keeps the conversation while you navigate.
- Light and dark themes (existing), responsive layout, loading skeletons, empty and error states on every page.

## 4. AI assistant

| Capability | How it works |
|---|---|
| Questions it answers | Executive overview, top risks, critical issues needing management attention, API / collection failures with the fix, pending actions and decisions, trends this month, unusual activity, cost, budgets, forecast, privileged / expired access, idle VMs, "how do I…" help |
| Source of truth | Permission-checked data tools over the platform's own records; every answer shows **Verified data** with source and time, each line linked to its page |
| AI model | Uses the configured provider (`AI_PROVIDER=gemini|openai`, key on the server only). Model text is shown separately as **AI insight**, written only from the verified facts. With no model configured the assistant still answers with the factual summary (labelled) |
| Follow-ups | "and for AWS only?", "why?" reuse the previous question's tools with the new filter |
| Security | Role-based: tools the role may not use are refused and named; mixed tools leave out what the role cannot see. Prompts sent to a model are masked (e-mails, IPs, key IDs). Every question is stored (`ai_conversations`) and written to the central audit trail (`ai.ask`). The assistant never changes anything |

Without `AI_PROVIDER` and a key, no AI-written text is produced — this is a configuration item, not a defect.

## 5. Test results (executed)

| Suite | Result |
|---|---|
| Backend lint (ruff) | Clean |
| Backend tests, SQLite | **304 passed, 1 skipped** |
| Backend tests, MySQL 8 | **303 passed, 2 skipped** (the dry-run test runs on SQLite only) |
| API sweep — 195 endpoints as administrator | **0 server errors**; GETs return data; invalid input → 4xx (`api-sweep-report.md`) |
| API sweep — anonymous | Every non-public endpoint refuses (401/403) |
| API sweep — read-only executive | Every write endpoint refused, except recording management decisions and using the assistant |
| Assistant tests | 15 passed (each management question, real numbers, follow-up, RBAC, AI labelling, failing source) |
| End-to-end UI (Playwright) | **89 / 89 passed** (`e2e-report.md`): 57 pages, 18 sidebar links, Back with filters, breadcrumbs, 404, 5 redirects, assistant, CSV export, decorative-control scan |
| Production build under the CSP | 57 pages render, 0 console errors |
| TypeScript | Clean |
| Dependency audit | pip-audit: no known vulnerabilities; npm audit: 0 vulnerabilities |

## 6. Remaining limitations and external dependencies

- **Live data:** the tests use a fictional sample estate; on your machine the pages show your Azure data. AWS and GCP need
  their connections enabled (`AWS_ENABLED`, `GCP_ENABLED`) and read roles.
- **Microsoft Graph:** for names, groups, admin roles and Entra logs, the service principal needs Graph application
  permissions `User.Read.All`, `Group.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory`,
  `AuditLog.Read.All` with admin consent, and Reader on the Tenant Root Group. Sign-in logs need Entra ID P1/P2.
- **AI insight text** needs `AI_PROVIDER` and its API key (server side). Without them the assistant gives the verified
  factual summary only.
- **Delete operations:** the platform is read-only towards clouds; the single DELETE endpoint (remove a report schedule) is covered
  by the sweep's authorization checks.
- Browsers tested: Chromium (Edge uses the same engine).

## 7. Run it (Windows, from the project folder)

```powershell
# backend
cd "$HOME\Documents\LV NEXUS\backend"
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt
alembic upgrade head                      # adds nothing new in v4; keeps your data
python -m app.database.triggers
python -m pytest -W ignore                # expect: 304 passed, 1 skipped
python -m app.demo_check --allow-partial  # pre-flight + dry run against your clouds

# frontend (production build served by the API on http://localhost:8000)
cd ..\frontend
npm install
npm run build
cd ..\backend
$env:FRONTEND_DIST = "$HOME\Documents\LV NEXUS\frontend\dist"
python -m uvicorn app.main:app --port 8000          # terminal 1
python -m app.workers.local_scheduler                 # terminal 2 (keeps data fresh)
```

Open **http://localhost:8000**. For development with live reload use `npm run dev` (http://localhost:5173) instead of the build.

End-to-end check (optional, needs Node + Playwright): `node scripts/validation/e2e.cjs http://localhost:8000`.
