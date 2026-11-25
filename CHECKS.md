# LV NEXUS Prod-V0.2 (0.2.0) – release checks

Run on 25-11-2026 against a fresh copy of this package's `code/` folder, with the development test suite placed
next to it only for checks 1–2 (the tests are not shipped). Every result below was actually executed; raw output is in
`checks/`. Anything that could not be run is listed under "Not run here".

## Results

| # | Check | How | Result |
|---|---|---|---|
| 1 | Backend tests (SQLite) | `python -m pytest` (Python 3.13.18) | **396 passed, 1 skipped, 0 failed** |
| 2 | Backend tests (MySQL-compatible server) | `TEST_DATABASE_URL=mysql+pymysql://…` on MariaDB 10.11 | **395 passed, 2 skipped, 0 failed** |
| 3 | Lint, backend | `ruff check app tests` | **0 issues** |
| 4 | Database migrations | `alembic upgrade head` on an empty MariaDB 10.11 database | **0001 → 0014 applied**; 98 application tables |
| 5 | Migration rollback | `alembic downgrade 0013`, then `upgrade head` | **OK** |
| 6 | Models vs migrations | `alembic check` | **No drift** ("No new upgrade operations detected") |
| 7 | Append-only audit triggers | `python -m app.database.triggers` | **48 triggers** in the database |
| 8 | Frontend dependencies | `npm ci` (clean install from package-lock.json) | **OK**, 102 packages |
| 9 | Frontend type check + build | `npm run build` (`tsc -b` + Vite) | **OK**, 2,535 modules |
| 10 | Lint, frontend | `npm run lint` (oxlint) | **0 errors**, 152 warnings (note A) |
| 11 | Dependency vulnerabilities, frontend | `npm audit --omit=dev` | **0 vulnerabilities** |
| 12 | Dependency vulnerabilities, backend | `pip-audit -r requirements.txt` | **No known vulnerabilities** |
| 13 | Secrets, demo and sample data in the package | file-type and pattern scan (`.env`, keys, `.db`, `.zip`, logs, AWS keys, private keys, 12-digit account IDs, e-mail addresses, demo / sample markers) | **None found** in code. Only placeholders remain (input placeholders such as `owner@company.com`, role addresses in `.env.example`, AWS documentation ID `123456789012` in a usage comment) |
| 14 | Production settings guards | `Settings(...)` with `APP_ENV=production` | Valid settings accepted; **refused**: `AUTH_MODE=dev`, short session secret, `http://` URL. No `demo_mode` setting exists |
| 15 | Production boot | API with `APP_ENV=production`, Google SSO (placeholder client), MariaDB | `/health` 200 (`environment: production`); `/api/v1/auth/me` **401** without sign-in; no `demo_mode` in responses; CSP, HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy present |
| 16 | UI smoke test, production build | Playwright, 39 routes, light and dark theme, empty MariaDB database | **39/39 light, 39/39 dark**: page heading, **no demo banner**, no script errors, no HTTP 5xx |
| 17 | Mobile layout | 390 px viewport, 5 key pages | **0 px horizontal overflow** |
| 18 | Write protection (CSRF) | signed-in `PUT` without / with the CSRF header | **403** without; **422** (validation, CSRF passed) with |
| 19 | Cloud role templates | YAML parse of the AWS CloudFormation templates; `bash -n` on the shell scripts in `code/` | **OK** |

## Notes

A. Frontend lint warnings (152, no errors): most are `jsx-key` warnings for table cells passed as data (the `Table`
component renders each cell inside a keyed `<td>`); the rest are React-compiler advisories with no runtime error. The
smoke test (16) found no script errors.

B. MariaDB 10.11 was used as the MySQL-compatible test server. Production uses MySQL 8.4 (container
`lvnexus-database`); run check 4 once on the target MySQL before go-live.

## Not run here (run on the target server)

- **Container image builds**: see the container package (`Documents\LV NEXUS CONATINER\Prod-V0.2\CHECKS.md`);
  build and scan the images on your CI agent / server, with the organisation's SAST and image scan.
- **Live cloud collection** (AWS, Azure, GCP), including the new asset collectors: run pre-flight
  (Administration → System health) and `python -m app.demo_check` after connecting each cloud.
- **E-mail / Google Chat delivery**: needs your SMTP or Gmail settings.
