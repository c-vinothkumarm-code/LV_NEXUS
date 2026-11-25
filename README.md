# LV NEXUS – Prod-V0.2 (0.2.0) – application code

Production-grade release of LV NEXUS: the **non-container** application code. It contains **no demo mode, no demo data
and no sample or test data**. Results of every check: [CHECKS.md](CHECKS.md) (raw output in `checks/`).
What changed: [RELEASE_NOTES.md](RELEASE_NOTES.md).

The container package (Dockerfiles, compose, nginx, MySQL, start / backup scripts and a copy of the source the images
are built from) is released separately in **`Documents\LV NEXUS CONATINER\Prod-V0.2`**. Both come from the same checked build.

```
Prod-V0.2/
├── README.md            this file
├── RELEASE_NOTES.md     what is in this release
├── CHECKS.md            tests, migrations, builds, security and smoke-test results
├── MANIFEST.sha256      SHA-256 of every file in the package
├── checks/              raw output of each check
└── code/
    ├── backend/         FastAPI API, scheduler, jobs, Alembic migrations 0001 → 0014 (Python 3.13)
    ├── frontend/        React 19 + TypeScript web application
    ├── deploy/aws, gcp  read-only cloud role kits (AWS member / management role templates, GCP reader setup)
    ├── docs/            architecture, deployment and go-live guides, security, troubleshooting
    ├── infrastructure/  Terraform and scheduler notes
    ├── scripts/         Windows run / scheduled-task scripts, Linux dev setup
    └── .env.example     settings reference (variable names and placeholders only)
```

Deliberately **not** in this folder: container files (see the container package), the demo loader, demo banner and
`DEMO_MODE` setting, the automated test suite and its fictional fixtures (kept in the development copy `Documents\LV NEXUS`,
where the checks in CHECKS.md were run against this exact code), and any `.env`, key, database, log or archive file.

## 1. Install with containers (recommended)

Use `Documents\LV NEXUS CONATINER\Prod-V0.2` and follow its README (`setup.sh`, certificate, `secrets/lvnexus.env`,
`start.sh 0.2.0`).

## 2. Run without containers (Windows or Linux server)

```powershell
cd code\backend
py -3.13 -m venv .venv;  .\.venv\Scripts\Activate.ps1   # Linux: python3.13 -m venv .venv && . .venv/bin/activate
python -m pip install -r requirements.txt
# settings come from environment variables / the secret manager (see code\.env.example); APP_ENV=production
python -m alembic upgrade head          # 0001 -> 0014; existing data is untouched
python -m app.database.triggers         # append-only audit triggers (48)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
python -m app.workers.local_scheduler   # exactly one scheduler instance
cd ..\frontend;  npm ci;  npm run build # serve frontend\dist behind HTTPS (or set FRONTEND_DIST for the API to serve it)
```

Windows helpers: `code\scripts\windows\run-api.cmd`, `run-scheduler.cmd`, `register-tasks.cmd`.
Production refuses `AUTH_MODE=dev`, weak session secrets and non-HTTPS URLs.

## 3. Upgrade an existing installation

Run `python -m alembic upgrade head` (0013 → 0014 adds the Cloud Services & Asset Management tables) and
`python -m app.database.triggers`. Update the AWS member-role StackSet with `code/deploy/aws/cloudnexus-member-role.yaml`
(new read-only policy `lvnexus-asset-details-read`), then run `asset_details_sync` and `asset_activity_review` once from
**Automation**.

## 4. After start-up

Connect clouds one at a time with **Integrations → Onboard a cloud**, then run **Administration → System health → Run pre-flight**.
`python -m app.demo_check` is the release-readiness check (pre-flight plus a dry run of every collection workflow on the
real, read-only cloud APIs, ending in PASS / FAIL); despite its name it uses no demo data.

Read-only towards every cloud. Never put real secrets in any file of this folder.
