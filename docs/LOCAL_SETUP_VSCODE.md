# Step-by-step: run and implement the platform locally in VS Code (MySQL)

Commands are for **Windows PowerShell** (the VS Code terminal). On macOS/Linux use `source .venv/bin/activate`
instead of `.venv\Scripts\Activate.ps1`; everything else is the same.

Work through the steps in order. Steps 1-8 need no cloud access and take about 20 minutes.
Steps 9-14 switch the modules on one at a time; each one tells you what "working" looks like before you move on.

---

## Part A - get it running (no cloud access needed)

### Step 1 - Install the tools

| Tool | Version | Check |
|---|---|---|
| Python | 3.13 | `python --version` |
| Node.js | 22 LTS | `node --version` |
| MySQL Server + MySQL Workbench | 8.0 or newer | Workbench connects to `localhost:3306` |
| Git | any | `git --version` |
| VS Code | current | with the recommended extensions (VS Code offers them when you open the folder) |

### Step 2 - Open the project

1. Unzip `multicloud-control-plane.zip`, for example to `C:\work\multicloud-control-plane`.
2. VS Code -> **File > Open Folder** -> select that folder. Accept "Install recommended extensions".

### Step 3 - Create the database in MySQL Workbench

Open a query tab as `root` and run (choose your own password):

```sql
CREATE DATABASE mcp      CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE mcp_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;   -- used only by the automated tests
CREATE USER 'mcp'@'localhost' IDENTIFIED BY 'ChooseAStrongPassword';
GRANT ALL PRIVILEGES ON mcp.*      TO 'mcp'@'localhost';
GRANT ALL PRIVILEGES ON mcp_test.* TO 'mcp'@'localhost';
-- lets the application user create the append-only triggers that protect audit history:
SET GLOBAL log_bin_trust_function_creators = 1;
```

### Step 4 - Create your `.env`

In the VS Code terminal, at the project root:

```powershell
Copy-Item .env.example .env
```

Open `.env` and set only this for now (URL-encode special characters in the password, e.g. `@` becomes `%40`):

```
DATABASE_URL=mysql+pymysql://mcp:ChooseAStrongPassword@127.0.0.1:3306/mcp?charset=utf8mb4
```

`.env` is git-ignored. Never commit it and never paste cloud keys into it - the platform does not use access keys.

### Step 5 - Backend: install and create the tables

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
pip install -r requirements-dev.txt
python -m alembic upgrade head      # creates 24 tables
python -m app.database.triggers     # prints "append-only triggers created"
```

In VS Code press `Ctrl+Shift+P` -> **Python: Select Interpreter** -> choose `backend\.venv`.

Check in Workbench: schema `mcp` now lists tables such as `cloud_accounts`, `audit_events`, `billing_records`, `vm_inventory`.

### Step 6 - Start the API

Run and Debug panel (`Ctrl+Shift+D`) -> **API (FastAPI)** -> press F5. Or in a terminal:

```powershell
cd backend; .venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --reload --port 8000
```

Check:
- http://localhost:8000/health -> `{"status":"ok", ...}`
- http://localhost:8000/health/ready -> `"database":"ok","job_catalogue":14`
- http://localhost:8000/docs -> interactive API documentation

### Step 7 - Start the dashboard

Open a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. You are signed in as a local admin (`AUTH_MODE=dev`). All six pages load and say
"not collected yet" - that is correct, nothing has been collected.

### Step 8 - Run the automated tests

```powershell
cd backend; .venv\Scripts\Activate.ps1
python -m pytest -W ignore                                # fast run on in-memory SQLite: 118 passed, 1 skipped
$env:TEST_DATABASE_URL="mysql+pymysql://mcp:ChooseAStrongPassword@127.0.0.1:3306/mcp_test?charset=utf8mb4"
$env:TEST_DB_TRIGGERS="1"
python -m pytest -W ignore                                # same suite on your MySQL: 119 passed
Remove-Item Env:TEST_DATABASE_URL, Env:TEST_DB_TRIGGERS
```

If both pass, the foundation is correct on your machine.

---

## Part B - switch the modules on, one at a time

After each change to `.env`, restart the API (stop and press F5 again).
Run a job from the dashboard (**Automation Status -> Run now**) or from VS Code (**Run and Debug -> Run one job**).
A job result is `success`, `partial` or `failed`, and partial/failed runs list the exact scope and reason.

### Step 9 - Connect the clouds (Phase 2: discovery and onboarding)

Do one cloud at a time. You sign in with your own CLI login; no key files are needed locally.

**You can do all of this from the dashboard instead of editing `.env`:** open **Account Onboarding -> Connect your clouds**,
fill in the cloud's identifiers, tick "Include ... in discovery", choose **Save and test connection**, then **Run discovery now**.
Values saved there override `.env` and apply to the next job run without restarting the API. The dashboard takes identifiers
only (role name, organisation ID, tenant ID); it never asks for a password, key or secret. The `.env` route below still works.

**AWS**
1. `aws sso login --profile <management-profile>` then `$env:AWS_PROFILE="<management-profile>"` in the terminal that runs the API.
2. In `.env`: `AWS_ENABLED=true`, `AWS_MEMBER_ROLE_NAME=<read-only role present in each member account>`, `AWS_EXTERNAL_ID=<if used>`.
3. Run job `account_discovery`. Expected: **Account Onboarding** lists every account in the organisation.
   Accounts where the role is missing show **Access Failed** with a task "Create read-only IAM role ... requires approval".

**GCP**
1. `gcloud auth application-default login`
2. In `.env`: `GCP_ENABLED=true`, `GCP_ORGANIZATION_ID=<your organisation ID>`.
3. Run `account_discovery`. Expected: every project, including those inside folders.

**Azure**
1. `az login --tenant <tenant-id>`
2. In `.env`: `AZURE_ENABLED=true`, `AZURE_TENANT_ID=...`, `AZURE_PRINCIPAL_OBJECT_ID=<object ID of the signed-in identity>`
   (`az ad signed-in-user show --query id -o tsv`).
3. Run `account_discovery`. Expected: every subscription in the tenant.

What to check: the counts match your organisation; each scope shows Pass/Fail per check; gaps appear under
**Tasks awaiting human approval**. The platform never fixes a gap itself.

### Step 10 - SOC (Phase 3)

1. Optional in `.env`: `SOC_TRUSTED_CIDRS=<office and VPN ranges>` to flag changes from other networks.
2. Run job `security_events`. The first run reads the last 24 hours; later runs continue from a checkpoint per scope.
3. Open **SOC Operations**: findings appear as **Pending Review**. Open a finding, choose a status, add notes, **Record review**.
   Confirming a finding as suspicious opens an incident and queues an alert.

Good to know: AWS collects write (change) events by default; GCP collects Admin Activity, System Event and Policy Denied.
Set `SOC_AWS_INCLUDE_READ_EVENTS=true` or `SOC_GCP_INCLUDE_DATA_ACCESS=true` only if you want the much larger volume.

### Step 11 - FinOps (Phase 4)

1. AWS needs nothing more (Cost Explorer through the management account).
2. GCP: set `GCP_BILLING_EXPORT_TABLE=project.dataset.gcp_billing_export_v1_XXXX` (the BigQuery billing export table).
3. Azure needs Cost Management Reader on each subscription.
4. Optional: `FX_USD_INR_RATE=84.10` to fill INR columns (the rate and timestamp are stored on every record).
5. Run job `billing_refresh`, then open **FinOps**. Add approved budgets with the form under **Budget versus actual**.

Figures are labelled provisional until the provider finalises the month.

### Step 12 - VM monitoring (Phase 5)

Run job `vm_metrics`, then open **Infrastructure**. CPU and network come from the cloud platform. Memory and disk need a
guest agent (CloudWatch agent, Google Ops Agent, Azure Monitor agent); without it the VM shows **Partial data** and a
"missing metrics" alert rather than "healthy".

### Step 13 - Google Sheets, Google Chat, email (Phases 3 and 7)

**Google Sheets**
1. Create a Google Sheet named `Multi-Cloud-Operations-Control-Register`.
2. Share it (Editor) with the Google identity the platform runs as.
3. In `.env`: `SHEETS_ENABLED=true`, `SHEETS_SPREADSHEET_ID=<the ID from the sheet URL>`.
4. For local runs sign in with the Sheets scope:
   `gcloud auth application-default login --scopes=https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/spreadsheets`
5. Run job `sheets_sync`. Expected: 17 tabs with headers and data. Run it again: no duplicate rows.
   Columns **Reviewer / Reviewer Notes / Evidence Link** belong to people and are never overwritten.

**Google Chat**: create an incoming webhook in the Cloud Operations space, set `CHAT_WEBHOOK_URL=...`, run `notification_dispatch`.

**Email (Gmail API)**: needs a Google service account with domain-wide delegation for `gmail.send`, then
`NOTIFY_EMAIL_ENABLED=true`, `GMAIL_SENDER=...`, `NOTIFY_EMAIL_TO=...`. Until that exists, email stays **queued** and is
reported as not configured - it is never shown as sent.

Then run `consolidated_daily_report` once. The first line of the message is `REPORT STATUS: COMPLETE | PARTIAL | FAILED`.

### Step 14 - AI analysis (Phase 8, optional)

In `.env`: `AI_PROVIDER=gemini`, `GEMINI_API_KEY=...`, `GEMINI_MODEL=<model name available to your key>`.
Run job `ai_analysis`. Each Medium-or-higher finding gets an advisory note with evidence, affected resource, risk,
confidence and a suggested action. AI never changes a review status. With `AI_PROVIDER=none` everything else works unchanged.

### Step 15 - Let it run on schedule

Run and Debug -> **Scheduler (all jobs on their cron)**, or:

```powershell
cd backend; .venv\Scripts\Activate.ps1
python -m app.workers.local_scheduler
```

Schedules (Asia/Kolkata): discovery and VM metrics every 15 min, security events every 5 min, billing hourly,
SOC review 07:00, VM review 07:30, billing review 08:00, consolidated report 08:30, weekly report Monday 09:00,
monthly report on the 1st at 09:00. Keep the API and the scheduler terminals open while you want automation to run.

---

## Part C - daily developer workflow

| I want to... | Do this |
|---|---|
| Change backend code | Edit under `backend/app`; the API reloads automatically |
| Change the dashboard | Edit under `frontend/src`; the browser reloads automatically |
| Add a detection rule | Add a `Rule(...)` to `backend/app/services/soc/rules.py` and a test in `backend/tests/unit/test_soc.py` |
| Change the schema | Edit a model, then `python -m alembic revision --autogenerate -m "what changed"` and `python -m alembic upgrade head` |
| Look at the data | MySQL Workbench -> schema `mcp` |
| Debug a job | Set a breakpoint, Run and Debug -> **Run one job** |
| Check before committing | `python -m ruff check .` and `python -m pytest -W ignore` in `backend`, `npm run build` in `frontend` |

## Part D - common problems

| Symptom | Fix |
|---|---|
| `Access denied for user 'mcp'` | Password in `DATABASE_URL` is wrong or not URL-encoded |
| `Can't connect to MySQL server` | Start the MySQL80 service (Windows Services) |
| Triggers "NOT created" (error 1419) | Run `SET GLOBAL log_bin_trust_function_creators = 1;` as root, then `python -m app.database.triggers` |
| Dashboard says the API is not reachable | Start the API (Step 6); it must be on port 8000 |
| Job failed: "No cloud provider is enabled" | Expected until Step 9 |
| Job failed: "No onboarded scopes yet" | Run `account_discovery` first |
| AWS `ExpiredToken` / `Unable to locate credentials` | `aws sso login` again and set `$env:AWS_PROFILE` in the API terminal |
| GCP `Reauthentication is needed` | `gcloud auth application-default login` |
| GCP `quota project` / `API not enabled` errors with your user login | `gcloud auth application-default set-quota-project <management-project>` |
| Google blocks the Sheets scope for `gcloud` login | Use a service account instead: `gcloud auth application-default login --impersonate-service-account=<sa-email>` and share the sheet with that service account |
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
