# Moving from MySQL to Azure SQL (planned)

The application is written to be database-neutral, so the move is configuration plus a data copy. It has **not** been
run against Azure SQL yet; MySQL 8 and SQLite are the tested databases. Treat the first Azure SQL run as a test cycle.

## What is already portable

- All models use SQLAlchemy types only. JSON columns become `NVARCHAR(MAX)` on SQL Server.
- Timestamps go through `UTCDateTime` (`backend/app/models/base.py`): stored as UTC `DATETIME2`, returned timezone-aware.
- Aggregations avoid database-specific functions.
- The Alembic migration contains no MySQL-only syntax; append-only triggers have a SQL Server variant
  (`backend/app/database/triggers.py`).
- Sessions use READ COMMITTED on MySQL and SQL Server.

## Steps

1. Create the Azure SQL database. Use a UTF-8 collation (for example `Latin1_General_100_CI_AS_SC_UTF8`) so text columns keep non-Latin characters.
2. On the host or in the image: install *Microsoft ODBC Driver 18 for SQL Server*, then `pip install -r requirements-azure-sql.txt`.
3. Set `DATABASE_URL=mssql+pyodbc://USER:PASSWORD@SERVER.database.windows.net:1433/DB?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes`
   (prefer Microsoft Entra authentication / managed identity over a SQL password in production).
4. `python -m alembic upgrade head` then `python -m app.database.triggers`.
5. Run the test suite against a scratch Azure SQL database. `tests/conftest.py` resets MySQL and PostgreSQL today; add a
   SQL Server branch (drop all tables) before using it there.
6. Copy data from MySQL (Azure Database Migration Service, or export/import table by table in dependency order).
   History tables are append-only: load them before creating the triggers.
7. Point the API and the jobs at the new `DATABASE_URL`, run `account_discovery`, compare dashboard figures with the old database.

## Things to verify during that cycle

- Row-count and totals parity for `billing_records`, `audit_events`, `security_findings`.
- Unique indexes on long text keys (`cloud_resources.resource_id`, `vm_inventory.instance_id`) are within SQL Server's index key size.
- Job locking under two concurrent schedulers (the lock is a single atomic UPDATE and should behave the same).

## Hosting on Azure

The container image is cloud-neutral. On Azure: Container Apps for the API, Container Apps jobs (cron) calling
`python -m app.workers.run <job>` in place of the local scheduler, Key Vault for secrets, managed identity for Azure access.
`infrastructure/terraform/main.tf` targets Google Cloud Run and is a draft; an Azure equivalent still has to be written.
