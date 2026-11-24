#!/usr/bin/env bash
# Lint + full test suite. Set TEST_DATABASE_URL to run against PostgreSQL through the Alembic migration.
set -euo pipefail
cd "$(dirname "$0")/../../backend"
.venv/bin/ruff check .
.venv/bin/pytest -W ignore "$@"
(cd ../frontend && npm run build)
