#!/usr/bin/env bash
# Local setup without Docker. Needs Python 3.13, Node 22 and a MySQL 8 database (see .env.example).
set -euo pipefail
cd "$(dirname "$0")/../.."
python3.13 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements-dev.txt
(cd backend && .venv/bin/alembic upgrade head)
(cd frontend && npm ci)
echo "Run:  (cd backend && .venv/bin/uvicorn app.main:app --port 8000)   and   (cd frontend && npm run dev)"
