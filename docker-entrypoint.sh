#!/bin/sh
# LV NEXUS container entrypoint. Roles:
#   api              web application + API (uvicorn, behind the TLS reverse proxy)
#   scheduler        the job scheduler (run exactly ONE instance)
#   migrate          apply database migrations (alembic upgrade head) and exit
#   job <name>       run one job once, e.g.  job compliance_evaluation
#   validate <cloud> live read-only connection check: aws | azure | gcp
set -eu

role="${1:-api}"
[ "$#" -gt 0 ] && shift

case "$role" in
  api)
    # --proxy-headers + FORWARDED_ALLOW_IPS: the real client IP is taken from X-Forwarded-For ONLY when the request comes
    # from the reverse proxy's address range, so per-IP rate limiting and audit logs see the user, not the proxy.
    exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8080}" --workers "${WEB_CONCURRENCY:-2}" \
      --proxy-headers --forwarded-allow-ips "${FORWARDED_ALLOW_IPS:-127.0.0.1}" \
      --no-server-header --no-date-header --timeout-keep-alive 15 --log-level "${UVICORN_LOG_LEVEL:-warning}"
    ;;
  scheduler)
    exec python -m app.workers.local_scheduler
    ;;
  migrate)
    alembic upgrade head
    # reference data (roles, permissions, job catalogue, default rules) once, before the API workers start
    exec python -c "from app.database.session import get_session_factory; from app.database.seed import seed_reference_data; db = get_session_factory()(); seed_reference_data(db); db.commit(); db.close(); print('reference data ok')"
    ;;
  job)
    [ "$#" -ge 1 ] || { echo "usage: job <job_name>" >&2; exit 64; }
    exec python -m app.workers.run "$@"
    ;;
  validate)
    exec python -m app.validate_cloud "$@"
    ;;
  *)
    exec "$role" "$@"
    ;;
esac
