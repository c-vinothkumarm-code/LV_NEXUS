#!/usr/bin/env bash
# LV NEXUS - deploy or upgrade with a pre-deploy backup, migrations, health gate and automatic rollback of the application.
#   sudo ./scripts/deploy.sh <version>            build lvnexus:<version> from this repository and deploy it
#   sudo LVNEXUS_IMAGE=registry/lvnexus:1.4.0 ./scripts/deploy.sh 1.4.0   deploy an image built and scanned by CI
# Environment: BUNDLED_DB=true (default) uses the db container; false = external MySQL from DATABASE_URL.
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
VERSION="${1:-}"
BUNDLED_DB="${BUNDLED_DB:-true}"
cd "$HERE"

die() { echo "ERROR: $*" >&2; exit 1; }
log() { echo "[$(date -u +%H:%M:%SZ)] $*"; }

[[ -n "$VERSION" ]] || die "usage: sudo ./scripts/deploy.sh <version>"
[[ "$VERSION" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid version: $VERSION"

# ---------------------------------------------------------------- preflight
[[ -s secrets/lvnexus.env ]] || die "secrets/lvnexus.env missing - run scripts/install.sh first"
[[ "$(stat -c %a secrets/lvnexus.env)" == "600" ]] || die "secrets/lvnexus.env must be chmod 600"
grep -q '<' secrets/lvnexus.env && die "secrets/lvnexus.env still contains <placeholders>"
grep -q '^APP_ENV=production' secrets/lvnexus.env || die "APP_ENV must be production"
grep -q '^AUTH_MODE=dev' secrets/lvnexus.env && die "AUTH_MODE=dev is not allowed in production"
[[ -s certs/fullchain.pem && -s certs/privkey.pem ]] || die "TLS certificate missing in certs/"
days_left=$(( ( $(date -d "$(openssl x509 -enddate -noout -in certs/fullchain.pem | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
(( days_left > 7 )) || die "TLS certificate expires in $days_left days - renew it first"
log "preflight ok (certificate valid $days_left more days)"

PROFILES=()
[[ "$BUNDLED_DB" == "true" ]] && PROFILES=(--profile bundled-db)
compose() { docker compose "${PROFILES[@]}" "$@"; }

PREVIOUS_IMAGE="$(cat .last-good-image 2>/dev/null || true)"

# ---------------------------------------------------------------- image
if [[ -n "${LVNEXUS_IMAGE:-}" ]]; then
  log "pulling $LVNEXUS_IMAGE"
  docker pull "$LVNEXUS_IMAGE"
  export LVNEXUS_IMAGE
else
  export LVNEXUS_IMAGE="lvnexus:${VERSION}"
  log "building $LVNEXUS_IMAGE from $REPO"
  docker build --pull -t "$LVNEXUS_IMAGE" \
    --build-arg VERSION="$VERSION" --build-arg REVISION="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)" "$REPO"
fi

# ---------------------------------------------------------------- database + backup + migrations
if [[ "$BUNDLED_DB" == "true" ]]; then
  compose up -d db
  log "waiting for the database"
  for _ in $(seq 1 60); do
    [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q db)")" == "healthy" ]] && break; sleep 3
  done
  [[ "$(docker inspect -f '{{.State.Health.Status}}' "$(compose ps -q db)")" == "healthy" ]] || die "database did not become healthy"
  if [[ -n "$PREVIOUS_IMAGE" ]]; then
    log "pre-deploy backup"
    "$HERE/scripts/backup.sh" "pre-deploy-${VERSION}"
  fi
fi

log "applying database migrations"
compose run --rm migrate || die "migration failed - the running version was not changed. Restore from backups/ if the failure was partial."

# ---------------------------------------------------------------- roll out
log "starting $LVNEXUS_IMAGE"
compose up -d --remove-orphans api scheduler proxy

healthy=false
for _ in $(seq 1 40); do
  api_id="$(compose ps -q api)"
  if [[ -n "$api_id" && "$(docker inspect -f '{{.State.Health.Status}}' "$api_id")" == "healthy" ]] \
     && curl -fsS --max-time 5 --resolve "$(grep -oP 'server_name \K[^;]+' nginx/lvnexus.conf | tail -1):443:127.0.0.1" \
        "https://$(grep -oP 'server_name \K[^;]+' nginx/lvnexus.conf | tail -1)/health" -o /dev/null; then
    healthy=true; break
  fi
  sleep 3
done

if [[ "$healthy" != "true" ]]; then
  log "health check FAILED for $LVNEXUS_IMAGE"
  compose logs --tail 80 api || true
  if [[ -n "$PREVIOUS_IMAGE" ]]; then
    log "rolling back the application to $PREVIOUS_IMAGE (database migrations are NOT reverted; see the runbook)"
    LVNEXUS_IMAGE="$PREVIOUS_IMAGE" compose up -d api scheduler proxy
  fi
  die "deployment of $VERSION failed"
fi

echo "$LVNEXUS_IMAGE" > .last-good-image
log "deployed $LVNEXUS_IMAGE - https://$(grep -oP 'server_name \K[^;]+' nginx/lvnexus.conf | tail -1)"
docker image prune -f --filter "until=720h" >/dev/null || true
