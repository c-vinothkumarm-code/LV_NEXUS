#!/usr/bin/env bash
# LV NEXUS - restore an encrypted backup into the bundled database. DESTRUCTIVE: replaces the current database.
#   sudo ./scripts/restore.sh backups/lvnexus-<time>-<label>.sql.gz.enc
# Stops the api and scheduler, verifies the checksum, restores, applies migrations, starts the application again.
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
FILE="${1:-}"
[[ -f "$FILE" ]] || { echo "usage: sudo ./scripts/restore.sh <backup file>" >&2; exit 64; }
[[ -f "$FILE.sha256" ]] && sha256sum -c "$FILE.sha256"

echo "This REPLACES the LV NEXUS database with $FILE."
read -r -p "Type RESTORE to continue: " answer
[[ "$answer" == "RESTORE" ]] || { echo "cancelled"; exit 1; }

compose() { docker compose --profile bundled-db "$@"; }
"$HERE/scripts/backup.sh" "before-restore"            # keep the current state, just in case
compose stop api scheduler proxy
DB="$(compose ps -q db)"
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:secrets/backup_key -in "$FILE" \
  | gunzip \
  | docker exec -i "$DB" sh -c 'exec mysql -u root --password="$(cat /run/secrets/mysql_root_password)"'
LVNEXUS_IMAGE="$(cat .last-good-image)" compose run --rm migrate
LVNEXUS_IMAGE="$(cat .last-good-image)" compose up -d api scheduler proxy
echo "restore complete; check: ./scripts/healthcheck.sh"
