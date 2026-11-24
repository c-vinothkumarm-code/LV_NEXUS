#!/usr/bin/env bash
# LV NEXUS - encrypted logical backup of the bundled MySQL database.
#   ./scripts/backup.sh [label]          (run nightly by lvnexus-backup.timer)
# Output: backups/lvnexus-<UTC time>-<label>.sql.gz.enc + .sha256   (AES-256, key in secrets/backup_key)
# Copy the backups directory off the server (BACKUP_OFFSITE_DIR, e.g. a mounted NAS share) and keep backup_key in the
# company password vault: without it a backup cannot be restored.
set -Eeuo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
LABEL="${1:-scheduled}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="backups/lvnexus-${STAMP}-${LABEL//[^A-Za-z0-9._-]/_}.sql.gz.enc"

[[ -s secrets/backup_key ]] || { echo "secrets/backup_key missing" >&2; exit 1; }
DB="$(docker compose --profile bundled-db ps -q db)"
[[ -n "$DB" ]] || { echo "database container is not running" >&2; exit 1; }

# --single-transaction: consistent InnoDB snapshot without locking the application
docker exec "$DB" sh -c 'exec mysqldump -u root --password="$(cat /run/secrets/mysql_root_password)" \
    --single-transaction --routines --triggers --events --hex-blob --set-gtid-purged=OFF --databases lvnexus' \
  | gzip -9 \
  | openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass file:secrets/backup_key -out "$OUT"

[[ -s "$OUT" ]] || { echo "backup is empty" >&2; rm -f "$OUT"; exit 1; }
sha256sum "$OUT" > "$OUT.sha256"
echo "backup written: $OUT ($(du -h "$OUT" | cut -f1))"

if [[ -n "${BACKUP_OFFSITE_DIR:-}" ]]; then
  cp "$OUT" "$OUT.sha256" "$BACKUP_OFFSITE_DIR/" && echo "copied to $BACKUP_OFFSITE_DIR"
fi
find backups -name 'lvnexus-*.sql.gz.enc*' -mtime +"$RETENTION_DAYS" -delete
