#!/usr/bin/env bash
# LV NEXUS - one-time server preparation. Safe to re-run: existing secrets and settings are never overwritten.
#   sudo ./scripts/install.sh lvnexus.your-domain
# Creates secrets/ (0700) with generated database, session and backup keys, the settings file from the template,
# the nginx host name, and installs the systemd units (start on boot + nightly encrypted backup).
set -Eeuo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${1:-}"
cd "$HERE"

die() { echo "ERROR: $*" >&2; exit 1; }
ok()  { echo "  [ok] $*"; }

[[ $EUID -eq 0 ]] || die "run with sudo (installs systemd units and sets file ownership)"
[[ -n "$HOST" ]] || die "usage: sudo ./scripts/install.sh <host name, e.g. lvnexus.latentview.internal>"
[[ "$HOST" =~ ^[A-Za-z0-9.-]+$ ]] || die "invalid host name: $HOST"

echo "LV NEXUS install in $HERE for https://$HOST"
command -v docker >/dev/null || die "Docker Engine is not installed (https://docs.docker.com/engine/install/)"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 plugin is not installed"
command -v openssl >/dev/null || die "openssl is required"
ok "docker $(docker version --format '{{.Server.Version}}'), $(docker compose version --short)"

mkdir -p secrets/cloud/aws certs backups
chmod 700 secrets backups
chmod 755 certs
# cloud identity files are read inside the containers by the service user (uid 10001) and by nobody else
chown -R 10001:10001 secrets/cloud
chmod -R u=rwX,go= secrets/cloud

gen() { openssl rand -base64 48 | tr -d '\n/+=' | cut -c1-"$1"; }
new_secret() {  # file, length
  if [[ -s "$1" ]]; then ok "$1 exists (kept)"; else gen "$2" > "$1"; chmod 600 "$1"; ok "$1 generated"; fi
}
new_secret secrets/mysql_password 40
new_secret secrets/mysql_root_password 40
new_secret secrets/backup_key 64
# the mysql container reads the password files as its own user
chmod 644 secrets/mysql_password secrets/mysql_root_password

if [[ -s secrets/lvnexus.env ]]; then
  ok "secrets/lvnexus.env exists (kept; compare with lvnexus.env.example after upgrades)"
else
  cp lvnexus.env.example secrets/lvnexus.env
  db_pw="$(cat secrets/mysql_password)"
  sed -i \
    -e "s|^SESSION_SECRET=.*|SESSION_SECRET=$(gen 64)|" \
    -e "s|^DATABASE_URL=.*|DATABASE_URL=mysql+pymysql://lvnexus:${db_pw}@db:3306/lvnexus?charset=utf8mb4|" \
    -e "s|<lvnexus.your-domain>|${HOST}|g" \
    secrets/lvnexus.env
  chmod 600 secrets/lvnexus.env
  ok "secrets/lvnexus.env created - now fill in the <placeholders>"
fi

sed -i "s|server_name lvnexus.example.internal;|server_name ${HOST};|" nginx/lvnexus.conf
ok "nginx server_name set to $HOST"

if [[ -s certs/fullchain.pem && -s certs/privkey.pem ]]; then
  chmod 644 certs/fullchain.pem; chmod 640 certs/privkey.pem; chgrp 101 certs/privkey.pem 2>/dev/null || true  # nginx uid/gid 101
  end="$(openssl x509 -enddate -noout -in certs/fullchain.pem | cut -d= -f2)"
  openssl x509 -noout -checkhost "$HOST" -in certs/fullchain.pem | grep -q "does match" || die "certs/fullchain.pem is not valid for $HOST"
  ok "TLS certificate valid for $HOST until $end"
else
  echo "  [todo] put the TLS certificate chain in certs/fullchain.pem and the key in certs/privkey.pem (from your internal CA)"
fi

# systemd: start the stack on boot, nightly encrypted backup
for unit in systemd/*.service systemd/*.timer; do
  sed "s|@LVNEXUS_DIR@|${HERE}|g" "$unit" > "/etc/systemd/system/$(basename "$unit")"
done
systemctl daemon-reload
systemctl enable lvnexus.service lvnexus-backup.timer >/dev/null
ok "systemd units installed (lvnexus.service, lvnexus-backup.timer)"

cat <<EOF

Next steps
  1. Edit secrets/lvnexus.env and replace every <placeholder> (see docs/deployment/production-go-live.md).
  2. Put cloud identity files in secrets/cloud (Azure certificate, AWS Roles Anywhere config, GCP federation config).
  3. Put the TLS certificate in certs/ if not done.
  4. Deploy:  sudo ./scripts/deploy.sh <version tag>
EOF
