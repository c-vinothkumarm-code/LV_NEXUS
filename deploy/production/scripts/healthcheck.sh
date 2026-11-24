#!/usr/bin/env bash
# LV NEXUS - operational health check (exit 1 when anything needs attention). Suitable for cron / monitoring agents.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE"
HOST="$(grep -oP 'server_name \K[^;]+' nginx/lvnexus.conf | tail -1)"
problems=0
check() { if eval "$2" >/dev/null 2>&1; then echo "  [ok]   $1"; else echo "  [FAIL] $1"; problems=$((problems + 1)); fi; }

echo "LV NEXUS health ($(date -u +%FT%TZ))"
for svc in proxy api scheduler; do
  check "container $svc running" "[[ \$(docker inspect -f '{{.State.Running}}' \$(docker compose ps -q $svc)) == true ]]"
done
check "api healthy" "[[ \$(docker inspect -f '{{.State.Health.Status}}' \$(docker compose ps -q api)) == healthy ]]"
check "HTTPS /health answers" "curl -fsS --max-time 5 --resolve $HOST:443:127.0.0.1 https://$HOST/health"
check "HTTP redirects to HTTPS" "[[ \$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/) == 301 ]]"
check "database ready (inside api)" "docker compose exec -T api python -c \"import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health/ready',timeout=4).status==200 else 1)\""
days=$(( ( $(date -d "$(openssl x509 -enddate -noout -in certs/fullchain.pem | cut -d= -f2)" +%s) - $(date +%s) ) / 86400 ))
check "TLS certificate valid > 21 days ($days)" "(( $days > 21 ))"
check "disk usage below 85 %" "(( \$(df --output=pcent . | tail -1 | tr -dc 0-9) < 85 ))"
latest="$(ls -1t backups/lvnexus-*.sql.gz.enc 2>/dev/null | head -1)"
check "backup in the last 26 h (${latest:-none})" "[[ -n '$latest' ]] && (( \$(date +%s) - \$(stat -c %Y '$latest') < 93600 ))"

(( problems == 0 )) && echo "all checks passed" || echo "$problems check(s) need attention"
exit $(( problems > 0 ))
