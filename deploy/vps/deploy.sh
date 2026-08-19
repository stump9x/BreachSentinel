#!/usr/bin/env bash
# BreachSentinel — VPS deploy helper.
#
# Hardens .env for a DEBUG=False run, then builds & starts the stack using the
# VPS overlay (only the frontend UI is published, default :3100). Idempotent:
# secrets are generated only when still placeholders, so re-running will NOT
# rotate the Postgres password out from under an existing data volume.
#
# Usage (run from the project root on the VPS):
#   bash deploy/vps/deploy.sh
#
# Optional overrides:
#   VPS_IP=1.2.3.4 FRONTEND_PORT=3100 bash deploy/vps/deploy.sh
set -euo pipefail

VPS_IP="${VPS_IP:-107.161.168.82}"
FRONTEND_PORT="${FRONTEND_PORT:-3100}"
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vps.yml"
ORIGIN="http://${VPS_IP}:${FRONTEND_PORT}"

# --- locate project root (parent of this script's deploy/vps dir) -----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."

# --- preflight --------------------------------------------------------------
command -v docker >/dev/null || { echo "ERROR: docker not installed" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: 'docker compose' plugin missing" >&2; exit 1; }
[ -f .env ] || { echo "ERROR: .env not found in $(pwd). Transfer it first." >&2; exit 1; }

# Normalize CRLF -> LF (files were authored on Windows); stray \r corrupts
# .env values (e.g. ports/passwords) once they reach compose/Django.
sed -i 's/\r$//' .env

if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -q ":${FRONTEND_PORT} "; then
  echo "ERROR: port ${FRONTEND_PORT} is already in use on this host. Pick another via FRONTEND_PORT=..." >&2
  exit 1
fi

# --- .env helpers -----------------------------------------------------------
get_val() { grep -m1 "^$1=" .env 2>/dev/null | sed "s/^$1=//" || true; }

set_kv() {
  local key="$1" val="$2"
  if grep -q "^${key}=" .env; then
    awk -v k="$key" -v v="$val" 'BEGIN{FS=OFS="="} $1==k{print k"="v; next} {print}' .env > .env.tmp && mv .env.tmp .env
  else
    printf '%s=%s\n' "$key" "$val" >> .env
  fi
}

# Subshell disables pipefail locally: the trailing `head -c` closes the pipe
# early (SIGPIPE upstream), which would otherwise trip `set -o pipefail`.
gen_secret() { ( set +o pipefail; head -c 60 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 50 ); }

is_placeholder_secret() { case "$1" in ""|*change-me*|*django-insecure*|*insecure-dev-only*) return 0;; esac; [ "${#1}" -lt 32 ]; }

echo ">> Hardening .env for production (DEBUG=False)"
cp -n .env ".env.bak.$(date +%Y%m%d%H%M%S)" 2>/dev/null || true

# Django SECRET_KEY — generate only if placeholder/too short.
if is_placeholder_secret "$(get_val DJANGO_SECRET_KEY)"; then
  set_kv DJANGO_SECRET_KEY "$(gen_secret)"
  echo "   - generated new DJANGO_SECRET_KEY"
fi

# Postgres password — generate only if placeholder (avoid breaking existing volume).
PG="$(get_val POSTGRES_PASSWORD)"
case "$PG" in ""|change-me-db-password|password|postgres)
  set_kv POSTGRES_PASSWORD "$(gen_secret)"; echo "   - generated new POSTGRES_PASSWORD";;
esac

# Redis password — generate only if empty or the shipped default.
RP="$(get_val REDIS_PASSWORD)"
case "$RP" in ""|breachsentinel-redis)
  RP="$(gen_secret)"; set_kv REDIS_PASSWORD "$RP"; echo "   - generated new REDIS_PASSWORD";;
esac
RP="$(get_val REDIS_PASSWORD)"
set_kv REDIS_URL "redis://:${RP}@redis:6379/0"
set_kv CELERY_BROKER_URL "redis://:${RP}@redis:6379/0"
set_kv CELERY_RESULT_BACKEND "redis://:${RP}@redis:6379/1"

# Host / origin config for this VPS (HTTP over IP:port, no TLS).
set_kv DJANGO_DEBUG "False"
set_kv DJANGO_ALLOWED_HOSTS "${VPS_IP},localhost,127.0.0.1,backend"
set_kv DJANGO_CSRF_TRUSTED_ORIGINS "${ORIGIN}"
set_kv DJANGO_CORS_ALLOWED_ORIGINS "${ORIGIN}"
set_kv FRONTEND_URL "${ORIGIN}"
set_kv BACKEND_URL "${ORIGIN}"
set_kv FRONTEND_PORT "${FRONTEND_PORT}"

# --- build & run ------------------------------------------------------------
echo ">> Tuning, building & starting stack (only UI published on :${FRONTEND_PORT})"
bash deploy/vps/optimize_vps.sh

# --- verify -----------------------------------------------------------------
echo ">> Waiting for backend to become healthy..."
for _ in $(seq 1 60); do
  status="$(docker inspect --format '{{.State.Health.Status}}' bs-backend 2>/dev/null || echo starting)"
  [ "$status" = healthy ] && break
  sleep 5
done
echo "   backend health: ${status:-unknown}"

echo ">> Checking UI at ${ORIGIN} ..."
if curl -fsS "http://127.0.0.1:${FRONTEND_PORT}/" >/dev/null 2>&1; then
  echo "   UI is up."
else
  echo "   WARNING: UI did not respond yet; check: ${COMPOSE} logs -f frontend" >&2
fi

echo ""
echo "Done. Open: ${ORIGIN}"
echo "Bootstrap Wire data (fresh DB is empty until Celery runs):"
echo "  bash deploy/vps/bootstrap_data.sh"
echo "Manage:  ${COMPOSE} ps | logs -f | down"

# Auto-seed RSS catalog on first deploy (idempotent).
echo ">> Seeding RSS sources catalog"
${COMPOSE} exec -T backend python manage.py seed_rss_sources --watcher-csv || \
  echo "WARNING: seed_rss_sources failed — run manually later" >&2
${COMPOSE} exec -T backend python manage.py shell -c "
from apps.integrations.tasks import translate_threat_titles_task
from apps.workers.tasks import ingest_cert_rss, ingest_cve_feed, ingest_ransomware_feed
print('queued', {
  'cve': ingest_cve_feed.delay(limit=40).id,
  'ransomware': ingest_ransomware_feed.delay(limit=50).id,
  'cert': ingest_cert_rss.delay(limit_per_feed=40).id,
  'translate': translate_threat_titles_task.delay(limit=100).id,
})
" || true
