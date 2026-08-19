#!/usr/bin/env bash
# Restore a local BreachSentinel Postgres dump onto the VPS so data + login
# match the developer machine exactly (users keep the same password hash).
#
# Prerequisites on VPS:
#   - Stack already running via docker-compose.vps.yml
#   - Dump file present: deploy/vps/breachsentinel.dump
#
# Usage:
#   bash deploy/vps/restore_from_local.sh
set -euo pipefail

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vps.yml"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."

DUMP="${DUMP_PATH:-deploy/vps/breachsentinel.dump}"
[ -f "$DUMP" ] || { echo "ERROR: dump not found: $DUMP" >&2; exit 1; }

# Read DB credentials from .env (already hardened on VPS).
get_val() { grep -m1 "^$1=" .env 2>/dev/null | sed "s/^$1=//" | tr -d '\r' || true; }
PGUSER="$(get_val POSTGRES_USER)"; PGUSER="${PGUSER:-breachsentinel}"
PGDB="$(get_val POSTGRES_DB)"; PGDB="${PGDB:-breachsentinel}"
PGPASS="$(get_val POSTGRES_PASSWORD)"
[ -n "$PGPASS" ] || { echo "ERROR: POSTGRES_PASSWORD missing in .env" >&2; exit 1; }
REDISPASS="$(get_val REDIS_PASSWORD)"
[ -n "$REDISPASS" ] || { echo "ERROR: REDIS_PASSWORD missing in .env" >&2; exit 1; }

echo ">> Stopping writers (backend/celery) during restore"
${COMPOSE} stop backend celery celery-beat

echo ">> Backing up current VPS database before replacement"
mkdir -p deploy/vps/backups
backup="deploy/vps/backups/vps-before-local-restore-$(date +%Y%m%d%H%M%S).dump"
docker exec -e PGPASSWORD="$PGPASS" bs-postgres \
  pg_dump -U "$PGUSER" -d "$PGDB" -Fc -f /tmp/vps-before-restore.dump
docker cp bs-postgres:/tmp/vps-before-restore.dump "$backup"
echo "   backup: $backup"

echo ">> Clearing stale Celery jobs/results before database replacement"
docker exec bs-redis redis-cli -a "$REDISPASS" -n 0 FLUSHDB >/dev/null
docker exec bs-redis redis-cli -a "$REDISPASS" -n 1 FLUSHDB >/dev/null

echo ">> Copy dump into postgres container"
docker cp "$DUMP" bs-postgres:/tmp/breachsentinel.dump

echo ">> Dropping & recreating database ${PGDB}"
docker exec -e PGPASSWORD="$PGPASS" bs-postgres \
  psql -U "$PGUSER" -d postgres -v ON_ERROR_STOP=1 -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${PGDB}' AND pid <> pg_backend_pid();"
docker exec -e PGPASSWORD="$PGPASS" bs-postgres \
  psql -U "$PGUSER" -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS ${PGDB};"
docker exec -e PGPASSWORD="$PGPASS" bs-postgres \
  psql -U "$PGUSER" -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${PGDB} OWNER ${PGUSER};"

echo ">> Restoring dump"
docker exec -e PGPASSWORD="$PGPASS" bs-postgres \
  pg_restore -U "$PGUSER" -d "$PGDB" --no-owner --role="$PGUSER" \
  --exit-on-error /tmp/breachsentinel.dump

echo ">> Starting services"
${COMPOSE} start backend celery celery-beat
echo ">> Waiting for backend healthy..."
for _ in $(seq 1 40); do
  status="$(docker inspect --format '{{.State.Health.Status}}' bs-backend 2>/dev/null || echo starting)"
  [ "$status" = healthy ] && break
  sleep 5
done
echo "   backend: ${status:-unknown}"
${COMPOSE} exec -T backend python manage.py migrate --noinput

echo ">> Verify counts + users"
${COMPOSE} exec -T backend python manage.py shell -c "
from django.contrib.auth import get_user_model
from apps.intel.models import Threat, FeedSource
U=get_user_model()
print('users=', [(u.username, u.is_superuser, u.email) for u in U.objects.all()])
print('threats=', Threat.objects.count())
print('with_title_vi=', Threat.objects.exclude(title_vi='').count())
print('feeds=', FeedSource.objects.count())
"

echo ""
echo "Done. Login on VPS with the SAME username/password as local."
echo "Open: http://\$(hostname -I | awk '{print \$1}'):\${FRONTEND_PORT:-3100}/login"
