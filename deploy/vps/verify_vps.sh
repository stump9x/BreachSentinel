#!/usr/bin/env bash
# End-to-end VPS verification. Exits non-zero for a broken core dependency.
set -euo pipefail

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vps.yml"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."
port="$(grep -m1 '^FRONTEND_PORT=' .env | cut -d= -f2 | tr -d '\r')"
port="${port:-3100}"

echo "===== Containers ====="
${COMPOSE} ps

echo "===== Django / migrations ====="
${COMPOSE} exec -T backend python manage.py check
${COMPOSE} exec -T backend python manage.py migrate --check

echo "===== Database parity data ====="
${COMPOSE} exec -T backend python manage.py shell -c "
from django.contrib.auth import get_user_model
from apps.intel.models import *
from apps.integrations.models import IntegrationSyncLog
U = get_user_model()
print('users=', list(U.objects.values_list('username','is_active','is_staff','is_superuser')))
print('threats=', Threat.objects.count())
print('wire_translated=', Threat.objects.exclude(title_vi='').count())
print('feed_sources=', FeedSource.objects.count())
print('active_feeds=', FeedSource.objects.filter(is_active=True).count())
print('indicators=', Indicator.objects.count())
print('leaks=', DataLeak.objects.count())
print('credentials=', CompromisedCredential.objects.count())
print('actors=', ThreatActor.objects.count())
print('integration_logs=', IntegrationSyncLog.objects.count())
"

echo "===== Internal dependencies ====="
${COMPOSE} exec -T backend python - <<'PY'
import json
import urllib.request

for name, url in {
    "backend": "http://127.0.0.1:8000/api/health/",
    "osint": "http://osint:8080/health",
    "searxng": "http://searxng:8080/healthz",
}.items():
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            print(name, response.status, response.read(200).decode(errors="replace"))
    except Exception as exc:
        print(name, "ERROR", type(exc).__name__, exc)
        if name in {"backend", "osint"}:
            raise
PY

echo "===== Celery worker / schedule ====="
${COMPOSE} exec -T celery celery -A config inspect ping --timeout 15
${COMPOSE} exec -T celery celery -A config inspect registered --timeout 15 |
  grep -E 'workers.ingest_cert_rss|integrations.translate_threat_titles|integrations.scan_searx_leaks'
${COMPOSE} logs --tail=30 celery-beat | grep -E 'beat: Starting|Scheduler|ERROR|CRITICAL' || true

echo "===== Public frontend / reverse proxy ====="
curl -fsS "http://127.0.0.1:${port}/" >/dev/null
curl -fsS "http://127.0.0.1:${port}/api/health/"
echo

echo "===== Recent critical errors ====="
errors="$(${COMPOSE} logs --since=15m backend celery celery-beat osint 2>&1 |
  grep -Ei 'Traceback|ModuleNotFoundError|ImportError|CRITICAL|unrecoverable error' || true)"
if [ -n "$errors" ]; then
  echo "$errors"
  echo "WARNING: critical-looking log lines found above." >&2
else
  echo "No critical errors in the last 15 minutes."
fi

echo "VPS core verification passed."
