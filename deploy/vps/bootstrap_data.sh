#!/usr/bin/env bash
# Bootstrap VPS data so RSS Sources + The Wire match a populated local install.
#
# Root causes this fixes on a fresh VPS:
#   1) FeedSource catalog empty → seed_rss_sources never ran
#   2) The Wire hides items with empty title_vi → need Google title translation
#   3) Translation provider must be healthy before draining pending titles
#
# Usage (from project root on the VPS):
#   bash deploy/vps/bootstrap_data.sh
set -euo pipefail

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vps.yml"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."

set_kv() {
  local key="$1" val="$2"
  if grep -q "^${key}=" .env; then
    awk -v k="$key" -v v="$val" 'BEGIN{FS=OFS="="} $1==k{print k"="v; next} {print}' .env > .env.tmp && mv .env.tmp .env
  else
    printf '%s=%s\n' "$key" "$val" >> .env
  fi
}

echo "===== 1) Enable translation (provider selected by optimize_vps.sh) ====="
sed -i 's/\r$//' .env
set_kv TITLE_TRANSLATE_ENABLED "true"
${COMPOSE} up -d backend celery celery-beat
sleep 8

echo ""
echo "===== 2) Seed RSS / Watcher catalog ====="
${COMPOSE} exec -T backend python manage.py seed_rss_sources --watcher-csv
${COMPOSE} exec -T backend python manage.py shell -c "
from apps.intel.models import FeedSource
print('feed_sources=', FeedSource.objects.count(), 'active=', FeedSource.objects.filter(is_active=True).count())
"

echo ""
echo "===== 3) Probe the real title translation path ====="
${COMPOSE} exec -T backend python manage.py shell <<'PY'
from apps.integrations.ai.translate import google_translate_title
print("translation_probe=", google_translate_title("Security incident reported"))
PY

echo ""
echo "===== 4) Queue ingest + title translation ====="
${COMPOSE} exec -T backend python manage.py shell -c "
from apps.workers.tasks import ingest_cve_feed, ingest_ransomware_feed, ingest_cert_rss, ingest_zoneh_archive, ingest_forum_claims
from apps.integrations.tasks import translate_threat_titles_task
print({
  'cve': ingest_cve_feed.delay(limit=40).id,
  'ransomware': ingest_ransomware_feed.delay(limit=50).id,
  'cert': ingest_cert_rss.delay(limit_per_feed=40).id,
  'zoneh': ingest_zoneh_archive.delay(pages=2).id,
  'forum': ingest_forum_claims.delay(limit_per_feed=25).id,
  'translate': translate_threat_titles_task.delay(limit=200).id,
})
"

echo "Waiting ~3 minutes for ingest + translate..."
sleep 180

# Drain remaining pending titles a few more times
for i in 1 2 3 4; do
  ${COMPOSE} exec -T backend python manage.py shell -c "
from apps.integrations.tasks import translate_threat_titles_task
print('translate_round_${i}=', translate_threat_titles_task.delay(limit=200).id)
" || true
  sleep 45
done

echo ""
echo "===== 5) Final counts (what Wire / RSS UI need) ====="
${COMPOSE} exec -T backend python manage.py shell -c "
from apps.intel.models import Threat, FeedSource
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
now = timezone.now()
gcut = now - timedelta(days=int(getattr(settings,'WIRE_MAX_AGE_DAYS',7) or 7))
vcut = now - timedelta(days=int(getattr(settings,'WIRE_VIETNAM_MAX_AGE_DAYS',30) or 30))
qs = Threat.objects.filter(wire_relevant=True).exclude(title_vi='').filter(
    Q(tags__slug='vietnam', published_at__gte=vcut) | Q(published_at__gte=gcut)
).distinct()
print('threats_total=', Threat.objects.count())
print('threats_with_title_vi=', Threat.objects.exclude(title_vi='').count())
print('threats_pending_vi=', Threat.objects.filter(title_vi='', wire_relevant=True).count())
print('wire_visible=', qs.count())
print('feed_sources_active=', FeedSource.objects.filter(is_active=True).count())
"

echo ""
echo "===== 6) Celery errors (if any) ====="
${COMPOSE} logs --tail=100 celery 2>&1 | grep -Ei 'Error|Exception|Traceback|ModuleNotFound|ImportError|translate|failed' | tail -50 || true

echo ""
echo "Done. Hard-refresh The Wire + RSS Sources in the browser."
