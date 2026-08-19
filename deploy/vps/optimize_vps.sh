#!/usr/bin/env bash
# Tune BreachSentinel on the shared VPS (with NewsCrawler).
# Translation priority: Google → shared nc-ollama (qwen2.5:3b) → MyMemory.
# Does NOT start a second Ollama — reuses NewsCrawler's nc-ollama container.
set -euo pipefail

COMPOSE="docker compose -f docker-compose.yml -f docker-compose.vps.yml"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}/../.."

set_kv() {
  local key="$1" val="$2"
  if grep -q "^${key}=" .env; then
    awk -v k="$key" -v v="$val" 'BEGIN{FS=OFS="="} $1==k{print k"="v; next} {print}' .env > .env.tmp
    mv .env.tmp .env
  else
    printf '%s=%s\n' "$key" "$val" >> .env
  fi
}

cpu="$(nproc)"
mem_kb="$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"
mem_gb=$(( (mem_kb + 1048575) / 1048576 ))
disk_free_gb="$(df -Pk . | awk 'NR==2 {printf "%d", $4/1024/1024}')"

# Conservative workers — Ollama RAM is already spent by NewsCrawler's nc-ollama.
if [ "$mem_gb" -le 4 ] || [ "$cpu" -le 1 ]; then
  gunicorn=1
  celery=1
  osint=15
elif [ "$mem_gb" -le 8 ] || [ "$cpu" -le 2 ]; then
  gunicorn=2
  celery=1
  osint=25
else
  gunicorn=2
  celery=2
  osint=35
fi

echo "VPS resources: cpu=${cpu}, ram=${mem_gb}GiB, free_disk=${disk_free_gb}GiB"
echo "Selected: gunicorn=${gunicorn}, celery=${celery}, osint=${osint}"
echo "Ollama: share NewsCrawler nc-ollama (no second container)"

set_kv GUNICORN_WORKERS "$gunicorn"
set_kv CELERY_WORKER_CONCURRENCY "$celery"
set_kv CELERY_MAX_TASKS_PER_CHILD "100"
set_kv CELERY_MAX_MEMORY_PER_CHILD_KB "450000"
set_kv CELERY_RESULT_EXPIRES "3600"
set_kv OSINT_MAX_CONCURRENCY "$osint"
set_kv DJANGO_DB_CONN_MAX_AGE "60"
set_kv TITLE_TRANSLATE_ENABLED "true"
set_kv TITLE_TRANSLATE_AI_REFINE "false"
set_kv TITLE_TRANSLATE_MYMEMORY_FALLBACK "true"
set_kv TITLE_TRANSLATE_OLLAMA_FALLBACK "true"
set_kv SUMMARY_TRANSLATE_OLLAMA_FALLBACK "true"
set_kv GOOGLE_TRANSLATE_TIMEOUT_SEC "20"
set_kv GOOGLE_TRANSLATE_CIRCUIT_SEC "120"
set_kv GOOGLE_TRANSLATE_PACING_SEC "0.15"
# Match NewsCrawler Ollama tuning.
set_kv OLLAMA_ENABLED "true"
set_kv OLLAMA_BASE_URL "http://ollama:11434"
set_kv OLLAMA_TRANSLATE_MODEL "${OLLAMA_TRANSLATE_MODEL:-qwen2.5:3b}"
set_kv OLLAMA_TIMEOUT_SEC "120"
set_kv OLLAMA_NUM_PREDICT "128"
set_kv OLLAMA_NUM_CTX "1024"
set_kv OLLAMA_KEEP_ALIVE "15m"
set_kv SUMMARY_TRANSLATE_OLLAMA_NUM_PREDICT "360"

if ! docker network inspect newscrawler_default >/dev/null 2>&1; then
  echo "ERROR: Docker network newscrawler_default not found. Start NewsCrawler first." >&2
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -qx 'nc-ollama'; then
  echo ">> Starting NewsCrawler Ollama (nc-ollama)..."
  if [ -d "$HOME/NewsCrawler" ]; then
    (cd "$HOME/NewsCrawler" && docker compose up -d ollama)
  else
    echo "ERROR: nc-ollama is not running and ~/NewsCrawler is missing." >&2
    exit 1
  fi
fi

echo "Recreating BreachSentinel services (join newscrawler_default for shared Ollama)..."
${COMPOSE} up -d --build --remove-orphans

# Ensure model is present (idempotent; NewsCrawler usually already pulled it).
docker exec nc-ollama ollama list >/dev/null 2>&1 || true
if ! docker exec nc-ollama ollama list 2>/dev/null | grep -q 'qwen2.5:3b'; then
  echo ">> Pulling qwen2.5:3b into shared nc-ollama..."
  docker exec nc-ollama ollama pull qwen2.5:3b
fi

echo "Probing translation providers (Google first, then shared Ollama)..."
google_ok=0
ollama_ok=0
if ${COMPOSE} exec -T backend python manage.py shell <<'PY'
from apps.integrations.ai.translate import google_translate_title, reset_google_circuit
reset_google_circuit()
print(google_translate_title("Security incident reported"))
PY
then
  google_ok=1
  echo "Google: OK (primary)"
else
  echo "Google: blocked/unavailable — shared Ollama covers new titles"
fi

if ${COMPOSE} exec -T backend python manage.py shell <<'PY'
from apps.integrations.ai.translate import ollama_translate_title
print(ollama_translate_title("Security incident reported"))
PY
then
  ollama_ok=1
  echo "Ollama (nc-ollama shared): OK (fallback)"
else
  echo "WARNING: cannot reach shared Ollama from BreachSentinel backend" >&2
fi

echo "Provider policy: Google → Ollama(shared) → MyMemory"
echo "  google_ok=${google_ok} ollama_ok=${ollama_ok}"

${COMPOSE} up -d backend celery celery-beat
echo "Optimization applied."
