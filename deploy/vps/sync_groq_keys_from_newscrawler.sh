#!/usr/bin/env bash
# Partition the master Groq key list so NewsCrawler and BreachSentinel never
# share the same API keys (avoids cross-project 429 / quota fights).
# Source of truth: NewsCrawler .env (full pool). Never prints raw keys.
set -euo pipefail

NC_ENV="${1:-/root/NewsCrawler/.env}"
BS_ENV="${2:-/root/BreachSentinel/.env}"

if [[ ! -f "$NC_ENV" || ! -f "$BS_ENV" ]]; then
  echo "Missing .env (NC=$NC_ENV BS=$BS_ENV)" >&2
  exit 1
fi

python3 - <<'PY'
import re
from pathlib import Path
from datetime import datetime, timezone

nc_path = Path("/root/NewsCrawler/.env")
bs_path = Path("/root/BreachSentinel/.env")

def parse_keys(text: str) -> list[str]:
    keys: list[str] = []
    for line in text.splitlines():
        if line.startswith(("GROQ_API_KEY=", "GROQ_API_KEYS=")):
            v = line.split("=", 1)[1]
            keys.extend(p.strip() for p in re.split(r"[,;\n]+", v) if p.strip())
    # stable unique order
    return list(dict.fromkeys(keys))

def strip_groq_lines(text: str) -> str:
    drop = re.compile(
        r"^(GROQ_API_KEY|GROQ_API_KEYS|GROQ_MODEL|GROQ_TIMEOUT_SEC|"
        r"GROQ_KEY_COOLDOWN_SEC|GROQ_MAX_KEY_ATTEMPTS|GROQ_MIN_INTERVAL_SEC|"
        r"GROQ_STOP_ON_FIRST_429|GROQ_CIRCUIT_TTL_SEC|GROQ_FAIL_TRIP_THRESHOLD|"
        r"TITLE_TRANSLATE_GROQ|TITLE_TRANSLATE_PREFER_GROQ|"
        r"GROQ_POOL_NAMESPACE)="
    )
    lines = [ln for ln in text.splitlines() if not drop.match(ln)]
    # drop trailing empty lines then one blank separator
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines) + "\n"

def write_project(path: Path, keys: list[str], *, namespace: str, prefer: bool, max_attempts: int) -> None:
    text = path.read_text(errors="ignore")
    # Keep non-key Groq model/timeout from existing file when present
    model = "llama-3.3-70b-versatile"
    timeout = "12"
    cooldown = "120"
    for line in text.splitlines():
        if line.startswith("GROQ_MODEL="):
            model = line.split("=", 1)[1].strip() or model
        elif line.startswith("GROQ_TIMEOUT_SEC="):
            timeout = line.split("=", 1)[1].strip() or timeout
        elif line.startswith("GROQ_KEY_COOLDOWN_SEC="):
            cooldown = line.split("=", 1)[1].strip() or cooldown
    body = strip_groq_lines(text)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    primary = keys[0] if keys else ""
    extras = ",".join(keys[1:]) if len(keys) > 1 else ""
    block = [
        "",
        f"# --- Groq pool isolated for {namespace} ({stamp}) ---",
        f"GROQ_POOL_NAMESPACE={namespace}",
        f"GROQ_API_KEY={primary}",
        f"GROQ_API_KEYS={extras}",
        f"GROQ_MODEL={model}",
        f"GROQ_TIMEOUT_SEC={timeout}",
        f"GROQ_KEY_COOLDOWN_SEC={cooldown}",
        f"GROQ_MAX_KEY_ATTEMPTS={max_attempts}",
        "GROQ_MIN_INTERVAL_SEC=1.25",
        "GROQ_STOP_ON_FIRST_429=true",
        "GROQ_CIRCUIT_TTL_SEC=180",
        "GROQ_FAIL_TRIP_THRESHOLD=1",
        f"TITLE_TRANSLATE_GROQ={'true' if prefer else 'false'}",
        f"TITLE_TRANSLATE_PREFER_GROQ={'true' if prefer else 'false'}",
        "",
    ]
    path.write_text(body + "\n".join(block), encoding="utf-8")

nc_text = nc_path.read_text(errors="ignore")
bs_text = bs_path.read_text(errors="ignore")
# Prefer union so a previous full-copy into BS is not lost if NC was already sliced.
all_keys = list(dict.fromkeys(parse_keys(nc_text) + parse_keys(bs_text)))
if len(all_keys) < 2:
    raise SystemExit(f"need >=2 Groq keys to partition, found {len(all_keys)}")

# Deterministic split: first half → NewsCrawler, second half → BreachSentinel.
mid = (len(all_keys) + 1) // 2
nc_keys = all_keys[:mid]
bs_keys = all_keys[mid:]
if not bs_keys:
    bs_keys = [all_keys[-1]]
    nc_keys = all_keys[:-1]

write_project(nc_path, nc_keys, namespace="newscrawler", prefer=True, max_attempts=min(2, len(nc_keys)))
write_project(bs_path, bs_keys, namespace="breachsentinel", prefer=True, max_attempts=min(2, len(bs_keys)))

print(f"partition total={len(all_keys)} newscrawler={len(nc_keys)} breachsentinel={len(bs_keys)}")
print("overlap=0 (exclusive key slices)")
PY

echo "Recreate BOTH stacks so env_file reloads:"
echo "  cd /root/NewsCrawler && docker compose up -d --force-recreate backend celery"
echo "  cd /root/BreachSentinel && docker compose -f docker-compose.yml -f docker-compose.vps.yml up -d --force-recreate backend celery"
