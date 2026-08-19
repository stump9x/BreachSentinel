#!/usr/bin/env bash
# Sync local BreachSentinel sources to the VPS over the same SSH key as NewsCrawler,
# then optionally run a remote command (no password prompts).
#
# Usage (Git Bash / WSL) from the project root:
#   bash deploy/vps/sync_to_vps.sh
#   bash deploy/vps/sync_to_vps.sh --optimize
#   bash deploy/vps/sync_to_vps.sh --remote "docker compose -f docker-compose.yml -f docker-compose.vps.yml ps"
#
# PowerShell equivalent is deploy/vps/sync_to_vps.ps1
set -euo pipefail

HOST="${VPS_SSH_HOST:-breachsentinel}"
REMOTE_DIR="${VPS_REMOTE_DIR:-~/BreachSentinel}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_OPTIMIZE=0
REMOTE_CMD=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --optimize) RUN_OPTIMIZE=1; shift ;;
    --remote) REMOTE_CMD="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

echo ">> SSH host: ${HOST}"
ssh -o BatchMode=yes -o ConnectTimeout=15 "$HOST" "mkdir -p ${REMOTE_DIR}"

echo ">> Syncing changed files to ${HOST}:${REMOTE_DIR}"
# Prefer rsync when available; fall back to scp of known paths.
if command -v rsync >/dev/null 2>&1; then
  rsync -az --delete \
    --exclude '.git/' \
    --exclude 'frontend/node_modules/' \
    --exclude 'frontend/dist/' \
    --exclude '.env' \
    --exclude 'deploy/vps/*.dump' \
    --exclude 'deploy/vps/backups/' \
    --exclude '__pycache__/' \
    --exclude '*.pyc' \
    -e "ssh -o BatchMode=yes" \
    "${ROOT}/" "${HOST}:${REMOTE_DIR}/"
else
  scp -o BatchMode=yes \
    "${ROOT}/docker-compose.yml" \
    "${ROOT}/docker-compose.vps.yml" \
    "${ROOT}/docker-compose.prod.yml" \
    "${ROOT}/.env.example" \
    "${ROOT}/README.md" \
    "${HOST}:${REMOTE_DIR}/"
  scp -o BatchMode=yes -r \
    "${ROOT}/backend/apps" \
    "${ROOT}/backend/config" \
    "${HOST}:${REMOTE_DIR}/backend/"
  scp -o BatchMode=yes -r \
    "${ROOT}/deploy/vps" \
    "${HOST}:${REMOTE_DIR}/deploy/"
  scp -o BatchMode=yes \
    "${ROOT}/frontend/nginx.conf" \
    "${HOST}:${REMOTE_DIR}/frontend/"
fi

ssh -o BatchMode=yes "$HOST" "sed -i 's/\r\$//' ${REMOTE_DIR}/deploy/vps/*.sh && chmod +x ${REMOTE_DIR}/deploy/vps/*.sh"

if [[ "$RUN_OPTIMIZE" -eq 1 ]]; then
  echo ">> Running optimize_vps.sh on VPS"
  ssh -o BatchMode=yes "$HOST" "cd ${REMOTE_DIR} && bash deploy/vps/optimize_vps.sh"
fi

if [[ -n "$REMOTE_CMD" ]]; then
  echo ">> Remote: ${REMOTE_CMD}"
  ssh -o BatchMode=yes "$HOST" "cd ${REMOTE_DIR} && ${REMOTE_CMD}"
fi

echo "Done."
