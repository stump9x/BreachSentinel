#!/usr/bin/env sh
# Post-build / post-test cleanup — free disk + reclaim RAM.
# Run after every `docker compose build` / frontend npm build / pytest.
# On this shared VPS also run NewsCrawler's copy when that project built.
# Usage: sh scripts/post-build-cleanup.sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
echo "[post-build-cleanup] project=$(basename "$ROOT")"

# --- Frontend / TypeScript caches ---
rm -rf frontend/node_modules/.vite \
       frontend/node_modules/.cache \
       frontend/.vite \
       frontend/coverage \
       frontend/.turbo \
       frontend/dist 2>/dev/null || true
find frontend -name '*.tsbuildinfo' -type f -delete 2>/dev/null || true

# --- Python test / lint caches ---
find . \( -path './.git' -o -path './data' -o -path '*/node_modules/*' \) -prune -o \
  \( -type d -name '__pycache__' -o -type d -name '.pytest_cache' -o -type d -name '.mypy_cache' -o -type d -name '.ruff_cache' \) \
  -print0 2>/dev/null | xargs -0 rm -rf 2>/dev/null || true
rm -rf .coverage htmlcov .tox .nox 2>/dev/null || true

# --- Host package manager caches ---
npm cache clean --force >/dev/null 2>&1 || true
yarn cache clean >/dev/null 2>&1 || true
pip cache purge >/dev/null 2>&1 || true
apt-get clean >/dev/null 2>&1 || true

# --- Stopped one-shot / test leftovers (never wipe named app data volumes) ---
docker container prune -f >/dev/null 2>&1 || true
docker network prune -f >/dev/null 2>&1 || true

# --- Docker buildkit / dangling layers ---
docker builder prune -af >/dev/null 2>&1 || true
docker image prune -f >/dev/null 2>&1 || true

# --- Drop Linux page cache when root ---
if [ "$(id -u)" = "0" ] && [ -w /proc/sys/vm/drop_caches ]; then
  sync
  echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
fi

echo "[post-build-cleanup] memory after:"
free -h | head -2
echo "[post-build-cleanup] done"
