#!/usr/bin/env sh
# Thin wrapper — shared RAM guard lives in NewsCrawler.
# Usage: same env vars as /root/NewsCrawler/scripts/ram-guard.sh
exec /root/NewsCrawler/scripts/ram-guard.sh "$@"
