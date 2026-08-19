# Watcher parity notes — what BreachSentinel has vs still deferred

## Delivered (Watcher-aligned)

| Watcher capability | BreachSentinel status |
|---|---|
| Keyword Watch Rules + alerts | ✅ `/api/v1/watch-rules/`, UI **Watch Rules** |
| Multi-source RSS + live Wire | ✅ FeedSource + 5‑min beat + auto-refresh UI |
| Full Watcher `sources.csv` (~220) | ✅ `seed_rss_sources --watcher-csv` + `rss_sources.json` (~228 incl. CERT/breach extras) |
| Auto-disable dead feeds | ✅ `last_status=error` → `is_active=False` |
| **SearxNG metasearch leak hunting** | ✅ Docker `searxng`, client, Celery 5‑min sweep, APIs, OSINT/Leaks/Workers UI |
| CVE + ransomware feeds | ✅ |
| AI briefing / weekly digest | ✅ |
| MISP | ✅ (env required) |
| Stealer parsing + Go OSINT | ✅ |

### SearxNG usage (ops)

```bash
# .env
SEARXNG_URL=http://searxng:8080
SEARXNG_ENGINES=github,gitlab,bitbucket,npm,stackoverflow

docker compose up -d searxng
# Host UI (optional): http://localhost:8888

# Create a Watch Rule with target=searx (or leaks), then:
# POST /api/v1/searx/scan/  or wait for beat every 5 minutes
# Ad-hoc OSINT: POST /api/v1/searx/search/  (UI: OSINT Scan page)

# Re-import full Watcher RSS catalog (preserves auto-disabled feeds):
docker compose exec backend python manage.py seed_rss_sources --watcher-csv
```

Security notes: Searx base URL is **env-only** (not request-controlled); engines allowlisted; query/result size capped.

## Still deferred

| Capability | Notes |
|---|---|
| Pastebin Pro scrape API | Needs paid Pastebin + IP allowlist (Watcher optional path) |
| dnstwist / certstream / TLSH | Separate modules |
| TheHive / SSO / Slack | Next integration slices |

Reference: [Watcher docs](https://thalesgroup-cert.github.io/Watcher/) · [SearxNG](https://github.com/searxng/searxng)
