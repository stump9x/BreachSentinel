"""Zone-H / defacement archive → The Wire.

## Why not Selenium + 2captcha?

[BAUZACE7/Zone-H](https://github.com/BAUZACE7/Zone-H) scrapes zone-h.org with
Chrome + 2captcha. That is heavy for Docker and costs captcha credits.

BreachSentinel instead:

1. **Default:** crawl **haxor.id/archive** (Zone-H-style table, no captcha from
   typical cloud IPs) on a Celery beat every 15 minutes.
2. **Optional:** crawl **zone-h.org** when you paste session cookies after a
   one-time browser captcha (same cookie idea as Mizper / zone-H-checker).

## Config (`.env`)

```env
ZONEH_ENABLED=true
ZONEH_PROVIDER=haxor
ZONEH_PAGES=2
ZONEH_INCLUDE_SPECIAL=true
```

Official Zone-H (after solving captcha in browser → Cookie-Editor):

```env
ZONEH_PROVIDER=zoneh
ZONEH_PHPSESSID=paste_phpsessid
ZONEH_ZHE=paste_zhe
```

Then recreate workers:

```bat
docker compose up -d --force-recreate backend celery
```

## Task

- Celery: `workers.ingest_zoneh_archive`
- Beat: every 15 minutes (`pages=2`)
- Ingest: `ingest_rss_items` with `category=breach` → The Wire

Manual run:

```bat
docker compose exec -T backend python manage.py shell -c "from apps.workers.tasks import ingest_zoneh_archive; print(ingest_zoneh_archive())"
```
"""
