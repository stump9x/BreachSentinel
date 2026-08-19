# Claim / dark-web news → The Wire

Defensive CTI pipeline for **alleged claims** from clearnet secondary sources.
No underground-forum login, no cookies/VNC, no deepdarkCTI/darc, no samples.

## Collection

| Layer | What | How |
|-------|------|-----|
| Claim / dark-web news | Headlines about breaches, ransomware, forum claims | Curated clearnet RSS (`CLAIM_NEWS_FEED_NAMES`) |
| Ransomware victims | Public victim claims | ransomware.live API |
| Safety gate | Reject dumps + direct forum permalinks | `forum_safety.py` |

## Hard rules

1. Store **title + clearnet link + safe blurb** only.
2. Drop dump hosts, archive extensions, credential blocks.
3. Reject primary URLs on known underground forum hosts.
4. Tags: `forum` + `alleged-claim` when article mentions forums; else `alleged-claim` for claim-news tier.

## Ops

```bat
docker compose exec backend python manage.py seed_rss_sources
docker compose up -d --force-recreate celery celery-beat backend
```

Beat: `workers.ingest_forum_claims` every 30 minutes (claim RSS only).

## Code

- `forum_fetch.py` — claim RSS
- `prepare_wire_item_for_safety` — scrub / reject
