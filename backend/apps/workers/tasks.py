from __future__ import annotations

import logging

from celery import shared_task

from apps.workers.feeds.clients import (
    fetch_cert_rss_feeds,
    fetch_cve_recent,
    fetch_ransomware_recent,
)
from apps.workers.feeds.wordpress import fetch_wordpress_vietnam_backfill
from apps.workers.services import (
    ingest_cve_items,
    ingest_ransomware_items,
    ingest_rss_items,
    ingest_stealer_content,
)

logger = logging.getLogger(__name__)


@shared_task(bind=True, name="workers.parse_stealer_log", max_retries=2)
def parse_stealer_log_task(
    self,
    content: str,
    leak_id: int | None = None,
    stealer_family: str | None = None,
    create_leak: bool = False,
    leak_title: str = "Stealer log ingest",
) -> dict:
    """Parse stealer dump text and persist compromised credentials."""
    try:
        return ingest_stealer_content(
            leak_id=leak_id,
            content=content,
            stealer_family=stealer_family,
            create_leak=create_leak,
            leak_title=leak_title,
        )
    except Exception as exc:  # noqa: BLE001 — Celery retry boundary
        logger.exception("parse_stealer_log_task failed")
        raise self.retry(exc=exc, countdown=30)


@shared_task(bind=True, name="workers.ingest_cve_feed", max_retries=3)
def ingest_cve_feed(self, limit: int = 30) -> dict:
    try:
        items = fetch_cve_recent(limit=limit)
        stats = ingest_cve_items(items)
        stats["fetched"] = len(items)
        return stats
    except Exception as exc:  # noqa: BLE001
        logger.exception("ingest_cve_feed failed")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, name="workers.ingest_ransomware_feed", max_retries=3)
def ingest_ransomware_feed(self, limit: int = 30) -> dict:
    try:
        items = fetch_ransomware_recent(limit=limit)
        stats = ingest_ransomware_items(items)
        stats["fetched"] = len(items)
        return stats
    except Exception as exc:  # noqa: BLE001
        logger.exception("ingest_ransomware_feed failed")
        raise self.retry(exc=exc, countdown=60)


@shared_task(bind=True, name="workers.ingest_cert_rss", max_retries=3)
def ingest_cert_rss(self, limit_per_feed: int = 15) -> dict:
    """Ingest all active RSS FeedSource rows (CERT, breach, news, …)."""
    from apps.core.task_lock import single_flight

    # Skip overlapping sweeps: one full catalog pass can exceed the beat interval.
    with single_flight("workers.ingest_cert_rss", ttl_sec=900) as acquired:
        if not acquired:
            return {"skipped": True, "reason": "already_running"}
        try:
            rss_items = fetch_cert_rss_feeds(limit_per_feed=limit_per_feed)
            backfill_items = fetch_wordpress_vietnam_backfill()
            items = rss_items + backfill_items
            stats = ingest_rss_items(items, source_label="rss")
            stats["fetched"] = len(items)
            stats["rss_fetched"] = len(rss_items)
            stats["vietnam_backfill_fetched"] = len(backfill_items)
            stats["feeds"] = len({i.get("feed") for i in items if i.get("feed")})
            return stats
        except Exception as exc:  # noqa: BLE001
            logger.exception("ingest_cert_rss failed")
            raise self.retry(exc=exc, countdown=60)



@shared_task(bind=True, name="workers.ingest_forum_claims", max_retries=2)
def ingest_forum_claims(self, limit_per_feed: int = 25) -> dict:
    """Clearnet claim/dark-web news + forum-status → Wire (no forum login/cookies)."""
    from apps.core.task_lock import single_flight
    from apps.workers.feeds.forum_enrich import enrich_forum_items
    from apps.workers.feeds.forum_fetch import fetch_forum_claim_items

    with single_flight("workers.ingest_forum_claims", ttl_sec=1200) as acquired:
        if not acquired:
            return {"skipped": True, "reason": "already_running"}
        try:
            items, meta = fetch_forum_claim_items(limit_per_feed=limit_per_feed)
            if meta.get("skipped"):
                return {**meta, "created": 0}
            items = enrich_forum_items(items)
            stats = ingest_rss_items(items, source_label="claim-news")
            return {**stats, **meta, "fetched": len(items)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("ingest_forum_claims failed")
            raise self.retry(exc=exc, countdown=180) from exc


@shared_task(bind=True, name="workers.ingest_zoneh_archive", max_retries=2)
def ingest_zoneh_archive(self, pages: int = 2) -> dict:
    """Zone-H-style defacement archive (haxor.id bypass or cookie zone-h.org) → Wire."""
    from apps.core.task_lock import single_flight
    from apps.workers.feeds.zoneh import fetch_zoneh_archive_items, zoneh_enabled

    if not zoneh_enabled():
        return {"skipped": True, "reason": "zoneh_disabled"}
    with single_flight("workers.ingest_zoneh_archive", ttl_sec=600) as acquired:
        if not acquired:
            return {"skipped": True, "reason": "already_running"}
        try:
            items, meta = fetch_zoneh_archive_items(pages=pages)
            if meta.get("skipped"):
                return {**meta, "created": 0}
            stats = ingest_rss_items(items, source_label=str(meta.get("provider") or "zoneh"))
            return {**stats, **meta, "fetched": len(items)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("ingest_zoneh_archive failed")
            raise self.retry(exc=exc, countdown=120) from exc


@shared_task(bind=True, name="workers.wire_housekeeping", max_retries=1)
def wire_housekeeping_task(self, reset_feed_cache: bool = False) -> dict:
    """
    Daily safe retention: purge Wire items past age windows + cleanup generic tags.
    Does not touch Postgres volumes, Redis broker, or Docker images.
    """
    from apps.core.task_lock import single_flight
    from apps.workers.housekeeping import run_wire_housekeeping

    with single_flight("workers.wire_housekeeping", ttl_sec=3600) as acquired:
        if not acquired:
            return {"skipped": True, "reason": "already_running"}
        try:
            return run_wire_housekeeping(reset_feed_cache=bool(reset_feed_cache))
        except Exception as exc:  # noqa: BLE001
            logger.exception("wire_housekeeping failed")
            raise self.retry(exc=exc, countdown=300) from exc


@shared_task(bind=True, name="workers.run_log_scan", max_retries=1)
def run_log_scan_task(self, scan_id: int) -> dict:
    """Keyword-scan uploaded credential dumps for a LogScan row."""
    from apps.workers.log_scanner import run_log_scan

    try:
        return run_log_scan(scan_id)
    except Exception as exc:  # noqa: BLE001
        logger.exception("run_log_scan_task failed scan_id=%s", scan_id)
        raise self.retry(exc=exc, countdown=15) from exc


@shared_task(name="workers.ingest_all_feeds")
def ingest_all_feeds(limit: int = 30) -> dict:
    """Fan-out helper used by beat and manual API triggers."""
    cve = ingest_cve_feed.delay(limit=limit)
    ran = ingest_ransomware_feed.delay(limit=limit)
    cert = ingest_cert_rss.delay(limit_per_feed=max(5, limit // 2))
    zoneh = ingest_zoneh_archive.delay(pages=2)
    return {
        "cve_task_id": cve.id,
        "ransomware_task_id": ran.id,
        "cert_task_id": cert.id,
        "zoneh_task_id": zoneh.id,
    }
