"""Targeted WordPress sitemap backfill for Vietnam-related Wire items."""

from __future__ import annotations

import html
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from urllib.parse import unquote, urlparse

import httpx
from django.conf import settings
from django.utils import timezone

from apps.intel.models import FeedSource
from apps.workers.feed_dates import parse_feed_datetime
from apps.workers.feeds.clients import _fetch_rss_body
from apps.workers.services import is_vietnam_related

logger = logging.getLogger(__name__)

MAX_SITEMAP_SHARDS = 100
MAX_BACKFILL_ITEMS = 250


def _normalized_host(url: str) -> str:
    host = (urlparse(url).hostname or "").lower().rstrip(".")
    return host.removeprefix("www.")


def _is_same_allowed_host(url: str, expected_host: str) -> bool:
    parsed = urlparse(url)
    # Exact HTTPS host matching prevents sitemap-controlled cross-host requests.
    # The actual request is additionally checked by _fetch_rss_body's SSRF guard.
    return parsed.scheme == "https" and _normalized_host(url) == expected_host


def _fetch_public_text(url: str) -> str:
    """Fetch a validated public HTTPS document with the RSS redirect policy."""
    body, _meta = _fetch_rss_body(url)
    return body or ""


def _child_text(node: ET.Element, suffix: str) -> str:
    for child in node:
        if child.tag.endswith(suffix):
            return (child.text or "").strip()
    return ""


def _slug_title(url: str) -> str:
    slug = unquote(urlparse(url).path.strip("/").split("/")[-1])
    words = re.sub(r"[-_]+", " ", slug)
    return html.unescape(re.sub(r"\s+", " ", words).strip()).title()


def _parse_sitemap(xml_text: str) -> list[tuple[str, datetime | None]]:
    root = ET.fromstring(xml_text)
    rows: list[tuple[str, datetime | None]] = []
    for node in root:
        loc = _child_text(node, "loc")
        if not loc:
            continue
        rows.append(
            (
                _child_text(node, "loc"),
                parse_feed_datetime(_child_text(node, "lastmod")),
            )
        )
    return rows


def _eligible_feeds(now: datetime) -> list[FeedSource]:
    interval = int(
        getattr(settings, "WIRE_WORDPRESS_BACKFILL_INTERVAL_MINUTES", 360) or 360
    )
    due_before = now - timedelta(minutes=max(5, interval))
    source_limit = max(
        1, int(getattr(settings, "WIRE_WORDPRESS_SOURCES_PER_SWEEP", 3) or 3)
    )
    feeds: list[FeedSource] = []
    fields = (
        "id",
        "name",
        "url",
        "category",
        "confidence",
        "country",
        "country_code",
        "wordpress_site_url",
        "sitemap_last_scanned_at",
    )
    queryset = (
        FeedSource.objects.filter(is_active=True, is_wordpress=True)
        .only(*fields)
        .order_by("sitemap_last_scanned_at", "id")
    )
    for feed in queryset:
        if feed.sitemap_last_scanned_at and feed.sitemap_last_scanned_at > due_before:
            continue
        feeds.append(feed)
        if len(feeds) >= source_limit:
            break
    return feeds


def fetch_wordpress_vietnam_backfill(
    *, now: datetime | None = None
) -> list[dict[str, str | int]]:
    """
    Discover Vietnam-related posts that have fallen out of short rolling RSS feeds.

    Post sitemaps are expected newest-first. Scanning stops as soon as a whole
    shard is older than the 30-day window, then a persisted watermark suppresses
    repeated scans until the configured recovery interval.
    """
    current = now or timezone.now()
    max_age_days = int(
        getattr(settings, "WIRE_VIETNAM_MAX_AGE_DAYS", 30) or 30
    )
    cutoff = current - timedelta(days=max_age_days)
    collected: list[dict[str, str | int]] = []
    seen_urls: set[str] = set()

    for feed in _eligible_feeds(current):
        host = _normalized_host(feed.wordpress_site_url or feed.url)
        index_url = f"https://{host}/wp-sitemap.xml"
        try:
            index_rows = _parse_sitemap(_fetch_public_text(index_url))
            shards = [
                url
                for url, _modified in index_rows
                if (
                    "post-sitemap" in urlparse(url).path
                    or "wp-sitemap-posts-post" in urlparse(url).path
                )
                and _is_same_allowed_host(url, host)
            ][:MAX_SITEMAP_SHARDS]

            for shard_url in shards:
                if len(collected) >= MAX_BACKFILL_ITEMS:
                    break
                shard_rows = _parse_sitemap(_fetch_public_text(shard_url))
                for article_url, modified in shard_rows:
                    if len(collected) >= MAX_BACKFILL_ITEMS:
                        break
                    if (
                        not modified
                        or modified < cutoff
                        or not _is_same_allowed_host(article_url, host)
                        or article_url in seen_urls
                    ):
                        continue
                    title = _slug_title(article_url)
                    if not is_vietnam_related(title, article_url):
                        continue
                    seen_urls.add(article_url)
                    collected.append(
                        {
                            "title": title,
                            "link": article_url,
                            "summary": "",
                            "published": modified.isoformat(),
                            "feed": feed.name,
                            "feed_url": feed.wordpress_site_url or feed.url,
                            "category": feed.category,
                            "country": "Vietnam",
                            "country_code": "VN",
                            "feed_confidence": feed.confidence,
                            "discovery": "wordpress-sitemap",
                        }
                    )
                dated_rows = [modified for _url, modified in shard_rows if modified]
                if dated_rows and max(dated_rows) < cutoff:
                    break

            FeedSource.objects.filter(pk=feed.pk).update(
                sitemap_last_scanned_at=current
            )
        except (ET.ParseError, ValueError, OSError, httpx.HTTPError) as exc:
            logger.warning("WordPress sitemap backfill failed for %s: %s", host, exc)
            # Throttle unsupported/broken WordPress sitemap endpoints too.
            FeedSource.objects.filter(pk=feed.pk).update(
                sitemap_last_scanned_at=current
            )

    return collected
