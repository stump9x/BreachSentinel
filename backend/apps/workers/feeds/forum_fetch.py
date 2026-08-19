"""Fetch clearnet claim/dark-web news RSS for The Wire (no forum login)."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Any

from apps.workers.feeds.forum_safety import (
    CLAIM_NEWS_FEED_NAMES,
    prepare_wire_item_for_safety,
)

logger = logging.getLogger(__name__)


def _looks_like_xml_feed(body: str) -> bool:
    head = (body or "")[:800].lstrip().lower()
    return head.startswith("<?xml") or "<rss" in head or "<feed" in head


def fetch_forum_claim_items(*, limit_per_feed: int = 25) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Pull metadata-only items from curated clearnet claim feeds.

    No Tor forum boards, no session cookies, no VNC, no deepdarkCTI/darc.
    Failures use the shared feed lifecycle (delete after FEED_DELETE_AFTER_FAILURES).
    Tor-successful fetches stay active and reset the failure counter.
    """
    from apps.intel.models import FeedSource
    from apps.workers.feeds.clients import (
        _mark_feed_status,
        fetch_feed_body_with_tor_fallback,
    )

    limit_n = max(1, min(int(limit_per_feed or 25), 50))
    qs = FeedSource.objects.filter(
        is_active=True,
        name__in=sorted(CLAIM_NEWS_FEED_NAMES),
    )
    items: list[dict[str, Any]] = []
    per_feed: dict[str, Any] = {}
    errors: list[str] = []

    for feed in qs:
        name = feed.name
        url = feed.url
        prefer_tor = bool(feed.requires_tor)
        feed_ref = {"id": feed.pk, "requires_tor": prefer_tor}
        try:
            body, meta, used_tor = fetch_feed_body_with_tor_fallback(
                url,
                prefer_tor=prefer_tor,
            )
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)[:160]
            errors.append(f"{name}: {msg}")
            per_feed[name] = {"status": "error", "error": msg, "items": 0}
            _mark_feed_status(feed_ref, status="error", error=msg)
            continue

        if body is None and meta.get("not_modified"):
            per_feed[name] = {"status": "not_modified", "items": 0}
            _mark_feed_status(feed_ref, status="not_modified")
            continue
        if not body:
            hint = "empty_body"
            errors.append(f"{name}: {hint}")
            per_feed[name] = {"status": "error", "error": hint, "items": 0}
            _mark_feed_status(feed_ref, status="error", error=hint)
            continue
        if not _looks_like_xml_feed(body):
            hint = "non_rss_body"
            errors.append(f"{name}: {hint}")
            per_feed[name] = {"status": "error", "error": hint, "items": 0}
            _mark_feed_status(feed_ref, status="error", error=hint)
            continue

        batch = _parse_rss_metadata(
            body,
            feed_name=name,
            feed_url=url,
            category=feed.category or "breach",
            country=feed.country or "",
            country_code=feed.country_code or "",
            limit=limit_n,
            notes=feed.notes or "claim/dark-web news",
        )
        per_feed[name] = {
            "status": "ok",
            "items": len(batch),
            "via_tor": used_tor,
        }
        _mark_feed_status(feed_ref, status="ok", item_count=len(batch))
        # Persist Tor route when clearnet is blocked but Tor works.
        if used_tor and not feed.requires_tor:
            FeedSource.objects.filter(pk=feed.pk).update(requires_tor=True)
        elif (not used_tor) and feed.requires_tor:
            FeedSource.objects.filter(pk=feed.pk).update(requires_tor=False)
        items.extend(batch)

    return items, {
        "skipped": False,
        "fetched": len(items),
        "feeds": per_feed,
        "errors": errors[:12],
    }


def _parse_rss_metadata(
    raw: str,
    *,
    feed_name: str,
    feed_url: str,
    category: str,
    country: str,
    country_code: str,
    limit: int,
    notes: str,
) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    nodes = root.findall(".//item") or root.findall(".//atom:entry", ns)
    out: list[dict[str, Any]] = []

    for node in nodes[:limit]:
        def _text(paths: list[str]) -> str:
            for p in paths:
                el = node.find(p)
                if el is None:
                    el = node.find(p, ns)
                if el is not None and (el.text or "").strip():
                    return (el.text or "").strip()
                if el is not None and el.get("href"):
                    return el.get("href", "")
            return ""

        title = _text(["title", "atom:title"])
        link = _text(["link", "atom:link"])
        if not link:
            link_el = node.find("link") or node.find("atom:link", ns)
            if link_el is not None:
                link = link_el.get("href") or (link_el.text or "")
        summary = _text(
            ["description", "summary", "atom:summary", "content", "atom:content"]
        )
        published = _text(
            ["pubDate", "published", "atom:published", "updated", "atom:updated"]
        )
        if not title:
            continue
        row = {
            "title": title,
            "link": link,
            "summary": summary,
            "published": published,
            "feed": feed_name,
            "feed_url": feed_url,
            "category": category or "breach",
            "country": country,
            "country_code": country_code,
            "feed_notes": notes or "claim/dark-web news",
            "discovery": "claim-news",
            "metadata_only": True,
        }
        safe = prepare_wire_item_for_safety(row)
        if safe:
            out.append(safe)
    return out
