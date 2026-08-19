"""HTTP clients for public (and keyed) threat intel feeds."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
# v5: forum RSS metadata-only scrub (no dump bodies in collected items).
RSS_PROCESSING_VERSION = 5

RSS_HEADERS = {
    "User-Agent": "BreachSentinelRSS/1.0 (+threat-intel; compatible; RSS aggregator)",
    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
}


def _client(
    *,
    follow_redirects: bool = False,
    via_tor: bool = False,
    cookies: dict[str, str] | None = None,
) -> httpx.Client:
    # Default: do not follow redirects blindly (SSRF via open redirect → private IP).
    proxy = None
    if via_tor:
        if not bool(getattr(settings, "TOR_ENABLED", False)):
            raise httpx.ProxyError("Tor is disabled (TOR_ENABLED=false)")
        proxy = (getattr(settings, "TOR_SOCKS_PROXY", "") or "").strip()
        if not proxy:
            raise httpx.ProxyError("TOR_SOCKS_PROXY is empty")
    return httpx.Client(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=follow_redirects,
        headers=RSS_HEADERS,
        proxy=proxy,
        cookies=cookies or None,
    )


def fetch_cve_recent(limit: int = 30) -> list[dict[str, Any]]:
    """
    Fetch recent CVEs from CIRCL (no API key required).
    https://cve.circl.lu/api/last
    """
    url = "https://cve.circl.lu/api/last"
    with _client() as client:
        response = client.get(url)
        response.raise_for_status()
        data = response.json()
    if not isinstance(data, list):
        return []
    return data[:limit]


def fetch_ransomware_recent(limit: int = 30) -> list[dict[str, Any]]:
    """
    Fetch recent ransomware victims from ransomware.live with ransomlook.io fallback.
    """
    items = _fetch_ransomware_live(limit=limit)
    if items:
        return items
    return _fetch_ransomlook(limit=limit)


def _fetch_ransomware_live(limit: int) -> list[dict[str, Any]]:
    url = "https://api.ransomware.live/v2/recentvictims"
    try:
        with _client() as client:
            response = client.get(url)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as exc:
        logger.warning("ransomware.live feed failed: %s", exc)
        return []

    if isinstance(data, list):
        return data[:limit]
    if isinstance(data, dict):
        for key in ("victims", "data", "results"):
            if isinstance(data.get(key), list):
                return data[key][:limit]
    return []


def _fetch_ransomlook(limit: int) -> list[dict[str, Any]]:
    """Watcher-compatible secondary ransomware source."""
    url = "https://www.ransomlook.io/api/recent"
    try:
        with _client() as client:
            response = client.get(url)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as exc:
        logger.warning("ransomlook.io feed failed: %s", exc)
        return []

    rows: list[dict[str, Any]] = []
    if isinstance(data, list):
        for item in data[:limit]:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "victim": item.get("victim") or item.get("post_title") or item.get("name"),
                    "group": item.get("group") or item.get("group_name"),
                    "discovered": item.get("discovered") or item.get("date"),
                    "website": item.get("website") or item.get("link"),
                    "post_url": item.get("post_url") or item.get("link"),
                    "source": "ransomlook.io",
                }
            )
    return rows


# Default CERT / advisory RSS feeds (fallback when FeedSource table is empty)
DEFAULT_CERT_FEEDS = [
    {
        "name": "cert-fr",
        "url": "https://www.cert.ssi.gouv.fr/feed/",
        "category": "cert",
    },
    {
        "name": "us-cert",
        "url": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "category": "cert",
    },
    {
        "name": "acsc",
        "url": "https://www.cyber.gov.au/rss/news",
        "category": "cert",
    },
    {
        "name": "hibp-breaches",
        "url": "https://haveibeenpwned.com/Feed/TitleAndBreaches",
        "category": "breach",
    },
    {
        "name": "databreaches-net",
        "url": "https://www.databreaches.net/feed/",
        "category": "breach",
    },
]


def _is_terminal_feed_error(error: str) -> bool:
    """Errors that will not recover without a URL change — delete immediately."""
    text = (error or "").lower()
    # DNS failures and resolver outages can recover; retry them normally.
    if any(
        marker in text
        for marker in (
            "dns resolution failed",
            "name or service not known",
            "nodename nor servname",
            "getaddrinfo failed",
        )
    ):
        return False
    markers = (
        "404",
        "410",
        "ssrf_blocked",
    )
    return any(m in text for m in markers)


def _looks_like_rss_or_atom(body: str) -> bool:
    head = (body or "")[:800].lstrip().lower()
    return head.startswith("<?xml") or "<rss" in head or "<feed" in head


def _should_retry_via_tor(exc: BaseException) -> bool:
    """Use Tor for IP/geo blocks, rate limits, and common transport failures."""
    if isinstance(exc, (httpx.TimeoutException, httpx.ConnectError, httpx.ProxyError)):
        return True
    response = getattr(exc, "response", None)
    status_code = getattr(response, "status_code", None)
    if status_code in {403, 429, 451, 502, 503}:
        return True
    text = str(exc).lower()
    return any(
        marker in text
        for marker in (
            "403",
            "429",
            "451",
            "502",
            "503",
            "timed out",
            "timeout",
            "connect",
            "proxy",
        )
    )


def _is_onion_url(url: str) -> bool:
    host = (urlparse(str(url or "")).hostname or "").lower()
    return host.endswith(".onion")


def fetch_feed_body_with_tor_fallback(
    url: str,
    *,
    prefer_tor: bool = False,
    etag: str = "",
    last_modified: str = "",
    cookies: dict[str, str] | None = None,
) -> tuple[str | None, dict[str, Any], bool]:
    """
    Fetch RSS/Atom with Tor optimization for blocked clearnet sources.

    - .onion → Tor only (when enabled)
    - clearnet → preferred path then fallback (clearnet ↔ Tor)
    - HTML/login walls fail that path so the alternate path can run

    Returns (body_or_none, meta, used_tor).
    """
    tor_on = bool(getattr(settings, "TOR_ENABLED", False))
    onion = _is_onion_url(url)

    if onion:
        if not tor_on:
            raise httpx.ProxyError("Onion feed requires TOR_ENABLED=true")
        body, meta = _fetch_rss_body(
            url,
            etag=etag,
            last_modified=last_modified,
            via_tor=True,
            cookies=cookies,
        )
        return body, meta, True

    if prefer_tor and tor_on:
        order = [True, False]
    else:
        order = [False]
        if tor_on:
            order.append(True)

    errors: list[str] = []
    for idx, via_tor in enumerate(order):
        has_next = idx < len(order) - 1
        try:
            body, meta = _fetch_rss_body(
                url,
                etag=etag,
                last_modified=last_modified,
                via_tor=via_tor,
                cookies=cookies,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{'tor' if via_tor else 'direct'}:{exc}")
            if not has_next:
                raise httpx.HTTPError("; ".join(errors[:4])) from exc
            if via_tor is False and not _should_retry_via_tor(exc):
                raise
            continue

        if meta.get("not_modified") or body is None:
            return body, meta, via_tor
        if _looks_like_rss_or_atom(body):
            return body, meta, via_tor
        errors.append(f"{'tor' if via_tor else 'direct'}:non_rss_body")
        if not has_next:
            raise httpx.HTTPError("; ".join(errors[:4]))
        continue

    raise httpx.HTTPError("; ".join(errors[:4]) or "feed_fetch_failed")


def _fetch_rss_body(
    url: str,
    *,
    max_redirects: int | None = None,
    etag: str = "",
    last_modified: str = "",
    via_tor: bool = False,
    cookies: dict[str, str] | None = None,
) -> tuple[str | None, dict[str, Any]]:
    """
    GET feed body with optional conditional headers.

    Returns (body_or_none, meta) where meta includes not_modified, etag,
    last_modified, body_sha256.
    """
    import hashlib
    from urllib.parse import urljoin

    from apps.core.security import validate_fetch_http_url

    if max_redirects is None:
        max_redirects = int(getattr(settings, "FEED_MAX_REDIRECTS", 5) or 5)

    current = validate_fetch_http_url(url, via_tor=via_tor, allow_http=True)
    cond: dict[str, str] = {}
    if etag:
        cond["If-None-Match"] = etag
    if last_modified:
        cond["If-Modified-Since"] = last_modified

    with _client(follow_redirects=False, via_tor=via_tor, cookies=cookies) as client:
        for _ in range(max_redirects + 1):
            response = client.get(current, headers=cond or None)
            if response.status_code == 304:
                return None, {
                    "not_modified": True,
                    "etag": response.headers.get("etag") or etag,
                    "last_modified": response.headers.get("last-modified")
                    or last_modified,
                    "body_sha256": "",
                }
            if response.is_redirect:
                loc = response.headers.get("location")
                if not loc:
                    response.raise_for_status()
                nxt = urljoin(str(response.url), loc)
                current = validate_fetch_http_url(
                    nxt, via_tor=via_tor, allow_http=True
                )
                continue
            response.raise_for_status()
            text = response.text
            digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
            return text, {
                "not_modified": False,
                "etag": response.headers.get("etag") or "",
                "last_modified": response.headers.get("last-modified") or "",
                "body_sha256": digest,
            }
    raise httpx.HTTPError(f"Exceeded {max_redirects} redirects for {url}")


def load_active_rss_feeds() -> list[dict[str, Any]]:
    """Prefer DB FeedSource rows; fall back to DEFAULT_CERT_FEEDS."""
    try:
        from apps.intel.models import FeedSource

        from django.db.models import Case, IntegerField, When

        # Breach/ransomware/CERT first so short beat windows don't starve high-signal feeds.
        category_rank = Case(
            When(category="breach", then=0),
            When(category="ransomware", then=1),
            When(category="cert", then=2),
            default=3,
            output_field=IntegerField(),
        )
        rows = list(
            FeedSource.objects.filter(is_active=True)
            .annotate(_category_rank=category_rank)
            .order_by("_category_rank", "confidence", "name")
            .values(
                "id",
                "name",
                "url",
                "category",
                "confidence",
                "country",
                "country_code",
                "http_etag",
                "http_last_modified",
                "last_body_sha256",
                "processing_version",
                "is_wordpress",
                "wordpress_site_url",
                "requires_tor",
            )
        )
        if rows:
            return rows
    except Exception as exc:  # noqa: BLE001 — migrations / boot edge
        logger.debug("load_active_rss_feeds skipped DB: %s", exc)
    return list(DEFAULT_CERT_FEEDS)


def _mark_feed_status(
    feed: dict[str, Any],
    *,
    status: str,
    item_count: int = 0,
    error: str = "",
    etag: str = "",
    last_modified: str = "",
    body_sha256: str = "",
    processing_version: int | None = None,
    is_wordpress: bool | None = None,
    wordpress_site_url: str | None = None,
) -> None:
    feed_id = feed.get("id")
    if not feed_id:
        return
    try:
        from apps.intel.models import FeedSource

        row = FeedSource.objects.filter(pk=feed_id).first()
        if row is None:
            return

        if status in ("ok", "not_modified"):
            updates: dict[str, Any] = {
                "last_fetched_at": timezone.now(),
                # 304 and identical-body responses are successful checks.
                "last_status": "ok",
                "last_error": "",
                "consecutive_failures": 0,
                "is_active": True,
            }
            if status == "ok":
                updates["last_item_count"] = item_count
            if etag:
                updates["http_etag"] = etag[:255]
            if last_modified:
                updates["http_last_modified"] = last_modified[:128]
            if body_sha256:
                updates["last_body_sha256"] = body_sha256[:64]
            if processing_version is not None:
                updates["processing_version"] = processing_version
            if is_wordpress is not None:
                updates["is_wordpress"] = is_wordpress
            if wordpress_site_url is not None:
                updates["wordpress_site_url"] = wordpress_site_url[:2048]
            FeedSource.objects.filter(pk=feed_id).update(**updates)
            return

        # Soft skip: keep curated feeds when Tor is offline or policy-disabled.
        if status in ("tor_off", "skipped", "disabled"):
            FeedSource.objects.filter(pk=feed_id).update(
                last_fetched_at=timezone.now(),
                last_status=status[:16],
                last_error=(error or "")[:2000],
            )
            return

        failures = int(row.consecutive_failures or 0) + 1
        delete_after = int(getattr(settings, "FEED_DELETE_AFTER_FAILURES", 3) or 3)
        terminal = _is_terminal_feed_error(error)
        # Soft-block SSRF noise on Tor-routed HTTPS feeds (clearnet DNS quirk).
        # Tor-successful feeds reset failures via status=ok and are kept.
        # After delete_after consecutive hard failures (clearnet+Tor), delete anyway.
        if bool(feed.get("requires_tor")) and "ssrf_blocked" in (error or "").lower():
            terminal = False
        if terminal or failures >= delete_after:
            logger.info(
                "Deleting feed source pk=%s after %s failure(s) terminal=%s: %s",
                feed_id,
                failures,
                terminal,
                (error or "")[:120],
            )
            FeedSource.objects.filter(pk=feed_id).delete()
            return

        FeedSource.objects.filter(pk=feed_id).update(
            last_fetched_at=timezone.now(),
            last_status="error",
            last_error=(error or "")[:2000],
            last_item_count=item_count,
            consecutive_failures=failures,
            # Keep transient failures in the sweep until the configured limit.
            is_active=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("feed status update failed: %s", exc)


def fetch_cert_rss_feeds(
    feeds: list[dict[str, Any]] | None = None, limit_per_feed: int = 20
) -> list[dict[str, Any]]:
    """Parse configured RSS/Atom feeds into normalized threat items."""
    import xml.etree.ElementTree as ET

    collected: list[dict[str, Any]] = []
    feed_list = feeds if feeds is not None else load_active_rss_feeds()
    for feed in feed_list:
        name = feed.get("name") or "rss"
        url = feed.get("url") or ""
        category = feed.get("category") or "news"
        processing_version = int(
            getattr(settings, "RSS_PROCESSING_VERSION", RSS_PROCESSING_VERSION)
            or RSS_PROCESSING_VERSION
        )
        cache_is_current = (
            int(feed.get("processing_version") or 0) == processing_version
        )
        if not url:
            continue
        try:
            from apps.workers.feeds.forum_safety import feed_name_is_direct_forum

            if feed_name_is_direct_forum(name):
                logger.info("RSS feed %s skipped (direct forum scrape disabled)", name)
                _mark_feed_status(
                    feed,
                    status="disabled",
                    error="direct_forum_feed_disabled — use clearnet claim/status sources",
                )
                continue
        except Exception:  # noqa: BLE001
            pass
        prefer_tor = bool(feed.get("requires_tor")) and bool(
            getattr(settings, "TOR_ENABLED", False)
        )
        # Clearnet HTTPS always allowed to attempt (even if requires_tor was set historically).
        # Onion-only skip when Tor is off is handled inside fetch_feed_body_with_tor_fallback.
        if _is_onion_url(url) and not bool(getattr(settings, "TOR_ENABLED", False)):
            logger.info("RSS feed %s skipped (onion requires Tor)", name)
            _mark_feed_status(
                feed,
                status="tor_off",
                error="Onion feed requires TOR_ENABLED=true",
            )
            continue
        try:
            from apps.core.security import UnsafeURLError, validate_fetch_http_url

            validate_fetch_http_url(
                url,
                via_tor=prefer_tor or _is_onion_url(url),
                allow_http=True,
            )
        except UnsafeURLError as exc:
            # If Tor-prefer validation fails but clearnet might work, allow clearnet attempt.
            if prefer_tor and not _is_onion_url(url):
                try:
                    validate_fetch_http_url(url, via_tor=False, allow_http=True)
                except UnsafeURLError as exc2:
                    logger.warning("RSS feed %s blocked (SSRF policy): %s", name, exc2)
                    _mark_feed_status(feed, status="error", error=f"ssrf_blocked:{exc2}")
                    continue
            else:
                logger.warning("RSS feed %s blocked (SSRF policy): %s", name, exc)
                _mark_feed_status(feed, status="error", error=f"ssrf_blocked:{exc}")
                continue
        request_etag = str(feed.get("http_etag") or "") if cache_is_current else ""
        request_last_modified = (
            str(feed.get("http_last_modified") or "") if cache_is_current else ""
        )
        try:
            raw, meta, used_tor = fetch_feed_body_with_tor_fallback(
                url,
                prefer_tor=prefer_tor,
                etag=request_etag,
                last_modified=request_last_modified,
            )
        except httpx.HTTPError as exc:
            logger.warning("RSS feed %s failed: %s", name, exc)
            _mark_feed_status(feed, status="error", error=str(exc)[:500])
            continue
        except Exception as exc:  # noqa: BLE001
            from apps.core.security import UnsafeURLError

            if isinstance(exc, UnsafeURLError):
                logger.warning("RSS feed %s redirect blocked: %s", name, exc)
                _mark_feed_status(feed, status="error", error=f"ssrf_blocked:{exc}")
                continue
            raise

        via_tor = used_tor
        if used_tor and not bool(feed.get("requires_tor")):
            from apps.intel.models import FeedSource

            feed["requires_tor"] = True
            FeedSource.objects.filter(pk=feed.get("id")).update(requires_tor=True)
            logger.info("RSS feed %s recovered via Tor; route persisted", name)
        elif (not used_tor) and bool(feed.get("requires_tor")) and not _is_onion_url(url):
            # Clearnet works — clear sticky Tor preference for HTTPS sources.
            from apps.intel.models import FeedSource

            feed["requires_tor"] = False
            FeedSource.objects.filter(pk=feed.get("id")).update(requires_tor=False)

        if meta.get("not_modified") or raw is None:
            _mark_feed_status(
                feed,
                status="not_modified",
                etag=str(meta.get("etag") or ""),
                last_modified=str(meta.get("last_modified") or ""),
                processing_version=processing_version,
            )
            continue

        body_hash = str(meta.get("body_sha256") or "")
        prev_hash = (
            str(feed.get("last_body_sha256") or "") if cache_is_current else ""
        )
        if body_hash and prev_hash and body_hash == prev_hash:
            _mark_feed_status(
                feed,
                status="not_modified",
                etag=str(meta.get("etag") or ""),
                last_modified=str(meta.get("last_modified") or ""),
                body_sha256=body_hash,
                processing_version=processing_version,
            )
            continue

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            logger.warning("RSS feed %s XML parse error: %s", name, exc)
            _mark_feed_status(feed, status="error", error=str(exc))
            continue

        ns = {"atom": "http://www.w3.org/2005/Atom"}
        is_wordpress = any(
            child.tag.endswith("generator")
            and "wordpress" in (child.text or "").casefold()
            for child in root.iter()
        )
        wordpress_site_url = ""
        if is_wordpress:
            site_link = (root.findtext(".//channel/link") or "").strip()
            parsed_site = urlparse(site_link)
            if parsed_site.scheme in {"http", "https"} and parsed_site.hostname:
                wordpress_site_url = site_link
        items = root.findall(".//item")
        if not items:
            items = root.findall(".//atom:entry", ns)

        feed_count = 0
        for node in items[:limit_per_feed]:
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
            if title:
                from apps.workers.feeds.forum_safety import prepare_wire_item_for_safety

                row = {
                    "title": title,
                    "link": link,
                    "summary": summary,
                    "published": published,
                    "feed": name,
                    "feed_url": url,
                    "category": category,
                    "country": feed.get("country") or "",
                    "country_code": feed.get("country_code") or "",
                    "feed_confidence": feed.get("confidence"),
                    "feed_notes": feed.get("notes") or "",
                    "requires_tor": via_tor,
                }
                safe = prepare_wire_item_for_safety(row)
                if safe is None:
                    continue
                collected.append(safe)
                feed_count += 1
        _mark_feed_status(
            feed,
            status="ok",
            item_count=feed_count,
            etag=str(meta.get("etag") or ""),
            last_modified=str(meta.get("last_modified") or ""),
            body_sha256=body_hash,
            processing_version=processing_version,
            is_wordpress=is_wordpress,
            wordpress_site_url=wordpress_site_url,
        )
    return collected


def fetch_hudson_rock_search(domain: str) -> dict[str, Any]:
    """Optional keyed lookup — returns empty dict when key missing."""
    api_key = getattr(settings, "HUDSON_ROCK_API_KEY", "") or ""
    if not api_key or not domain:
        return {}
    # Placeholder URL shape; real integration refined in Phase 6.
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
    try:
        with _client() as client:
            response = client.get(
                url,
                params={"domain": domain},
                headers={"api-key": api_key},
            )
            if response.status_code >= 400:
                logger.warning("Hudson Rock HTTP %s", response.status_code)
                return {}
            return response.json()
    except httpx.HTTPError as exc:
        logger.warning("Hudson Rock feed failed: %s", exc)
        return {}
