"""Zone-H / defacement archive → Wire RSS-shaped items.

Zone-h.org itself is captcha-walled from datacenter IPs (see BAUZACE7/Zone-H
Selenium+2captcha approach). BreachSentinel prefers accessible mirrors that
expose the same archive style without a browser:

  - haxor.id/archive (+ /special) — works without cookies from cloud IPs
  - zone-h.org/archive — optional when ZONEH_PHPSESSID + ZONEH_ZHE are set

Items are ingested via ingest_rss_items (category=defacement) into The Wire.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin

import httpx
from django.conf import settings
from django.utils.dateparse import parse_datetime

from apps.workers.geography import infer_country_from_domain, infer_country_from_flag_html

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30.0
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)
_TAG_RE = re.compile(r"<[^>]+>")
_MIRROR_RE = re.compile(r'href=["\']([^"\']*mirror/\d+)["\']', re.I)
_TR_RE = re.compile(r"<tr[^>]*>(.*?)</tr>", re.I | re.S)
_TD_RE = re.compile(r"<td[^>]*>(.*?)</td>", re.I | re.S)
_ATTACKER_RE = re.compile(
    r'href=["\'][^"\']*attacker/[^"\']*["\'][^>]*>(.*?)</', re.I | re.S
)


def zoneh_enabled() -> bool:
    return bool(getattr(settings, "ZONEH_ENABLED", True))


def _strip_tags(value: str) -> str:
    text = _TAG_RE.sub(" ", value or "")
    return " ".join(text.replace("&nbsp;", " ").split()).strip()


def _provider() -> str:
    raw = str(getattr(settings, "ZONEH_PROVIDER", "haxor") or "haxor").strip().lower()
    if raw in {"haxor", "haxor.id", "mirror"}:
        return "haxor"
    if raw in {"zoneh", "zone-h", "zone-h.org"}:
        return "zoneh"
    return "haxor"


def _base_url() -> str:
    custom = (getattr(settings, "ZONEH_BASE_URL", "") or "").strip().rstrip("/")
    if custom:
        return custom
    if _provider() == "zoneh":
        return "https://www.zone-h.org"
    return "https://haxor.id"


def _cookies() -> dict[str, str]:
    cookies: dict[str, str] = {}
    phpsessid = (getattr(settings, "ZONEH_PHPSESSID", "") or "").strip()
    zhe = (getattr(settings, "ZONEH_ZHE", "") or "").strip()
    if phpsessid:
        cookies["PHPSESSID"] = phpsessid
    if zhe:
        cookies["ZHE"] = zhe
    return cookies


def _archive_paths() -> list[str]:
    """Relative archive paths to crawl (latest pages)."""
    special = bool(getattr(settings, "ZONEH_INCLUDE_SPECIAL", True))
    paths = ["/archive"]
    if special:
        paths.append("/archive/special")
    # zone-h style special flag
    if _provider() == "zoneh":
        paths = ["/archive/published=0"]
        if special:
            paths.append("/archive/special=1")
    return paths


def _parse_published(raw: str) -> datetime | None:
    text = (raw or "").strip()
    if not text:
        return None
    # haxor: 2026-07-20 09:12:18
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M"):
        try:
            dt = datetime.strptime(text[:19], fmt).replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    dt = parse_datetime(text.replace(" ", "T"))
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def parse_defacement_archive_html(
    html: str, *, base_url: str, source_label: str
) -> list[dict[str, Any]]:
    """
    Parse Zone-H-style / HaxorID archive tables into Wire RSS-shaped dicts.
    """
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for tr in _TR_RE.finditer(html or ""):
        inner = tr.group(1)
        if re.search(r"<th\b", inner, re.I):
            continue
        tds = _TD_RE.findall(inner)
        if len(tds) < 3:
            continue
        mirror_m = _MIRROR_RE.search(inner)
        if not mirror_m:
            continue
        mirror_path = mirror_m.group(1).strip()
        mirror_url = urljoin(base_url + "/", mirror_path.lstrip("/"))
        if mirror_url in seen:
            continue

        published_raw = _strip_tags(tds[0])
        attacker_m = _ATTACKER_RE.search(inner)
        attacker = _strip_tags(attacker_m.group(1) if attacker_m else "")
        if not attacker and len(tds) > 1:
            attacker = _strip_tags(tds[1])

        # Haxor columns: Date, Attacker, Team, H, M, R, L, S, URL, Os, Mirror
        # Zone-H layouts vary; pick the longest domain-like cell.
        domain = ""
        for cell in tds:
            text = _strip_tags(cell)
            if "." in text and " " not in text and len(text) < 256:
                if text.count(".") >= 1 and not text.startswith("http"):
                    domain = text
                    break
                if text.startswith("http"):
                    domain = text
                    break
        if not domain and len(tds) >= 9:
            domain = _strip_tags(tds[8])

        published = _parse_published(published_raw)
        country_code, country = infer_country_from_flag_html(inner)
        if not country_code:
            country_code, country = infer_country_from_domain(domain)
        title_host = domain or mirror_path
        title = f"Defacement: {title_host}"
        if attacker:
            title = f"Defacement by {attacker}: {title_host}"

        summary_parts = [
            "Zone-H-style defacement archive hit.",
            f"Attacker: {attacker}" if attacker else "",
            f"Target: {domain}" if domain else "",
            f"Country: {country}" if country else "",
            f"Mirror: {mirror_url}",
        ]
        summary = "\n".join(p for p in summary_parts if p)

        seen.add(mirror_url)
        items.append(
            {
                "title": title[:512],
                "link": mirror_url[:2048],
                "summary": summary[:5000],
                "published": published.isoformat() if published else "",
                "feed": source_label,
                "feed_url": urljoin(base_url + "/", "archive"),
                "category": "defacement",
                "discovery": "zoneh-archive",
                "attacker": attacker[:128],
                "defaced_url": domain[:512],
                "country_code": country_code[:8],
                "country": country[:64],
            }
        )
    return items


def _fetch_html(client: httpx.Client, url: str) -> tuple[str, str | None]:
    """Return (html, error)."""
    try:
        response = client.get(url, cookies=_cookies() or None)
        if response.status_code in {401, 403}:
            return "", f"HTTP {response.status_code}"
        # Zone-H bot wall often returns tiny redirect body.
        if "zone-h.org" in url and len(response.text) < 2000:
            if "captcha" in response.text.lower() or "?hz=" in response.text:
                return "", "captcha_or_bot_wall — set ZONEH_PHPSESSID + ZONEH_ZHE or use ZONEH_PROVIDER=haxor"
        response.raise_for_status()
        return response.text, None
    except httpx.HTTPError as exc:
        return "", str(exc)[:160]


def fetch_zoneh_archive_items(
    *,
    pages: int | None = None,
    now=None,  # noqa: ARG001 — reserved for age filters
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Fetch latest defacement archive pages and return Wire-ready items + meta.
    """
    if not zoneh_enabled():
        return [], {"skipped": True, "reason": "zoneh_disabled", "fetched": 0}

    pages_n = max(1, min(int(pages if pages is not None else getattr(settings, "ZONEH_PAGES", 2) or 2), 10))
    base = _base_url()
    provider = _provider()
    source_label = f"zoneh:{provider}"
    timeout = float(getattr(settings, "ZONEH_TIMEOUT", _DEFAULT_TIMEOUT) or _DEFAULT_TIMEOUT)

    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    errors: list[str] = []
    pages_ok = 0

    headers = {
        "User-Agent": _UA,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers) as client:
            for path in _archive_paths():
                for page in range(1, pages_n + 1):
                    if provider == "haxor":
                        url = f"{base}{path}" if page == 1 else f"{base}{path}?page={page}"
                    else:
                        # Zone-H pagination: /archive/published=0/page=N
                        url = f"{base}{path}" if page == 1 else f"{base}{path}/page={page}"
                    html, err = _fetch_html(client, url)
                    if err:
                        errors.append(f"{url}: {err}")
                        continue
                    if not html:
                        continue
                    batch = parse_defacement_archive_html(
                        html, base_url=base, source_label=source_label
                    )
                    if not batch:
                        # Empty page — stop this path.
                        break
                    pages_ok += 1
                    for row in batch:
                        link = row.get("link") or ""
                        if not link or link in seen:
                            continue
                        seen.add(link)
                        items.append(row)
    except httpx.HTTPError as exc:
        errors.append(str(exc)[:160])

    meta: dict[str, Any] = {
        "skipped": False,
        "reason": "",
        "provider": provider,
        "base_url": base,
        "pages_ok": pages_ok,
        "fetched": len(items),
        "errors": errors[:8],
    }
    if not items and errors:
        meta["reason"] = errors[0]
    return items, meta


def doctor_zoneh() -> dict[str, Any]:
    enabled = zoneh_enabled()
    provider = _provider()
    cookies = _cookies()
    detail = f"provider={provider}"
    if provider == "zoneh" and not (cookies.get("PHPSESSID") and cookies.get("ZHE")):
        detail += " — set ZONEH_PHPSESSID + ZONEH_ZHE (or use ZONEH_PROVIDER=haxor)"
        ok = False
    else:
        ok = enabled
    return {
        "id": "zoneh",
        "label": "Zone-H / defacement archive",
        "role": "discover",
        "ok": ok and enabled,
        "configured": enabled,
        "detail": detail if enabled else "ZONEH_ENABLED=false",
    }
