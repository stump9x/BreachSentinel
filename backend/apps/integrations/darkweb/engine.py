from __future__ import annotations

import hashlib
import html
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urljoin, urlparse, urlunparse

import httpx
from django.conf import settings

# Search catalog adapted from Robin's public engine list. Engines are treated as
# volatile: every request records explicit per-engine health instead of silently
# swallowing failures.
SEARCH_ENGINES: tuple[tuple[str, str], ...] = (
    ("Ahmia", "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"),
    ("OnionLand", "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}"),
    ("Torgle", "http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/?query={query}"),
    ("Amnesia", "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}"),
    ("Kaizer", "http://kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid.onion/search?q={query}"),
    ("Anima", "http://anima4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4odf7k74tbid.onion/search?q={query}"),
    ("TorNet", "http://tornetupfu7gcgidt33ftnungxzyfq2pygui5qdoyss34xbgx2qruzid.onion/search?q={query}"),
    ("Onionway", "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}"),
    ("Tor66", "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}"),
    ("Torgol", "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}"),
)

_ONION_LABEL_RE = re.compile(r"^[a-z2-7]{56}$")
_URL_IN_TEXT_RE = re.compile(r"https?://[a-z2-7]{56}\.onion[^\s\"'<>]*", re.I)
_SPACE_RE = re.compile(r"\s+")
_TRACKING_KEYS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content"}
_USER_AGENT = "BreachSentinel-DarkWebInvestigator/1.0"


@dataclass(frozen=True)
class SearchHit:
    engine: str
    title: str
    url: str


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href = ""
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        values = dict(attrs)
        self._href = str(values.get("href") or "")
        self._text = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href:
            self.links.append((self._href, _clean_text(" ".join(self._text))))
            self._href = ""
            self._text = []


class _TextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        del attrs
        if tag.lower() in {"script", "style", "noscript", "svg"}:
            self._ignored_depth += 1
        elif not self._ignored_depth and tag.lower() in {"p", "br", "li", "h1", "h2", "h3", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript", "svg"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)


def _clean_text(value: str, limit: int = 512) -> str:
    return _SPACE_RE.sub(" ", html.unescape(value or "")).strip()[:limit]


def normalize_query(value: str, *, limit: int = 512) -> str:
    value = "".join(ch for ch in str(value or "") if ord(ch) >= 32)
    return _clean_text(value, limit=limit)


def canonicalize_onion_url(raw_url: str, *, base_url: str = "") -> str | None:
    """Return a safe v3 onion HTTP(S) URL, otherwise None."""
    candidate = html.unescape(unquote(str(raw_url or "").strip()))
    match = _URL_IN_TEXT_RE.search(candidate)
    if match:
        candidate = match.group(0)
    elif base_url:
        candidate = urljoin(base_url, candidate)

    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    hostname = parsed.hostname.rstrip(".").lower()
    labels = hostname.split(".")
    if len(labels) < 2 or labels[-1] != "onion" or not _ONION_LABEL_RE.fullmatch(labels[-2]):
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    if port not in {None, 80, 443}:
        return None

    # Some engines wrap targets in redirect query parameters.
    query = parse_qs(parsed.query)
    for key in ("url", "target", "redirect", "r"):
        wrapped = (query.get(key) or [""])[0]
        if wrapped and wrapped != candidate:
            safe = canonicalize_onion_url(wrapped)
            if safe:
                return safe

    clean_query = "&".join(
        part
        for part in parsed.query.split("&")
        if part and part.split("=", 1)[0].lower() not in _TRACKING_KEYS
    )
    netloc = hostname if port is None else f"{hostname}:{port}"
    return urlunparse(
        (parsed.scheme.lower(), netloc, parsed.path or "/", "", clean_query, "")
    )[:2048]


def extract_search_hits(page_html: str, *, engine: str, base_url: str) -> list[SearchHit]:
    parser = _LinkParser()
    parser.feed(page_html or "")
    hits: list[SearchHit] = []
    seen: set[str] = set()
    engine_host = (urlparse(base_url).hostname or "").lower()
    for href, title in parser.links:
        url = canonicalize_onion_url(href, base_url=base_url)
        if not url or url in seen:
            continue
        if (urlparse(url).hostname or "").lower() == engine_host:
            continue
        seen.add(url)
        hits.append(SearchHit(engine=engine, title=title or urlparse(url).hostname or "Onion result", url=url))
    return hits


def html_to_text(page_html: str, *, limit: int = 50_000) -> str:
    parser = _TextParser()
    parser.feed(page_html or "")
    lines = [_clean_text(line, limit=limit) for line in "".join(parser.parts).splitlines()]
    return "\n".join(line for line in lines if line)[:limit]


def _tor_client(*, timeout: float) -> httpx.Client:
    if not bool(getattr(settings, "TOR_ENABLED", False)):
        raise RuntimeError("Tor is disabled (TOR_ENABLED=false)")
    proxy = str(getattr(settings, "TOR_SOCKS_PROXY", "") or "").strip()
    if not proxy:
        raise RuntimeError("TOR_SOCKS_PROXY is empty")
    return httpx.Client(
        proxy=proxy,
        timeout=httpx.Timeout(timeout, connect=timeout),
        follow_redirects=False,
        headers={"User-Agent": _USER_AGENT, "Accept": "text/html,text/plain;q=0.9"},
        limits=httpx.Limits(max_connections=8, max_keepalive_connections=2),
    )


def _read_limited(response: httpx.Response, *, max_bytes: int) -> bytes:
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > max_bytes:
        raise ValueError("response exceeds size limit")
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > max_bytes:
            raise ValueError("response exceeds size limit")
    return bytes(body)


def _fetch_onion_bytes(
    client: httpx.Client, url: str, *, max_bytes: int
) -> tuple[bytes, str, str, str]:
    """Fetch through Tor while validating every redirect remains a v3 onion URL."""
    current = canonicalize_onion_url(url)
    if not current:
        raise ValueError("unsafe or invalid onion URL")
    for _ in range(4):
        with client.stream("GET", current) as response:
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location") or ""
                target = canonicalize_onion_url(location, base_url=current)
                if not target:
                    raise ValueError("redirect target is not a safe onion URL")
                current = target
                continue
            response.raise_for_status()
            raw = _read_limited(response, max_bytes=max_bytes)
            return (
                raw,
                (response.headers.get("content-type") or "").lower(),
                response.encoding or "utf-8",
                current,
            )
    raise ValueError("too many onion redirects")


def _search_one(name: str, template: str, query: str, timeout: float) -> tuple[list[SearchHit], dict[str, Any]]:
    started = time.monotonic()
    url = template.format(query=quote_plus(query))
    hits: list[SearchHit] = []
    try:
        with _tor_client(timeout=timeout) as client:
            raw, _content_type, encoding, final_url = _fetch_onion_bytes(
                client, url, max_bytes=1_000_000
            )
            page = raw.decode(encoding, errors="replace")
        hits = extract_search_hits(page, engine=name, base_url=final_url)
        stat = {"engine": name, "status": "ok", "result_count": len(hits), "error": ""}
    except Exception as exc:  # noqa: BLE001
        stat = {"engine": name, "status": "error", "result_count": 0, "error": str(exc)[:240]}
    stat["latency_ms"] = int((time.monotonic() - started) * 1000)
    return hits, stat


def rank_hits(hits: list[SearchHit], query: str, *, limit: int) -> list[SearchHit]:
    tokens = {token.casefold() for token in re.findall(r"[\w.-]{3,}", query)}
    return sorted(
        hits,
        key=lambda hit: (
            -sum(token in f"{hit.title} {hit.url}".casefold() for token in tokens),
            hit.engine.casefold(),
            hit.url,
        ),
    )[:limit]


def search_onion(query: str, *, limit: int = 40) -> tuple[list[SearchHit], list[dict[str, Any]]]:
    timeout = float(getattr(settings, "DARKWEB_SEARCH_TIMEOUT_SEC", 25) or 25)
    workers = max(1, min(int(getattr(settings, "DARKWEB_CONCURRENCY", 4) or 4), 8))
    all_hits: list[SearchHit] = []
    stats: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_search_one, name, template, query, timeout): name
            for name, template in SEARCH_ENGINES
        }
        for future in as_completed(futures):
            hits, stat = future.result()
            all_hits.extend(hits)
            stats.append(stat)
    deduped: dict[str, SearchHit] = {}
    for hit in all_hits:
        deduped.setdefault(hit.url, hit)
    order = {name: index for index, (name, _) in enumerate(SEARCH_ENGINES)}
    stats.sort(key=lambda row: order.get(str(row.get("engine")), 999))
    return rank_hits(list(deduped.values()), query, limit=limit), stats


def scrape_onion(url: str) -> dict[str, Any]:
    safe_url = canonicalize_onion_url(url)
    if not safe_url:
        raise ValueError("unsafe or invalid onion URL")
    timeout = float(getattr(settings, "DARKWEB_SCRAPE_TIMEOUT_SEC", 40) or 40)
    max_bytes = max(64_000, min(int(getattr(settings, "DARKWEB_MAX_RESPONSE_BYTES", 1_000_000) or 1_000_000), 2_000_000))
    started = time.monotonic()
    with _tor_client(timeout=timeout) as client:
        raw, content_type, encoding, _final_url = _fetch_onion_bytes(
            client, safe_url, max_bytes=max_bytes
        )
        if not any(kind in content_type for kind in ("text/html", "text/plain", "application/xhtml+xml")):
            raise ValueError(f"unsupported content type: {content_type[:80]}")
        page = raw.decode(encoding, errors="replace")
    text = html_to_text(page)
    return {
        "text": text,
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest() if text else "",
        "bytes": len(raw),
        "content_type": content_type[:128],
        "latency_ms": int((time.monotonic() - started) * 1000),
    }


def probe_engines(*, limit: int = 4) -> dict[str, Any]:
    if not bool(getattr(settings, "DARKWEB_ENABLED", False)):
        return {"enabled": False, "tor_enabled": bool(getattr(settings, "TOR_ENABLED", False)), "engines": []}
    selected = SEARCH_ENGINES[: max(1, min(limit, len(SEARCH_ENGINES)))]
    timeout = min(10.0, float(getattr(settings, "DARKWEB_SEARCH_TIMEOUT_SEC", 25) or 25))
    rows: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(4, len(selected))) as pool:
        futures = {pool.submit(_search_one, name, template, "security", timeout): name for name, template in selected}
        for future in as_completed(futures):
            _, stat = future.result()
            rows.append(stat)
    return {
        "enabled": True,
        "tor_enabled": bool(getattr(settings, "TOR_ENABLED", False)),
        "configured_engines": len(SEARCH_ENGINES),
        "healthy_probed": sum(row.get("status") == "ok" for row in rows),
        "engines": rows,
    }
