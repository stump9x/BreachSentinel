"""SSRF-safe page reader: Jina Reader primary, plain HTTP text fallback."""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
from django.conf import settings

logger = logging.getLogger(__name__)

_TAG_RE = re.compile(r"<[^>]+>")
_DEFAULT_TIMEOUT = 20.0
_DEFAULT_MAX_BYTES = 200_000


@dataclass(frozen=True)
class ReadResult:
    ok: bool
    backend: str
    text: str
    error: str = ""


def web_reader_enabled() -> bool:
    return bool(getattr(settings, "WEB_READER_ENABLED", True))


def _max_bytes() -> int:
    return max(
        8_000,
        min(
            int(
                getattr(settings, "WEB_READER_MAX_BYTES", _DEFAULT_MAX_BYTES)
                or _DEFAULT_MAX_BYTES
            ),
            1_000_000,
        ),
    )


def _timeout() -> float:
    return float(
        getattr(settings, "WEB_READER_TIMEOUT", _DEFAULT_TIMEOUT) or _DEFAULT_TIMEOUT
    )


def _is_public_http_url(url: str) -> bool:
    """Block non-http(s) and private/link-local targets (SSRF hygiene)."""
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").strip().lower()
    if not host or host == "localhost" or host.endswith(".local"):
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return True
    return bool(addr.is_global)


def _strip_html(raw: str) -> str:
    text = _TAG_RE.sub(" ", raw or "")
    return re.sub(r"\s+", " ", text).strip()


def _read_via_jina(url: str) -> ReadResult:
    endpoint = f"https://r.jina.ai/{url}"
    try:
        with httpx.Client(timeout=_timeout(), follow_redirects=True) as client:
            response = client.get(
                endpoint,
                headers={"Accept": "text/plain,text/markdown,*/*"},
            )
            response.raise_for_status()
            body = response.content[: _max_bytes() + 1]
            if len(body) > _max_bytes():
                body = body[: _max_bytes()]
            text = body.decode("utf-8", errors="replace").strip()
            if not text:
                return ReadResult(False, "jina", "", "empty body")
            return ReadResult(True, "jina", text[: _max_bytes()])
    except httpx.HTTPError as exc:
        return ReadResult(False, "jina", "", str(exc)[:200])


def _read_via_httpx(url: str) -> ReadResult:
    try:
        with httpx.Client(timeout=_timeout(), follow_redirects=True) as client:
            response = client.get(
                url, headers={"User-Agent": "BreachSentinel-WebReader/1.0"}
            )
            response.raise_for_status()
            ctype = (response.headers.get("content-type") or "").lower()
            if any(
                x in ctype
                for x in ("image/", "audio/", "video/", "octet-stream", "zip", "pdf")
            ):
                return ReadResult(
                    False, "httpx", "", f"unsupported content-type: {ctype[:64]}"
                )
            body = response.content[: _max_bytes() + 1]
            if len(body) > _max_bytes():
                body = body[: _max_bytes()]
            raw = body.decode("utf-8", errors="replace")
            text = (
                _strip_html(raw)
                if "html" in ctype or raw.lstrip().startswith("<")
                else raw.strip()
            )
            if not text:
                return ReadResult(False, "httpx", "", "empty body")
            return ReadResult(True, "httpx", text[: _max_bytes()])
    except httpx.HTTPError as exc:
        return ReadResult(False, "httpx", "", str(exc)[:200])


def read_url(url: str) -> ReadResult:
    """Fetch readable text for a public URL. Primary: Jina; fallback: httpx."""
    if not web_reader_enabled():
        return ReadResult(False, "disabled", "", "web reader disabled")
    target = (url or "").strip()
    if not _is_public_http_url(target):
        return ReadResult(False, "blocked", "", "url blocked by SSRF policy")
    preferred = (
        getattr(settings, "WEB_READER_BACKEND", "jina") or "jina"
    ).strip().lower()
    backends = ["jina", "httpx"] if preferred == "jina" else ["httpx", "jina"]
    last = ReadResult(False, preferred, "", "no backend")
    for name in backends:
        last = _read_via_jina(target) if name == "jina" else _read_via_httpx(target)
        if last.ok:
            return last
        logger.info(
            "web_reader %s failed for %s: %s", name, target[:120], last.error
        )
    return last


def doctor_web_reader() -> dict[str, Any]:
    enabled = web_reader_enabled()
    return {
        "enabled": enabled,
        "ok": enabled,
        "backend": (getattr(settings, "WEB_READER_BACKEND", "jina") or "jina"),
        "max_bytes": _max_bytes(),
    }
