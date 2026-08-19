"""
Parse infostealer credential dumps (RedLine / Raccoon / Vidar style).

Supported line shapes (skip comments / blanks):
  - url:username:password
  - URL | USER | PASS
  - Soft / browser exports with tab separators
  - Multi-line blocks:
        URL: https://...
        Username: ...
        Password: ...
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


STEALER_HINTS = {
    "redline": re.compile(r"redline", re.I),
    "raccoon": re.compile(r"raccoon|rastealer", re.I),
    "vidar": re.compile(r"vidar", re.I),
}

PIPE_LINE = re.compile(
    r"^(?P<url>[^|]+)\|(?P<user>[^|]+)\|(?P<password>.+)$"
)

TAB_LINE = re.compile(
    r"^(?P<url>[^\t]+)\t(?P<user>[^\t]+)\t(?P<password>.+)$"
)

BLOCK_URL = re.compile(r"^\s*(?:URL|Host|Hostname)\s*[:=]\s*(?P<value>.+)\s*$", re.I)
BLOCK_USER = re.compile(
    r"^\s*(?:Username|User|Login|Email)\s*[:=]\s*(?P<value>.+)\s*$", re.I
)
BLOCK_PASS = re.compile(r"^\s*(?:Password|Pass|Pwd)\s*[:=]\s*(?P<value>.+)\s*$", re.I)


@dataclass(frozen=True)
class ParsedCredential:
    url: str = ""
    domain: str = ""
    email: str = ""
    username: str = ""
    password: str = ""
    stealer_family: str = "unknown"
    raw_line: str = ""


def detect_stealer_family(text: str, default: str = "unknown") -> str:
    for family, pattern in STEALER_HINTS.items():
        if pattern.search(text):
            return family
    return default


def extract_domain(url: str) -> str:
    candidate = (url or "").strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        host = urlparse(candidate).hostname or ""
    except ValueError:
        return ""
    return host.lower().lstrip(".")


def _split_identity(user: str) -> tuple[str, str]:
    user = (user or "").strip()
    if "@" in user and " " not in user:
        # Keep the complete login in username; email is also retained for
        # filtering/search. Many services use the full email as the login.
        return user, user
    return "", user


def _looks_like_url(value: str) -> bool:
    candidate = (value or "").strip()
    if not candidate:
        return False
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return False
    host = parsed.hostname or ""
    return bool(host and ("." in host or host.lower() == "localhost"))


def _parse_colon_line(line: str) -> tuple[str, str, str] | None:
    """Split URL:user:password while preserving URL ports/password colons."""
    parts = line.split(":")
    for separator in range(1, len(parts) - 1):
        url = ":".join(parts[:separator]).strip()
        user = parts[separator].strip()
        password = ":".join(parts[separator + 1 :]).strip()
        if not user or not password or "/" in user or "\\" in user:
            continue
        if _looks_like_url(url):
            return url, user, password
    return None


def _normalize_url(url: str) -> str:
    url = (url or "").strip().strip("\"'")
    if not url:
        return ""
    lowered = url.lower()
    if lowered.startswith(("http://", "https://", "ftp://", "ftps://")):
        return url
    if "://" in url:
        return url
    if "." in url:
        return f"https://{url}"
    return url


def parse_credential_line(
    line: str, stealer_family: str = "unknown"
) -> ParsedCredential | None:
    raw = line.rstrip("\n")
    stripped = raw.strip()
    if not stripped or stripped.startswith(("#", ";", "//")):
        return None

    parsed_parts = None
    pipe_match = PIPE_LINE.match(stripped)
    tab_match = TAB_LINE.match(stripped)
    if pipe_match:
        parsed_parts = (
            pipe_match.group("url").strip(),
            pipe_match.group("user").strip(),
            pipe_match.group("password").strip(),
        )
    elif tab_match:
        parsed_parts = (
            tab_match.group("url").strip(),
            tab_match.group("user").strip(),
            tab_match.group("password").strip(),
        )
    else:
        parsed_parts = _parse_colon_line(stripped)
    if not parsed_parts:
        return None

    url = _normalize_url(parsed_parts[0])
    email, username = _split_identity(parsed_parts[1])
    password = parsed_parts[2].strip()
    if not password:
        return None

    return ParsedCredential(
        url=url[:2048],
        domain=extract_domain(url),
        email=email[:254],
        username=username[:255],
        password=password[:512],
        stealer_family=stealer_family,
        raw_line=raw[:4000],
    )


def parse_stealer_log(
    content: str, stealer_family: str | None = None
) -> list[ParsedCredential]:
    """Parse dump text into credential records (deduped by email/user+domain+password)."""
    family = stealer_family or detect_stealer_family(content)
    results: list[ParsedCredential] = []
    seen: set[tuple[str, str, str, str]] = set()

    # Multi-line blocks first
    current: dict[str, str] = {}
    for line in content.splitlines():
        m_url = BLOCK_URL.match(line)
        m_user = BLOCK_USER.match(line)
        m_pass = BLOCK_PASS.match(line)
        if m_url:
            if current.get("url") and current.get("user") and current.get("password"):
                _append_block(current, family, results, seen)
            current = {"url": m_url.group("value").strip()}
            continue
        if m_user and current is not None:
            current["user"] = m_user.group("value").strip()
            continue
        if m_pass and current is not None:
            current["password"] = m_pass.group("value").strip()
            if current.get("url") and current.get("user"):
                _append_block(current, family, results, seen)
                current = {}
            continue

        parsed = parse_credential_line(line, stealer_family=family)
        if parsed:
            key = (parsed.email, parsed.username, parsed.domain, parsed.password)
            if key not in seen:
                seen.add(key)
                results.append(parsed)

    if current.get("url") and current.get("user") and current.get("password"):
        _append_block(current, family, results, seen)

    return results


def _append_block(
    block: dict[str, str],
    family: str,
    results: list[ParsedCredential],
    seen: set[tuple[str, str, str, str]],
) -> None:
    url = _normalize_url(block.get("url", ""))
    email, username = _split_identity(block.get("user", ""))
    password = (block.get("password") or "").strip()
    if not password:
        return
    parsed = ParsedCredential(
        url=url[:2048],
        domain=extract_domain(url),
        email=email[:254],
        username=username[:255],
        password=password[:512],
        stealer_family=family,
        raw_line=f"URL: {url} | User: {email or username}",
    )
    key = (parsed.email, parsed.username, parsed.domain, parsed.password)
    if key not in seen:
        seen.add(key)
        results.append(parsed)


def iter_batches(items: Iterable[ParsedCredential], size: int = 200):
    batch: list[ParsedCredential] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch
