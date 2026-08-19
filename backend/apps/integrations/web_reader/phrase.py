"""Phrase match helpers — reduce open-web false positives across all channels."""

from __future__ import annotations

import unicodedata
from typing import Any


def normalize_phrase(value: str) -> str:
    """
    Whitespace-collapse + Unicode NFC + casefold.

    NFC is required for Vietnamese (and other combining-mark languages):
    otherwise the same visible phrase in NFC vs NFD fails substring checks.
    """
    collapsed = " ".join((value or "").split())
    return unicodedata.normalize("NFC", collapsed).casefold()


def fold_diacritics(value: str) -> str:
    """ASCII-ish fold for VN CTI (Đại học ↔ Dai hoc) after NFC/casefold."""
    # đ/Đ are atomic letters (not base+combining mark) — map explicitly.
    base = normalize_phrase(value).replace("đ", "d")
    nfd = unicodedata.normalize("NFD", base)
    return "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")


def clean_search_phrase(phrase: str) -> str:
    """Strip Searx-style wrapping quotes from the user/rule keyword."""
    raw = " ".join((phrase or "").split()).strip()
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        raw = raw[1:-1].strip()
    return raw


def contains_phrase(text: str, phrase: str) -> bool:
    """
    True when the full search phrase appears contiguously in text
    (NFC-normalized, whitespace-collapsed, case-insensitive).

    Also accepts diacritic-insensitive match so Vietnamese keywords still
    hit posts written without tone marks.
    """
    needle = normalize_phrase(clean_search_phrase(phrase))
    if len(needle) < 2:
        return False
    hay = normalize_phrase(text)
    if needle in hay:
        return True
    folded_needle = fold_diacritics(needle)
    if len(folded_needle) < 2:
        return False
    return folded_needle in fold_diacritics(hay)

def hit_text_blob(hit: dict) -> str:
    parts = [
        str(hit.get("title") or ""),
        str(hit.get("content") or ""),
    ]
    return "\n".join(parts)


def open_web_hit_has_phrase(hit: dict, phrase: str) -> bool:
    """
    Every open-web hit (Searx / Exa / Reddit / X) must contain the full
    keyword/phrase in title or snippet body.

    Exception: pasted Reddit/X status URL with empty body — enrich verifies later.
    URL-only matches do not count (avoids path/slug false positives).
    """
    from apps.integrations.web_reader.channels.reddit import is_reddit_url
    from apps.integrations.web_reader.channels.x_twitter import is_x_url

    needle = clean_search_phrase(phrase)
    if len(normalize_phrase(needle)) < 2:
        return False

    url = str(hit.get("url") or "").strip()
    content = str(hit.get("content") or "").strip()
    if not content and (is_reddit_url(url) or is_x_url(url)):
        return True

    return contains_phrase(hit_text_blob(hit), needle)


def social_hit_has_phrase(hit: dict, phrase: str) -> bool:
    """Backward-compatible alias — now applies to all open-web engines."""
    return open_web_hit_has_phrase(hit, phrase)


def filter_hits_by_phrase(
    hits: list[dict[str, Any]], phrase: str
) -> list[dict[str, Any]]:
    """Drop hits that do not contain the search phrase in title/body."""
    return [h for h in hits if open_web_hit_has_phrase(h, phrase)]
