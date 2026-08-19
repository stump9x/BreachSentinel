"""Title translation: Google Translate first, optional AI refine."""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx
from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from apps.intel.models import Threat

logger = logging.getLogger(__name__)

# Skip Google after VPS/datacenter captcha/429 so the batch falls through to
# Groq/Ollama (or MyMemory) instead of hammering the captcha endpoint.
# Process-local floors; Redis keys keep backend+celery workers in sync.
_google_circuit_open_until = 0.0
_GOOGLE_CIRCUIT_SECONDS = 300.0
_GOOGLE_SUCCESS_PACING_SEC = 0.8
_GOOGLE_CIRCUIT_CACHE_KEY = "google_translate:circuit_open"
_GOOGLE_PACE_CACHE_KEY = "google_translate:last_call"
_LAST_GOOGLE_CALL_MONO = 0.0
_groq_circuit_open_until = 0.0
_groq_fail_count = 0


def _groq_circuit_cache_key() -> str:
    ns = (getattr(settings, "GROQ_POOL_NAMESPACE", "") or "breachsentinel").strip()
    return f"groq_pool:{ns}:circuit_open"

# CTI / product terms that may remain Latin in an otherwise Vietnamese title.
_KEEP_LATIN_TERMS = frozenset(
    {
        "cve",
        "cvss",
        "ransomware",
        "malware",
        "phishing",
        "botnet",
        "wordpress",
        "zero",
        "day",
        "apt",
        "ioc",
        "ddos",
        "vpn",
        "tor",
        "http",
        "https",
        "api",
        "sql",
        "xss",
        "rce",
        "nsa",
        "fbi",
        "cisa",
        "microsoft",
        "google",
        "openai",
        "hugging",
        "face",
        "huggingface",
        "linux",
        "windows",
        "android",
        "ios",
        "pdf",
        "url",
        "ip",
        "dns",
        "ssl",
        "tls",
        "ai",
        "llm",
        "video",
        "dark",
        "web",
    }
)

# Brands / multi-word proper nouns Google often translates literally (wrong).
# Each entry: source needles (casefold) → canonical Latin form + bad-VI fixups.
_BRAND_PROPER_NOUNS: tuple[dict[str, Any], ...] = (
    {
        "needles": ("hugging face", "huggingface"),
        "canonical": "Hugging Face",
        "fixes": (
            (re.compile(r"m[aá]y\s+ch[uủ]\s+ôm\s+mặt", re.IGNORECASE), "máy chủ Hugging Face"),
            (re.compile(r"ôm\s+mặt", re.IGNORECASE), "Hugging Face"),
        ),
    },
    {
        "needles": ("open ai", "openai"),
        "canonical": "OpenAI",
        "fixes": (),
    },
)

# Only exact structured ransomware ingest titles use a local rule.
_RANSOMWARE_TITLE_RE = re.compile(
    r"^Ransomware:\s*(?P<victim>.+?)\s*\((?P<group>[^)]+)\)\s*$",
    re.IGNORECASE,
)

_VIET_CHAR_RE = re.compile(
    r"[àáạảãâầấậẩẫăằắặẳẵèéẹẻẽêềếệểễìíịỉĩòóọỏõôồốộổỗơờớợởỡ"
    r"ùúụủũưừứựửữỳýỵỷỹđ"
    r"ÀÁẠẢÃÂẦẤẬẨẪĂẰẮẶẲẴÈÉẸẺẼÊỀẾỆỂỄÌÍỊỈĨÒÓỌỎÕÔỒỐỘỔỖƠỜỚỢỞỠ"
    r"ÙÚỤỦŨƯỪỨỰỬỮỲÝỴỶỸĐ]"
)

# Chars that almost never appear in EN/ES/FR headlines — used to avoid Mazatlán-style FPs.
_STRONG_VIET_RE = re.compile(
    r"[ăâêôơưđĂÂÊÔƠƯĐ"
    r"ạảãặẳẵậẩẫằắặẳẵầấậẩẫẹẻẽệểễềếệểễỉịọỏộổỗợởỡụủựửữỵỷỹ"
    r"ẠẢÃẶẲẴẬẨẪẰẮẶẲẴẦẤẬẨẪẸẺẼỆỂỄỀẾỆỂỄỈỊỌỎỘỔỖỢỞỠỤỦỰỬỮỴỶỸ]"
)

# Latin words (3+ letters) — proper nouns/CVE kept but counted for English remnants.
_LATIN_WORD_RE = re.compile(r"\b[A-Za-z]{3,}\b")

# Obvious garble: "Cơ quotate:" style prefix glued to an English headline.
_CO_ENGLISH_GARBLE_RE = re.compile(
    r"\b[Cc]ơ\s+(?:quot\w+|confirm\w*|agency\w*|registry\w*)\b"
    r"|\b[Cc]ơ\s+[a-z]{4,}\s*:\s*[A-Z]",
    re.IGNORECASE,
)

# Long contiguous English phrase inside a "Vietnamese" title.
_LONG_ENGLISH_RUN_RE = re.compile(r"[A-Za-z][A-Za-z\s,'\-]{24,}[A-Za-z]")

# Residual English headline fragments (Title Case chains), e.g. "National Land Registry".
_ENGLISH_HEADLINE_RE = re.compile(
    r"[A-Z][a-z]+(?:[''][sS])?(?:\s+[A-Z][a-z]+){2,}"
)

# CJK / Hangul must not appear in Vietnamese Wire titles unless already in source.
_FOREIGN_SCRIPT_RE = re.compile(
    r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uac00-\ud7af]"
)
_CJK_RE = re.compile(r"[\u3040-\u30ff\u3400-\u9fff\uf900-\ufaff\uac00-\ud7af]")
_NON_LATIN_SCRIPT_RE = re.compile(
    r"[\u0400-\u04FF\u0600-\u06FF\u0E00-\u0E7F\u0900-\u097F]"
)

# Adapted from NewsCrawler military doctrine + CTI Wire title constraints.
_CTI_WIRE_TRANSLATION_DOCTRINE = """
## Role
You are an expert military, defence, security, and cyber-threat-intelligence (CTI)
translator specializing in translating English and other languages into Vietnamese.

## Task
Translate the given OSINT / CTI / cyber-security TITLE into Vietnamese. Apply the
same fidelity rules you would use for headings in a military, defence, or
intelligence document — but keep the output to ONE Wire headline.

## Translation Requirements
1. Faithfully preserve the meaning of the original. Highest accuracy for military,
   defence, security, and cyber-threat content.
2. Do NOT paraphrase, summarize, omit, infer, embellish, or add commentary,
   explanations, or information that is not explicitly present in the source.
3. Preserve uncertainty exactly (assess / suggest / indicate / appear / likely /
   may / might / could / estimate / believe / judge / reportedly, alleged, claims).
   Never strengthen or weaken the author's assessment.
4. Do NOT invent countries, places, companies, or actors. Do NOT add Việt Nam
   unless the source mentions it.
5. Translate every meaningful content word into Vietnamese. Do not leave
   source-language content words untranslated.
6. Exceptions that MUST remain in the original form (no parenthetical gloss):
   - CVE-*, CVSS, domains, URLs, IPs, hashes
   - ransomware group names (LockBit, Nova, Qilin, RansomHouse…)
   - product / vendor / brand names (Microsoft, OpenAI, Hugging Face…)
   - emoji, code names, serials, technical designators when unsure
   - NEVER translate brand words literally. Example:
     "Hugging Face Servers" → "máy chủ Hugging Face"
     (WRONG: "máy chủ ôm mặt")
7. For agencies, bases, ports, vessels, aircraft, missiles, geographic names:
   use the official Vietnamese name when known with certainty; otherwise keep
   the original — NEVER guess.
8. Preferred CTI terminology:
   - ransomware → mã độc tống tiền
   - data breach → sự cố lộ dữ liệu
   - data leak → rò rỉ dữ liệu
   - threat actor → đối tượng đe dọa
   - victim / victims → nạn nhân
   - malware → mã độc
   - claim / claims → cáo buộc / tuyên bố
   - dark web → dark web
   - zero-day → zero-day
   - server / servers → máy chủ (keep the brand name Latin)
   - cyber warfare → tác chiến mạng
9. Use formal Vietnamese suitable for defence / security / intelligence /
   government publications (văn phong hành chính).
10. If the source is Chinese / Japanese / Korean / another non-English language:
    detect it, translate fully into Vietnamese; do not leave Han/Kanji/Hangul
    or other foreign scripts in the output (except proper nouns already Latin).

## Output Requirements
- Return ONLY the completed Vietnamese title.
- No introductions, summaries, notes, quotes, or prefixes.
- One clean title line, ready to display on The Wire.
""".strip()

DEFAULT_REFINE_PROMPT = f"""{_CTI_WIRE_TRANSLATION_DOCTRINE}

## Current job
Revise the Google Translate draft of this title so it fully complies with the
doctrine above. Prefer the source meaning over a bad draft. If the draft invents
places, leaves foreign script, or leaves content words untranslated, correct them.

Source title:
{{title}}

Google Translate draft (to revise):
{{draft}}
"""

DEFAULT_FALLBACK_PROMPT = f"""{_CTI_WIRE_TRANSLATION_DOCTRINE}

## Current job
Translate the following title into Vietnamese, strictly following the doctrine.
Auto-detect the source language (English or other).

Source title:
{{title}}
"""


class TitleTranslateError(Exception):
    pass


def title_hash(title: str) -> str:
    normalized = " ".join((title or "").split()).casefold()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def looks_vietnamese(text: str) -> bool:
    """True for real Vietnamese text — not Spanish/Portuguese accented Latin alone."""
    if not text or not text.strip():
        return False
    if _STRONG_VIET_RE.search(text):
        return True
    # Shared accents (áéíóú) need several hits plus overall density.
    hits = _VIET_CHAR_RE.findall(text)
    return len(hits) >= 4 and vietnamese_ratio(text) >= 0.18


def vietnamese_ratio(text: str) -> float:
    letters = [ch for ch in (text or "") if ch.isalpha()]
    if not letters:
        return 0.0
    viet = sum(1 for ch in letters if _VIET_CHAR_RE.match(ch))
    return viet / len(letters)


def english_word_count(text: str) -> int:
    return len(_LATIN_WORD_RE.findall(text or ""))


def has_foreign_script(text: str, *, original: str = "") -> bool:
    """True when draft introduces CJK/Hangul not present in the source title."""
    source = original or ""
    for ch in _FOREIGN_SCRIPT_RE.findall(text or ""):
        if ch not in source:
            return True
    return False


def cjk_char_ratio(text: str) -> float:
    chars = [ch for ch in (text or "") if not ch.isspace()]
    if not chars:
        return 0.0
    return sum(1 for ch in chars if _CJK_RE.match(ch)) / len(chars)


def is_cjk_title(text: str) -> bool:
    """True when the source title is primarily Chinese / Japanese / Korean script."""
    return cjk_char_ratio(text) >= 0.25


def translation_still_cjk(original: str, translated: str) -> bool:
    """True when CJK remains where it should not (failed CN/JP translate)."""
    text = translated or ""
    if not text:
        return False
    if not is_cjk_title(original):
        return bool(_CJK_RE.search(text))
    if _CJK_RE.search(text):
        return True
    return cjk_char_ratio(text) >= 0.08


def is_non_english_source(title: str, detected: str = "") -> bool:
    """Heuristic + Google-detected language: source is not English (nor Vietnamese)."""
    if is_cjk_title(title):
        return True
    if _NON_LATIN_SCRIPT_RE.search(title or ""):
        return True
    lang = (detected or "").strip().lower().split("-")[0]
    if lang and lang not in {"", "en", "und", "auto", "vi"}:
        return True
    return False


def cjk_prefer_ollama() -> bool:
    return bool(getattr(settings, "TITLE_TRANSLATE_CJK_PREFER_OLLAMA", True))


def non_english_ollama_compare() -> bool:
    """When non-EN Google draft is weak, compare Ollama and prefer the better VI."""
    return bool(getattr(settings, "TITLE_TRANSLATE_NON_EN_OLLAMA_COMPARE", True))


def has_obvious_garble(text: str, *, original: str = "") -> bool:
    if not text:
        return False
    if has_foreign_script(text, original=original):
        return True
    if _CO_ENGLISH_GARBLE_RE.search(text):
        return True
    if _LONG_ENGLISH_RUN_RE.search(text):
        return True
    return False


def is_mangled_title_vi(
    title_vi: str, *, provider: str = "", original: str = ""
) -> bool:
    """Detect broken translations (mixed EN/VI garble, large English remnants).

    Proper nouns / special CTI tokens that already appear in the source title are
    allowed to stay Latin and must not force a false "mangled" flag (esp. rule
    titles on the last Wire pages).
    """
    text = (title_vi or "").strip()
    if not text:
        return False
    if has_foreign_script(text, original=original):
        return True
    if original and translation_still_cjk(original, text):
        return True
    if original and brand_literal_mistranslated(original, text):
        return True
    if has_obvious_garble(text, original=original):
        # Allow long Latin runs that are clearly copied proper nouns from source.
        if original and _LONG_ENGLISH_RUN_RE.search(text):
            for match in _LONG_ENGLISH_RUN_RE.finditer(text):
                phrase = match.group(0).strip()
                if phrase and phrase.casefold() not in (original or "").casefold():
                    return True
            # All long runs were proper nouns from the source.
        else:
            return True
        if _CO_ENGLISH_GARBLE_RE.search(text):
            return True
    remnant = english_remnant_count(original, text)
    if not looks_vietnamese(text) and remnant >= 3:
        return True
    # Mixed EN lead-in + Vietnamese body (common Ollama garble).
    if looks_vietnamese(text) and re.match(
        r"^(?:Threat\s+Actor|Dark\s+Web|Ransomware\s+Group|Alleged\s+Data)\b",
        text,
        re.IGNORECASE,
    ):
        return True
    for match in _ENGLISH_HEADLINE_RE.finditer(text):
        phrase = match.group(0).strip()
        if phrase and phrase.casefold() not in (original or "").casefold():
            return True
    if str(provider).startswith(
        ("google+ollama", "ollama-fallback", "groq")
    ) and remnant >= 4:
        return True
    if re.fullmatch(r"[?¿!\s.…]{2,}", text):
        return True
    return False


def _source_has_brand(original: str, needles: tuple[str, ...]) -> bool:
    folded = " ".join((original or "").casefold().split())
    compact = folded.replace(" ", "")
    for needle in needles:
        n = needle.casefold()
        if n in folded or n.replace(" ", "") in compact:
            return True
    return False


def _draft_keeps_brand(draft: str, canonical: str) -> bool:
    folded = " ".join((draft or "").casefold().split())
    compact = folded.replace(" ", "")
    canon = canonical.casefold()
    return canon in folded or canon.replace(" ", "") in compact


def brand_literal_mistranslated(original: str, draft: str) -> bool:
    """True when a known brand was translated literally (e.g. Hugging Face → ôm mặt)."""
    text = draft or ""
    for brand in _BRAND_PROPER_NOUNS:
        if not _source_has_brand(original, brand["needles"]):
            continue
        for pattern, _replacement in brand["fixes"]:
            if pattern.search(text):
                return True
        if not _draft_keeps_brand(text, brand["canonical"]):
            # Brand present in source but vanished from VI draft.
            return True
    return False


def restore_brand_proper_nouns(original: str, draft: str) -> str:
    """Fix literal brand mistranslations; keep CTI proper nouns in Latin form."""
    text = (draft or "").strip()
    if not text:
        return text
    for brand in _BRAND_PROPER_NOUNS:
        if not _source_has_brand(original, brand["needles"]):
            continue
        for pattern, replacement in brand["fixes"]:
            text = pattern.sub(replacement, text)
        # If brand still missing after bug fixes, append is wrong — leave for Ollama.
        # Prefer inserting canonical only when a known bug was already rewritten.
    return " ".join(text.split())


def normalize_translated_title(original: str, translated: str) -> str:
    """Post-process any provider output so brand logic stays correct."""
    return restore_brand_proper_nouns(original, translated)[:512]


def proper_noun_tokens(original: str) -> set[str]:
    """Latin tokens that should be preserved (names, brands, CVE-like ids)."""
    text = original or ""
    tokens: set[str] = set()
    for match in re.finditer(
        r"\b(?:[A-Z]{2,}(?:-[A-Z0-9]+)*|"
        r"[A-Z][a-z]+(?:[''][sS])?(?:\s+[A-Z][a-z]+){0,4}|"
        r"CVE-\d{4}-\d+|"
        r"[A-Za-z0-9.-]+\.(?:com|net|org|io|vn|gov|edu))\b",
        text,
    ):
        for word in re.findall(r"[A-Za-z0-9]+", match.group(0)):
            tokens.add(word.casefold())
    for word in _LATIN_WORD_RE.findall(text):
        low = word.casefold()
        if low in _KEEP_LATIN_TERMS:
            tokens.add(low)
    # Multi-word brands (Hugging Face → hugging, face, huggingface).
    for brand in _BRAND_PROPER_NOUNS:
        if _source_has_brand(text, brand["needles"]):
            for part in re.findall(r"[A-Za-z0-9]+", brand["canonical"]):
                tokens.add(part.casefold())
    return tokens


def english_remnant_count(original: str, draft: str) -> int:
    """Count Latin words in draft that are not proper nouns / keep-terms."""
    keep = proper_noun_tokens(original) | _KEEP_LATIN_TERMS
    return sum(
        1
        for word in _LATIN_WORD_RE.findall(draft or "")
        if word.casefold() not in keep
    )


def google_draft_needs_ollama(original: str, draft: str) -> bool:
    """Return True only when Google output is not usable Vietnamese for The Wire."""
    source = (original or "").strip()
    # Restore brand literals first (Hugging Face ≠ ôm mặt); then judge quality.
    text = normalize_translated_title(source, draft or "").strip()
    if not text:
        return True
    if re.fullmatch(r"[?¿!\s.…]{2,}", text):
        return True
    if text.casefold() == source.casefold() and not looks_vietnamese(source):
        return True
    if translation_still_cjk(source, text):
        return True
    # Brand still missing after restore → need a smarter retranslate.
    for brand in _BRAND_PROPER_NOUNS:
        if _source_has_brand(source, brand["needles"]) and not _draft_keeps_brand(
            text, brand["canonical"]
        ):
            return True
    if is_mangled_title_vi(text, provider="google", original=source):
        return True
    if looks_vietnamese(text):
        # Accented Vietnamese with only allowed Latin remnants is fine.
        return english_remnant_count(source, text) >= 6
    # No Vietnamese accents: treat as failed unless it is almost only proper nouns.
    return english_remnant_count(source, text) >= 2


def accept_ollama_translation(original: str, translated: str) -> bool:
    """Validate Ollama output; reject CJK leftovers and EN/VI garble."""
    text = normalize_translated_title(original, translated).strip()
    if not text:
        return False
    if re.fullmatch(r"[?¿!\s.…]{2,}", text):
        return False
    if translation_still_cjk(original, text):
        return False
    if has_foreign_script(text, original=original):
        return False
    if is_mangled_title_vi(text, provider="ollama-fallback", original=original):
        return False
    if looks_vietnamese(text):
        return True
    # Soft accept for CJK sources: some accents + CTI signal words.
    if is_cjk_title(original) and vietnamese_ratio(text) >= 0.08:
        return english_remnant_count(original, text) <= 2
    return False


def ollama_beats_google(original: str, google_draft: str, ollama_text: str) -> bool:
    """Prefer Ollama when it is clearly better Vietnamese — esp. non-English sources."""
    if not accept_ollama_translation(original, ollama_text):
        return False
    draft = (google_draft or "").strip()
    if not draft or google_draft_needs_ollama(original, draft):
        return True
    if translation_still_cjk(original, draft) and not translation_still_cjk(
        original, ollama_text
    ):
        return True
    if has_foreign_script(draft, original=original) and not has_foreign_script(
        ollama_text, original=original
    ):
        return True
    # English sources: keep a usable Google draft (Ollama polish is a separate flag).
    if not is_non_english_source(original):
        return False
    # Non-EN: allow Ollama when VI density is better and remnants are not worse.
    o_ratio = vietnamese_ratio(ollama_text)
    g_ratio = vietnamese_ratio(draft)
    if o_ratio >= g_ratio + 0.05 and english_remnant_count(
        original, ollama_text
    ) <= english_remnant_count(original, draft) + 1:
        return True
    return accept_refine_result(original, draft, ollama_text)


def accept_refine_result(original: str, google_draft: str, refined: str) -> bool:
    """Keep Google draft unless Ollama output is clearly better Vietnamese."""
    refined = (refined or "").strip()
    google_draft = (google_draft or "").strip()
    if not refined or not looks_vietnamese(refined):
        return False
    if has_obvious_garble(refined, original=original):
        return False
    if has_foreign_script(refined, original=original):
        return False

    refined_ratio = vietnamese_ratio(refined)
    draft_ratio = vietnamese_ratio(google_draft)
    if refined_ratio < max(0.12, draft_ratio - 0.08):
        return False

    refined_eng = english_word_count(refined)
    draft_eng = english_word_count(google_draft)
    if _ENGLISH_HEADLINE_RE.search(refined) and not _ENGLISH_HEADLINE_RE.search(
        google_draft
    ):
        return False
    if _LONG_ENGLISH_RUN_RE.search(refined) and not _LONG_ENGLISH_RUN_RE.search(
        google_draft
    ):
        return False
    if refined_eng > draft_eng + 2 and refined_eng >= 5:
        return False

    return True


def prepare_title_for_translate(title: str) -> str:
    """Strip URLs / noise so Google is cheaper and more accurate; keep meaning."""
    text = re.sub(r"https?://\S+", " ", title or "", flags=re.I)
    text = re.sub(r"\bt\.co/\S+", " ", text, flags=re.I)
    text = re.sub(r"\s+", " ", text).strip()
    return (text or (title or "").strip())[:512]


def rule_translate_title(title: str) -> str | None:
    """Deterministic translation only for exact ransomware templates."""
    raw = (title or "").strip()
    if not raw:
        return None
    if looks_vietnamese(raw):
        return raw
    match = _RANSOMWARE_TITLE_RE.match(raw)
    if not match:
        return None
    victim = match.group("victim").strip()
    group = match.group("group").strip()
    return f"Mã độc tống tiền: {victim} ({group})"[:512]


def is_structured_ransomware_title(title: str) -> bool:
    return bool(_RANSOMWARE_TITLE_RE.match((title or "").strip()))


def reset_google_circuit() -> None:
    """Test helper — clear the Google 429 circuit breaker."""
    global _google_circuit_open_until
    _google_circuit_open_until = 0.0
    try:
        from django.core.cache import cache

        cache.delete(_GOOGLE_CIRCUIT_CACHE_KEY)
    except Exception:  # noqa: BLE001
        return


def is_google_circuit_open() -> bool:
    """True while Google direct/Tor should be skipped to avoid captcha storms."""
    if time.monotonic() < _google_circuit_open_until:
        return True
    try:
        from django.core.cache import cache

        return bool(cache.get(_GOOGLE_CIRCUIT_CACHE_KEY))
    except Exception:  # noqa: BLE001
        return False


def _google_circuit_open() -> bool:
    return is_google_circuit_open()


def trip_google_circuit(seconds: float | None = None) -> None:
    """Open Google circuit across workers (Redis) + local process floor."""
    global _google_circuit_open_until
    ttl = float(
        seconds
        if seconds is not None
        else getattr(settings, "GOOGLE_TRANSLATE_CIRCUIT_SEC", _GOOGLE_CIRCUIT_SECONDS)
        or _GOOGLE_CIRCUIT_SECONDS
    )
    ttl = max(30.0, ttl)
    _google_circuit_open_until = time.monotonic() + ttl
    try:
        from django.core.cache import cache

        cache.set(_GOOGLE_CIRCUIT_CACHE_KEY, True, timeout=int(ttl))
    except Exception:  # noqa: BLE001
        pass
    logger.warning("google translate circuit open for %.0fs", ttl)


def _trip_google_circuit(seconds: float | None = None) -> None:
    trip_google_circuit(seconds)


def pace_google_call() -> None:
    """Min interval between Google Translate calls (local + Redis)."""
    global _LAST_GOOGLE_CALL_MONO
    interval = float(
        getattr(settings, "GOOGLE_TRANSLATE_PACING_SEC", _GOOGLE_SUCCESS_PACING_SEC)
        or 0
    )
    interval = max(0.0, interval)
    if interval <= 0:
        return
    now_m = time.monotonic()
    wait_local = (_LAST_GOOGLE_CALL_MONO + interval) - now_m
    if wait_local > 0:
        time.sleep(wait_local)
    _LAST_GOOGLE_CALL_MONO = time.monotonic()
    try:
        from django.core.cache import cache

        last = cache.get(_GOOGLE_PACE_CACHE_KEY)
        if last is not None:
            wait = float(last) + interval - time.time()
            if wait > 0:
                time.sleep(min(wait, interval * 3))
        cache.set(_GOOGLE_PACE_CACHE_KEY, time.time(), timeout=int(interval) + 120)
    except Exception:  # noqa: BLE001
        return


def reset_groq_circuit() -> None:
    """Test helper — clear the Groq failure circuit breaker."""
    global _groq_circuit_open_until, _groq_fail_count
    _groq_circuit_open_until = 0.0
    _groq_fail_count = 0
    try:
        from django.core.cache import cache

        cache.delete(_groq_circuit_cache_key())
    except Exception:  # noqa: BLE001
        pass
    try:
        from apps.integrations.ai.groq_pool import clear_groq_key_cooldowns

        # clear_groq_key_cooldowns also drops the pool circuit key
        clear_groq_key_cooldowns()
    except Exception:  # noqa: BLE001
        return


def is_groq_circuit_open() -> bool:
    if time.monotonic() < _groq_circuit_open_until:
        return True
    try:
        from django.core.cache import cache

        if cache.get(_groq_circuit_cache_key()):
            return True
    except Exception:  # noqa: BLE001
        pass
    try:
        from apps.integrations.ai.groq_pool import is_groq_pool_circuit_open

        return is_groq_pool_circuit_open()
    except Exception:  # noqa: BLE001
        return False


def trip_groq_circuit(*, reason: str = "") -> None:
    global _groq_circuit_open_until, _groq_fail_count
    ttl = float(getattr(settings, "GROQ_CIRCUIT_TTL_SEC", 180) or 180)
    _groq_circuit_open_until = time.monotonic() + max(30.0, ttl)
    _groq_fail_count = 0
    try:
        from django.core.cache import cache

        cache.set(_groq_circuit_cache_key(), True, timeout=int(max(30.0, ttl)))
    except Exception:  # noqa: BLE001
        pass
    try:
        from apps.integrations.ai.groq_pool import trip_groq_pool_circuit

        trip_groq_pool_circuit(seconds=ttl, reason=reason)
    except Exception:  # noqa: BLE001
        pass
    ns = (getattr(settings, "GROQ_POOL_NAMESPACE", "") or "breachsentinel").strip()
    logger.warning(
        "groq translate circuit open for %.0fs ns=%s%s — falling back to Google/Ollama",
        ttl,
        ns,
        f" ({reason})" if reason else "",
    )


def note_groq_success() -> None:
    reset_groq_circuit()


def note_groq_failure(*, reason: str = "") -> None:
    global _groq_fail_count
    msg = (reason or "").casefold()
    # Pool already burned — open circuit immediately; do not retry next title.
    if any(
        token in msg
        for token in (
            "rate limited",
            "exhausted",
            "all groq keys cooling",
            "circuit open",
            "unavailable",
        )
    ):
        trip_groq_circuit(reason=reason or "pool unavailable")
        return
    threshold = int(getattr(settings, "GROQ_FAIL_TRIP_THRESHOLD", 1) or 1)
    _groq_fail_count += 1
    if _groq_fail_count >= max(1, threshold):
        trip_groq_circuit(reason=reason or f"{_groq_fail_count} consecutive failures")


def _is_google_rate_limit_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return "429" in msg or "rate limited" in msg or "sorry/index" in msg


@dataclass(frozen=True)
class GoogleTitleTranslation:
    text: str
    source_language: str = ""

    def __str__(self) -> str:
        return self.text


def _google_http_client(*, via_tor: bool = False) -> httpx.Client:
    timeout = float(getattr(settings, "GOOGLE_TRANSLATE_TIMEOUT_SEC", 20) or 20)
    proxy = None
    if via_tor:
        if not bool(getattr(settings, "TOR_ENABLED", False)):
            raise TitleTranslateError("Tor disabled for Google Translate")
        proxy = (getattr(settings, "TOR_SOCKS_PROXY", "") or "").strip()
        if not proxy:
            raise TitleTranslateError("TOR_SOCKS_PROXY is empty")
    return httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        proxy=proxy,
    )


def _parse_google_translate_response(response: httpx.Response) -> GoogleTitleTranslation:
    if response.status_code in {301, 302, 303, 307, 308}:
        location = str(response.headers.get("location") or "")
        raise TitleTranslateError(
            f"Google Translate redirected ({response.status_code}): {location[:120]}"
        )
    if response.status_code == 429:
        raise TitleTranslateError("Google Translate rate limited (429)")
    response.raise_for_status()
    content_type = str(response.headers.get("content-type") or "")
    if "json" not in content_type and "javascript" not in content_type:
        raise TitleTranslateError(
            f"Google Translate returned non-JSON content-type: {content_type[:80]}"
        )
    data = response.json()
    try:
        translated = "".join(
            str(segment[0] or "")
            for segment in (data[0] or [])
            if isinstance(segment, list) and segment
        ).strip()
        detected = str(data[2] or "").strip().lower() if len(data) > 2 else ""
    except (IndexError, TypeError) as exc:
        raise TitleTranslateError("Google Translate returned an invalid response") from exc
    if not translated:
        raise TitleTranslateError("Google Translate returned empty text")
    return GoogleTitleTranslation(text=translated[:512], source_language=detected[:16])


def _google_tor_fallback_enabled() -> bool:
    if not bool(getattr(settings, "GOOGLE_TRANSLATE_TOR_FALLBACK", True)):
        return False
    if not bool(getattr(settings, "TOR_ENABLED", False)):
        return False
    return bool((getattr(settings, "TOR_SOCKS_PROXY", "") or "").strip())


def google_translate_title(title: str) -> GoogleTitleTranslation | str:
    """Translate auto-detected source language → Vietnamese (POST, no captcha follow).

    Direct egress first; on datacenter 429/captcha (or open circuit), use Tor SOCKS.
    Never follow captcha redirects. Pace every call to avoid VPS IP burns.
    """
    text = prepare_title_for_translate(title)
    if not text:
        raise TitleTranslateError("empty title")
    source_language = (
        getattr(settings, "GOOGLE_TRANSLATE_SOURCE_LANGUAGE", "auto") or "auto"
    ).strip()
    form = {
        "client": "gtx",
        "sl": source_language,
        "tl": "vi",
        "dt": "t",
        "q": text[:512],
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; BreachSentinel/1.0; +local)",
        "Accept": "application/json",
    }

    def _post(*, via_tor: bool) -> GoogleTitleTranslation:
        pace_google_call()
        with _google_http_client(via_tor=via_tor) as client:
            response = client.post(
                "https://translate.googleapis.com/translate_a/single",
                data=form,
                headers=headers,
            )
            return _parse_google_translate_response(response)

    def _fail_tor(exc: Exception) -> None:
        # Tor also captcha/429 ⇒ cool Google entirely; batch must use Ollama/MyMemory.
        if _is_google_rate_limit_error(exc) or "redirected" in str(exc).lower():
            trip_google_circuit(
                float(getattr(settings, "GOOGLE_TRANSLATE_CIRCUIT_SEC", 300) or 300)
            )

    # Circuit open ⇒ never hit burned direct IP; Tor only when available.
    if is_google_circuit_open():
        if not _google_tor_fallback_enabled():
            raise TitleTranslateError("Google Translate circuit open after 429")
        try:
            return _post(via_tor=True)
        except (TitleTranslateError, httpx.HTTPError, ValueError) as tor_exc:
            _fail_tor(tor_exc)
            raise TitleTranslateError(
                f"Google Translate via Tor failed: {tor_exc}"
            ) from tor_exc

    try:
        return _post(via_tor=False)
    except TitleTranslateError as direct_exc:
        if not (
            _is_google_rate_limit_error(direct_exc)
            or "redirected" in str(direct_exc).lower()
        ):
            raise
        trip_google_circuit()
        if not _google_tor_fallback_enabled():
            raise
        logger.info("google translate direct blocked (%s); retrying via Tor", direct_exc)
        try:
            return _post(via_tor=True)
        except (TitleTranslateError, httpx.HTTPError, ValueError) as tor_exc:
            _fail_tor(tor_exc)
            raise TitleTranslateError(
                f"Google Translate via Tor failed: {tor_exc}"
            ) from tor_exc
    except (httpx.HTTPError, ValueError) as exc:
        if not _google_tor_fallback_enabled():
            raise TitleTranslateError(f"Google Translate failed: {exc}") from exc
        logger.info("google translate direct error (%s); retrying via Tor", exc)
        try:
            return _post(via_tor=True)
        except (TitleTranslateError, httpx.HTTPError, ValueError) as tor_exc:
            _fail_tor(tor_exc)
            raise TitleTranslateError(
                f"Google Translate failed: {exc}; tor: {tor_exc}"
            ) from tor_exc


def mymemory_fallback_available() -> bool:
    if not getattr(settings, "TITLE_TRANSLATE_ENABLED", True):
        return False
    return bool(getattr(settings, "TITLE_TRANSLATE_MYMEMORY_FALLBACK", True))


def mymemory_translate_title(title: str) -> str:
    """Free MyMemory HTTP fallback when Google is blocked/rate-limited on VPS."""
    text = prepare_title_for_translate(title)
    if not text:
        raise TitleTranslateError("empty title")
    timeout = float(getattr(settings, "GOOGLE_TRANSLATE_TIMEOUT_SEC", 20) or 20)
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(
                "https://api.mymemory.translated.net/get",
                params={"q": text[:500], "langpair": "en|vi"},
            )
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise TitleTranslateError(f"MyMemory Translate failed: {exc}") from exc

    payload = data.get("responseData") if isinstance(data, dict) else None
    translated = ""
    if isinstance(payload, dict):
        translated = str(payload.get("translatedText") or "").strip()
    # MyMemory echoes the source when quota is exhausted.
    if not translated or translated.casefold() == text.casefold():
        raise TitleTranslateError("MyMemory Translate returned empty/unchanged text")
    if "MYMEMORY WARNING" in translated.upper():
        raise TitleTranslateError("MyMemory Translate quota warning")
    return translated[:512]


def _try_mymemory_fallback(threat: Threat, title: str) -> str | None:
    """Persist a validated MyMemory translation after Google fails."""
    if not mymemory_fallback_available():
        return None
    try:
        translated = mymemory_translate_title(title)
    except TitleTranslateError as exc:
        logger.warning("mymemory fallback failed threat=%s: %s", threat.id, exc)
        return None
    if is_mangled_title_vi(translated, provider="mymemory"):
        logger.warning("mymemory fallback rejected threat=%s: invalid Vietnamese", threat.id)
        return None
    _persist_translation(
        threat,
        title_vi=translated,
        status=Threat.TitleViStatus.OK,
        provider="mymemory",
    )
    return "mymemory"


def needs_ai_refine(
    original: str,
    draft: str,
    *,
    wire_priority: int = 0,
) -> bool:
    """
    Optional Ollama polish — only for high-priority Wire titles when enabled.

    Default TITLE_TRANSLATE_AI_REFINE=false (Google-only = cheapest).
    When refine is on, skip low-priority noise to save local LLM tokens.
    """
    if not getattr(settings, "TITLE_TRANSLATE_AI_REFINE", False):
        return False
    min_pri = int(getattr(settings, "TITLE_TRANSLATE_AI_MIN_PRIORITY", 50) or 50)
    if int(wire_priority or 0) < min_pri:
        return False
    return True


def build_refine_prompt(title: str, draft: str) -> str:
    template = getattr(settings, "TITLE_TRANSLATE_REFINE_PROMPT", "") or DEFAULT_REFINE_PROMPT
    return template.replace("{title}", title.strip()).replace("{draft}", draft.strip())


def ollama_available() -> bool:
    if not getattr(settings, "TITLE_TRANSLATE_ENABLED", True):
        return False
    if not getattr(settings, "OLLAMA_ENABLED", False):
        return False
    if not getattr(settings, "TITLE_TRANSLATE_AI_REFINE", False):
        return False
    base = (getattr(settings, "OLLAMA_BASE_URL", "") or "").strip()
    return bool(base)


def ollama_fallback_available() -> bool:
    if not getattr(settings, "TITLE_TRANSLATE_ENABLED", True):
        return False
    if not getattr(settings, "TITLE_TRANSLATE_OLLAMA_FALLBACK", True):
        return False
    if not getattr(settings, "OLLAMA_ENABLED", False):
        return False
    return bool((getattr(settings, "OLLAMA_BASE_URL", "") or "").strip())


def groq_translate_available() -> bool:
    if not getattr(settings, "TITLE_TRANSLATE_ENABLED", True):
        return False
    if not getattr(settings, "TITLE_TRANSLATE_GROQ", True):
        return False
    from apps.integrations.ai.groq_pool import groq_keys_configured

    return groq_keys_configured()


def prefer_groq_translate() -> bool:
    """True when Groq should run before Google — false while Groq circuit is open."""
    if not groq_translate_available():
        return False
    if not bool(getattr(settings, "TITLE_TRANSLATE_PREFER_GROQ", True)):
        return False
    if is_groq_circuit_open():
        return False
    try:
        from apps.integrations.ai.groq_pool import (
            is_groq_pool_circuit_open,
            ready_groq_key_count,
        )

        if is_groq_pool_circuit_open() or ready_groq_key_count() <= 0:
            return False
    except Exception:  # noqa: BLE001
        pass
    return True


def accept_groq_translation(original: str, translated: str) -> bool:
    """Validate Groq output (CTI Wire): Vietnamese, no CJK leftover, brands intact."""
    text = normalize_translated_title(original, translated).strip()
    if not text:
        return False
    if re.fullmatch(r"[?¿!\s.…]{2,}", text):
        return False
    if translation_still_cjk(original, text):
        return False
    if has_foreign_script(text, original=original):
        return False
    if is_mangled_title_vi(text, provider="groq", original=original):
        return False
    if looks_vietnamese(text):
        return True
    if is_cjk_title(original) and vietnamese_ratio(text) >= 0.08:
        return english_remnant_count(original, text) <= 2
    return False


def groq_translate_title(title: str) -> str:
    """Translate a title via Groq multi-key pool (preferred over Google/Ollama)."""
    from apps.integrations.ai.groq_pool import groq_chat_completion

    model = (
        getattr(settings, "GROQ_MODEL", "llama-3.3-70b-versatile")
        or "llama-3.3-70b-versatile"
    )
    timeout = float(getattr(settings, "GROQ_TIMEOUT_SEC", 12) or 12)
    prepared = prepare_title_for_translate(title)
    if is_cjk_title(title):
        user_prompt = (
            f"{_CTI_WIRE_TRANSLATION_DOCTRINE}\n\n"
            "## Current job\n"
            "Translate this Chinese/Japanese/Korean CTI title into formal Vietnamese. "
            "No Han/Kanji/Hangul left. Keep brand names Latin (Hugging Face, OpenAI…). "
            "Output ONLY one Vietnamese title line.\n\n"
            f"Source title:\n{prepared}"
        )
    else:
        user_prompt = (
            getattr(settings, "TITLE_TRANSLATE_FALLBACK_PROMPT", "")
            or DEFAULT_FALLBACK_PROMPT
        ).replace("{title}", prepared)
    try:
        result = groq_chat_completion(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert CTI / cyber-security translator. "
                        "Translate news titles into formal Vietnamese. "
                        "Preserve meaning exactly; do not invent countries, people, or facts. "
                        "Keep brand names and CVE IDs in Latin "
                        "(Hugging Face, OpenAI, LockBit, CVE-…). "
                        "Never translate brands literally "
                        '(e.g. Hugging Face Servers → máy chủ Hugging Face, NOT "ôm mặt"). '
                        "Reply with ONLY the Vietnamese title — no quotes, notes, or explanation."
                    ),
                },
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=160 if is_cjk_title(title) else 120,
            temperature=0.1,
            model=model,
            timeout=timeout,
        )
    except Exception as exc:
        from apps.integrations.ai.groq_pool import GroqUnavailable

        if isinstance(exc, (GroqUnavailable, RuntimeError)):
            raise TitleTranslateError(str(exc)) from exc
        raise
    text = normalize_translated_title(
        title, _clean_model_output(str(result.get("text") or ""))
    )[:512]
    if not text:
        raise TitleTranslateError("Groq returned empty text")
    if not accept_groq_translation(title, text):
        raise TitleTranslateError(f"unaccepted draft: {text[:80]}")
    return text


def ollama_translate_title(title: str) -> str:
    """Translate via shared Ollama (NewsCrawler nc-ollama); preferred for CJK / non-EN rescue."""
    base = (getattr(settings, "OLLAMA_BASE_URL", "") or "").rstrip("/")
    model = getattr(settings, "OLLAMA_TRANSLATE_MODEL", "qwen2.5:3b")
    timeout = float(getattr(settings, "OLLAMA_TIMEOUT_SEC", 120) or 120)
    default_predict = 128 if is_cjk_title(title) else 96
    num_predict = int(
        getattr(settings, "OLLAMA_NUM_PREDICT", default_predict) or default_predict
    )
    num_ctx = int(getattr(settings, "OLLAMA_NUM_CTX", 1024) or 1024)
    keep_alive = getattr(settings, "OLLAMA_KEEP_ALIVE", "15m")
    template = (
        getattr(settings, "TITLE_TRANSLATE_FALLBACK_PROMPT", "")
        or DEFAULT_FALLBACK_PROMPT
    )
    prepared = prepare_title_for_translate(title)
    prompts = [template.replace("{title}", prepared)]
    if is_cjk_title(title):
        prompts.append(
            f"{_CTI_WIRE_TRANSLATION_DOCTRINE}\n\n"
            "## Current job\n"
            "Translate fully into Vietnamese. No Han/Kanji/Hangul left. "
            "Output ONLY one Vietnamese title.\n\n"
            f"Source title:\n{prepared}"
        )
    else:
        prompts.append(
            f"{_CTI_WIRE_TRANSLATION_DOCTRINE}\n\n"
            "## Current job\n"
            "Translate into Vietnamese. Do not invent places or actors. "
            "Do not leave source content words untranslated. "
            "Output ONLY one Vietnamese title.\n\n"
            f"Source title:\n{prepared}"
        )

    last_error: BaseException | None = None
    for prompt in prompts:
        body = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "keep_alive": keep_alive,
            "options": {
                "temperature": 0.05,
                "num_predict": max(48, num_predict),
                "num_ctx": max(512, num_ctx),
                "top_p": 0.9,
            },
        }
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(f"{base}/api/generate", json=body)
                response.raise_for_status()
                data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            last_error = exc
            continue
        text = _clean_model_output(str(data.get("response") or ""))
        if not text:
            last_error = TitleTranslateError("Ollama fallback returned empty text")
            continue
        if accept_ollama_translation(title, text):
            return text[:512]
        last_error = TitleTranslateError("Ollama fallback failed validation")
    raise TitleTranslateError(
        f"Ollama fallback failed: {last_error or 'invalid output'}"
    )

def ollama_refine_title(title: str, draft: str) -> str:
    base = (getattr(settings, "OLLAMA_BASE_URL", "") or "").rstrip("/")
    model = getattr(settings, "OLLAMA_TRANSLATE_MODEL", "qwen2.5:3b")
    timeout = float(getattr(settings, "OLLAMA_TIMEOUT_SEC", 120) or 120)
    num_predict = int(getattr(settings, "OLLAMA_NUM_PREDICT", 128) or 128)
    num_ctx = int(getattr(settings, "OLLAMA_NUM_CTX", 1024) or 1024)
    keep_alive = getattr(settings, "OLLAMA_KEEP_ALIVE", "15m")
    url = f"{base}/api/generate"
    body = {
        "model": model,
        "prompt": build_refine_prompt(title, draft),
        "stream": False,
        "keep_alive": keep_alive,
        "options": {
            "temperature": 0.1,
            "num_predict": num_predict,
            "num_ctx": max(512, num_ctx),
        },
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.post(url, json=body)
    except httpx.HTTPError as exc:
        raise TitleTranslateError(f"Ollama refine failed: {exc}") from exc

    data = response.json() if response.content else {}
    if response.status_code >= 400:
        raise TitleTranslateError(
            f"Ollama HTTP {response.status_code}: {data.get('error') or data}"
        )
    text = _clean_model_output(str(data.get("response") or ""))
    if not text:
        raise TitleTranslateError("Ollama refine returned empty text")
    return text[:512]


def _clean_model_output(text: str) -> str:
    cleaned = (text or "").strip()
    if "\n" in cleaned:
        lines = [ln.strip() for ln in cleaned.splitlines() if ln.strip()]
        cleaned = lines[-1] if lines else cleaned
    cleaned = cleaned.strip().strip('"').strip("'").strip("`")
    prefixes = (
        "vietnamese:",
        "translation:",
        "title:",
        "bản dịch:",
        "tiêu đề:",
    )
    low = cleaned.casefold()
    for prefix in prefixes:
        if low.startswith(prefix):
            cleaned = cleaned[len(prefix) :].strip()
            break
    return cleaned


def cached_translation(title: str) -> Threat | None:
    digest = title_hash(title)
    return (
        Threat.objects.filter(title_hash=digest, title_vi_status__in=["ok", "rule"])
        .exclude(title_vi="")
        .exclude(title_vi_provider="rule")  # avoid reusing old phrase-rule hybrids
        .filter(
            Q(title_vi_provider__startswith="google")
            | Q(title_vi_provider__startswith="cache:")
            | Q(title_vi_provider__startswith="ollama")
            | Q(title_vi_provider__startswith="groq")
            | Q(title_vi_provider="skip_vi")
        )
        .order_by("-id")
        .only("id", "title_vi", "title_vi_status", "title_vi_provider")
        .first()
    )


def _persist_translation(
    threat: Threat,
    *,
    title_vi: str,
    status: str,
    provider: str,
) -> None:
    cleaned = normalize_translated_title(threat.title or "", title_vi)
    threat.title_vi = cleaned[:512]
    threat.title_vi_status = status
    threat.title_vi_provider = provider[:64]
    threat.title_vi_translated_at = timezone.now()
    threat.title_hash = title_hash(threat.title or "")
    threat.save(
        update_fields=[
            "title_vi",
            "title_vi_status",
            "title_vi_provider",
            "title_vi_translated_at",
            "title_hash",
            "updated_at",
        ]
    )
    # After VI text exists, re-scan geo/topic tags (non-EN posts often miss flags).
    try:
        from apps.workers.services import enrich_threat_tags

        enrich_threat_tags(threat)
    except Exception:  # noqa: BLE001 — translation must not fail on retag
        logger.debug("enrich_threat_tags failed threat=%s", threat.id, exc_info=True)


def apply_inline_rule_translation(threat: Threat) -> bool:
    """Instant path: Vietnamese skip, cache, structured rule, or inline Google."""
    title = threat.title or ""
    threat.title_hash = title_hash(title)

    if looks_vietnamese(title) and vietnamese_ratio(title) >= 0.12:
        _persist_translation(
            threat,
            title_vi=title,
            status=Threat.TitleViStatus.SKIPPED,
            provider="skip_vi",
        )
        return True

    hit = cached_translation(title)
    if hit:
        _persist_translation(
            threat,
            title_vi=hit.title_vi,
            status=hit.title_vi_status,
            provider=f"cache:{hit.title_vi_provider}"[:64],
        )
        return True

    ruled = rule_translate_title(title)
    if ruled and is_structured_ransomware_title(title):
        _persist_translation(
            threat,
            title_vi=ruled,
            status=Threat.TitleViStatus.RULE,
            provider="rule",
        )
        return True

    # CJK / high-quality LLM: prefer Groq (shared pool), then Ollama, before Google.
    if cjk_prefer_ollama() and is_cjk_title(title):
        if _try_ai_fallback(threat, title):
            return True
    elif prefer_groq_translate():
        if _try_groq_fallback(threat, title):
            return True

    # Realtime: Google Translate inline so Wire shows Vietnamese immediately.
    if getattr(settings, "TITLE_TRANSLATE_INLINE_GOOGLE", True):
        try:
            google_result = google_translate_title(title)
            if isinstance(google_result, GoogleTitleTranslation):
                draft = google_result.text
                detected = (google_result.source_language or "").lower()
            else:
                draft = str(google_result or "").strip()
                detected = ""
            if detected.startswith("vi") or (
                looks_vietnamese(title) and vietnamese_ratio(title) >= 0.12
            ):
                _persist_translation(
                    threat,
                    title_vi=(title.strip() or draft)[:512],
                    status=Threat.TitleViStatus.SKIPPED,
                    provider="google:detected_vi",
                )
                return True
            _persist_translation(
                threat,
                title_vi=draft,
                status=Threat.TitleViStatus.OK,
                provider="google",
            )
            # Queue LLM rescue only when Google is poor, or non-EN may beat Google.
            if (
                google_draft_needs_ollama(title, draft)
                or (
                    non_english_ollama_compare()
                    and is_non_english_source(title, detected)
                )
            ) and (groq_translate_available() or ollama_fallback_available()):
                enqueue_title_translations([threat.id])
            return True
        except TitleTranslateError as exc:
            logger.info("inline google skipped threat=%s: %s", threat.id, exc)
            if _try_ai_fallback(threat, title):
                return True

    threat.title_vi_status = Threat.TitleViStatus.PENDING
    threat.save(update_fields=["title_hash", "title_vi_status", "updated_at"])
    return False


def _should_force_retranslate(threat: Threat) -> bool:
    """Re-run translation on mangled drafts; never churn structured ransomware rules."""
    if is_structured_ransomware_title(threat.title or "") and (
        threat.title_vi_status == Threat.TitleViStatus.RULE
        or str(threat.title_vi_provider or "") == "rule"
    ):
        return False
    if is_mangled_title_vi(
        threat.title_vi or "",
        provider=str(threat.title_vi_provider or ""),
        original=threat.title or "",
    ):
        return True
    if threat.title_vi_status != Threat.TitleViStatus.RULE:
        return False
    if is_structured_ransomware_title(threat.title or ""):
        return False
    return True


def _try_ollama_refine(
    threat: Threat,
    title: str,
    google_draft: str,
    *,
    google_only: bool = False,
) -> str | None:
    """Return provider string if refine accepted; None to keep Google draft."""
    if google_only:
        return None
    if (
        not needs_ai_refine(
            title,
            google_draft,
            wire_priority=int(threat.wire_priority or 0),
        )
        or not ollama_available()
    ):
        return None
    try:
        refined = ollama_refine_title(title, google_draft)
    except TitleTranslateError as exc:
        logger.info("ai refine skipped threat=%s: %s", threat.id, exc)
        return None
    if not accept_refine_result(title, google_draft, refined):
        logger.info(
            "ai refine rejected threat=%s: output worse than google draft",
            threat.id,
        )
        return None
    provider = f"google+ollama:{getattr(settings, 'OLLAMA_TRANSLATE_MODEL', 'qwen2.5:3b')}"
    _persist_translation(
        threat,
        title_vi=refined,
        status=Threat.TitleViStatus.OK,
        provider=provider[:64],
    )
    return provider


def _try_groq_fallback(threat: Threat, title: str) -> str | None:
    """Persist a validated Groq translation (preferred cloud LLM path)."""
    if not groq_translate_available() or is_groq_circuit_open():
        return None
    try:
        translated = groq_translate_title(title)
    except TitleTranslateError as exc:
        logger.warning("groq translate failed threat=%s: %s", threat.id, exc)
        note_groq_failure(reason=str(exc)[:120])
        return None
    note_groq_success()
    model = getattr(settings, "GROQ_MODEL", "llama-3.3-70b-versatile")
    provider = f"groq:{model}"[:64]
    _persist_translation(
        threat,
        title_vi=translated,
        status=Threat.TitleViStatus.OK,
        provider=provider,
    )
    return provider


def _try_ai_fallback(threat: Threat, title: str) -> str | None:
    """Prefer Groq (shared key pool), then local Ollama as last LLM resort."""
    hit = _try_groq_fallback(threat, title)
    if hit:
        return hit
    return _try_ollama_fallback(threat, title)


def _existing_draft_is_usable(threat: Threat, title: str) -> bool:
    """Prefer keeping a prior Google/MyMemory draft over a worse Ollama rewrite."""
    draft = (threat.title_vi or "").strip()
    if not draft:
        return False
    provider = str(threat.title_vi_provider or "")
    if provider.startswith(("ollama-fallback", "google+ollama")):
        return False
    if is_mangled_title_vi(draft, provider=provider, original=title):
        return False
    return looks_vietnamese(draft) or english_remnant_count(title, draft) <= 2


def _try_ollama_fallback(threat: Threat, title: str) -> str | None:
    """Persist a validated Ollama translation after Google fails / draft is poor."""
    if not ollama_fallback_available():
        return None
    # When Google is rate-limited, do not trash a usable prior draft with qwen garble.
    if _google_circuit_open() and _existing_draft_is_usable(threat, title):
        logger.info(
            "ollama fallback skipped threat=%s: keeping usable draft while Google circuit open",
            threat.id,
        )
        return None
    try:
        translated = ollama_translate_title(title)
    except TitleTranslateError as exc:
        logger.warning("ollama fallback failed threat=%s: %s", threat.id, exc)
        return None
    if not accept_ollama_translation(title, translated):
        logger.warning("ollama fallback rejected threat=%s: invalid Vietnamese", threat.id)
        return None
    existing = (threat.title_vi or "").strip()
    provider_now = str(threat.title_vi_provider or "")
    if (
        existing
        and provider_now.startswith("google")
        and not provider_now.startswith("google+ollama")
        and not ollama_beats_google(title, existing, translated)
    ):
        logger.info("ollama fallback rejected threat=%s: worse than google draft", threat.id)
        return None
    provider = (
        f"ollama-fallback:{getattr(settings, 'OLLAMA_TRANSLATE_MODEL', 'qwen2.5:3b')}"
    )
    _persist_translation(
        threat,
        title_vi=translated,
        status=Threat.TitleViStatus.OK,
        provider=provider[:64],
    )
    return provider


def _try_ollama_compare_non_en(
    threat: Threat, title: str, google_draft: str, *, detected: str = ""
) -> str | None:
    """For non-English sources: run Ollama and keep it only if better than Google."""
    if not non_english_ollama_compare():
        return None
    if not is_non_english_source(title, detected):
        return None
    if not ollama_fallback_available():
        return None
    try:
        translated = ollama_translate_title(title)
    except TitleTranslateError as exc:
        logger.info("non-en ollama compare skipped threat=%s: %s", threat.id, exc)
        return None
    if not ollama_beats_google(title, google_draft, translated):
        logger.info(
            "non-en ollama compare kept google threat=%s (ollama not better)",
            threat.id,
        )
        return None
    provider = (
        f"ollama-fallback:{getattr(settings, 'OLLAMA_TRANSLATE_MODEL', 'qwen2.5:3b')}"
    )
    _persist_translation(
        threat,
        title_vi=translated,
        status=Threat.TitleViStatus.OK,
        provider=provider[:64],
    )
    return provider


def translate_threat(threat: Threat, *, force: bool = False) -> dict[str, Any]:
    """Translate one threat: Groq → Google → Ollama when needed.

    Order (NewsCrawler-aligned, CTI-tuned):
    1. Skip Vietnamese / cache / ransomware rule
    2. Groq first (shared multi-key pool with NewsCrawler)
    3. CJK leftovers: Ollama if Groq unavailable
    4. Google auto→VI (Tor fallback on captcha)
    5. If Google draft is poor → Groq/Ollama rescue
    6. Non-English: compare LLM vs Google, keep better VI
    7. MyMemory last resort
    """
    title = threat.title or ""
    if not title.strip():
        threat.title_vi_status = Threat.TitleViStatus.SKIPPED
        threat.title_vi_provider = "empty"
        threat.save(update_fields=["title_vi_status", "title_vi_provider", "updated_at"])
        return {"id": threat.id, "status": "skipped", "provider": "empty"}

    # Source already Vietnamese — keep as-is, never spend provider tokens.
    if looks_vietnamese(title) and vietnamese_ratio(title) >= 0.12:
        if (
            not force
            and threat.title_vi
            and threat.title_vi_status
            in {Threat.TitleViStatus.OK, Threat.TitleViStatus.SKIPPED}
        ):
            return {
                "id": threat.id,
                "status": threat.title_vi_status,
                "provider": threat.title_vi_provider,
                "cached": True,
            }
        _persist_translation(
            threat,
            title_vi=title.strip()[:512],
            status=Threat.TitleViStatus.SKIPPED,
            provider="skip_vi",
        )
        return {"id": threat.id, "status": "skipped", "provider": "skip_vi"}

    force = force or _should_force_retranslate(threat)

    # Good Groq draft already stored — leave alone unless force/mangled.
    if (
        not force
        and threat.title_vi
        and threat.title_vi_status == Threat.TitleViStatus.OK
        and str(threat.title_vi_provider or "").startswith("groq")
    ):
        return {
            "id": threat.id,
            "status": threat.title_vi_status,
            "provider": threat.title_vi_provider,
            "cached": True,
        }

    # Good Google draft already stored: rescue only when poor / non-EN compare.
    if (
        not force
        and threat.title_vi
        and threat.title_vi_status == Threat.TitleViStatus.OK
        and str(threat.title_vi_provider or "").startswith("google")
        and not str(threat.title_vi_provider or "").startswith("google+ollama")
    ):
        if google_draft_needs_ollama(title, threat.title_vi):
            rescued = _try_ai_fallback(threat, title)
            if rescued:
                return {"id": threat.id, "status": "ok", "provider": rescued}
        elif is_non_english_source(title):
            compared = _try_ollama_compare_non_en(threat, title, threat.title_vi)
            if compared:
                return {"id": threat.id, "status": "ok", "provider": compared}
            # Prefer Groq over Ollama for non-EN compare when Google is mediocre.
            if prefer_groq_translate():
                groq_hit = _try_groq_fallback(threat, title)
                if groq_hit:
                    return {"id": threat.id, "status": "ok", "provider": groq_hit}
        elif needs_ai_refine(
            title, threat.title_vi, wire_priority=int(threat.wire_priority or 0)
        ):
            provider = _try_ollama_refine(threat, title, threat.title_vi)
            if provider:
                return {"id": threat.id, "status": "ok", "provider": provider}
        return {
            "id": threat.id,
            "status": threat.title_vi_status,
            "provider": threat.title_vi_provider,
            "cached": True,
        }

    if (
        not force
        and threat.title_vi
        and threat.title_vi_status
        in {
            Threat.TitleViStatus.OK,
            Threat.TitleViStatus.RULE,
            Threat.TitleViStatus.SKIPPED,
        }
    ):
        return {
            "id": threat.id,
            "status": threat.title_vi_status,
            "provider": threat.title_vi_provider,
            "cached": True,
        }

    if not force:
        apply_inline_rule_translation(threat)
        threat.refresh_from_db(
            fields=["title_vi", "title_vi_status", "title_vi_provider", "title_hash"]
        )
        if threat.title_vi and threat.title_vi_status != Threat.TitleViStatus.PENDING:
            provider_now = str(threat.title_vi_provider or "")
            if provider_now.startswith("google") and not provider_now.startswith(
                "google+ollama"
            ):
                if google_draft_needs_ollama(title, threat.title_vi):
                    rescued = _try_ai_fallback(threat, title)
                    if rescued:
                        return {"id": threat.id, "status": "ok", "provider": rescued}
                elif is_non_english_source(title):
                    compared = _try_ollama_compare_non_en(
                        threat, title, threat.title_vi
                    )
                    if compared:
                        return {"id": threat.id, "status": "ok", "provider": compared}
                elif needs_ai_refine(
                    title,
                    threat.title_vi,
                    wire_priority=int(threat.wire_priority or 0),
                ):
                    refined = _try_ollama_refine(threat, title, threat.title_vi)
                    if refined:
                        return {"id": threat.id, "status": "ok", "provider": refined}
            return {
                "id": threat.id,
                "status": threat.title_vi_status,
                "provider": threat.title_vi_provider,
            }

    # Groq-first (NewsCrawler): shared key pool before Google captcha risk.
    if prefer_groq_translate():
        groq_provider = _try_groq_fallback(threat, title)
        if groq_provider:
            return {
                "id": threat.id,
                "status": "ok",
                "provider": groq_provider,
                "google_skipped": True,
            }

    # CJK leftovers: Ollama after Groq miss.
    if cjk_prefer_ollama() and is_cjk_title(title) and ollama_fallback_available():
        rescued = _try_ollama_fallback(threat, title)
        if rescued:
            return {"id": threat.id, "status": "ok", "provider": rescued}

    try:
        if is_google_circuit_open() and not _google_tor_fallback_enabled():
            raise TitleTranslateError("Google Translate circuit open after 429")
        google_result = google_translate_title(title)
    except TitleTranslateError as exc:
        logger.warning("google translate failed threat=%s: %s", threat.id, exc)
        if _is_google_rate_limit_error(exc) or "circuit open" in str(exc).lower():
            if not is_google_circuit_open() and "circuit open" not in str(exc).lower():
                trip_google_circuit()
        fallback_provider = _try_ai_fallback(threat, title)
        if fallback_provider:
            return {
                "id": threat.id,
                "status": "ok",
                "provider": fallback_provider,
            }
        fallback_provider = _try_mymemory_fallback(threat, title)
        if fallback_provider:
            return {
                "id": threat.id,
                "status": "ok",
                "provider": fallback_provider,
            }
        if _existing_draft_is_usable(threat, title):
            return {
                "id": threat.id,
                "status": threat.title_vi_status or Threat.TitleViStatus.OK,
                "provider": threat.title_vi_provider,
                "cached": True,
            }
        threat.title_vi_status = Threat.TitleViStatus.PENDING
        threat.title_vi_provider = "awaiting_google"
        threat.save(
            update_fields=["title_vi_status", "title_vi_provider", "updated_at"]
        )
        return {"id": threat.id, "status": "pending", "provider": "awaiting_google"}

    if isinstance(google_result, GoogleTitleTranslation):
        draft = google_result.text
        detected = (google_result.source_language or "").lower()
    else:
        draft = str(google_result or "").strip()
        detected = ""

    # Google says source is already Vietnamese — keep source text.
    if detected.startswith("vi") or (
        looks_vietnamese(title) and vietnamese_ratio(title) >= 0.12
    ):
        _persist_translation(
            threat,
            title_vi=(title.strip() or draft)[:512],
            status=Threat.TitleViStatus.SKIPPED,
            provider="google:detected_vi",
        )
        return {"id": threat.id, "status": "skipped", "provider": "google:detected_vi"}

    # Never store placeholder garbage like "????".
    if re.fullmatch(r"[?¿!\s.…]{2,}", draft.strip()):
        rescued = _try_ai_fallback(threat, title)
        if rescued:
            return {"id": threat.id, "status": "ok", "provider": rescued}
        threat.title_vi_status = Threat.TitleViStatus.PENDING
        threat.title_vi_provider = "awaiting_google"
        threat.save(
            update_fields=["title_vi_status", "title_vi_provider", "updated_at"]
        )
        return {"id": threat.id, "status": "pending", "provider": "awaiting_google"}

    # Persist Google first so Wire can show Vietnamese immediately.
    _persist_translation(
        threat,
        title_vi=draft,
        status=Threat.TitleViStatus.OK,
        provider="google",
    )

    # LLM rescue only when Google draft is actually poor.
    if google_draft_needs_ollama(title, draft):
        rescued = _try_ai_fallback(threat, title)
        if rescued:
            return {"id": threat.id, "status": "ok", "provider": rescued}

    # Non-English: compare Ollama; keep only when clearly better.
    if is_non_english_source(title, detected):
        compared = _try_ollama_compare_non_en(
            threat, title, draft, detected=detected
        )
        if compared:
            return {"id": threat.id, "status": "ok", "provider": compared}

    provider = "google"
    if needs_ai_refine(title, draft, wire_priority=int(threat.wire_priority or 0)):
        refined_provider = _try_ollama_refine(threat, title, draft)
        if refined_provider:
            provider = refined_provider

    return {"id": threat.id, "status": "ok", "provider": provider}


def translate_threats(
    threat_ids: list[int] | None = None,
    *,
    limit: int = 40,
    force: bool = False,
) -> dict[str, Any]:
    """Process pending / bad-rule titles via Google (sequential, rate-friendly)."""
    qs = Threat.objects.all().order_by("-wire_priority", "-published_at", "-id")
    if threat_ids:
        qs = qs.filter(id__in=threat_ids)
    else:
        # Only unfinished / known-bad titles. Valid rule/google results stay untouched.
        qs = qs.filter(
            Q(title_vi_status=Threat.TitleViStatus.PENDING)
            | Q(title_vi_status=Threat.TitleViStatus.FAILED)
            | Q(title_vi="")
            | Q(title_vi_provider__startswith="google+ollama")
            | Q(title_vi_provider__startswith="ollama-fallback")
            | Q(title_vi_provider__startswith="mymemory")
            | (
                Q(title_vi_status=Threat.TitleViStatus.RULE)
                & ~Q(title__istartswith="Ransomware:")
            )
        ).exclude(title_vi_status=Threat.TitleViStatus.SKIPPED)
    rows = list(qs[: max(1, limit * 3)])
    selected: list[Threat] = []
    for threat in rows:
        if threat_ids:
            selected.append(threat)
        elif force:
            selected.append(threat)
        elif _should_force_retranslate(threat):
            selected.append(threat)
        elif is_mangled_title_vi(
            threat.title_vi or "",
            provider=str(threat.title_vi_provider or ""),
        ):
            selected.append(threat)
        elif threat.title_vi_status in {
            Threat.TitleViStatus.PENDING,
            Threat.TitleViStatus.FAILED,
        } or not (threat.title_vi or "").strip():
            selected.append(threat)
        if len(selected) >= max(1, limit):
            break

    stats = {
        "processed": 0,
        "ok": 0,
        "rule": 0,
        "failed": 0,
        "skipped": 0,
        "cached": 0,
        "pending": 0,
    }
    for threat in selected:
        result = translate_threat(
            threat,
            force=force or _should_force_retranslate(threat),
        )
        stats["processed"] += 1
        status = result.get("status") or ""
        if result.get("cached"):
            stats["cached"] += 1
        if status in stats:
            stats[status] += 1
    return stats


def enqueue_title_translations(threat_ids: list[int]) -> None:
    """Fire-and-forget Celery enqueue; never raise into ingest path."""
    ids = [int(i) for i in threat_ids if i]
    if not ids:
        return
    if not getattr(settings, "TITLE_TRANSLATE_ENABLED", True):
        return
    try:
        from apps.integrations.tasks import translate_threat_titles_task

        translate_threat_titles_task.delay(ids)
    except Exception:  # noqa: BLE001 — ingest must not fail on broker blips
        logger.exception("enqueue_title_translations failed ids=%s", ids[:5])
