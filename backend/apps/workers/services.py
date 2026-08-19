"""Persist parsed stealer rows and feed payloads into intel models."""

from __future__ import annotations

import hashlib
import logging
import re
from decimal import Decimal, InvalidOperation
from typing import Any
from urllib.parse import urlparse

from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.conf import settings

from apps.core.crypto import encrypt_secret, password_fingerprint
from apps.intel.models import CompromisedCredential, DataLeak, Indicator, Tag, Threat
from apps.intel.watching import (
    match_indicator_against_rules,
    match_leak_against_rules,
    match_threat_against_rules,
)
from apps.workers.feed_dates import clamp_published_at, is_within_max_age, parse_feed_datetime
from apps.workers.geography import detect_geography_tag_slugs
from apps.workers.parsers.stealer import ParsedCredential, parse_stealer_log

logger = logging.getLogger(__name__)

BREACH_KEYWORDS = (
    "data breach",
    "databreach",
    "data leak",
    "dataleak",
    "leaked",
    "credential dump",
    "credentials leaked",
    "exposed database",
    "ransomware",
    "stolen data",
    "compromised accounts",
    "have i been pwned",
    "infostealer",
)

# High-signal Wire topics: breaches, leaks, ransomware, malware on orgs — not generic tech.
WIRE_IMPACT_KEYWORDS = (
    *BREACH_KEYWORDS,
    "breach",
    "customer records",
    "citizen records",
    "patient records",
    "records leaked",
    "records exposed",
    "million records",
    "million users",
    "data exposure",
    "database leak",
    "database dump",
    "dark web",
    "leak site",
    "malware attack",
    "malware campaign",
    "ransomware attack",
    "ransomware group",
    "double extortion",
    "exfiltrated",
    "exfiltration",
    # High-signal CTI phrasing that previously fell through as "generic cyber".
    "cyberattack",
    "cyber attack",
    "cyber-attack",
    "hacked",
    "compromised",
    "zero-day",
    "zero day",
    "zeroday",
    "supply chain attack",
    "threat actor",
    "apt group",
    "phishing campaign",
    "stolen credentials",
    "credential stuffing",
    "nation-state",
    "espionage",
    "critical infrastructure",
    "wiper malware",
    "initial access broker",
    "defacement",
    "defaced",
)

WIRE_IMPACT_PATTERNS = tuple(
    re.compile(rf"(?<!\w){re.escape(keyword.casefold())}(?!\w)")
    for keyword in WIRE_IMPACT_KEYWORDS
)

# Precise topic tags — do not confuse "cyberattack" / ransomware claim with data-breach.
_DATA_BREACH_RE = re.compile(
    r"(?i)\b("
    r"data[\s-]?breach|databreach|"
    r"personal data|customer data|patient data|user data|citizen data|health data|"
    r"(customer|patient|citizen|user|employee)\s+(data|database|records?)\b|"
    r"pii\b|phi\b|personally identifiable|"
    r"database\s+(?:\w+\s+){0,3}(leak|dump|breach|exposed)|"
    r"(customer|patient|citizen|user|employee)\s+records?\b|"
    r"records?\s+(leaked|exposed|stolen|compromised)|"
    r"(leaked|exposed|stolen)\s+(?:\d[\d,.\s]*\s*)?(records?|accounts?|credentials?|emails?)|"
    r"credentials?\s+(leaked|exposed|stolen|dump)|"
    r"stolen data|exfiltrated data|data exposure|"
    r"exfiltration|exfiltrated|alleged\s+exfiltration"
    r")\b"
)
_DATA_LEAK_RE = re.compile(
    r"(?i)\b("
    r"data[\s-]?leak|dataleak|"
    r"database\s+(leak|dump)|"
    r"records?\s+leaked|"
    r"leaked\s+(?:\d[\d,.\s]*\s*)?(records?|accounts?|credentials?|emails?|data)|"
    r"credentials?\s+leak"
    r")\b"
)
_RANSOMWARE_TOPIC_RE = re.compile(
    r"(?i)\b(ransomware|ransom\s*ware|lockbit|akira|qilin|cl0p|clop)\b"
)


def looks_like_data_breach(text: str) -> bool:
    """True only for explicit data-breach signals — not every 'breach' / cyberattack."""
    return bool(_DATA_BREACH_RE.search(text or ""))


def looks_like_data_leak(text: str) -> bool:
    return bool(_DATA_LEAK_RE.search(text or ""))


def looks_like_ransomware_topic(text: str) -> bool:
    return bool(_RANSOMWARE_TOPIC_RE.search(text or ""))


# Strong Vietnam identity / geography — safe on machine-translated VI titles.
VIETNAM_STRONG_KEYWORDS = (
    "vietnam",
    "viet nam",
    "việt nam",
    "viet-nam",
    "vietnamese",
    "người việt",
    "hanoi",
    "ha noi",
    "hà nội",
    "ho chi minh",
    "hồ chí minh",
    "saigon",
    "sài gòn",
    "tp.hcm",
    "tp hcm",
    # National CERTs / bodies (content mentions) — NOT X account handles.
    # "vecertradar" must never be a keyword: every tweet URL contains it.
    "vncert",
    "vnisa",
    "bac ninh",
    "bắc ninh",
    "da nang",
    "đà nẵng",
    "hai phong",
    "hải phòng",
    "can tho",
    "cần thơ",
    "越南",
    "ベトナム",
    "베트남",
    "🇻🇳",
)

# Vietnamese company legal forms — only in original content, never as the sole
# signal from a translated title ("các công ty…" / "tập đoàn…" appear for any country).
VIETNAM_COMPANY_KEYWORDS = (
    "công ty cổ phần",
    "cong ty co phan",
    "công ty tnhh",
    "cong ty tnhh",
)

# Back-compat: union used by older imports/tests.
VIETNAM_KEYWORDS = VIETNAM_STRONG_KEYWORDS + VIETNAM_COMPANY_KEYWORDS

# .vn domains / paths are a strong Vietnam signal even without the word "Vietnam".
_VN_TLD_RE = re.compile(r"(?<![a-z0-9-])(?:[a-z0-9-]+\.)+vn\b", re.IGNORECASE)
# Require legal-form suffix — bare "công ty" matches every translated foreign firm.
_VN_ENTITY_RE = re.compile(
    r"c(?:ô|o)ng\s+ty\s+(?:c(?:ổ|o)\s+ph(?:ầ|a)n|tnhh)\b",
    re.IGNORECASE,
)


def vietnam_wire_priority() -> int:
    return int(getattr(settings, "WIRE_VIETNAM_PRIORITY", 100) or 100)


def impact_wire_priority() -> int:
    return int(getattr(settings, "WIRE_IMPACT_PRIORITY", 50) or 50)


# Back-compat aliases for tests/imports.
VIETNAM_WIRE_PRIORITY = 100
IMPACT_WIRE_PRIORITY = 50


def is_vietnam_related(*parts: str, allow_company_forms: bool = True) -> bool:
    """True when title/summary/feed metadata mentions Vietnam.

    ``allow_company_forms=False`` skips bare translated corporate wording so
    VI titles about foreign firms are not pinned as Vietnam intel.
    """
    text = " ".join(str(p or "") for p in parts)
    if not text.strip():
        return False
    folded = text.casefold()
    if any(k.casefold() in folded for k in VIETNAM_STRONG_KEYWORDS):
        return True
    if _VN_TLD_RE.search(text):
        return True
    if allow_company_forms:
        if any(k.casefold() in folded for k in VIETNAM_COMPANY_KEYWORDS):
            return True
        if _VN_ENTITY_RE.search(text):
            return True
    return False


def threat_looks_vietnam_related(
    *,
    title: str = "",
    summary: str = "",
    source_url: str = "",
    raw_payload: Any = None,
    country_code: str = "",
) -> bool:
    """Shared detector for RSS + ransomware ingest and retag backfills.

    Publisher URLs / X handles are NOT content signals (VECERTRadar also posts
    Yemen, regional aviation, etc.). Only ``.vn`` hosts in URLs count.
    """
    payload = raw_payload if isinstance(raw_payload, dict) else {}
    country = str(
        country_code
        or payload.get("country_code")
        or payload.get("country")
        or ""
    ).strip()
    if country.upper() in {"VN", "VNM", "VIETNAM", "VIET NAM"}:
        return True
    content = " ".join(
        [
            title,
            summary,
            str(payload.get("description") or ""),
            str(payload.get("summary") or ""),
            str(payload.get("victim") or ""),
            str(payload.get("domain") or ""),
            str(payload.get("website") or ""),
            country,
        ]
    )
    if is_vietnam_related(content):
        return True
    url_blob = " ".join(
        [
            source_url,
            str(payload.get("post_url") or ""),
            str(payload.get("url") or ""),
            str(payload.get("link") or ""),
            str(payload.get("domain") or ""),
            str(payload.get("website") or ""),
        ]
    )
    return bool(_VN_TLD_RE.search(url_blob))


def is_high_impact_intel(text: str) -> bool:
    """Breach / leak / ransomware / large-scale exposure / malware-on-org signal."""
    return any(pattern.search(text) for pattern in WIRE_IMPACT_PATTERNS)


def is_wire_relevant(item: dict[str, Any]) -> bool:
    """Keep high-impact threat intel; discard generic technology/cyber fluff."""
    category = str(item.get("category") or "news").lower()
    if category in {"breach", "ransomware", "cert", "defacement"}:
        return True
    if str(item.get("discovery") or "") in {
        "zoneh-archive",
        "forum-rss",
        "forum-claim",
        "claim-news",
        "x-wire",
    }:
        return True
    if item.get("forum_claim") or item.get("alleged_claim"):
        return True

    text = " ".join(
        str(item.get(key) or "")
        for key in ("title", "summary", "description", "feed")
    ).casefold()
    if is_high_impact_intel(text):
        return True
    # Vietnam: keep regional security incidents (still exclude pure tech/lifestyle).
    if is_vietnam_related(text) or str(item.get("country_code") or "").upper() == "VN":
        return bool(
            re.search(
                r"\b(cyber|security|breach|leak|ransomware|malware|hack|"
                r"attack|csirt|cert|threat|extortion|compromise|phishing|"
                r"vulnerability|exploit)\b",
                text,
            )
        )
    return False


def website_tag_slug(item: dict[str, Any]) -> str:
    """Return a stable site-* tag for RSS, Tor, sitemap, or Searx items."""
    candidate = str(
        item.get("feed_url")
        or item.get("website_url")
        or item.get("link")
        or item.get("url")
        or ""
    ).strip()
    host = (urlparse(candidate).hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]

    # Onion addresses are unreadable and exceed Tag's max length; use source name.
    if host.endswith(".onion"):
        host = str(item.get("feed") or "onion").strip().lower()
    if not host:
        host = str(item.get("feed") or "").strip().lower()

    clean = re.sub(r"[^a-z0-9]+", "-", host).strip("-")
    if not clean:
        return ""
    return f"site-{clean}"[:64].rstrip("-")


def _classify_rss_item(item: dict[str, Any]) -> tuple[str, str, list[str], Decimal, int]:
    """Return (threat_source, severity, tag_slugs, evidence_score, wire_priority)."""
    category = str(item.get("category") or "news").lower()
    discovery = str(item.get("discovery") or "")
    is_defacement = discovery == "zoneh-archive" or category == "defacement"
    is_forum_claim = bool(item.get("forum_claim")) or discovery in {
        "forum-rss",
        "forum-claim",
    }
    is_claim_news = bool(item.get("alleged_claim")) or discovery == "claim-news"
    is_x_wire = discovery == "x-wire" or str(item.get("engine") or "") == "x_twitter"
    text = f"{item.get('title') or ''} {item.get('summary') or ''} {item.get('description') or ''}".lower()
    meta = (
        f"{item.get('feed') or ''} {item.get('country') or ''} "
        f"{item.get('country_code') or ''} {item.get('link') or ''} {item.get('url') or ''}"
    )
    hit = is_high_impact_intel(text)
    vietnam = threat_looks_vietnam_related(
        title=str(item.get("title") or ""),
        summary=f"{item.get('summary') or ''} {item.get('description') or ''}",
        source_url=str(item.get("link") or item.get("url") or ""),
        raw_payload=item,
        country_code=str(item.get("country_code") or ""),
    ) or is_vietnam_related(meta)

    # Do not emit noisy generic tags ("rss", "news", "alleged-claim") into Wire.
    tags: list[str] = []
    if is_defacement:
        tags.append("defacement")
    elif is_forum_claim:
        tags.append("forum")
    elif is_x_wire:
        tags.append("x")
        handle = str(item.get("x_handle") or "").lstrip("@").strip().lower()
        if handle:
            tags.append(f"x-{re.sub(r'[^a-z0-9]+', '-', handle).strip('-')}"[:64])
    elif is_claim_news:
        pass  # Topic tags come from content signals below — no generic claim stamp.
    elif category and category not in {"news", "other", "breach"}:
        # Avoid auto-tagging category=breach as data-breach (often wrong for claims).
        tags.append(category)
    website_tag = website_tag_slug(item)
    if website_tag:
        tags.append(website_tag)

    if category == "cert":
        source = Threat.Source.CERT
        severity = Threat.Severity.MEDIUM
        score = Decimal("55")
    elif is_defacement:
        source = Threat.Source.NEWS
        severity = Threat.Severity.HIGH
        score = Decimal("70")
    elif is_x_wire:
        source = Threat.Source.X
        severity = Threat.Severity.MEDIUM
        score = Decimal("60")
    elif is_forum_claim or is_claim_news:
        # Alleged claim / secondary reporting — lower evidence than confirmed breach.
        source = Threat.Source.NEWS
        severity = Threat.Severity.MEDIUM
        score = Decimal("58")
    elif category == "breach":
        source = Threat.Source.NEWS
        severity = Threat.Severity.HIGH
        score = Decimal("75")
    elif category == "ransomware":
        source = Threat.Source.RANSOMWARE
        severity = Threat.Severity.HIGH
        score = Decimal("70")
        if "ransomware" not in tags:
            tags.append("ransomware")
    else:
        source = Threat.Source.NEWS
        severity = Threat.Severity.MEDIUM
        score = Decimal("50")

    # Topic tags: precise content match only (never stamp data-breach on vague 'breach').
    if looks_like_data_breach(text) and "data-breach" not in tags:
        tags.append("data-breach")
    if looks_like_data_leak(text) and "data-leak" not in tags:
        tags.append("data-leak")
    if looks_like_ransomware_topic(text) and "ransomware" not in tags:
        tags.append("ransomware")

    if hit and not is_defacement and not is_forum_claim and not is_claim_news and not is_x_wire:
        severity = Threat.Severity.HIGH
        score = max(score, Decimal("72"))
    elif hit and is_defacement:
        severity = Threat.Severity.HIGH
        score = max(score, Decimal("72"))
    elif hit and (is_forum_claim or is_claim_news or is_x_wire):
        severity = Threat.Severity.MEDIUM
        score = max(score, Decimal("62"))

    wire_priority = 0
    if hit or category in {"breach", "ransomware"} or is_defacement:
        wire_priority = impact_wire_priority()
    if is_forum_claim and not vietnam:
        wire_priority = max(wire_priority, max(1, impact_wire_priority() // 2))
    if is_claim_news and not vietnam and not is_forum_claim and not is_x_wire:
        wire_priority = max(wire_priority, max(1, impact_wire_priority() // 2))
    if is_x_wire and not vietnam:
        wire_priority = max(wire_priority, max(1, impact_wire_priority() // 2))
    if vietnam:
        severity = Threat.Severity.HIGH
        score = max(score, Decimal("85"))
        wire_priority = vietnam_wire_priority()
        if "vietnam" not in tags:
            tags.append("vietnam")

    victim_country_code = (
        str(item.get("country_code") or "")
        if is_defacement
        else ""
    )
    for geo_tag in detect_geography_tag_slugs(
        item.get("title"),
        item.get("summary"),
        item.get("description"),
        str(item.get("country") or "") if is_defacement else "",
        country_code=victim_country_code,
    ):
        if geo_tag not in tags:
            tags.append(geo_tag)

    return source, severity, tags, score, wire_priority


def _password_fingerprint(password: str) -> str:
    return password_fingerprint(password)


def _ensure_tags(slugs: list[str]) -> list[Tag]:
    out: list[Tag] = []
    for slug in slugs:
        clean = (slug or "").strip().lower().replace(" ", "-")[:64]
        if not clean:
            continue
        tag, _ = Tag.objects.get_or_create(
            slug=clean, defaults={"name": clean.replace("-", " ").title()}
        )
        out.append(tag)
    return out


def enrich_threat_tags(threat: Threat) -> list[str]:
    """Add missing geography / topic tags; strip false-positive Vietnam tags.

    Vietnam detection uses original title/summary/url with full rules. Translated
    ``title_vi`` / ``summary_vi`` only contribute *strong* geo signals (🇻🇳,
    "Việt Nam", cities) — never bare "công ty" / "tập đoàn" from MT.
    """
    payload = threat.raw_payload if isinstance(threat.raw_payload, dict) else {}
    title = str(threat.title or "")
    summary = str(threat.summary or "")
    title_vi = str(getattr(threat, "title_vi", "") or "")
    summary_vi = str(getattr(threat, "summary_vi", "") or "")
    source_url = str(threat.source_url or "")
    original_parts = [
        title,
        summary,
        str(payload.get("description") or ""),
        str(payload.get("summary") or ""),
        str(payload.get("victim") or ""),
    ]
    original_blob = " ".join(original_parts)
    vi_blob = f"{title_vi} {summary_vi}".strip()
    existing = set(threat.tags.values_list("slug", flat=True))
    wanted: list[str] = []

    vietnam = threat_looks_vietnam_related(
        title=title,
        summary=summary,
        source_url=source_url,
        raw_payload=payload,
    )
    # Translated text: strong identity only (flag / country name / cities).
    if not vietnam and vi_blob:
        vietnam = is_vietnam_related(vi_blob, allow_company_forms=False)

    # Never soft-tag Vietnam from publisher handle (VECERTRadar also covers
    # Yemen / regional CTI). Geography must come from title/summary content.

    if vietnam:
        wanted.append("vietnam")

    # Geo from original content + VI + flag emoji (not publisher URL).
    for geo_tag in detect_geography_tag_slugs(
        *original_parts, title_vi, summary_vi
    ):
        if geo_tag not in wanted:
            wanted.append(geo_tag)

    topic_blob = f"{original_blob} {vi_blob}"
    if looks_like_data_breach(topic_blob) and "data-breach" not in wanted:
        wanted.append("data-breach")
    if looks_like_data_leak(topic_blob) and "data-leak" not in wanted:
        wanted.append("data-leak")
    if looks_like_ransomware_topic(topic_blob) and "ransomware" not in wanted:
        wanted.append("ransomware")

    to_add = [slug for slug in wanted if slug and slug not in existing]
    if to_add:
        threat.tags.add(*_ensure_tags(to_add))

    removed: list[str] = []
    if not vietnam and "vietnam" in existing:
        vn_tag = Tag.objects.filter(slug="vietnam").first()
        if vn_tag:
            threat.tags.remove(vn_tag)
            removed.append("vietnam")
            existing.discard("vietnam")

    updates: list[str] = []
    if vietnam and int(threat.wire_priority or 0) < vietnam_wire_priority():
        threat.wire_priority = vietnam_wire_priority()
        updates.append("wire_priority")
        if threat.severity != Threat.Severity.HIGH:
            threat.severity = Threat.Severity.HIGH
            updates.append("severity")
        if threat.evidence_score is None or threat.evidence_score < Decimal("85"):
            threat.evidence_score = Decimal("85")
            updates.append("evidence_score")
    elif not vietnam and int(threat.wire_priority or 0) >= vietnam_wire_priority():
        # Demote false Vietnam pins.
        if "ransomware" in existing or looks_like_ransomware_topic(topic_blob):
            threat.wire_priority = impact_wire_priority()
        elif str(payload.get("discovery") or "") == "x-wire":
            threat.wire_priority = max(1, impact_wire_priority() // 2)
        elif looks_like_data_breach(topic_blob) or is_high_impact_intel(
            topic_blob.casefold()
        ):
            threat.wire_priority = impact_wire_priority()
        else:
            threat.wire_priority = 0
        updates.append("wire_priority")

    # Drop unused healthcare tag if present from earlier builds.
    if "healthcare" in existing:
        hc = Tag.objects.filter(slug="healthcare").first()
        if hc:
            threat.tags.remove(hc)
            removed.append("healthcare")

    if updates:
        updates.append("updated_at")
        threat.save(update_fields=updates)
    return to_add + [f"-{s}" for s in removed]


@transaction.atomic
def ingest_stealer_content(
    *,
    leak_id: int | None,
    content: str,
    stealer_family: str | None = None,
    create_leak: bool = False,
    leak_title: str = "Stealer log ingest",
) -> dict[str, Any]:
    leak = None
    if leak_id:
        leak = DataLeak.objects.select_for_update().get(pk=leak_id)
    elif create_leak:
        leak = DataLeak.objects.create(
            title=leak_title,
            leak_type=DataLeak.LeakType.STEALER_LOG,
            severity=DataLeak.Severity.HIGH,
            source=DataLeak.Source.OTHER,
            description="Created by Celery stealer ingest worker",
        )

    parsed = parse_stealer_log(content, stealer_family=stealer_family)
    created = 0
    skipped = 0

    for row in parsed:
        exists = CompromisedCredential.objects.filter(
            leak=leak,
            email=row.email,
            username=row.username,
            domain=row.domain,
            password_fingerprint=_password_fingerprint(row.password) or "",
        ).exists()
        if exists and row.password:
            skipped += 1
            continue
        # Also skip identical raw triple when no password fingerprint yet
        if not row.password:
            skipped += 1
            continue

        CompromisedCredential.objects.create(
            leak=leak,
            email=row.email,
            username=row.username,
            password=encrypt_secret(row.password),
            password_fingerprint=_password_fingerprint(row.password),
            url=row.url,
            domain=row.domain,
            stealer_family=(
                row.stealer_family
                if row.stealer_family
                in {
                    choice.value
                    for choice in CompromisedCredential.StealerFamily
                }
                else CompromisedCredential.StealerFamily.UNKNOWN
            ),
            raw_line=row.raw_line,
            metadata={"ingested_by": "workers.parse_stealer_log"},
        )
        created += 1

        if row.domain:
            ind, _ = Indicator.objects.update_or_create(
                ioc_type=Indicator.Type.DOMAIN,
                normalized_value=row.domain.lower(),
                defaults={
                    "value": row.domain,
                    "source": "stealer_log",
                    "confidence": Indicator.Confidence.MEDIUM,
                    "description": f"Domain seen in stealer credentials (leak={getattr(leak, 'id', None)})",
                    "last_seen": timezone.now(),
                    "is_active": True,
                },
            )
            match_indicator_against_rules(ind)

    if leak is not None:
        leak.record_count = leak.credentials.count()
        if leak.leak_type != DataLeak.LeakType.STEALER_LOG:
            leak.leak_type = DataLeak.LeakType.STEALER_LOG
        leak.save(update_fields=["record_count", "leak_type", "updated_at"])
        match_leak_against_rules(leak)

    return {
        "leak_id": getattr(leak, "id", None),
        "parsed": len(parsed),
        "created": created,
        "skipped": skipped,
    }


def _safe_decimal(value: Any, places_as_str: str = "0.0") -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def ingest_cve_items(items: list[dict[str, Any]]) -> dict[str, int]:
    created = 0
    updated = 0
    translate_ids: list[int] = []
    for item in items:
        cve_id = (
            item.get("id")
            or item.get("cve")
            or item.get("cve_id")
            or ""
        )
        cve_id = str(cve_id).strip().upper()
        if not cve_id.startswith("CVE-"):
            continue

        summary = (
            item.get("summary")
            or item.get("description")
            or item.get("details")
            or ""
        )
        cvss = _safe_decimal(
            item.get("cvss")
            or item.get("cvss3")
            or (item.get("metrics") or {}).get("cvss")
        )
        published = parse_datetime(str(item.get("Published") or item.get("published") or ""))
        if published is None:
            published = timezone.now()

        severity = Threat.Severity.MEDIUM
        if cvss is not None:
            if cvss >= Decimal("9.0"):
                severity = Threat.Severity.CRITICAL
            elif cvss >= Decimal("7.0"):
                severity = Threat.Severity.HIGH
            elif cvss >= Decimal("4.0"):
                severity = Threat.Severity.MEDIUM
            else:
                severity = Threat.Severity.LOW

        title = f"{cve_id}: {(summary or 'No summary')[:180]}"
        obj, was_created = Threat.objects.update_or_create(
            title=title[:512],
            source=Threat.Source.CVE_FEED,
            defaults={
                "summary": str(summary)[:5000],
                "severity": severity,
                "status": Threat.Status.NEW,
                "published_at": published,
                "cvss_score": cvss,
                "cve_ids": [cve_id],
                "evidence_score": cvss or Decimal("0"),
                "raw_payload": item,
                "source_url": f"https://cve.circl.lu/cve/{cve_id}",
            },
        )
        Indicator.objects.update_or_create(
            ioc_type=Indicator.Type.CVE,
            normalized_value=cve_id.lower(),
            defaults={
                "value": cve_id,
                "source": "cve.circl.lu",
                "confidence": Indicator.Confidence.HIGH,
                "description": str(summary)[:2000],
                "last_seen": timezone.now(),
                "is_active": True,
                "metadata": {"cvss": str(cvss) if cvss is not None else None},
            },
        )
        obj.tags.add(*_ensure_tags(["site-cve-circl-lu"]))
        if was_created:
            created += 1
            match_threat_against_rules(obj)
            from apps.integrations.ai.translate import apply_inline_rule_translation

            apply_inline_rule_translation(obj)
            translate_ids.append(obj.id)
        else:
            updated += 1
            obj.indicators.add(
                *Indicator.objects.filter(
                    ioc_type=Indicator.Type.CVE, normalized_value=cve_id.lower()
                )[:1]
            )

    if translate_ids:
        from apps.integrations.ai.translate import enqueue_title_translations

        enqueue_title_translations(translate_ids)
    return {"created": created, "updated": updated, "processed": created + updated}


_ONION_IN_URL_RE = re.compile(r"\.onion(?:[/:?#]|$)", re.I)
_DOMAIN_HINT_RE = re.compile(
    r"\b(?:https?://)?(?:www\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)\b",
    re.I,
)


def _is_onion_url(value: str) -> bool:
    text = str(value or "").strip().casefold()
    if not text:
        return False
    host = (urlparse(text).hostname or "").casefold()
    return host.endswith(".onion") or bool(_ONION_IN_URL_RE.search(text))


def _ransomware_clearnet_url(item: dict[str, Any]) -> str:
    """Prefer ransomware.live / clearnet detail pages — never onion claim URLs."""
    for key in ("url", "post_url", "link", "website"):
        value = str(item.get(key) or "").strip()
        if value.lower().startswith(("https://", "http://")) and not _is_onion_url(value):
            return value
    return "https://www.ransomware.live/"


def _scrub_onion_from_payload(item: dict[str, Any]) -> dict[str, Any]:
    """Drop onion destinations from stored Wire payload (metadata-only policy)."""
    out: dict[str, Any] = {}
    for key, value in dict(item or {}).items():
        if isinstance(value, str) and _is_onion_url(value):
            continue
        if key in {"claim_url", "screenshot"} and isinstance(value, str) and _is_onion_url(value):
            continue
        out[key] = value
    return out


def _domain_hint_from_text(text: str) -> str:
    match = _DOMAIN_HINT_RE.search(str(text or ""))
    if not match:
        return ""
    host = match.group(1).casefold()
    if host.endswith(".onion") or host in {"www.ransomware.live", "ransomware.live"}:
        return ""
    return host


def ingest_ransomware_items(items: list[dict[str, Any]]) -> dict[str, int]:
    created = 0
    updated = 0
    translate_ids: list[int] = []
    for item in items:
        victim = (
            item.get("victim")
            or item.get("post_title")
            or item.get("name")
            or item.get("company")
            or ""
        )
        group = item.get("group") or item.get("group_name") or item.get("gang") or "unknown"
        victim = str(victim).strip()
        if not victim:
            continue
        title = f"Ransomware: {victim} ({group})"[:512]
        discovered = parse_datetime(
            str(item.get("discovered") or item.get("published") or item.get("date") or "")
        )
        source_url = _ransomware_clearnet_url(item)
        safe_payload = _scrub_onion_from_payload(item)
        description = str(
            item.get("description") or item.get("summary") or item.get("activity") or ""
        ).strip()
        domain = str(item.get("domain") or item.get("website") or "").strip()
        if not domain:
            domain = _domain_hint_from_text(description)
        if description:
            summary = description[:5000]
        elif domain:
            summary = f"Victim reported by ransomware.live / group={group} / domain={domain}"
        else:
            summary = f"Victim reported by ransomware.live / group={group}"

        vietnam = threat_looks_vietnam_related(
            title=title,
            summary=summary,
            source_url=source_url,
            raw_payload=safe_payload,
            country_code=str(item.get("country") or item.get("country_code") or ""),
        )
        tags = ["site-ransomware-live"]
        severity = Threat.Severity.HIGH
        score = Decimal("70")
        wire_priority = impact_wire_priority()
        if vietnam:
            tags.append("vietnam")
            score = Decimal("85")
            wire_priority = vietnam_wire_priority()
        for geo_tag in detect_geography_tag_slugs(
            title,
            summary,
            description,
            str(item.get("country") or ""),
            country_code=str(item.get("country_code") or item.get("country") or ""),
        ):
            if geo_tag not in tags:
                tags.append(geo_tag)

        obj, was_created = Threat.objects.update_or_create(
            title=title,
            source=Threat.Source.RANSOMWARE,
            defaults={
                "summary": summary,
                "severity": severity,
                "status": Threat.Status.NEW,
                "published_at": clamp_published_at(discovered, now=timezone.now()),
                "evidence_score": score,
                "wire_priority": wire_priority,
                "raw_payload": safe_payload,
                "source_url": source_url[:2048],
            },
        )
        obj.tags.add(*_ensure_tags(tags))
        if domain:
            host = domain.replace("https://", "").replace("http://", "").split("/")[0]
            if host and not host.casefold().endswith(".onion"):
                Indicator.objects.update_or_create(
                    ioc_type=Indicator.Type.DOMAIN,
                    normalized_value=host.lower(),
                    defaults={
                        "value": host,
                        "source": "ransomware.live",
                        "confidence": Indicator.Confidence.MEDIUM,
                        "last_seen": timezone.now(),
                        "is_active": True,
                    },
                )
        if was_created:
            created += 1
            match_threat_against_rules(obj)
            from apps.integrations.ai.translate import apply_inline_rule_translation

            apply_inline_rule_translation(obj)
            translate_ids.append(obj.id)
        else:
            updated += 1
            from apps.integrations.ai.summary_translate import summary_hash

            if obj.summary_hash != summary_hash(summary):
                translate_ids.append(obj.id)
    if translate_ids:
        from apps.integrations.ai.translate import enqueue_title_translations

        enqueue_title_translations(translate_ids)
    return {"created": created, "updated": updated, "processed": created + updated}


def ingest_rss_items(items: list[dict[str, Any]], *, source_label: str = "rss") -> dict[str, int]:
    """Create Wire threats from RSS items.

    Age windows:
    - Vietnam-related → WIRE_VIETNAM_MAX_AGE_DAYS (0 = unlimited)
    - others → WIRE_MAX_AGE_DAYS (default 7)

    Already-ingested items (same source_url or title+source) are skipped — no rewrite.
    """
    created = 0
    updated = 0
    skipped_old = 0
    skipped_existing = 0
    skipped_irrelevant = 0
    skipped_unsafe = 0
    general_days = int(getattr(settings, "WIRE_MAX_AGE_DAYS", 7) or 7)
    vietnam_days = int(getattr(settings, "WIRE_VIETNAM_MAX_AGE_DAYS", 0) or 0)
    now = timezone.now()
    translate_ids: list[int] = []

    from apps.workers.feeds.forum_safety import prepare_wire_item_for_safety

    # Newest first so a large batch surfaces fresh high-signal intel before older rows.
    def _item_sort_key(row: dict[str, Any]) -> float:
        published = parse_feed_datetime(
            str(row.get("published") or row.get("updated") or "")
        )
        return published.timestamp() if published is not None else 0.0

    for raw_item in sorted(items, key=_item_sort_key, reverse=True):
        item = prepare_wire_item_for_safety(raw_item)
        if item is None:
            if str(raw_item.get("title") or "").strip():
                skipped_unsafe += 1
            continue
        title = str(item.get("title") or "").strip()
        if not title:
            continue
        link = str(item.get("link") or item.get("url") or "")[:2048]
        summary = str(item.get("summary") or item.get("description") or "")[:5000]
        if not is_wire_relevant(item):
            skipped_irrelevant += 1
            continue
        published = parse_feed_datetime(
            str(item.get("published") or item.get("updated") or "")
        )
        vietnam_hint = threat_looks_vietnam_related(
            title=title,
            summary=summary,
            source_url=link,
            raw_payload=item,
            country_code=str(item.get("country_code") or ""),
        )
        max_age_days = vietnam_days if vietnam_hint else general_days
        if published is not None and not is_within_max_age(
            published, max_age_days=max_age_days, now=now
        ):
            skipped_old += 1
            continue

        # Cheap existence check before classify/write (avoid re-scanning known items).
        existing = None
        if link:
            existing = Threat.objects.filter(source_url=link).only("id").first()
        if existing is None:
            category = str(item.get("category") or "news").lower()
            if category == "cert":
                threat_source_guess = Threat.Source.CERT
            elif category == "ransomware":
                threat_source_guess = Threat.Source.RANSOMWARE
            else:
                threat_source_guess = Threat.Source.NEWS
            existing = (
                Threat.objects.filter(title=title[:512], source=threat_source_guess)
                .only("id")
                .first()
            )
        if existing is not None:
            skipped_existing += 1
            continue

        threat_source, severity, tag_slugs, score, wire_priority = _classify_rss_item(item)
        published_at = clamp_published_at(published, now=now)
        obj = Threat.objects.create(
            title=title[:512],
            source=threat_source,
            status=Threat.Status.NEW,
            summary=summary,
            severity=severity,
            evidence_score=score,
            wire_priority=wire_priority,
            wire_relevant=True,
            raw_payload={**item, "feed_source": source_label},
            source_url=link,
            published_at=published_at,
        )
        tags = _ensure_tags(tag_slugs)
        if tags:
            obj.tags.add(*tags)
        created += 1
        match_threat_against_rules(obj)
        from apps.integrations.ai.translate import apply_inline_rule_translation

        apply_inline_rule_translation(obj)
        translate_ids.append(obj.id)

    if translate_ids:
        from apps.integrations.ai.translate import enqueue_title_translations

        enqueue_title_translations(translate_ids)

    return {
        "created": created,
        "updated": updated,
        "skipped_old": skipped_old,
        "skipped_existing": skipped_existing,
        "skipped_irrelevant": skipped_irrelevant,
        "skipped_unsafe": skipped_unsafe,
        "processed": created + updated,
    }

