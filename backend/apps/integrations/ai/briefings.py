from __future__ import annotations

from datetime import timedelta

from django.utils import timezone

from apps.intel.models import DataLeak, Indicator, Threat
from apps.integrations.ai.clients import AIProviderError, generate_briefing_text
from apps.integrations.models import AIBriefing


def collect_intel_snapshot(window_hours: int = 24) -> dict:
    since = timezone.now() - timedelta(hours=window_hours)
    threats = list(
        Threat.objects.filter(published_at__gte=since).order_by("-severity", "-published_at")[:40]
    )
    indicators = list(
        Indicator.objects.filter(last_seen__gte=since, is_active=True).order_by("-last_seen")[:60]
    )
    leaks = list(
        DataLeak.objects.filter(discovered_at__gte=since).order_by("-severity", "-discovered_at")[
            :20
        ]
    )
    return {
        "since": since.isoformat(),
        "threats": threats,
        "indicators": indicators,
        "leaks": leaks,
    }


def build_briefing_prompt(snapshot: dict) -> str:
    lines = [
        "You are a cyber threat intelligence analyst writing an executive daily briefing.",
        "Be concise, factual, and prioritize actionable items.",
        f"Reporting window starts: {snapshot['since']}",
        "",
        "## Threats / The Wire",
    ]
    for t in snapshot["threats"]:
        lines.append(
            f"- [{t.severity}] {t.title} (source={t.source}, kev={t.is_kev}, cvss={t.cvss_score})"
        )
    if not snapshot["threats"]:
        lines.append("- None in window")

    lines.append("\n## Indicators")
    for i in snapshot["indicators"][:40]:
        lines.append(f"- {i.ioc_type}:{i.value} (confidence={i.confidence}, source={i.source})")
    if not snapshot["indicators"]:
        lines.append("- None in window")

    lines.append("\n## Data leaks")
    for leak in snapshot["leaks"]:
        lines.append(
            f"- [{leak.severity}] {leak.title} type={leak.leak_type} domain={leak.affected_domain}"
        )
    if not snapshot["leaks"]:
        lines.append("- None in window")

    lines.append(
        "\nProduce: 1) Executive summary 2) Top risks 3) Recommended Blue Team actions."
    )
    return "\n".join(lines)


def create_ai_briefing(
    *,
    window_hours: int = 24,
    user=None,
    title: str | None = None,
) -> AIBriefing:
    snapshot = collect_intel_snapshot(window_hours=window_hours)
    prompt = build_briefing_prompt(snapshot)
    briefing = AIBriefing.objects.create(
        title=title
        or f"AI Briefing — last {window_hours}h ({timezone.now().date().isoformat()})",
        status=AIBriefing.Status.PENDING,
        window_hours=window_hours,
        threat_count=len(snapshot["threats"]),
        indicator_count=len(snapshot["indicators"]),
        leak_count=len(snapshot["leaks"]),
        created_by=user if getattr(user, "is_authenticated", False) else None,
    )
    try:
        result = generate_briefing_text(prompt)
        briefing.provider = result["provider"]
        briefing.content = result["text"]
        briefing.raw_response = {
            "provider_meta": result.get("raw", {}),
            "prompt_chars": len(prompt),
        }
        briefing.status = AIBriefing.Status.READY
        briefing.error_message = ""
    except AIProviderError as exc:
        briefing.status = AIBriefing.Status.FAILED
        briefing.provider = AIBriefing.Provider.LOCAL
        briefing.error_message = str(exc)
        briefing.content = ""
    briefing.save()
    return briefing


def create_keyword_summary(*, keyword: str, window_hours: int = 168, user=None) -> AIBriefing:
    """On-demand Watcher-style keyword digest with related CVE / actors."""
    keyword = (keyword or "").strip()
    since = timezone.now() - timedelta(hours=window_hours)
    threats = list(
        Threat.objects.filter(published_at__gte=since)
        .filter(title__icontains=keyword)
        .order_by("-published_at")[:40]
    )
    if not threats:
        threats = list(
            Threat.objects.filter(published_at__gte=since)
            .filter(summary__icontains=keyword)
            .order_by("-published_at")[:40]
        )
    indicators = list(
        Indicator.objects.filter(last_seen__gte=since, is_active=True)
        .filter(value__icontains=keyword)
        .order_by("-last_seen")[:40]
    )
    actors = {
        a
        for t in threats
        for a in t.threat_actors.values_list("name", flat=True)
    }
    cves = sorted(
        {
            cve
            for t in threats
            for cve in (t.cve_ids or [])
            if str(cve).upper().startswith("CVE-")
        }
    )
    lines = [
        f"Keyword intelligence summary for: {keyword}",
        f"Window hours: {window_hours}",
        "",
        "## Matching threats",
    ]
    for t in threats:
        lines.append(f"- [{t.severity}] {t.title} ({t.source})")
    if not threats:
        lines.append("- No threat matches")
    lines.append("\n## Related CVEs")
    lines.extend([f"- {c}" for c in cves] or ["- None"])
    lines.append("\n## Threat actors")
    lines.extend([f"- {a}" for a in sorted(actors)] or ["- None attributed"])
    lines.append("\n## Matching indicators")
    for i in indicators:
        lines.append(f"- {i.ioc_type}:{i.value}")
    if not indicators:
        lines.append("- None")
    lines.append(
        "\nProduce: executive summary, related CVE/actors, and recommended watch actions."
    )
    prompt = "\n".join(lines)

    briefing = AIBriefing.objects.create(
        title=f"Keyword summary: {keyword}"[:512],
        status=AIBriefing.Status.PENDING,
        window_hours=window_hours,
        threat_count=len(threats),
        indicator_count=len(indicators),
        leak_count=0,
        created_by=user if getattr(user, "is_authenticated", False) else None,
    )
    try:
        result = generate_briefing_text(prompt)
        briefing.provider = result["provider"]
        briefing.content = result["text"]
        briefing.raw_response = {
            "keyword": keyword,
            "cves": cves,
            "actors": sorted(actors),
            "provider_meta": result.get("raw", {}),
        }
        briefing.status = AIBriefing.Status.READY
    except AIProviderError as exc:
        briefing.status = AIBriefing.Status.FAILED
        briefing.provider = AIBriefing.Provider.LOCAL
        briefing.error_message = str(exc)
    briefing.save()
    return briefing


def create_weekly_trending_digest(*, user=None) -> AIBriefing:
    """Watcher-style weekly top trending topics from The Wire."""
    since = timezone.now() - timedelta(days=7)
    threats = list(
        Threat.objects.filter(published_at__gte=since).order_by(
            "-evidence_score", "-published_at"
        )[:80]
    )
    # Simple topic clustering by source + first meaningful token / CVE family
    from collections import Counter

    topic_counter: Counter[str] = Counter()
    topic_examples: dict[str, list[str]] = {}
    for t in threats:
        if t.cve_ids:
            topic = f"CVE activity ({t.cve_ids[0]})"
        elif t.source == Threat.Source.RANSOMWARE:
            topic = "Ransomware campaigns"
        elif t.source == Threat.Source.CERT:
            topic = "CERT advisories"
        else:
            words = [w for w in (t.title or "").split() if len(w) > 3][:3]
            topic = " ".join(words)[:64] or t.source
        topic_counter[topic] += 1
        topic_examples.setdefault(topic, []).append(t.title)

    top5 = topic_counter.most_common(5)
    lines = [
        "Create a weekly cybersecurity digest of the TOP 5 trending topics.",
        f"Window start: {since.isoformat()}",
        "",
        "## Topic frequency",
    ]
    for topic, count in top5:
        lines.append(f"- {topic} (count={count})")
        for example in topic_examples.get(topic, [])[:3]:
            lines.append(f"  · {example}")
    lines.append(
        "\nFor each of the top 5: explain why it matters, notable CVEs/actors, and Blue Team actions."
    )
    prompt = "\n".join(lines)
    briefing = AIBriefing.objects.create(
        title=f"Weekly top-5 digest ({timezone.now().date().isoformat()})",
        status=AIBriefing.Status.PENDING,
        window_hours=24 * 7,
        threat_count=len(threats),
        indicator_count=0,
        leak_count=0,
        created_by=user if getattr(user, "is_authenticated", False) else None,
    )
    try:
        result = generate_briefing_text(prompt)
        briefing.provider = result["provider"]
        briefing.content = result["text"]
        briefing.raw_response = {
            "top_topics": [{"topic": t, "count": c} for t, c in top5],
            "provider_meta": result.get("raw", {}),
        }
        briefing.status = AIBriefing.Status.READY
    except AIProviderError as exc:
        briefing.status = AIBriefing.Status.FAILED
        briefing.provider = AIBriefing.Provider.LOCAL
        briefing.error_message = str(exc)
    briefing.save()
    return briefing
