"""Backfill vietnam tags + wire priority for missed Vietnam-related threats."""

from __future__ import annotations

import re

from django.core.management.base import BaseCommand

from apps.intel.models import Tag, Threat
from apps.workers.services import (
    impact_wire_priority,
    is_high_impact_intel,
    looks_like_data_breach,
    looks_like_data_leak,
    looks_like_ransomware_topic,
    threat_looks_vietnam_related,
    vietnam_wire_priority,
)

_RANSOMWARE_TITLE_RE = re.compile(
    r"^Ransomware:\s*(?P<victim>.+?)\s*\((?P<group>[^)]+)\)\s*$",
    re.IGNORECASE,
)


class Command(BaseCommand):
    help = "Retag Wire threats that mention Vietnam/.vn but lack the vietnam tag."

    def handle(self, *args, **options):
        vn_tag, _ = Tag.objects.get_or_create(
            slug="vietnam", defaults={"name": "Vietnam"}
        )
        priority = vietnam_wire_priority()
        scanned = 0
        tagged = 0
        prioritized = 0
        untagged = 0
        demoted = 0
        victims: set[str] = set()

        queryset = Threat.objects.prefetch_related("tags").order_by("id")
        for threat in queryset.iterator(chunk_size=300):
            scanned += 1
            looks_vn = threat_looks_vietnam_related(
                title=threat.title,
                summary=threat.summary or "",
                source_url=threat.source_url or "",
                raw_payload=threat.raw_payload,
            )
            if not looks_vn:
                # Reconcile stale tags created by older machine translations.
                # Vietnam must be supported by original content/metadata, never
                # by title_vi or summary_vi.
                if threat.tags.filter(slug="vietnam").exists():
                    threat.tags.remove(vn_tag)
                    untagged += 1
                if threat.wire_priority >= priority:
                    payload = threat.raw_payload if isinstance(threat.raw_payload, dict) else {}
                    blob = " ".join(
                        str(value or "")
                        for value in (
                            threat.title,
                            threat.summary,
                            payload.get("description"),
                            payload.get("summary"),
                        )
                    ).casefold()
                    if looks_like_ransomware_topic(blob) or looks_like_data_breach(blob) or looks_like_data_leak(blob) or is_high_impact_intel(blob):
                        threat.wire_priority = impact_wire_priority()
                    elif payload.get("discovery") in {"x-wire", "forum-rss", "forum-claim", "claim-news"}:
                        threat.wire_priority = max(1, impact_wire_priority() // 2)
                    else:
                        threat.wire_priority = 0
                    threat.save(update_fields=["wire_priority", "updated_at"])
                    demoted += 1
                continue

            changed_fields: list[str] = []
            if threat.wire_priority < priority:
                threat.wire_priority = priority
                prioritized += 1
                changed_fields.append("wire_priority")
            if threat.severity != Threat.Severity.HIGH:
                threat.severity = Threat.Severity.HIGH
                changed_fields.append("severity")
            if changed_fields:
                threat.save(update_fields=[*changed_fields, "updated_at"])

            if not threat.tags.filter(slug="vietnam").exists():
                threat.tags.add(vn_tag)
                tagged += 1

            match = _RANSOMWARE_TITLE_RE.match(threat.title or "")
            if match:
                victim = match.group("victim").strip()
                if len(victim) >= 4:
                    victims.add(victim.casefold())

        # Propagate Vietnam tag to related news that name the same ransomware victim.
        related = 0
        if victims:
            related_qs = (
                Threat.objects.exclude(tags__slug="vietnam")
                .filter(source=Threat.Source.NEWS)
                .prefetch_related("tags")
            )
            for threat in related_qs.iterator(chunk_size=300):
                title = (threat.title or "").casefold()
                if not any(victim in title for victim in victims):
                    continue
                # Require an impact cue so generic name collisions stay out.
                blob = f"{threat.title} {threat.summary}".casefold()
                if not any(
                    cue in blob
                    for cue in ("ransomware", "breach", "leak", "victim", "dark web")
                ):
                    continue
                threat.tags.add(vn_tag)
                if threat.wire_priority < priority:
                    threat.wire_priority = priority
                    threat.severity = Threat.Severity.HIGH
                    threat.save(
                        update_fields=["wire_priority", "severity", "updated_at"]
                    )
                related += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Vietnam retag complete · scanned={scanned} tagged={tagged} "
                f"prioritized={prioritized} untagged={untagged} demoted={demoted} "
                f"related_news={related}"
            )
        )
