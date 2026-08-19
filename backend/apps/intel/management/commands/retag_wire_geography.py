from django.core.management.base import BaseCommand

from apps.intel.models import Tag, Threat
from apps.workers.feeds.zoneh import fetch_zoneh_archive_items
from apps.workers.geography import detect_geography_tag_slugs, infer_country_from_domain


class Command(BaseCommand):
    help = "Add country/region tags to existing Wire threats from their content."

    def handle(self, *args, **options):
        detected: dict[int, set[str]] = {}
        all_slugs: set[str] = set()
        mirror_countries: dict[str, tuple[str, str]] = {}
        try:
            archive_items, _ = fetch_zoneh_archive_items()
            for row in archive_items:
                link = str(row.get("link") or "")
                code = str(row.get("country_code") or "")
                name = str(row.get("country") or "")
                if link and code:
                    mirror_countries[link] = (code, name)
        except Exception:
            mirror_countries = {}

        remove_defacement_slugs = {"breach", "data-breach"}
        remove_tag_ids = list(
            Tag.objects.filter(slug__in=remove_defacement_slugs).values_list("id", flat=True)
        )

        threats = Threat.objects.filter(wire_relevant=True).only(
            "id",
            "title",
            "summary",
            "title_vi",
            "summary_vi",
            "source",
            "source_url",
            "raw_payload",
        )
        for threat in threats.iterator(chunk_size=500):
            payload = threat.raw_payload if isinstance(threat.raw_payload, dict) else {}
            content = " ".join(
                str(payload.get(key) or "")
                for key in ("description", "summary", "victim", "activity")
            )
            country_code = ""
            if threat.source == Threat.Source.RANSOMWARE:
                country_code = str(
                    payload.get("country_code") or payload.get("country") or ""
                )
            elif payload.get("discovery") == "zoneh-archive":
                country_code = str(payload.get("country_code") or "")
                country_name = str(payload.get("country") or "")
                mirror = mirror_countries.get(threat.source_url or "")
                if mirror:
                    country_code, country_name = mirror
                    payload = {
                        **payload,
                        "country_code": country_code,
                        "country": country_name,
                    }
                    Threat.objects.filter(pk=threat.id).update(raw_payload=payload)
                elif not country_code:
                    country_code, country_name = infer_country_from_domain(
                        str(payload.get("defaced_url") or "")
                    )
                    if country_code:
                        payload = {
                            **payload,
                            "country_code": country_code,
                            "country": country_name,
                        }
                        Threat.objects.filter(pk=threat.id).update(raw_payload=payload)
                detected.setdefault(threat.id, set()).add("defacement")
                all_slugs.add("defacement")
                if remove_tag_ids:
                    threat.tags.remove(*Tag.objects.filter(id__in=remove_tag_ids))
            slugs = set(
                detect_geography_tag_slugs(
                    threat.title,
                    threat.summary,
                    getattr(threat, "title_vi", "") or "",
                    getattr(threat, "summary_vi", "") or "",
                    content,
                    str(payload.get("country") or ""),
                    country_code=country_code,
                )
            )
            if slugs:
                detected.setdefault(threat.id, set()).update(slugs)
                all_slugs.update(slugs)

        Tag.objects.bulk_create(
            [
                Tag(slug=slug, name=slug.removeprefix("geo-").replace("-", " ").title())
                for slug in sorted(all_slugs)
            ],
            ignore_conflicts=True,
        )
        tags_by_slug = {
            tag.slug: tag for tag in Tag.objects.filter(slug__in=all_slugs)
        }
        through = Threat.tags.through
        links = [
            through(threat_id=threat_id, tag_id=tags_by_slug[slug].id)
            for threat_id, slugs in detected.items()
            for slug in slugs
            if slug in tags_by_slug
        ]
        through.objects.bulk_create(links, ignore_conflicts=True, batch_size=1000)

        self.stdout.write(
            self.style.SUCCESS(
                f"Geography retag complete · threats={len(detected)} "
                f"tags={len(all_slugs)} links={len(links)}"
            )
        )
