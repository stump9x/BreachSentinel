"""Suggest RSS/intel URLs via SearxNG for sites without a stable public feed."""

from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.integrations.searx.client import search_searx, searx_configured

# Domains from the analyst list that often lack a public RSS endpoint.
MONITOR_DOMAINS = (
    "haveibeenpwned.com",
    "leakcheck.io",
    "dehashed.com",
    "intelx.io",
    "privacyrights.org",
    "breachsense.com",
    "breach.news",
    "databreachtoday.com",
    "cybersecurityventures.com",
    "undercodenews.com",
)

# Secondary OSINT only — never scrape these boards directly from this command.
FORUM_MENTION_QUERIES = (
    '"DarkForums" OR "BreachForums" OR LeakBase OR "XSS.is" '
    '("data breach" OR "data leak" OR "database" OR ransomware)',
)


class Command(BaseCommand):
    help = (
        "Query SearxNG for recent breach/leak mentions on curated domains "
        "and secondary forum-claim news headlines. "
        "Prints candidate URLs for analyst review — does not create FeedSource rows "
        "and does not scrape underground forums."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--domain",
            action="append",
            dest="domains",
            help="Domain to search (repeatable). Defaults to curated monitor list.",
        )
        parser.add_argument("--limit", type=int, default=8)
        parser.add_argument(
            "--forum-mentions",
            action="store_true",
            help="Also search clearnet news that mention underground forums (metadata candidates).",
        )

    def handle(self, *args, **options):
        if not searx_configured():
            self.stderr.write("SearxNG is not configured (SEARXNG_URL).")
            return
        domains = options["domains"] or list(MONITOR_DOMAINS)
        limit = max(1, min(25, int(options["limit"] or 8)))
        total = 0
        for domain in domains:
            query = (
                f'site:{domain} ("data breach" OR "data leak" OR ransomware OR '
                f'"stolen data" OR "credentials leaked")'
            )
            try:
                hits = search_searx(query, limit=limit, exact=False)
            except Exception as exc:  # noqa: BLE001
                self.stderr.write(f"{domain}: searx error: {exc}")
                continue
            self.stdout.write(self.style.NOTICE(f"\n## {domain} ({len(hits)} hits)"))
            for hit in hits:
                url = (hit.get("url") or hit.get("link") or "").strip()
                title = (hit.get("title") or "")[:120]
                if not url:
                    continue
                total += 1
                self.stdout.write(f"- {title}\n  {url}")
        if options.get("forum_mentions"):
            for query in FORUM_MENTION_QUERIES:
                try:
                    hits = search_searx(query, limit=limit, exact=False)
                except Exception as exc:  # noqa: BLE001
                    self.stderr.write(f"forum-mentions: searx error: {exc}")
                    continue
                self.stdout.write(
                    self.style.NOTICE(f"\n## forum-mentions secondary ({len(hits)} hits)")
                )
                for hit in hits:
                    url = (hit.get("url") or hit.get("link") or "").strip()
                    title = (hit.get("title") or "")[:120]
                    if not url:
                        continue
                    total += 1
                    self.stdout.write(f"- {title}\n  {url}")
        self.stdout.write(self.style.SUCCESS(f"\nCandidates printed: {total}"))
