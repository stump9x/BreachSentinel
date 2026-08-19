from __future__ import annotations

from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from apps.intel.models import Tag, Threat
from apps.integrations.searx.site_discovery import discover_unstable_site_items
from apps.workers.services import ingest_rss_items, website_tag_slug


class WebsiteTagTests(TestCase):
    def test_prefers_feed_website_over_article_link(self):
        slug = website_tag_slug(
            {
                "feed": "bitsight-blog",
                "feed_url": "https://www.bitsight.com/blog/rss.xml",
                "link": "https://cdn.example.net/article",
            }
        )
        self.assertEqual(slug, "site-bitsight-com")

    def test_onion_uses_readable_feed_name(self):
        slug = website_tag_slug(
            {
                "feed": "dread-onion",
                "feed_url": (
                    "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad"
                    ".onion/d/rss"
                ),
            }
        )
        self.assertEqual(slug, "site-dread-onion")

    def test_ingest_adds_website_tag(self):
        stats = ingest_rss_items(
            [
                {
                    "title": "Bank suffers major data breach",
                    "summary": "Customer records leaked by ransomware actors.",
                    "link": "https://www.bitsight.com/blog/bank-breach",
                    "feed_url": "https://www.bitsight.com/blog/rss.xml",
                    "feed": "bitsight-blog",
                    "category": "news",
                    "published": timezone.now().isoformat(),
                }
            ]
        )
        self.assertEqual(stats["created"], 1)
        threat = Threat.objects.get(source_url__contains="bank-breach")
        self.assertIn(
            "site-bitsight-com",
            set(threat.tags.values_list("slug", flat=True)),
        )
        self.assertNotIn(
            "rss",
            set(threat.tags.values_list("slug", flat=True)),
        )
        self.assertNotIn(
            "news",
            set(threat.tags.values_list("slug", flat=True)),
        )

    def test_backfill_adds_tag_to_existing_item(self):
        threat = Threat.objects.create(
            title="Existing breach",
            source=Threat.Source.NEWS,
            source_url="https://www.group-ib.com/blog/example",
            raw_payload={"feed_source": "rss"},
        )
        out = StringIO()

        call_command("backfill_website_tags", stdout=out)

        self.assertIn(
            "site-group-ib-com",
            set(threat.tags.values_list("slug", flat=True)),
        )
        self.assertIn("tagged=1", out.getvalue())

    def test_cleanup_removes_generic_news_and_rss_tags(self):
        threat = Threat.objects.create(
            title="Tagged breach",
            source=Threat.Source.NEWS,
        )
        threat.tags.add(
            Tag.objects.create(name="RSS", slug="rss"),
            Tag.objects.create(name="News", slug="news"),
            Tag.objects.create(name="Vietnam", slug="vietnam"),
        )

        call_command("cleanup_wire_tags", stdout=StringIO())

        self.assertEqual(
            set(threat.tags.values_list("slug", flat=True)),
            {"vietnam"},
        )


class SearxSiteDiscoveryTests(TestCase):
    @patch("apps.integrations.searx.site_discovery.searx_configured", return_value=True)
    @patch("apps.integrations.searx.site_discovery.search_searx")
    def test_returns_only_dated_same_domain_hits(self, search, _configured):
        published = timezone.now() - timedelta(hours=4)
        search.return_value = [
            {
                "title": "Large database leak",
                "url": "https://leakcheck.io/blog/database-leak",
                "content": "Millions of records exposed in a data breach.",
                "published": published.isoformat(),
                "engine": "brave",
            },
            {
                "title": "Search poisoning",
                "url": "https://evil.example/not-leakcheck",
                "content": "data breach",
                "published": published.isoformat(),
                "engine": "brave",
            },
            {
                "title": "Undated old result",
                "url": "https://leakcheck.io/blog/old",
                "content": "data breach",
                "published": "",
                "engine": "brave",
            },
        ]

        items, stats = discover_unstable_site_items(domains=["leakcheck.io"])

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["feed_url"], "https://leakcheck.io")
        self.assertEqual(items[0]["discovery"], "searx-site")
        self.assertEqual(stats["skipped_cross_domain"], 1)
        self.assertEqual(stats["skipped_undated"], 1)
