"""Tests for clearnet claim-news safety (no forum login)."""

from __future__ import annotations

from datetime import timedelta
from email.utils import format_datetime

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.intel.models import Threat
from apps.workers.feeds.forum_safety import (
    looks_like_sample_or_dump,
    prepare_wire_item_for_safety,
)
from apps.workers.feeds.intel_catalog import load_intel_catalog
from apps.workers.services import ingest_rss_items


class ForumSafetyUnitTests(SimpleTestCase):
    def test_rejects_dump_attachment_links(self):
        self.assertTrue(
            looks_like_sample_or_dump(
                title="Corp DB",
                link="https://mega.nz/file/abc",
            )
        )
        self.assertTrue(
            looks_like_sample_or_dump(
                title="dump.zip ready",
                link="https://example.com/files/customers.sql",
            )
        )

    def test_rejects_credential_blocks(self):
        summary = "\n".join(
            [
                "a@x.com:password1",
                "b@y.com:password2",
                "c@z.com:password3",
            ]
        )
        self.assertTrue(looks_like_sample_or_dump(title="combo", summary=summary))

    def test_allows_headline_claim_on_clearnet(self):
        self.assertFalse(
            looks_like_sample_or_dump(
                title="Alleged retail database for sale",
                summary="Actor claims access to an e-commerce database.",
                link="https://www.databreaches.net/story/",
            )
        )

    def test_rejects_direct_forum_permalink(self):
        self.assertIsNone(
            prepare_wire_item_for_safety(
                {
                    "title": "Victim Corp leak claim",
                    "link": "https://darkforums.me/thread-1",
                    "summary": "body",
                    "feed": "webhook",
                    "category": "news",
                }
            )
        )

    def test_prepare_marks_secondary_forum_claim(self):
        prepared = prepare_wire_item_for_safety(
            {
                "title": "DarkForums actors discuss retail breach",
                "link": "https://undercodenews.com/story",
                "summary": "Report summarizes claims on DarkForums.",
                "feed": "undercodenews",
                "category": "news",
            }
        )
        assert prepared is not None
        self.assertEqual(prepared["discovery"], "forum-claim")
        self.assertTrue(prepared["forum_claim"])

    def test_prepare_claim_news_feed(self):
        prepared = prepare_wire_item_for_safety(
            {
                "title": "Hospital records allegedly leaked online",
                "link": "https://darkwebinformer.com/story",
                "summary": "Secondary report of a data exposure claim.",
                "feed": "darkwebinformer",
                "feed_notes": "claim/dark-web news",
                "category": "breach",
                "discovery": "claim-news",
            }
        )
        assert prepared is not None
        self.assertEqual(prepared["discovery"], "claim-news")
        self.assertTrue(prepared.get("alleged_claim"))
        self.assertFalse(prepared.get("forum_claim"))

    def test_prepare_rejects_sample(self):
        self.assertIsNone(
            prepare_wire_item_for_safety(
                {
                    "title": "Full dump download",
                    "link": "https://mediafire.com/file/x/dump.rar",
                    "summary": "get it here",
                    "feed": "darkwebinformer",
                }
            )
        )


class ForumCatalogTests(SimpleTestCase):
    def test_catalog_has_claim_news_not_direct_forums(self):
        rows = load_intel_catalog()
        names = {r.get("name") for r in rows}
        self.assertIn("darkwebinformer", names)
        self.assertIn("databreaches-net", names)
        self.assertIn("therecord-media", names)
        self.assertNotIn("darkforums", names)
        self.assertNotIn("breachforums-st", names)
        claimish = [
            r
            for r in rows
            if "claim/dark-web news" in (r.get("notes") or "").casefold()
        ]
        self.assertGreaterEqual(len(claimish), 5)


class ForumIngestTests(TestCase):
    def test_secondary_forum_item_gets_alleged_tags(self):
        now = timezone.now()
        stats = ingest_rss_items(
            [
                {
                    "title": "BreachForums claim targets bank example.com",
                    "link": "https://www.hackread.com/breachforums-claim-bank/",
                    "summary": "Secondary clearnet report.",
                    "published": format_datetime(now - timedelta(hours=2)),
                    "feed": "www-hackread-com",
                    "feed_url": "https://www.hackread.com/feed/",
                    "category": "news",
                    "discovery": "forum-claim",
                    "forum_claim": True,
                    "metadata_only": True,
                }
            ],
            source_label="claim-news",
        )
        self.assertEqual(stats["created"], 1)
        threat = Threat.objects.get(
            source_url="https://www.hackread.com/breachforums-claim-bank/"
        )
        slugs = set(threat.tags.values_list("slug", flat=True))
        self.assertIn("forum", slugs)
        self.assertNotIn("alleged-claim", slugs)
        self.assertNotIn("data-breach", slugs)

    def test_claim_news_skips_alleged_claim_stamp(self):
        now = timezone.now()
        stats = ingest_rss_items(
            [
                {
                    "title": "Retailer customer database allegedly exposed",
                    "link": "https://darkwebinformer.com/retailer-claim/",
                    "summary": "Alleged claim reported by Dark Web Informer.",
                    "published": format_datetime(now - timedelta(hours=1)),
                    "feed": "darkwebinformer",
                    "category": "breach",
                    "discovery": "claim-news",
                    "alleged_claim": True,
                    "metadata_only": True,
                }
            ],
            source_label="claim-news",
        )
        self.assertEqual(stats["created"], 1)
        threat = Threat.objects.get(
            source_url="https://darkwebinformer.com/retailer-claim/"
        )
        slugs = set(threat.tags.values_list("slug", flat=True))
        self.assertNotIn("alleged-claim", slugs)
        self.assertNotIn("forum", slugs)
        # Precise signal: customer database exposed → data-breach OK
        self.assertIn("data-breach", slugs)

    def test_dump_item_skipped(self):
        now = timezone.now()
        stats = ingest_rss_items(
            [
                {
                    "title": "ULP combo list",
                    "link": "https://mega.nz/file/abc123",
                    "summary": "download dump.zip",
                    "published": format_datetime(now - timedelta(hours=1)),
                    "feed": "darkwebinformer",
                    "category": "breach",
                }
            ]
        )
        self.assertEqual(stats["created"], 0)
        self.assertGreaterEqual(stats.get("skipped_unsafe", 0), 1)
        self.assertFalse(Threat.objects.exists())
