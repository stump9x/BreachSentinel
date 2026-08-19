from __future__ import annotations

from django.test import TestCase

from apps.intel.feed_cleanup import cleanup_feed_sources, normalize_feed_url
from apps.intel.models import FeedSource


class NormalizeFeedUrlTests(TestCase):
    def test_strips_trailing_slash_and_www(self):
        self.assertEqual(
            normalize_feed_url("https://www.Example.com/feed/"),
            "https://example.com/feed",
        )

    def test_preserves_query(self):
        self.assertEqual(
            normalize_feed_url("https://feeds.example.com/x?format=xml"),
            "https://feeds.example.com/x?format=xml",
        )


class CleanupFeedSourcesTests(TestCase):
    def test_deletes_error_feeds(self):
        bad = FeedSource.objects.create(
            name="bad",
            url="https://example.com/bad.xml",
            category="news",
            is_active=True,
            last_status="error",
            last_error="403",
        )
        good = FeedSource.objects.create(
            name="good",
            url="https://example.com/good.xml",
            category="news",
            is_active=True,
            last_status="ok",
        )
        result = cleanup_feed_sources(purge_errors=True)
        self.assertFalse(FeedSource.objects.filter(pk=bad.pk).exists())
        good.refresh_from_db()
        self.assertTrue(good.is_active)
        self.assertEqual(result["errors_deleted"], 1)

    def test_deactivates_normalized_url_duplicates_keeps_best(self):
        keep = FeedSource.objects.create(
            name="kb",
            url="https://www.kb.cert.org/vuls/atomfeed/",
            category="cert",
            confidence=1,
            is_active=True,
            last_status="ok",
            last_item_count=10,
        )
        drop = FeedSource.objects.create(
            name="kb-dup",
            url="https://kb.cert.org/vuls/atomfeed",
            category="cert",
            confidence=2,
            is_active=True,
            last_status="ok",
            last_item_count=1,
        )
        result = cleanup_feed_sources()
        keep.refresh_from_db()
        drop.refresh_from_db()
        self.assertTrue(keep.is_active)
        self.assertFalse(drop.is_active)
        self.assertEqual(result["duplicates_deactivated"], 1)
        self.assertEqual(result["errors_deleted"], 0)

    def test_dry_run_does_not_write(self):
        bad = FeedSource.objects.create(
            name="bad",
            url="https://example.com/dry.xml",
            category="news",
            is_active=True,
            last_status="error",
        )
        result = cleanup_feed_sources(purge_errors=True, dry_run=True)
        bad.refresh_from_db()
        self.assertTrue(bad.is_active)
        self.assertEqual(result["errors_deleted"], 1)
