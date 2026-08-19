"""Claim-news fetch shares the 3-strike feed deletion lifecycle."""

from __future__ import annotations

from unittest.mock import patch

import httpx
from django.test import TestCase, override_settings

from apps.intel.models import FeedSource
from apps.workers.feeds.forum_fetch import fetch_forum_claim_items


@override_settings(FEED_DELETE_AFTER_FAILURES=3, TOR_ENABLED=True)
class ForumFetchLifecycleTests(TestCase):
    @patch("apps.workers.feeds.clients.fetch_feed_body_with_tor_fallback")
    def test_three_errors_delete_claim_feed(self, fetch_body):
        feed = FeedSource.objects.create(
            name="darkwebinformer",
            url="https://darkwebinformer.com/rss/",
            category="breach",
            is_active=True,
            consecutive_failures=2,
        )
        pk = feed.pk
        fetch_body.side_effect = httpx.HTTPError("direct:403; tor:timeout")
        items, meta = fetch_forum_claim_items(limit_per_feed=5)
        self.assertEqual(items, [])
        self.assertFalse(FeedSource.objects.filter(pk=pk).exists())
        self.assertIn("darkwebinformer", meta["feeds"])

    @patch("apps.workers.feeds.clients.fetch_feed_body_with_tor_fallback")
    def test_tor_ok_keeps_claim_feed_and_resets_failures(self, fetch_body):
        feed = FeedSource.objects.create(
            name="databreachtoday",
            url="https://www.databreachtoday.com/rss.xml",
            category="breach",
            requires_tor=False,
            is_active=True,
            consecutive_failures=2,
        )
        fetch_body.return_value = (
            "<rss><channel><item><title>Alleged claim leak</title>"
            "<link>https://www.databreachtoday.com/a</link>"
            "<description>ransomware victim claim</description>"
            "</item></channel></rss>",
            {"not_modified": False},
            True,
        )
        items, meta = fetch_forum_claim_items(limit_per_feed=5)
        feed.refresh_from_db()
        self.assertGreaterEqual(len(items), 1)
        self.assertTrue(feed.is_active)
        self.assertTrue(feed.requires_tor)
        self.assertEqual(feed.consecutive_failures, 0)
        self.assertEqual(feed.last_status, "ok")
        self.assertTrue(meta["feeds"]["databreachtoday"].get("via_tor"))
