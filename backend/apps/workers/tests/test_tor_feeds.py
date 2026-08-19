from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
from django.test import TestCase, override_settings

from apps.intel.models import FeedSource
from apps.workers.feeds.clients import fetch_cert_rss_feeds
from apps.workers.feeds.intel_catalog import load_intel_catalog


class IntelCatalogTests(TestCase):
    def test_catalog_includes_bitsight_and_claim_news(self):
        rows = load_intel_catalog()
        urls = {row["url"] for row in rows}
        names = {row["name"] for row in rows}
        self.assertIn("https://www.bitsight.com/blog/rss.xml", urls)
        self.assertIn("darkwebinformer", names)
        self.assertNotIn("dread-onion", names)
        self.assertNotIn("breach-news", names)
        tor_rows = [r for r in rows if r.get("requires_tor")]
        self.assertGreaterEqual(len(tor_rows), 1)


@override_settings(
    TOR_ENABLED=True,
    TOR_SOCKS_PROXY="socks5h://127.0.0.1:9050",
)
class TorFeedFetchTests(TestCase):
    @patch("apps.workers.feeds.clients._fetch_rss_body")
    def test_requires_tor_feed_prefers_socks_first(self, fetch_body):
        feed = FeedSource.objects.create(
            name="databreachtoday",
            url="https://www.databreachtoday.com/rss.xml",
            category=FeedSource.Category.BREACH,
            requires_tor=True,
            is_active=True,
        )
        fetch_body.return_value = (
            "<rss><channel><item><title>Leak discussion</title>"
            "<link>https://www.databreachtoday.com/post/1</link>"
            "<description>data breach records leaked</description>"
            "</item></channel></rss>",
            {
                "not_modified": False,
                "etag": "",
                "last_modified": "",
                "body_sha256": "abc",
            },
        )

        items = fetch_cert_rss_feeds(
            feeds=[
                {
                    "id": feed.id,
                    "name": feed.name,
                    "url": feed.url,
                    "category": feed.category,
                    "requires_tor": True,
                    "processing_version": 5,
                }
            ],
            limit_per_feed=5,
        )
        self.assertEqual(len(items), 1)
        self.assertTrue(fetch_body.call_args.kwargs.get("via_tor"))

    @override_settings(TOR_ENABLED=False)
    @patch("apps.workers.feeds.clients._fetch_rss_body")
    def test_requires_tor_uses_clearnet_when_tor_disabled(self, fetch_body):
        feed = FeedSource.objects.create(
            name="databreachtoday",
            url="https://www.databreachtoday.com/rss.xml",
            category=FeedSource.Category.BREACH,
            requires_tor=True,
            is_active=True,
        )
        fetch_body.return_value = (
            "<rss><channel><item><title>Ok</title>"
            "<link>https://www.databreachtoday.com/a</link></item></channel></rss>",
            {
                "not_modified": False,
                "etag": "",
                "last_modified": "",
                "body_sha256": "z",
            },
        )
        items = fetch_cert_rss_feeds(
            feeds=[
                {
                    "id": feed.id,
                    "name": feed.name,
                    "url": feed.url,
                    "category": feed.category,
                    "requires_tor": True,
                    "processing_version": 5,
                }
            ],
            limit_per_feed=5,
        )
        self.assertEqual(len(items), 1)
        self.assertFalse(fetch_body.call_args.kwargs.get("via_tor"))
        feed.refresh_from_db()
        self.assertNotEqual(feed.last_status, "tor_off")

    def test_direct_forum_feed_skipped(self):
        feed = FeedSource.objects.create(
            name="darkforums",
            url="https://darkforums.me/external.php?type=RSS2",
            category=FeedSource.Category.OTHER,
            requires_tor=True,
            is_active=True,
        )
        items = fetch_cert_rss_feeds(
            feeds=[
                {
                    "id": feed.id,
                    "name": feed.name,
                    "url": feed.url,
                    "category": feed.category,
                    "requires_tor": True,
                    "processing_version": 5,
                }
            ],
            limit_per_feed=5,
        )
        self.assertEqual(items, [])
        feed.refresh_from_db()
        self.assertEqual(feed.last_status, "disabled")
