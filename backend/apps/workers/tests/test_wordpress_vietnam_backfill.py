from __future__ import annotations

from datetime import timedelta, timezone as dt_timezone
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.intel.models import FeedSource
from apps.workers.feeds.wordpress import fetch_wordpress_vietnam_backfill
from apps.workers.services import ingest_rss_items


INDEX_XML = """<?xml version="1.0"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://undercodenews.com/post-sitemap1.xml</loc>
    <lastmod>2026-07-15T13:03:21+00:00</lastmod>
  </sitemap>
  <sitemap>
    <loc>https://undercodenews.com/post-sitemap2.xml</loc>
    <lastmod>2026-07-13T10:31:35+00:00</lastmod>
  </sitemap>
  <sitemap>
    <loc>https://evil.example/post-sitemap3.xml</loc>
    <lastmod>2026-07-13T10:31:35+00:00</lastmod>
  </sitemap>
</sitemapindex>
"""

SHARD_1_XML = """<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://undercodenews.com/global-security-story/</loc>
    <lastmod>2026-07-15T12:00:00+00:00</lastmod>
  </url>
</urlset>
"""

SHARD_2_XML = """<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://undercodenews.com/alleged-thang-long-university-data-breach-sparks-cybersecurity-concerns-in-vietnam-dark-web-recent-claims-video/</loc>
    <lastmod>2026-07-13T10:31:35+00:00</lastmod>
  </url>
  <url>
    <loc>https://undercodenews.com/a-darkweb-threat-actor-claim-thang-long-university-vietnam-allegedly-targeted-in-data-breach-attempt-dark-web-recent-claims-video/</loc>
    <lastmod>2026-07-13T10:27:52+00:00</lastmod>
  </url>
</urlset>
"""


@override_settings(
    WIRE_VIETNAM_MAX_AGE_DAYS=30,
    WIRE_WORDPRESS_BACKFILL_INTERVAL_MINUTES=60,
)
class WordPressVietnamBackfillTests(TestCase):
    def setUp(self):
        self.feed = FeedSource.objects.create(
            name="undercodenews",
            url="https://undercodenews.com/feed/",
            category=FeedSource.Category.NEWS,
            is_active=True,
            is_wordpress=True,
        )

    @patch("apps.workers.feeds.wordpress._fetch_public_text")
    def test_discovers_vietnam_posts_missing_from_rolling_rss(self, fetch):
        fetch.side_effect = [INDEX_XML, SHARD_1_XML, SHARD_2_XML]
        now = timezone.datetime(2026, 7, 16, 3, 0, tzinfo=dt_timezone.utc)

        items = fetch_wordpress_vietnam_backfill(now=now)

        self.assertEqual(len(items), 2)
        self.assertTrue(all(i["feed"] == "undercodenews" for i in items))
        self.assertTrue(all(i["country_code"] == "VN" for i in items))
        self.assertTrue(all("vietnam" in i["title"].lower() for i in items))
        self.assertEqual(fetch.call_count, 3)

        stats = ingest_rss_items(items)
        self.assertEqual(stats["created"], 2)
        self.assertEqual(stats["skipped_old"], 0)

    @patch("apps.workers.feeds.wordpress._fetch_public_text")
    def test_recent_scan_skips_network(self, fetch):
        self.feed.sitemap_last_scanned_at = timezone.now() - timedelta(minutes=10)
        self.feed.save(update_fields=["sitemap_last_scanned_at"])

        items = fetch_wordpress_vietnam_backfill()

        self.assertEqual(items, [])
        fetch.assert_not_called()

    @patch("apps.workers.feeds.wordpress._fetch_public_text")
    def test_rejects_cross_host_sitemap_urls(self, fetch):
        fetch.side_effect = [INDEX_XML, SHARD_1_XML, SHARD_2_XML]
        now = timezone.datetime(2026, 7, 16, 3, 0, tzinfo=dt_timezone.utc)

        fetch_wordpress_vietnam_backfill(now=now)

        called_urls = [call.args[0] for call in fetch.call_args_list]
        self.assertNotIn("https://evil.example/post-sitemap3.xml", called_urls)

    @patch("apps.workers.feeds.wordpress._fetch_public_text")
    def test_scans_other_detected_wordpress_sources(self, fetch):
        FeedSource.objects.create(
            name="other-security",
            url="https://feeds.feedburner.com/other-security",
            category=FeedSource.Category.NEWS,
            is_active=True,
            is_wordpress=True,
            wordpress_site_url="https://security.example/",
        )
        other_index = """<sitemapindex>
          <sitemap><loc>https://security.example/post-sitemap1.xml</loc></sitemap>
        </sitemapindex>"""
        other_shard = """<urlset><url>
          <loc>https://security.example/vietnam-ransomware-incident/</loc>
          <lastmod>2026-07-14T10:00:00+00:00</lastmod>
        </url></urlset>"""

        def response(url):
            documents = {
                "https://undercodenews.com/wp-sitemap.xml": INDEX_XML,
                "https://undercodenews.com/post-sitemap1.xml": SHARD_1_XML,
                "https://undercodenews.com/post-sitemap2.xml": SHARD_2_XML,
                "https://security.example/wp-sitemap.xml": other_index,
                "https://security.example/post-sitemap1.xml": other_shard,
            }
            return documents[url]

        fetch.side_effect = response
        now = timezone.datetime(2026, 7, 16, 3, 0, tzinfo=dt_timezone.utc)

        items = fetch_wordpress_vietnam_backfill(now=now)

        self.assertTrue(
            any(
                item["feed"] == "other-security"
                and "Vietnam Ransomware" in item["title"]
                for item in items
            )
        )
