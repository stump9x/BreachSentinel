from __future__ import annotations

from datetime import timedelta
from email.utils import format_datetime
from unittest.mock import MagicMock, patch

import httpx
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.intel.models import FeedSource, Threat
from apps.workers.feeds.clients import _fetch_rss_body, fetch_cert_rss_feeds
from apps.workers.services import ingest_rss_items


class SkipAlreadyIngestedTests(TestCase):
    def test_generic_technology_news_is_skipped_as_irrelevant(self):
        stats = ingest_rss_items(
            [
                {
                    "title": "Apple lifehacks for a new music accessory",
                    "link": "https://example.com/general-tech",
                    "summary": "A consumer product announcement with new colors.",
                    "category": "news",
                    "published": format_datetime(timezone.now()),
                }
            ]
        )

        self.assertEqual(stats["created"], 0)
        self.assertEqual(stats["skipped_irrelevant"], 1)
        self.assertFalse(Threat.objects.filter(source_url__contains="general-tech").exists())

    def test_vietnam_cyber_news_remains_relevant_and_prioritized(self):
        stats = ingest_rss_items(
            [
                {
                    "title": "Vietnamese university reports a data breach",
                    "link": "https://example.com/vietnam-breach",
                    "summary": "Threat actors exposed student records.",
                    "category": "news",
                    "published": format_datetime(timezone.now()),
                }
            ]
        )

        self.assertEqual(stats["created"], 1)
        self.assertEqual(stats["skipped_irrelevant"], 0)
        threat = Threat.objects.get(source_url__contains="vietnam-breach")
        self.assertTrue(threat.wire_relevant)
        self.assertEqual(threat.wire_priority, 100)

    @override_settings(WIRE_MAX_AGE_DAYS=7)
    def test_second_ingest_skips_existing_without_rewrite(self):
        published = timezone.now() - timedelta(hours=2)
        item = {
            "title": "Unique Wire Story XYZ",
            "link": "https://example.com/unique-wire-xyz",
            "summary": "first data breach summary",
            "category": "news",
            "published": format_datetime(published),
        }
        first = ingest_rss_items([item])
        self.assertEqual(first["created"], 1)
        t = Threat.objects.get(title="Unique Wire Story XYZ")
        self.assertEqual(t.summary, "first data breach summary")

        second = ingest_rss_items(
            [{**item, "summary": "data breach update should not overwrite"}]
        )
        self.assertEqual(second["created"], 0)
        self.assertEqual(second["updated"], 0)
        self.assertEqual(second["skipped_existing"], 1)
        t.refresh_from_db()
        self.assertEqual(t.summary, "first data breach summary")

    @override_settings(WIRE_MAX_AGE_DAYS=7)
    def test_vietnam_item_still_pinned_high_on_create(self):
        published = timezone.now() - timedelta(hours=3)
        stats = ingest_rss_items(
            [
                {
                    "title": "Data breach in Viet Nam banking sector",
                    "link": "https://example.com/vn-bank",
                    "summary": "Hanoi reported leaked customer records",
                    "category": "news",
                    "published": format_datetime(published),
                }
            ]
        )
        self.assertEqual(stats["created"], 1)
        t = Threat.objects.get(title="Data breach in Viet Nam banking sector")
        self.assertEqual(t.severity, Threat.Severity.HIGH)
        self.assertEqual(t.wire_priority, 100)


class ConditionalFeedFetchTests(TestCase):
    @patch("apps.workers.feeds.clients._client")
    @patch("apps.core.security.socket.getaddrinfo")
    def test_304_not_modified_skips_body(self, gai, client_cls):
        gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        resp = httpx.Response(
            304,
            headers={"etag": '"abc"', "last-modified": "Wed, 01 Jan 2020 00:00:00 GMT"},
            request=httpx.Request("GET", "https://example.com/feed"),
        )
        mock_get = MagicMock(return_value=resp)
        mock_client = MagicMock()
        mock_client.__enter__.return_value.get = mock_get
        client_cls.return_value = mock_client

        body, meta = _fetch_rss_body(
            "https://example.com/feed",
            etag='"abc"',
            last_modified="Wed, 01 Jan 2020 00:00:00 GMT",
        )
        self.assertIsNone(body)
        self.assertTrue(meta["not_modified"])

    @patch("apps.workers.feeds.clients._fetch_rss_body")
    def test_unchanged_body_hash_skips_parse(self, fetch_body):
        feed = FeedSource.objects.create(
            name="hash-feed",
            url="https://example.com/hash-feed.xml",
            category="news",
            is_active=True,
            last_body_sha256="deadbeef",
            processing_version=4,
            last_item_count=17,
        )
        # Body that hashes differently would parse; we return same hash via mock meta
        import hashlib

        raw = "<rss><channel></channel></rss>"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        feed.last_body_sha256 = digest
        feed.save(update_fields=["last_body_sha256"])

        fetch_body.return_value = (
            raw,
            {
                "not_modified": False,
                "etag": "",
                "last_modified": "",
                "body_sha256": digest,
            },
        )
        items = fetch_cert_rss_feeds(
            feeds=[
                {
                    "id": feed.id,
                    "name": feed.name,
                    "url": feed.url,
                    "category": "news",
                    "last_body_sha256": digest,
                    "processing_version": 4,
                }
            ],
            limit_per_feed=10,
        )
        self.assertEqual(items, [])
        feed.refresh_from_db()
        self.assertEqual(feed.last_status, "ok")
        self.assertEqual(feed.consecutive_failures, 0)
        self.assertEqual(feed.last_item_count, 17)

    @patch("apps.workers.feeds.clients._fetch_rss_body")
    def test_policy_version_change_forces_full_reprocess(self, fetch_body):
        feed = FeedSource.objects.create(
            name="old-policy",
            url="https://example.com/old-policy.xml",
            category="news",
            is_active=True,
            http_etag='"old"',
            last_body_sha256="same",
            processing_version=1,
        )
        raw = (
            "<rss><channel><generator>https://wordpress.org/?v=6.8</generator>"
            "<link>https://publisher.example/</link>"
            "<item><title>Vietnam policy story</title>"
            "<link>https://example.com/vn</link>"
            "<pubDate>Mon, 13 Jul 2026 10:00:00 GMT</pubDate>"
            "</item></channel></rss>"
        )
        fetch_body.return_value = (
            raw,
            {
                "not_modified": False,
                "etag": '"new"',
                "last_modified": "",
                "body_sha256": "same",
            },
        )

        items = fetch_cert_rss_feeds(
            feeds=[
                {
                    "id": feed.id,
                    "name": feed.name,
                    "url": feed.url,
                    "category": "news",
                    "http_etag": '"old"',
                    "last_body_sha256": "same",
                    "processing_version": 1,
                }
            ],
            limit_per_feed=10,
        )

        self.assertEqual(len(items), 1)
        fetch_body.assert_called_once_with(
            feed.url,
            etag="",
            last_modified="",
            via_tor=False,
        )
        feed.refresh_from_db()
        self.assertEqual(feed.processing_version, 4)
        self.assertTrue(feed.is_wordpress)
        self.assertEqual(feed.wordpress_site_url, "https://publisher.example/")
