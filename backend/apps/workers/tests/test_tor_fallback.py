"""Tests for clearnet-first Tor fallback and unreachable feed pruning."""

from __future__ import annotations

from unittest.mock import patch

import httpx
from django.test import SimpleTestCase, TestCase, override_settings

from apps.intel.models import FeedSource
from apps.workers.feeds.clients import (
    _looks_like_rss_or_atom,
    _should_retry_via_tor,
    fetch_cert_rss_feeds,
)
from apps.workers.feeds.forum_safety import CLAIM_NEWS_FEED_NAMES
from apps.workers.feeds.intel_catalog import load_intel_catalog


class TorFallbackUnitTests(SimpleTestCase):
    def test_retry_via_tor_on_403_429_and_timeout(self):
        req = httpx.Request("GET", "https://example.com/feed")
        forbidden = httpx.HTTPStatusError(
            "403",
            request=req,
            response=httpx.Response(403, request=req),
        )
        self.assertTrue(_should_retry_via_tor(forbidden))
        self.assertTrue(_should_retry_via_tor(httpx.TimeoutException("timed out")))
        self.assertTrue(_should_retry_via_tor(httpx.ConnectError("connect")))

    def test_looks_like_rss(self):
        self.assertTrue(_looks_like_rss_or_atom("<?xml version='1.0'?><rss>"))
        self.assertFalse(_looks_like_rss_or_atom("<!DOCTYPE html><html>"))


class CatalogPruneTests(SimpleTestCase):
    def test_dead_breach_news_removed_from_catalog_and_claim_names(self):
        rows = load_intel_catalog()
        names = {r.get("name") for r in rows}
        self.assertNotIn("breach-news", names)
        self.assertNotIn("data-breach-news", names)
        self.assertNotIn("breach-news", CLAIM_NEWS_FEED_NAMES)
        self.assertNotIn("data-breach-news", CLAIM_NEWS_FEED_NAMES)


@override_settings(TOR_ENABLED=True, TOR_SOCKS_PROXY="socks5h://127.0.0.1:9050")
class TorFallbackFetchTests(TestCase):
    @patch("apps.workers.feeds.clients._fetch_rss_body")
    def test_requires_tor_feed_falls_back_to_clearnet_when_tor_fails(self, fetch_body):
        feed = FeedSource.objects.create(
            name="blocked-then-ok",
            url="https://example.com/feed.xml",
            category="breach",
            requires_tor=True,
            is_active=True,
        )
        fetch_body.side_effect = [
            httpx.ProxyError("tor down"),
            (
                "<rss><channel><item><title>Claim leak</title>"
                "<link>https://example.com/a</link></item></channel></rss>",
                {
                    "not_modified": False,
                    "etag": "",
                    "last_modified": "",
                    "body_sha256": "x",
                },
            ),
        ]
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
        self.assertEqual(
            [c.kwargs["via_tor"] for c in fetch_body.call_args_list],
            [True, False],
        )

    @patch("apps.workers.feeds.clients._fetch_rss_body")
    def test_clearnet_403_retries_tor(self, fetch_body):
        feed = FeedSource.objects.create(
            name="geo-block",
            url="https://example.com/geo.xml",
            category="news",
            requires_tor=False,
            is_active=True,
        )
        req = httpx.Request("GET", feed.url)
        forbidden = httpx.HTTPStatusError(
            "403 Forbidden",
            request=req,
            response=httpx.Response(403, request=req),
        )
        fetch_body.side_effect = [
            forbidden,
            (
                "<rss><channel><item><title>Breach report</title></item></channel></rss>",
                {
                    "not_modified": False,
                    "etag": "",
                    "last_modified": "",
                    "body_sha256": "y",
                },
            ),
        ]
        items = fetch_cert_rss_feeds(
            feeds=[
                {
                    "id": feed.id,
                    "name": feed.name,
                    "url": feed.url,
                    "category": "news",
                    "requires_tor": False,
                    "processing_version": 5,
                }
            ],
            limit_per_feed=5,
        )
        self.assertEqual(len(items), 1)
        feed.refresh_from_db()
        self.assertTrue(feed.requires_tor)

    @override_settings(TOR_ENABLED=False)
    @patch("apps.workers.feeds.clients._fetch_rss_body")
    def test_requires_tor_still_tries_clearnet_when_tor_disabled(self, fetch_body):
        feed = FeedSource.objects.create(
            name="tor-flagged",
            url="https://example.com/tor-flagged.xml",
            category="breach",
            requires_tor=True,
            is_active=True,
        )
        fetch_body.return_value = (
            "<rss><channel><item><title>Ok</title></item></channel></rss>",
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
                    "category": "breach",
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

    @patch("apps.workers.feeds.clients._fetch_rss_body")
    def test_non_rss_html_triggers_tor_then_fails_clean(self, fetch_body):
        fetch_body.side_effect = [
            (
                "<!DOCTYPE html><html>login</html>",
                {
                    "not_modified": False,
                    "etag": "",
                    "last_modified": "",
                    "body_sha256": "h",
                },
            ),
            (
                "<!DOCTYPE html><html>cf</html>",
                {
                    "not_modified": False,
                    "etag": "",
                    "last_modified": "",
                    "body_sha256": "h2",
                },
            ),
        ]
        feed = FeedSource.objects.create(
            name="html-wall",
            url="https://example.com/wall.xml",
            category="news",
            is_active=True,
        )
        items = fetch_cert_rss_feeds(
            feeds=[
                {
                    "id": feed.id,
                    "name": feed.name,
                    "url": feed.url,
                    "category": "news",
                    "requires_tor": False,
                    "processing_version": 5,
                }
            ],
            limit_per_feed=5,
        )
        self.assertEqual(items, [])
        feed.refresh_from_db()
        self.assertEqual(feed.last_status, "error")
