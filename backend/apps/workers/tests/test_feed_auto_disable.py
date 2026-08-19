from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
from django.core.management import call_command
from django.test import TestCase, override_settings

from apps.intel.models import FeedSource
from apps.workers.feeds.clients import (
    _fetch_rss_body,
    _is_terminal_feed_error,
    _mark_feed_status,
    fetch_cert_rss_feeds,
)


class TerminalFeedErrorTests(TestCase):
    def test_404_and_unsafe_ssrf_are_terminal_but_dns_is_retryable(self):
        self.assertTrue(_is_terminal_feed_error("Client error '404 Not Found'"))
        self.assertTrue(_is_terminal_feed_error("ssrf_blocked:Blocked private IP"))
        self.assertFalse(_is_terminal_feed_error("ssrf_blocked:DNS resolution failed"))
        self.assertFalse(_is_terminal_feed_error("Client error '403 Forbidden'"))
        self.assertFalse(_is_terminal_feed_error("Redirect response '301'"))


class FeedFailureLifecycleTests(TestCase):
    @override_settings(FEED_DELETE_AFTER_FAILURES=3)
    def test_repair_command_normalizes_success_and_reactivates_retryable_errors(self):
        unchanged = FeedSource.objects.create(
            name="unchanged",
            url="https://example.com/unchanged.xml",
            last_status="not_modified",
            is_active=True,
        )
        retryable = FeedSource.objects.create(
            name="retryable",
            url="https://example.com/retryable.xml",
            last_status="error",
            last_error="The read operation timed out",
            consecutive_failures=1,
            is_active=False,
        )
        exhausted = FeedSource.objects.create(
            name="exhausted",
            url="https://example.com/exhausted.xml",
            last_status="error",
            last_error="502 Bad Gateway",
            consecutive_failures=3,
            is_active=False,
        )

        call_command("repair_feed_statuses")

        unchanged.refresh_from_db()
        retryable.refresh_from_db()
        exhausted.refresh_from_db()
        self.assertEqual(unchanged.last_status, "ok")
        self.assertTrue(retryable.is_active)
        self.assertFalse(exhausted.is_active)

    def test_mark_transient_error_increments_and_keeps_active_for_retry(self):
        feed = FeedSource.objects.create(
            name="dead",
            url="https://example.com/dead.xml",
            category="news",
            is_active=True,
        )
        _mark_feed_status({"id": feed.id}, status="error", error="403 Forbidden")
        feed.refresh_from_db()
        self.assertTrue(feed.is_active)
        self.assertEqual(feed.consecutive_failures, 1)
        self.assertEqual(feed.last_status, "error")

    def test_mark_ok_resets_failures(self):
        feed = FeedSource.objects.create(
            name="alive",
            url="https://example.com/ok.xml",
            category="news",
            is_active=True,
            consecutive_failures=2,
        )
        _mark_feed_status({"id": feed.id}, status="ok", item_count=5)
        feed.refresh_from_db()
        self.assertTrue(feed.is_active)
        self.assertEqual(feed.consecutive_failures, 0)
        self.assertEqual(feed.last_item_count, 5)

    @override_settings(FEED_DELETE_AFTER_FAILURES=3)
    def test_deletes_after_consecutive_failures(self):
        feed = FeedSource.objects.create(
            name="flaky",
            url="https://example.com/flaky.xml",
            category="news",
            is_active=True,
            consecutive_failures=2,
        )
        pk = feed.pk
        _mark_feed_status({"id": pk}, status="error", error="502 Bad Gateway")
        self.assertFalse(FeedSource.objects.filter(pk=pk).exists())

    @override_settings(FEED_DELETE_AFTER_FAILURES=3)
    def test_requires_tor_feed_also_deleted_after_three_failures(self):
        """Tor preference does not exempt dead feeds once both paths keep failing."""
        feed = FeedSource.objects.create(
            name="tor-dead",
            url="https://example.com/tor-dead.xml",
            category="breach",
            requires_tor=True,
            is_active=True,
            consecutive_failures=2,
        )
        pk = feed.pk
        _mark_feed_status(
            {"id": pk, "requires_tor": True},
            status="error",
            error="direct:403; tor:ProxyError",
        )
        self.assertFalse(FeedSource.objects.filter(pk=pk).exists())

    @override_settings(TOR_ENABLED=True, FEED_DELETE_AFTER_FAILURES=3)
    @patch("apps.workers.feeds.clients._fetch_rss_body")
    def test_tor_success_keeps_feed_and_resets_failure_counter(self, fetch_body):
        feed = FeedSource.objects.create(
            name="tor-ok",
            url="https://example.com/tor-ok.xml",
            category="breach",
            requires_tor=False,
            is_active=True,
            consecutive_failures=2,
        )
        request = httpx.Request("GET", feed.url)
        forbidden = httpx.HTTPStatusError(
            "403 Forbidden",
            request=request,
            response=httpx.Response(403, request=request),
        )
        fetch_body.side_effect = [
            forbidden,
            (
                "<rss><channel><item><title>Leak via Tor</title>"
                "<link>https://example.com/a</link></item></channel></rss>",
                {
                    "not_modified": False,
                    "etag": "",
                    "last_modified": "",
                    "body_sha256": "tor1",
                },
            ),
        ]
        items = fetch_cert_rss_feeds(
            feeds=[
                {
                    "id": feed.id,
                    "name": feed.name,
                    "url": feed.url,
                    "category": "breach",
                    "requires_tor": False,
                    "processing_version": 5,
                }
            ],
            limit_per_feed=5,
        )
        feed.refresh_from_db()
        self.assertEqual(len(items), 1)
        self.assertTrue(feed.is_active)
        self.assertTrue(feed.requires_tor)
        self.assertEqual(feed.consecutive_failures, 0)
        self.assertEqual(feed.last_status, "ok")

    def test_terminal_404_deletes_immediately(self):
        feed = FeedSource.objects.create(
            name="gone",
            url="https://example.com/gone.xml",
            category="news",
            is_active=True,
        )
        pk = feed.pk
        _mark_feed_status(
            {"id": pk},
            status="error",
            error="Client error '404 Not Found' for url 'https://example.com/gone.xml'",
        )
        self.assertFalse(FeedSource.objects.filter(pk=pk).exists())

    @patch("apps.workers.feeds.clients._client")
    @patch("apps.core.security.socket.getaddrinfo")
    @override_settings(TOR_ENABLED=False)
    def test_http_error_during_fetch_stays_active_for_retry(self, gai, client_cls):
        gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        feed = FeedSource.objects.create(
            name="cylance",
            url="https://www.cylance.com/rss/GlobalCylanceThreatReport",
            category="news",
            confidence=1,
            is_active=True,
        )
        mock_client = MagicMock()
        mock_client.__enter__.return_value.get.side_effect = httpx.HTTPError("403")
        client_cls.return_value = mock_client

        fetch_cert_rss_feeds(
            feeds=[
                {
                    "id": feed.id,
                    "name": feed.name,
                    "url": feed.url,
                    "category": "news",
                }
            ],
            limit_per_feed=5,
        )
        feed.refresh_from_db()
        self.assertTrue(feed.is_active)
        self.assertEqual(feed.last_status, "error")
        self.assertEqual(feed.consecutive_failures, 1)

    @override_settings(TOR_ENABLED=True)
    @patch("apps.workers.feeds.clients._fetch_rss_body")
    def test_403_retries_through_tor_and_marks_feed_ok(self, fetch_body):
        feed = FeedSource.objects.create(
            name="blocked",
            url="https://example.com/feed.xml",
            category="news",
            is_active=True,
        )
        request = httpx.Request("GET", feed.url)
        forbidden = httpx.HTTPStatusError(
            "403 Forbidden",
            request=request,
            response=httpx.Response(403, request=request),
        )
        fetch_body.side_effect = [
            forbidden,
            (
                "<rss><channel><item><title>Fresh data breach</title></item></channel></rss>",
                {
                    "not_modified": False,
                    "etag": "",
                    "last_modified": "",
                    "body_sha256": "abc",
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
                }
            ],
            limit_per_feed=5,
        )

        feed.refresh_from_db()
        self.assertEqual(len(items), 1)
        self.assertTrue(feed.requires_tor)
        self.assertTrue(feed.is_active)
        self.assertEqual(feed.last_status, "ok")
        self.assertEqual(
            [call.kwargs["via_tor"] for call in fetch_body.call_args_list],
            [False, True],
        )


class SafeRedirectFetchTests(TestCase):
    @patch("apps.workers.feeds.clients._client")
    @patch("apps.core.security.socket.getaddrinfo")
    def test_follows_validated_redirect(self, gai, client_cls):
        gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        redirect = httpx.Response(
            301,
            headers={"location": "https://example.com/feed/"},
            request=httpx.Request("GET", "https://example.com/feed"),
        )
        ok = httpx.Response(
            200,
            text="<rss><channel><item><title>a</title></item></channel></rss>",
            request=httpx.Request("GET", "https://example.com/feed/"),
        )
        mock_get = MagicMock(side_effect=[redirect, ok])
        mock_client = MagicMock()
        mock_client.__enter__.return_value.get = mock_get
        client_cls.return_value = mock_client

        body, meta = _fetch_rss_body("https://example.com/feed")
        self.assertIn("<rss>", body or "")
        self.assertFalse(meta.get("not_modified"))
        self.assertEqual(mock_get.call_count, 2)
