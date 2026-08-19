"""X CTI accounts → The Wire discovery / ingest tests."""

from __future__ import annotations

from datetime import timedelta
from email.utils import format_datetime
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.intel.models import Threat
from apps.integrations.web_reader.x_wire import (
    DEFAULT_X_WIRE_ACCOUNTS,
    discover_x_wire_items,
    x_wire_accounts,
)
from apps.workers.services import ingest_rss_items, vietnam_wire_priority


class XWireAccountTests(SimpleTestCase):
    def test_default_pack_includes_requested_handles(self):
        names = {n.casefold() for n in DEFAULT_X_WIRE_ACCOUNTS}
        for handle in (
            "ibreaches",
            "darkwebsonar",
            "beralock",
            "h4ckmanac",
            "dailydarkweb",
            "falconfeedsio",
            "vecertradar",
            "6xvdpx",
            "groupib_ti",
        ):
            self.assertIn(handle, names)

    @override_settings(X_WIRE_ACCOUNTS="IBreaches, NewSource | GroupIB_TI")
    def test_env_accounts_override_and_dedupe(self):
        self.assertEqual(
            x_wire_accounts(),
            ["IBreaches", "NewSource", "GroupIB_TI"],
        )


@override_settings(
    X_WIRE_ENABLED=True,
    X_TWITTER_ENABLED=True,
    X_AUTH_TOKEN="tok",
    X_CT0="ct0",
    X_WIRE_MAX_AGE_DAYS=7,
    X_WIRE_PAUSE_MS=0,
    X_WIRE_ACCOUNTS="IBreaches,DailyDarkWeb",
)
class XWireDiscoveryTests(SimpleTestCase):
    @override_settings(X_AUTH_TOKEN="", X_CT0="")
    def test_skips_when_unconfigured(self):
        items, meta = discover_x_wire_items()
        self.assertEqual(items, [])
        self.assertTrue(meta["skipped"])

    @patch("apps.integrations.web_reader.x_wire.fetch_x_user_posts")
    def test_keeps_important_posts_drops_noise(self, mock_fetch):
        now = timezone.now()

        def _side(handle, limit=12):
            if handle == "IBreaches":
                return {
                    "hits": [
                        {
                            "title": "@IBreaches: leak",
                            "url": "https://x.com/IBreaches/status/1",
                            "content": (
                                "Alleged data breach at ACME Corp — 2M records leaked "
                                "https://t.co/abc"
                            ),
                            "published": format_datetime(now - timedelta(hours=2)),
                            "screen_name": "IBreaches",
                        },
                        {
                            "title": "@IBreaches: gm",
                            "url": "https://x.com/IBreaches/status/2",
                            "content": "Good morning followers ☕",
                            "published": format_datetime(now - timedelta(hours=1)),
                            "screen_name": "IBreaches",
                        },
                    ],
                    "error": None,
                    "configured": True,
                    "screen_name": handle,
                }
            return {
                "hits": [
                    {
                        "title": "@DailyDarkWeb: vn",
                        "url": "https://x.com/DailyDarkWeb/status/9",
                        "content": (
                            "Vietnam bank hit by ransomware claim on dark web"
                        ),
                        "published": format_datetime(now - timedelta(hours=3)),
                        "screen_name": "DailyDarkWeb",
                    }
                ],
                "error": None,
                "configured": True,
                "screen_name": handle,
            }

        mock_fetch.side_effect = _side
        items, meta = discover_x_wire_items(limit_per_account=5, now=now)
        urls = {i["link"] for i in items}
        self.assertIn("https://x.com/IBreaches/status/1", urls)
        self.assertIn("https://x.com/DailyDarkWeb/status/9", urls)
        self.assertNotIn("https://x.com/IBreaches/status/2", urls)
        self.assertEqual(meta["fetched"], 2)
        self.assertTrue(all(i["discovery"] == "x-wire" for i in items))
        self.assertTrue(all(i.get("x_handle") for i in items))


@override_settings(
    X_WIRE_ENABLED=True,
    X_TWITTER_ENABLED=True,
    X_AUTH_TOKEN="tok",
    X_CT0="ct0",
    X_WIRE_PAUSE_MS=0,
    X_WIRE_ACCOUNTS="IBreaches",
    WIRE_VIETNAM_PRIORITY=100,
    TITLE_TRANSLATE_INLINE_GOOGLE=False,
)
class XWireIngestTests(TestCase):
    @patch("apps.integrations.web_reader.x_wire.fetch_x_user_posts")
    def test_ingest_creates_tagged_x_threat_and_pins_vietnam(self, mock_fetch):
        now = timezone.now()
        mock_fetch.return_value = {
            "hits": [
                {
                    "title": "@IBreaches: vn leak",
                    "url": "https://x.com/IBreaches/status/42",
                    "content": (
                        "Alleged data breach affecting a Vietnam company — "
                        "customer records leaked"
                    ),
                    "published": format_datetime(now - timedelta(hours=1)),
                    "screen_name": "IBreaches",
                }
            ],
            "error": None,
            "configured": True,
            "screen_name": "IBreaches",
        }
        items, _ = discover_x_wire_items(limit_per_account=5, now=now)
        self.assertEqual(len(items), 1)
        stats = ingest_rss_items(items, source_label="x-wire")
        self.assertEqual(stats["created"], 1)
        threat = Threat.objects.get(source_url="https://x.com/IBreaches/status/42")
        self.assertEqual(threat.source, Threat.Source.X)
        self.assertTrue(threat.wire_relevant)
        self.assertEqual(threat.wire_priority, vietnam_wire_priority())
        slugs = set(threat.tags.values_list("slug", flat=True))
        self.assertIn("vietnam", slugs)
        self.assertIn("x", slugs)
        self.assertIn("x-ibreaches", slugs)
        self.assertNotIn("alleged-claim", slugs)
        self.assertIn("data-breach", slugs)
