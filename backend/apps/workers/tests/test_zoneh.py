"""Zone-H / HaxorID defacement archive → Wire tests."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.intel.models import Threat
from apps.workers.feeds.zoneh import (
    fetch_zoneh_archive_items,
    parse_defacement_archive_html,
)
from apps.workers.services import ingest_rss_items

SAMPLE_HAXOR_HTML = """
<html><body>
<table>
<tr><th>Date</th><th>Attacker</th><th>Team</th><th>H</th><th>M</th><th>R</th>
<th>L</th><th>S</th><th>URL</th><th>Os</th><th>Mirror</th></tr>
<tr>
  <td>2026-07-20 09:12:18</td>
  <td><a title='ASİ INTERNATIONAL' href='/archive/attacker/ASI'>ASİ INTERNATIONAL</a></td>
  <td>TeamX</td><td></td><td></td><td></td>
  <td><i class='flag flag-us' alt='United States' title='United States'></i></td><td></td>
  <td>example-victim.com/defaced.html</td>
  <td>Linux</td>
  <td><a href="/mirror/251315">mirror</a></td>
</tr>
<tr>
  <td>2026-07-19 08:00:00</td>
  <td><a href='/archive/attacker/Foo'>FooBar</a></td>
  <td></td><td></td><td></td><td></td><td></td><td></td>
  <td>vn-bank.example.vn/</td>
  <td>Linux</td>
  <td><a href="/mirror/251300">mirror</a></td>
</tr>
</table>
</body></html>
"""


class ZoneHParseTests(SimpleTestCase):
    def test_parses_haxor_style_rows(self):
        items = parse_defacement_archive_html(
            SAMPLE_HAXOR_HTML,
            base_url="https://haxor.id",
            source_label="zoneh:haxor",
        )
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["link"], "https://haxor.id/mirror/251315")
        self.assertIn("example-victim.com", items[0]["title"])
        self.assertIn("ASİ INTERNATIONAL", items[0]["title"])
        self.assertEqual(items[0]["category"], "defacement")
        self.assertEqual(items[0]["discovery"], "zoneh-archive")
        self.assertTrue(items[0]["published"].startswith("2026-07-20"))
        self.assertEqual(items[0]["country_code"], "US")
        self.assertEqual(items[0]["country"], "United States")
        self.assertIn("Country: United States", items[0]["summary"])
        self.assertEqual(items[1]["country_code"], "VN")
        self.assertEqual(items[1]["country"], "Vietnam")
        self.assertIn("Country: Vietnam", items[1]["summary"])

    @override_settings(ZONEH_ENABLED=False)
    def test_disabled_skips(self):
        items, meta = fetch_zoneh_archive_items()
        self.assertEqual(items, [])
        self.assertTrue(meta["skipped"])


class ZoneHFetchTests(SimpleTestCase):
    @override_settings(
        ZONEH_ENABLED=True,
        ZONEH_PROVIDER="haxor",
        ZONEH_PAGES=1,
        ZONEH_INCLUDE_SPECIAL=False,
    )
    @patch("apps.workers.feeds.zoneh.httpx.Client")
    def test_fetch_maps_html(self, mock_client_cls):
        response = MagicMock()
        response.status_code = 200
        response.text = SAMPLE_HAXOR_HTML
        response.raise_for_status = MagicMock()
        client = MagicMock()
        client.__enter__.return_value = client
        client.get.return_value = response
        mock_client_cls.return_value = client

        items, meta = fetch_zoneh_archive_items(pages=1)
        self.assertGreaterEqual(len(items), 1)
        self.assertEqual(meta["provider"], "haxor")
        self.assertFalse(meta["skipped"])
        self.assertTrue(client.get.called)


class ZoneHIngestTests(TestCase):
    def test_ingest_creates_wire_threat(self):
        now = timezone.now()
        items = [
            {
                "title": "Defacement by X: bank.example.vn/",
                "link": "https://haxor.id/mirror/999001",
                "summary": "Zone-H-style defacement archive hit.\nTarget: bank.example.vn/\nCountry: Vietnam",
                "published": (now - timedelta(hours=1)).isoformat(),
                "feed": "zoneh:haxor",
                "feed_url": "https://haxor.id/archive",
                "category": "defacement",
                "discovery": "zoneh-archive",
                "defaced_url": "bank.example.vn/",
                "country_code": "VN",
                "country": "Vietnam",
            }
        ]
        stats = ingest_rss_items(items, source_label="zoneh")
        self.assertEqual(stats["created"], 1)
        threat = Threat.objects.get(source_url="https://haxor.id/mirror/999001")
        self.assertTrue(threat.wire_relevant)
        self.assertEqual(threat.raw_payload.get("discovery"), "zoneh-archive")
        slugs = set(threat.tags.values_list("slug", flat=True))
        self.assertIn("defacement", slugs)
        self.assertIn("vietnam", slugs)
        self.assertNotIn("breach", slugs)
        self.assertNotIn("data-breach", slugs)
