"""Exa → The Wire discovery tests."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.intel.models import Threat
from apps.integrations.web_reader.exa_wire import (
    discover_exa_wire_items,
    discover_exa_wire_news,
)
from apps.workers.services import ingest_rss_items


class ExaWireDiscoveryTests(SimpleTestCase):
    @override_settings(EXA_API_KEY="", EXA_WIRE_ENABLED=True)
    def test_skips_when_unconfigured(self):
        items, meta = discover_exa_wire_items()
        self.assertEqual(items, [])
        self.assertTrue(meta["skipped"])

    @override_settings(
        EXA_API_KEY="test-key",
        EXA_WIRE_ENABLED=True,
        EXA_WIRE_MAX_AGE_DAYS=14,
        EXA_WIRE_QUERIES="Latest ransomware attacks",
    )
    @patch("apps.integrations.web_reader.exa_wire.search_exa")
    def test_maps_dated_hits_and_rejects_undated(self, mock_search):
        now = timezone.now()
        mock_search.return_value = [
            {
                "title": "Go2Joy ransomware attack",
                "url": "https://breach.house/go2joy",
                "content": "ransomexx claimed a data breach",
                "published": (now - timedelta(days=2)).isoformat(),
                "engine": "exa",
            },
            {
                "title": "Undated junk",
                "url": "https://example.com/old",
                "content": "breach",
                "published": "",
                "engine": "exa",
            },
        ]
        items, meta = discover_exa_wire_news(limit=10, now=now)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["link"], "https://breach.house/go2joy")
        self.assertEqual(items[0]["discovery"], "exa-wire")
        self.assertIn(items[0]["category"], {"breach", "ransomware", "news"})
        self.assertEqual(meta["skipped_undated"], 1)


class ExaWireIngestTests(TestCase):
    @override_settings(EXA_API_KEY="test-key", EXA_WIRE_ENABLED=True)
    @patch("apps.integrations.web_reader.exa_wire.search_exa")
    def test_ingest_creates_wire_threat(self, mock_search):
        now = timezone.now()
        mock_search.return_value = [
            {
                "title": "Bank hit by ransomware and data leak",
                "url": "https://dexpose.io/bank-leak",
                "content": "Customer records leaked after ransomware attack",
                "published": (now - timedelta(days=1)).isoformat(),
                "engine": "exa",
            }
        ]
        # Only news path; empty domain list avoids many site calls.
        items, _ = discover_exa_wire_items(
            limit=5, limit_per_domain=1, domains=[], now=now
        )
        self.assertEqual(len(items), 1)
        stats = ingest_rss_items(items, source_label="exa-wire")
        self.assertEqual(stats["created"], 1)
        threat = Threat.objects.get(source_url="https://dexpose.io/bank-leak")
        self.assertTrue(threat.wire_relevant)
        self.assertEqual(threat.raw_payload.get("discovery"), "exa-wire")
