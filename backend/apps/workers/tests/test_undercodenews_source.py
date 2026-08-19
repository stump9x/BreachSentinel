from __future__ import annotations

import json
from pathlib import Path

from django.test import TestCase

from apps.intel.models import FeedSource
from apps.workers.services import ingest_rss_items


RSS_SOURCES = (
    Path(__file__).resolve().parents[1] / "feeds" / "rss_sources.json"
)


class UndercodeNewsSourceTests(TestCase):
    def test_rss_sources_json_includes_undercodenews_site_feed(self):
        data = json.loads(RSS_SOURCES.read_text(encoding="utf-8"))
        urls = {row.get("url") for row in data}
        self.assertIn("https://undercodenews.com/feed/", urls)
        row = next(r for r in data if r.get("url") == "https://undercodenews.com/feed/")
        self.assertEqual(row.get("name"), "undercodenews")
        self.assertEqual(row.get("category"), "news")

    def test_seed_creates_active_undercodenews_feed(self):
        from django.core.management import call_command

        call_command("seed_rss_sources")
        feed = FeedSource.objects.get(url="https://undercodenews.com/feed/")
        self.assertEqual(feed.name, "undercodenews")
        self.assertTrue(feed.is_active)
        self.assertEqual(feed.category, FeedSource.Category.NEWS)
