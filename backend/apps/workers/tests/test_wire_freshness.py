from __future__ import annotations

from datetime import timedelta
from email.utils import format_datetime

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.intel.models import Threat
from apps.workers.feed_dates import is_within_max_age, parse_feed_datetime
from apps.workers.services import ingest_rss_items


class ParseFeedDatetimeTests(TestCase):
    def test_parses_rfc822_pubdate(self):
        dt = parse_feed_datetime("Wed, 15 Jul 2026 10:30:00 GMT")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 7)
        self.assertEqual(dt.day, 15)
        self.assertEqual(dt.hour, 10)
        self.assertTrue(timezone.is_aware(dt))

    def test_parses_iso8601(self):
        dt = parse_feed_datetime("2026-07-14T08:00:00Z")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.day, 14)
        self.assertTrue(timezone.is_aware(dt))

    def test_empty_returns_none(self):
        self.assertIsNone(parse_feed_datetime(""))
        self.assertIsNone(parse_feed_datetime(None))


class WireAgeFilterTests(TestCase):
    @override_settings(WIRE_MAX_AGE_DAYS=7)
    def test_skips_items_older_than_one_week(self):
        old = timezone.now() - timedelta(days=10)
        recent = timezone.now() - timedelta(days=5)
        stats = ingest_rss_items(
            [
                {
                    "title": "Ancient breach report",
                    "link": "https://example.com/old",
                    "summary": "old",
                    "category": "news",
                    "published": format_datetime(old),
                },
                {
                    "title": "Fresh leak this week",
                    "link": "https://example.com/new",
                    "summary": "data breach leaked credentials",
                    "category": "news",
                    "published": format_datetime(recent),
                },
            ]
        )
        self.assertEqual(stats["skipped_old"], 1)
        self.assertEqual(stats["created"], 1)
        self.assertFalse(Threat.objects.filter(title="Ancient breach report").exists())
        t = Threat.objects.get(title="Fresh leak this week")
        self.assertAlmostEqual(
            t.published_at.timestamp(), recent.timestamp(), delta=2
        )

    @override_settings(WIRE_MAX_AGE_DAYS=7)
    def test_skips_reingest_of_existing_item(self):
        published = timezone.now() - timedelta(hours=6)
        item = {
            "title": "Same story",
            "link": "https://example.com/a",
            "summary": "data breach v1",
            "category": "news",
            "published": published.isoformat(),
        }
        ingest_rss_items([item])
        first = Threat.objects.get(title="Same story").published_at
        stats = ingest_rss_items(
            [{**item, "summary": "data breach v2 should be ignored"}]
        )
        self.assertEqual(stats["skipped_existing"], 1)
        self.assertEqual(stats["created"], 0)
        t = Threat.objects.get(title="Same story")
        self.assertEqual(t.published_at, first)
        self.assertEqual(t.summary, "data breach v1")

    def test_is_within_max_age(self):
        now = timezone.now()
        self.assertTrue(is_within_max_age(now - timedelta(days=3), max_age_days=7))
        self.assertFalse(is_within_max_age(now - timedelta(days=10), max_age_days=7))
