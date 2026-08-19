"""Tests for feed datetime parse + publish clamp."""

from __future__ import annotations

from datetime import timedelta

from django.test import SimpleTestCase
from django.utils import timezone

from apps.workers.feed_dates import clamp_published_at, parse_feed_datetime


class ClampPublishedAtTests(SimpleTestCase):
    def test_missing_becomes_now(self):
        now = timezone.now()
        self.assertEqual(clamp_published_at(None, now=now), now)

    def test_past_preserved(self):
        now = timezone.now()
        past = now - timedelta(hours=3)
        self.assertEqual(clamp_published_at(past, now=now), past)

    def test_far_future_clamped_to_now(self):
        now = timezone.now()
        future = now + timedelta(days=2)
        self.assertEqual(clamp_published_at(future, now=now), now)

    def test_small_skew_allowed(self):
        now = timezone.now()
        slight = now + timedelta(minutes=20)
        self.assertEqual(clamp_published_at(slight, now=now), slight)

    def test_parse_rfc2822(self):
        dt = parse_feed_datetime("Mon, 20 Jul 2026 10:00:00 +0000")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.year, 2026)
