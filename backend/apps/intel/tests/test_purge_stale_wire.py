from __future__ import annotations

from datetime import timedelta
from io import StringIO

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.intel.models import FeedSource, Tag, Threat


@override_settings(WIRE_MAX_AGE_DAYS=7, WIRE_VIETNAM_MAX_AGE_DAYS=0)
class PurgeStaleWireTests(TestCase):
    def test_from_today_keeps_vietnam_and_wipes_other_rss(self):
        now = timezone.now()
        vn_tag = Tag.objects.create(name="Vietnam", slug="vietnam")
        vn = Threat.objects.create(
            title="VN keep",
            source=Threat.Source.NEWS,
            wire_relevant=True,
            published_at=now - timedelta(days=10),
            raw_payload={"feed_source": "rss", "feed": "x"},
        )
        vn.tags.add(vn_tag)
        old_foreign = Threat.objects.create(
            title="June foreign",
            source=Threat.Source.NEWS,
            wire_relevant=True,
            published_at=now - timedelta(days=20),
            raw_payload={"feed_source": "rss", "feed": "y"},
        )
        fresh_foreign = Threat.objects.create(
            title="Yesterday foreign",
            source=Threat.Source.NEWS,
            wire_relevant=True,
            published_at=now - timedelta(hours=12),
            raw_payload={"feed_source": "rss", "feed": "z"},
        )
        feed = FeedSource.objects.create(
            name="cache-feed",
            url="https://example.com/purge-feed.xml",
            http_etag='"abc"',
            last_body_sha256="deadbeef",
            processing_version=4,
            is_active=True,
        )

        out = StringIO()
        call_command("purge_stale_wire", "--from-today", "--reset-feed-cache", stdout=out)

        self.assertTrue(Threat.objects.filter(pk=vn.pk).exists())
        self.assertFalse(Threat.objects.filter(pk=old_foreign.pk).exists())
        self.assertFalse(Threat.objects.filter(pk=fresh_foreign.pk).exists())
        feed.refresh_from_db()
        self.assertEqual(feed.http_etag, "")
        self.assertEqual(feed.last_body_sha256, "")
        self.assertEqual(feed.processing_version, 0)
        self.assertIn("non_vietnam=2", out.getvalue())

    def test_default_purge_removes_old_x_and_keeps_recent(self):
        now = timezone.now()
        old_x = Threat.objects.create(
            title="Old X claim",
            source=Threat.Source.X,
            wire_relevant=True,
            published_at=now - timedelta(days=10),
            raw_payload={"discovery": "x-wire", "feed_source": "x-wire"},
        )
        recent_x = Threat.objects.create(
            title="Recent X claim",
            source=Threat.Source.X,
            wire_relevant=True,
            published_at=now - timedelta(days=2),
            raw_payload={"discovery": "x-wire", "feed_source": "x-wire"},
        )
        # Manual / non-Wire payload must stay.
        manual = Threat.objects.create(
            title="Manual note",
            source=Threat.Source.MANUAL,
            published_at=now - timedelta(days=40),
            raw_payload={},
        )

        call_command("purge_stale_wire")

        self.assertFalse(Threat.objects.filter(pk=old_x.pk).exists())
        self.assertTrue(Threat.objects.filter(pk=recent_x.pk).exists())
        self.assertTrue(Threat.objects.filter(pk=manual.pk).exists())
