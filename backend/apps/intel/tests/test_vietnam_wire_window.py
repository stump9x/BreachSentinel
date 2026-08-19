from __future__ import annotations

from datetime import timedelta
from email.utils import format_datetime

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.intel.models import Threat
from apps.workers.services import (
    IMPACT_WIRE_PRIORITY,
    VIETNAM_WIRE_PRIORITY,
    ingest_rss_items,
)


class VietnamMonthWindowIngestTests(TestCase):
    @override_settings(WIRE_MAX_AGE_DAYS=7, WIRE_VIETNAM_MAX_AGE_DAYS=0)
    def test_vietnam_item_within_month_is_ingested(self):
        published = timezone.now() - timedelta(days=20)
        stats = ingest_rss_items(
            [
                {
                    "title": "Data breach hits organizations in Vietnam",
                    "link": "https://example.com/vn-20d",
                    "summary": "Hanoi CSIRT confirms leaked records.",
                    "category": "news",
                    "published": format_datetime(published),
                }
            ]
        )
        self.assertEqual(stats["created"], 1)
        self.assertEqual(stats["skipped_old"], 0)
        t = Threat.objects.get(title="Data breach hits organizations in Vietnam")
        self.assertEqual(t.severity, Threat.Severity.HIGH)
        self.assertEqual(t.wire_priority, VIETNAM_WIRE_PRIORITY)

    @override_settings(WIRE_MAX_AGE_DAYS=7, WIRE_VIETNAM_MAX_AGE_DAYS=30)
    def test_foreign_item_within_seven_days_is_ingested(self):
        published = timezone.now() - timedelta(days=5)
        stats = ingest_rss_items(
            [
                {
                    "title": "US retail data breach update",
                    "link": "https://example.com/us-5d",
                    "summary": "California retailers leaked customer records.",
                    "category": "news",
                    "published": format_datetime(published),
                }
            ]
        )
        self.assertEqual(stats["created"], 1)
        self.assertEqual(stats["skipped_old"], 0)

    @override_settings(WIRE_MAX_AGE_DAYS=7, WIRE_VIETNAM_MAX_AGE_DAYS=30)
    def test_foreign_item_older_than_seven_days_is_skipped(self):
        published = timezone.now() - timedelta(days=9)
        stats = ingest_rss_items(
            [
                {
                    "title": "US retail data breach update old",
                    "link": "https://example.com/us-9d",
                    "summary": "California retailers leaked customer records.",
                    "category": "news",
                    "published": format_datetime(published),
                }
            ]
        )
        self.assertEqual(stats["created"], 0)
        self.assertEqual(stats["skipped_old"], 1)
        self.assertFalse(
            Threat.objects.filter(title="US retail data breach update old").exists()
        )


class WireFeedWindowAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("wirevn", password="pass12345")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    @override_settings(
        WIRE_MAX_AGE_DAYS=7,
        WIRE_VIETNAM_MAX_AGE_DAYS=0,
        WIRE_VIETNAM_PIN_DAYS=7,
        WIRE_PRIORITY_PIN_HOURS=168,
        WIRE_STALE_PRIORITY_CAP=15,
    )
    def test_wire_feed_keeps_old_vietnam_and_drops_stale_foreign(self):
        from apps.intel.models import Tag

        now = timezone.now()
        vn_tag = Tag.objects.create(name="Vietnam", slug="vietnam")
        vn = Threat.objects.create(
            title="VN two month story",
            title_vi="Tin Việt Nam hai tháng trước",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.HIGH,
            wire_priority=VIETNAM_WIRE_PRIORITY,
            wire_relevant=True,
            published_at=now - timedelta(days=60),
        )
        vn.tags.add(vn_tag)
        foreign_old = Threat.objects.create(
            title="Foreign nine day story",
            title_vi="Tin nước ngoài cách đây chín ngày",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.HIGH,
            wire_priority=IMPACT_WIRE_PRIORITY,
            wire_relevant=True,
            published_at=now - timedelta(days=9),
        )
        foreign_mid = Threat.objects.create(
            title="Foreign five day story",
            title_vi="Tin nước ngoài cách đây năm ngày",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.HIGH,
            wire_priority=IMPACT_WIRE_PRIORITY,
            wire_relevant=True,
            published_at=now - timedelta(days=5),
        )
        # Misclassified: high priority but no vietnam tag — must not get unlimited window.
        fake_vn = Threat.objects.create(
            title="Fake priority June story",
            title_vi="Tin ưu tiên giả từ tháng Sáu",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.HIGH,
            wire_priority=VIETNAM_WIRE_PRIORITY,
            wire_relevant=True,
            published_at=now - timedelta(days=20),
        )
        foreign_new = Threat.objects.create(
            title="Foreign fresh breach",
            title_vi="Sự cố lộ dữ liệu mới ở nước ngoài",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.HIGH,
            wire_priority=IMPACT_WIRE_PRIORITY,
            wire_relevant=True,
            published_at=now - timedelta(days=1),
        )
        res = self.client.get(
            "/api/v1/threats/?wire_feed=true&ordering=-wire_sort_priority,-published_at,-id"
        )
        self.assertEqual(res.status_code, 200)
        ids = [row["id"] for row in res.data["results"]]
        self.assertIn(vn.id, ids)
        self.assertIn(foreign_new.id, ids)
        self.assertIn(foreign_mid.id, ids)
        self.assertNotIn(foreign_old.id, ids)
        self.assertNotIn(fake_vn.id, ids)
        # Old VN (60d) stays in feed but is not pinned above fresh impact.
        self.assertEqual(ids[0], foreign_new.id)
        self.assertLess(ids.index(foreign_new.id), ids.index(vn.id))

    @override_settings(
        WIRE_MAX_AGE_DAYS=7,
        WIRE_VIETNAM_MAX_AGE_DAYS=0,
        WIRE_VIETNAM_PIN_DAYS=7,
        WIRE_PRIORITY_PIN_HOURS=168,
        WIRE_STALE_PRIORITY_CAP=15,
    )
    def test_fresh_mid_priority_outranks_vietnam_older_than_pin_window(self):
        from apps.intel.models import Tag

        now = timezone.now()
        vn_tag = Tag.objects.create(name="Vietnam", slug="vietnam")
        stale_vn = Threat.objects.create(
            title="Stale VN pin",
            title_vi="Tin VN cũ hơn một tuần",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.HIGH,
            wire_priority=VIETNAM_WIRE_PRIORITY,
            wire_relevant=True,
            published_at=now - timedelta(days=10),
        )
        stale_vn.tags.add(vn_tag)
        fresh = Threat.objects.create(
            title="Fresh adobe flaw",
            title_vi="Lỗi Adobe mới",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.MEDIUM,
            wire_priority=25,
            wire_relevant=True,
            published_at=now - timedelta(minutes=10),
        )
        res = self.client.get(
            "/api/v1/threats/?wire_feed=true&ordering=-wire_sort_priority,-published_at,-id"
        )
        ids = [row["id"] for row in res.data["results"]]
        self.assertEqual(ids[0], fresh.id)
        self.assertIn(stale_vn.id, ids)

    @override_settings(
        WIRE_MAX_AGE_DAYS=7,
        WIRE_VIETNAM_MAX_AGE_DAYS=0,
        WIRE_VIETNAM_PIN_DAYS=7,
        WIRE_PRIORITY_PIN_HOURS=168,
        WIRE_STALE_PRIORITY_CAP=15,
    )
    def test_vietnam_within_pin_week_stays_above_fresh_mid_priority(self):
        from apps.intel.models import Tag

        now = timezone.now()
        vn_tag = Tag.objects.create(name="Vietnam", slug="vietnam")
        fresh_vn = Threat.objects.create(
            title="Fresh VN pin",
            title_vi="Tin VN trong tuần",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.HIGH,
            wire_priority=VIETNAM_WIRE_PRIORITY,
            wire_relevant=True,
            published_at=now - timedelta(days=3),
        )
        fresh_vn.tags.add(vn_tag)
        fresh = Threat.objects.create(
            title="Fresh adobe flaw",
            title_vi="Lỗi Adobe mới",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.MEDIUM,
            wire_priority=25,
            wire_relevant=True,
            published_at=now - timedelta(minutes=10),
        )
        res = self.client.get(
            "/api/v1/threats/?wire_feed=true&ordering=-wire_sort_priority,-published_at,-id"
        )
        ids = [row["id"] for row in res.data["results"]]
        self.assertEqual(ids[0], fresh_vn.id)
        self.assertLess(ids.index(fresh_vn.id), ids.index(fresh.id))

    @override_settings(WIRE_MAX_AGE_DAYS=7)
    def test_wire_feed_returns_all_relevant_items(self):
        now = timezone.now()
        Threat.objects.bulk_create(
            [
                Threat(
                    title=f"Relevant breach story {index}",
                    title_vi=f"Tin lộ dữ liệu liên quan {index}",
                    source=Threat.Source.NEWS,
                    published_at=now - timedelta(minutes=index),
                    wire_relevant=True,
                    wire_priority=IMPACT_WIRE_PRIORITY,
                )
                for index in range(1005)
            ]
        )
        Threat.objects.create(
            title="Hidden irrelevant story",
            source=Threat.Source.NEWS,
            published_at=now,
            wire_relevant=False,
        )

        res = self.client.get(
            "/api/v1/threats/?wire_feed=true&page_size=25"
            "&ordering=-wire_priority,-published_at,-id"
        )

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["count"], 1005)
        titles = [row["title"] for row in res.data["results"]]
        self.assertNotIn("Hidden irrelevant story", titles)

    def test_wire_feed_hides_untranslated_news(self):
        untranslated = Threat.objects.create(
            title="Untranslated fresh breach",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            wire_relevant=True,
        )
        translated = Threat.objects.create(
            title="Translated fresh breach",
            title_vi="Sự cố lộ dữ liệu mới đã được dịch",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            wire_relevant=True,
        )

        res = self.client.get("/api/v1/threats/?wire_feed=true&page_size=25")

        self.assertEqual(res.status_code, 200)
        ids = [row["id"] for row in res.data["results"]]
        self.assertNotIn(untranslated.id, ids)
        self.assertIn(translated.id, ids)
