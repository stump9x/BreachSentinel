from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from apps.intel.models import Threat
from apps.workers.services import ingest_rss_items


class FeedSourceAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user("analyst", password="pass12345")
        self.admin = User.objects.create_superuser(
            "admin", "admin@example.com", "pass12345"
        )
        self.client = APIClient()

    @patch("apps.core.security.socket.getaddrinfo")
    def test_staff_can_create_feed_source(self, gai):
        gai.return_value = [(2, 1, 6, "", ("93.184.216.34", 0))]
        self.client.force_authenticate(self.admin)
        res = self.client.post(
            "/api/v1/feed-sources/",
            {
                "name": "test-feed",
                "url": "https://example.com/rss.xml",
                "category": "breach",
                "confidence": 1,
            },
            format="json",
        )
        self.assertEqual(res.status_code, 201)
        listed = self.client.get("/api/v1/feed-sources/")
        self.assertEqual(listed.status_code, 200)
        self.assertGreaterEqual(listed.data["count"], 1)

    def test_analyst_cannot_create_feed_source(self):
        self.client.force_authenticate(self.analyst)
        res = self.client.post(
            "/api/v1/feed-sources/",
            {
                "name": "evil",
                "url": "http://127.0.0.1/feed",
                "category": "news",
                "confidence": 1,
            },
            format="json",
        )
        self.assertEqual(res.status_code, 403)

    @patch("apps.core.security.socket.getaddrinfo")
    def test_rejects_ssrf_url_even_for_staff(self, gai):
        gai.return_value = [(2, 1, 6, "", ("10.0.0.8", 0))]
        self.client.force_authenticate(self.admin)
        res = self.client.post(
            "/api/v1/feed-sources/",
            {
                "name": "ssrf",
                "url": "https://evil.internal/rss.xml",
                "category": "news",
                "confidence": 1,
            },
            format="json",
        )
        self.assertEqual(res.status_code, 400)


class RssIngestClassificationTests(TestCase):
    def test_breach_keywords_raise_severity(self):
        stats = ingest_rss_items(
            [
                {
                    "title": "Major data breach exposes customer emails",
                    "link": "https://example.com/breach",
                    "summary": "Credentials leaked from vendor DB",
                    "category": "news",
                    "feed": "unit-test",
                }
            ]
        )
        self.assertEqual(stats["created"], 1)
        t = Threat.objects.get(title="Major data breach exposes customer emails")
        self.assertEqual(t.severity, Threat.Severity.HIGH)
        self.assertEqual(t.source, Threat.Source.NEWS)
        self.assertTrue(t.source_url)
        slugs = set(t.tags.values_list("slug", flat=True))
        self.assertIn("data-breach", slugs)

    def test_vietnam_related_is_high_and_pinned(self):
        from datetime import timedelta

        from django.utils import timezone

        stats = ingest_rss_items(
            [
                {
                    "title": "Global ransomware campaign hits banks",
                    "link": "https://example.com/global",
                    "summary": "Europe and US banks report data leaks",
                    "category": "news",
                    "published": (timezone.now() - timedelta(hours=1)).isoformat(),
                },
                {
                    "title": "Data breach on Vietnamese government portal",
                    "link": "https://example.com/vn",
                    "summary": "Leaked records reported in Viet Nam / Hanoi",
                    "category": "news",
                    "published": (timezone.now() - timedelta(hours=5)).isoformat(),
                },
            ]
        )
        self.assertEqual(stats["created"], 2)
        vn = Threat.objects.get(title="Data breach on Vietnamese government portal")
        other = Threat.objects.get(title="Global ransomware campaign hits banks")
        self.assertEqual(vn.severity, Threat.Severity.HIGH)
        self.assertGreater(vn.wire_priority, other.wire_priority)
        self.assertIn("vietnam", set(vn.tags.values_list("slug", flat=True)))


class WireThreatOrderingTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("wire", password="pass12345")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_list_returns_newest_published_first(self):
        from datetime import timedelta

        from django.utils import timezone

        older = Threat.objects.create(
            title="Older story",
            source=Threat.Source.NEWS,
            published_at=timezone.now() - timedelta(days=2),
        )
        newer = Threat.objects.create(
            title="Newer story",
            source=Threat.Source.NEWS,
            published_at=timezone.now() - timedelta(hours=1),
        )
        # Same timestamp — higher id should win as tiebreaker
        same_t = timezone.now() - timedelta(minutes=30)
        first = Threat.objects.create(
            title="Tie A",
            source=Threat.Source.NEWS,
            published_at=same_t,
        )
        second = Threat.objects.create(
            title="Tie B",
            source=Threat.Source.NEWS,
            published_at=same_t,
        )
        res = self.client.get("/api/v1/threats/?ordering=-published_at,-id")
        self.assertEqual(res.status_code, 200)
        ids = [row["id"] for row in res.data["results"]]
        self.assertLess(ids.index(newer.id), ids.index(older.id))
        self.assertLess(ids.index(second.id), ids.index(first.id))

    def test_vietnam_priority_sorts_above_newer_foreign_news(self):
        from datetime import timedelta

        from django.utils import timezone

        foreign = Threat.objects.create(
            title="Fresh US breach",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.HIGH,
            wire_priority=0,
            published_at=timezone.now() - timedelta(minutes=10),
        )
        vietnam = Threat.objects.create(
            title="Older Viet Nam CERT advisory",
            source=Threat.Source.NEWS,
            severity=Threat.Severity.HIGH,
            wire_priority=100,
            published_at=timezone.now() - timedelta(days=1),
        )
        res = self.client.get(
            "/api/v1/threats/?ordering=-wire_priority,-published_at,-id"
        )
        self.assertEqual(res.status_code, 200)
        ids = [row["id"] for row in res.data["results"]]
        self.assertLess(ids.index(vietnam.id), ids.index(foreign.id))
