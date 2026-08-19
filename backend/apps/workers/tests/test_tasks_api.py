from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient

from apps.intel.models import CompromisedCredential, DataLeak, Indicator, Threat
from apps.workers.services import ingest_cve_items, ingest_ransomware_items, ingest_stealer_content
from apps.workers.tasks import ingest_cve_feed, parse_stealer_log_task


SAMPLE_STEALER = """
=== RedLine Logs ===
https://mail.corp.example/login:alice@corp.example:Passw0rd!
URL: https://vpn.corp.example
Username: bob
Password: hunter2
"""


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CELERY_TASK_EAGER_PROPAGATES=True,
)
class StealerIngestTests(TestCase):
    def test_ingest_creates_credentials_and_domain_iocs(self):
        leak = DataLeak.objects.create(
            title="Test dump",
            leak_type=DataLeak.LeakType.STEALER_LOG,
            severity=DataLeak.Severity.HIGH,
            source=DataLeak.Source.OTHER,
        )
        stats = ingest_stealer_content(leak_id=leak.id, content=SAMPLE_STEALER)
        self.assertEqual(stats["created"], 2)
        self.assertEqual(CompromisedCredential.objects.filter(leak=leak).count(), 2)
        leak.refresh_from_db()
        self.assertEqual(leak.record_count, 2)
        self.assertTrue(
            Indicator.objects.filter(
                ioc_type=Indicator.Type.DOMAIN, normalized_value="mail.corp.example"
            ).exists()
        )

    def test_task_create_leak(self):
        result = parse_stealer_log_task.apply(
            kwargs={
                "content": SAMPLE_STEALER,
                "create_leak": True,
                "leak_title": "Auto leak",
            }
        ).get()
        self.assertIsNotNone(result["leak_id"])
        self.assertEqual(result["created"], 2)


class FeedIngestServiceTests(TestCase):
    def test_ingest_cve_items(self):
        items = [
            {
                "id": "CVE-2024-1234",
                "summary": "Remote code execution in ExampleLib",
                "cvss": 9.8,
                "Published": "2024-01-15T10:00:00Z",
            }
        ]
        stats = ingest_cve_items(items)
        self.assertEqual(stats["created"], 1)
        self.assertTrue(Threat.objects.filter(cve_ids__contains=["CVE-2024-1234"]).exists())
        self.assertTrue(
            Indicator.objects.filter(
                ioc_type=Indicator.Type.CVE, value="CVE-2024-1234"
            ).exists()
        )

    def test_ingest_ransomware_items(self):
        items = [
            {
                "victim": "Acme Corp",
                "group": "lockbit",
                "website": "https://acme.example",
                "url": "https://www.ransomware.live/id/acme-lockbit",
                "discovered": "2024-06-01T12:00:00Z",
            }
        ]
        stats = ingest_ransomware_items(items)
        self.assertEqual(stats["created"], 1)
        threat = Threat.objects.get(
            source=Threat.Source.RANSOMWARE, title__icontains="Acme"
        )
        self.assertEqual(
            threat.source_url, "https://www.ransomware.live/id/acme-lockbit"
        )

    def test_ingest_ransomware_prefers_clearnet_over_onion_claim(self):
        ingest_ransomware_items(
            [
                {
                    "victim": "Onion Prefer Corp",
                    "group": "anubis",
                    "url": "https://www.ransomware.live/id/onion-prefer",
                    "claim_url": "http://abcxyz.onion/post/1",
                    "description": "www.fairlife.com",
                }
            ]
        )
        threat = Threat.objects.get(
            source=Threat.Source.RANSOMWARE, title__icontains="Onion Prefer"
        )
        self.assertEqual(
            threat.source_url, "https://www.ransomware.live/id/onion-prefer"
        )
        self.assertNotIn("claim_url", threat.raw_payload or {})
        self.assertFalse(
            any(
                ".onion" in str(v).casefold()
                for v in (threat.raw_payload or {}).values()
            )
        )

    def test_ingest_ransomware_item_without_detail_url_links_to_source(self):
        ingest_ransomware_items([{"victim": "No Link Corp", "group": "nova"}])

        threat = Threat.objects.get(
            source=Threat.Source.RANSOMWARE, title__icontains="No Link Corp"
        )
        self.assertEqual(threat.source_url, "https://www.ransomware.live/")

    def test_ingest_ransomware_detects_vietnam_from_description_and_vn_domain(self):
        from apps.workers.services import VIETNAM_WIRE_PRIORITY

        ingest_ransomware_items(
            [
                {
                    "victim": "Digipro",
                    "group": "nova",
                    "domain": "digipro.com.vn",
                    "url": "https://www.ransomware.live/id/digipro-nova",
                    "description": (
                        "digipro.com.vn appears to be the website of DIGIPRO TECH JSC "
                        "(Công ty Cổ phần Phát triển Công nghệ DIGIPRO), a Vietnamese IT "
                        "company based in Hanoi, Vietnam."
                    ),
                }
            ]
        )

        threat = Threat.objects.get(
            source=Threat.Source.RANSOMWARE, title__icontains="Digipro"
        )
        self.assertIn("vietnam", set(threat.tags.values_list("slug", flat=True)))
        self.assertEqual(threat.wire_priority, VIETNAM_WIRE_PRIORITY)
        self.assertIn("Vietnamese IT company", threat.summary)
        self.assertIn("digipro.com.vn", threat.summary)


@override_settings(
    CELERY_TASK_ALWAYS_EAGER=True,
    CELERY_TASK_EAGER_PROPAGATES=True,
)
class WorkerAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="ops", password="test-pass-123", is_staff=True
        )
        self.client.force_authenticate(user=self.user)

    def test_parse_stealer_sync_api(self):
        payload = {
            "content": SAMPLE_STEALER,
            "create_leak": True,
            "async_mode": False,
        }
        response = self.client.post(
            "/api/v1/workers/parse-stealer/", payload, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "completed")
        self.assertEqual(response.data["result"]["created"], 2)

    def test_ingest_feeds_sync_with_mocks(self):
        from unittest.mock import patch

        fake_cves = [
            {"id": "CVE-2025-0001", "summary": "Test vuln", "cvss": 7.5}
        ]
        with patch("apps.workers.tasks.fetch_cve_recent", return_value=fake_cves):
            response = self.client.post(
                "/api/v1/workers/ingest-feeds/",
                {"feeds": ["cve"], "limit": 5, "async_mode": False},
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["results"]["cve"]["created"], 1)

    def test_workers_health_requires_auth(self):
        anon = APIClient()
        response = anon.get("/api/v1/workers/health/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        authed = self.client.get("/api/v1/workers/health/")
        self.assertEqual(authed.status_code, status.HTTP_200_OK)
        self.assertEqual(authed.data["phase"], 3)
