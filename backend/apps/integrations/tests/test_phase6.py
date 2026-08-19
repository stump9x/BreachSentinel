from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient

from apps.intel.models import Indicator, Threat
from apps.integrations.ai.briefings import create_ai_briefing
from apps.integrations.ai.ner import extract_entities
from apps.integrations.misp.sync import export_indicators_to_misp
from apps.integrations.models import AIBriefing, IntegrationSyncLog


class NERTests(TestCase):
    def test_extract_entities(self):
        text = (
            "Host 10.0.0.8 contacted evil.example and dropped "
            "aabbccddeeff00112233445566778899 hash; see CVE-2024-9999 "
            "and user@corp.example"
        )
        entities = extract_entities(text)
        self.assertIn("10.0.0.8", entities["ipv4"])
        self.assertIn("evil.example", entities["domain"])
        self.assertIn("CVE-2024-9999", entities["cve"])
        self.assertIn("user@corp.example", entities["email"])


class BriefingTests(TestCase):
    def test_local_briefing_without_keys(self):
        Threat.objects.create(
            title="Test ransom note",
            severity=Threat.Severity.HIGH,
            source=Threat.Source.RANSOMWARE,
        )
        Indicator.objects.create(
            ioc_type=Indicator.Type.DOMAIN,
            value="bad.example",
            source="test",
        )
        briefing = create_ai_briefing(window_hours=24)
        self.assertEqual(briefing.status, AIBriefing.Status.READY)
        self.assertEqual(briefing.provider, AIBriefing.Provider.LOCAL)
        self.assertIn("BreachSentinel", briefing.content)
        self.assertGreaterEqual(briefing.threat_count, 1)


class MISPSyncTests(TestCase):
    def test_export_skipped_when_unconfigured(self):
        log = export_indicators_to_misp()
        self.assertEqual(log.status, IntegrationSyncLog.Status.SKIPPED)
        self.assertEqual(log.target, IntegrationSyncLog.Target.MISP)


@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
class IntegrationsAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="intel", password="test-pass-123", is_staff=True
        )
        self.client.force_authenticate(user=self.user)

    def test_generate_briefing_api(self):
        response = self.client.post(
            "/api/v1/ai/briefings/generate/",
            {"window_hours": 24, "async_mode": False},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data["status"], "ready")

    def test_extract_and_persist(self):
        response = self.client.post(
            "/api/v1/ai/extract-entities/",
            {
                "text": "IOC 8.8.8.8 and CVE-2023-1234 on malware.test",
                "persist": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("ipv4", response.data["entities"])
        self.assertTrue(
            Indicator.objects.filter(ioc_type=Indicator.Type.IPV4, value="8.8.8.8").exists()
        )

    def test_misp_sync_skipped(self):
        response = self.client.post(
            "/api/v1/misp/sync/",
            {"direction": "export", "async_mode": False},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["results"][0]["status"], "skipped")

    def test_integrations_health_requires_auth(self):
        anon = APIClient()
        response = anon.get("/api/v1/integrations/health/")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        authed = self.client.get("/api/v1/integrations/health/")
        self.assertEqual(authed.status_code, status.HTTP_200_OK)
        self.assertEqual(authed.data["phase"], 6)
