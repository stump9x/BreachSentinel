from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from apps.intel.models import Indicator, Threat
from apps.workers.osint_client import OSINTClientError


class OSINTAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.user = User.objects.create_user(username="hunter", password="test-pass-123")
        self.client.force_authenticate(user=self.user)

    def test_scan_persists_found_urls(self):
        fake = {
            "username": "alice",
            "total": 2,
            "found": 1,
            "not_found": 1,
            "errors": 0,
            "unknown": 0,
            "duration_ms": 12,
            "results": [
                {
                    "site": "GitHub",
                    "category": "coding",
                    "url": "https://github.com/alice",
                    "status": "found",
                    "http_code": 200,
                    "latency_ms": 5,
                },
                {
                    "site": "Missing",
                    "category": "social",
                    "url": "https://example.com/alice",
                    "status": "not_found",
                    "http_code": 404,
                    "latency_ms": 3,
                },
            ],
        }

        with patch("apps.workers.osint_views.scan_username", return_value=fake):
            response = self.client.post(
                "/api/v1/osint/scan/",
                {"username": "alice", "persist": True, "only_found": False},
                format="json",
            )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["persisted"]["found_profiles"], 1)
        self.assertTrue(
            Indicator.objects.filter(
                ioc_type=Indicator.Type.URL, value="https://github.com/alice"
            ).exists()
        )
        self.assertTrue(
            Threat.objects.filter(source=Threat.Source.OSINT, title__icontains="alice").exists()
        )

    def test_invalid_username(self):
        response = self.client.post(
            "/api/v1/osint/scan/",
            {"username": "bad user"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_sites_proxy_error(self):
        with patch(
            "apps.workers.osint_views.list_sites",
            side_effect=OSINTClientError("down"),
        ):
            response = self.client.get("/api/v1/osint/sites/")
        self.assertEqual(response.status_code, status.HTTP_502_BAD_GATEWAY)
