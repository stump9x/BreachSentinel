from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APIClient

from apps.intel.models import CompromisedCredential, Indicator


class IntelAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="analyst", password="test-pass-123"
        )
        self.client.force_authenticate(user=self.user)

    def test_create_and_list_indicator(self):
        payload = {
            "ioc_type": "domain",
            "value": "Evil.Example.COM",
            "confidence": "high",
            "source": "manual",
        }
        create = self.client.post("/api/v1/indicators/", payload, format="json")
        self.assertEqual(create.status_code, status.HTTP_201_CREATED)
        self.assertEqual(create.data["normalized_value"], "evil.example.com")

        listed = self.client.get("/api/v1/indicators/?ioc_type=domain")
        self.assertEqual(listed.status_code, status.HTTP_200_OK)
        self.assertEqual(listed.data["count"], 1)

    def test_threat_and_leak_credential_flow(self):
        threat = self.client.post(
            "/api/v1/threats/",
            {
                "title": "Active ransomware campaign",
                "severity": "high",
                "source": "ransomware",
                "cve_ids": ["CVE-2024-0001"],
            },
            format="json",
        )
        self.assertEqual(threat.status_code, status.HTTP_201_CREATED)

        leak = self.client.post(
            "/api/v1/leaks/",
            {
                "title": "Corp stealer dump",
                "leak_type": "stealer_log",
                "severity": "critical",
                "source": "hudson_rock",
                "affected_domain": "corp.example",
            },
            format="json",
        )
        self.assertEqual(leak.status_code, status.HTTP_201_CREATED)

        cred = self.client.post(
            "/api/v1/credentials/",
            {
                "leak": leak.data["id"],
                "email": "user@corp.example",
                "password": "SuperSecret!",
                "domain": "corp.example",
                "stealer_family": "redline",
            },
            format="json",
        )
        self.assertEqual(cred.status_code, status.HTTP_201_CREATED)
        self.assertNotIn("password", cred.data)
        self.assertNotIn("raw_line", cred.data)
        self.assertTrue(cred.data["password_present"])
        self.assertTrue(cred.data["password_fingerprint"])

        stored = CompromisedCredential.objects.get(pk=cred.data["id"])
        self.assertTrue(stored.password.startswith("enc:"))
        self.assertNotEqual(stored.password, "SuperSecret!")

    def test_unauthenticated_rejected(self):
        anon = APIClient()
        response = anon.get("/api/v1/indicators/")
        self.assertIn(
            response.status_code,
            (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN),
        )


class IndicatorNormalizeTests(TestCase):
    def test_normalize_helpers(self):
        self.assertEqual(Indicator.normalize("domain", " Evil.COM "), "evil.com")
        self.assertEqual(Indicator.normalize("sha256", "ABC"), "abc")
