"""Security unit tests — SSRF URL guard + credential field redaction."""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework import status
from rest_framework.test import APIClient

from apps.core.security import UnsafeURLError, validate_public_http_url
from apps.intel.models import CompromisedCredential, DataLeak


class ValidatePublicHttpUrlTests(SimpleTestCase):
    def test_rejects_empty_and_file_scheme(self):
        with self.assertRaises(UnsafeURLError):
            validate_public_http_url("")
        with self.assertRaises(UnsafeURLError):
            validate_public_http_url("file:///etc/passwd")

    def test_rejects_userinfo_and_localhost(self):
        with self.assertRaises(UnsafeURLError):
            validate_public_http_url("https://user:pass@example.com/feed")
        with self.assertRaises(UnsafeURLError):
            validate_public_http_url("http://localhost/feed")
        with self.assertRaises(UnsafeURLError):
            validate_public_http_url("http://127.0.0.1/feed")
        with self.assertRaises(UnsafeURLError):
            validate_public_http_url("http://169.254.169.254/latest/meta-data/")

    def test_rejects_private_dns_resolution(self):
        with patch("apps.core.security.socket.getaddrinfo") as gai:
            gai.return_value = [
                (2, 1, 6, "", ("10.0.0.5", 0)),
            ]
            with self.assertRaises(UnsafeURLError):
                validate_public_http_url("https://evil-internal.example/feed.xml")

    def test_accepts_public_resolution(self):
        with patch("apps.core.security.socket.getaddrinfo") as gai:
            gai.return_value = [
                (2, 1, 6, "", ("93.184.216.34", 0)),
            ]
            out = validate_public_http_url("https://example.com/rss.xml")
            self.assertEqual(out, "https://example.com/rss.xml")


class CredentialApiRedactionTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("analyst", password="pass12345")
        self.client = APIClient()
        self.client.force_authenticate(self.user)
        leak = DataLeak.objects.create(
            title="t",
            leak_type=DataLeak.LeakType.STEALER_LOG,
            severity=DataLeak.Severity.HIGH,
        )
        self.cred = CompromisedCredential.objects.create(
            leak=leak,
            email="a@b.com",
            password="SuperSecret!",
            raw_line="https://x:a@b.com:SuperSecret!",
            password_fingerprint="abc",
        )

    def test_api_hides_password_and_raw_line(self):
        res = self.client.get(f"/api/v1/credentials/{self.cred.id}/")
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertNotIn("password", res.data)
        self.assertNotIn("raw_line", res.data)
        self.assertTrue(res.data.get("password_present"))


@override_settings(DEBUG=False, SECRET_KEY="insecure-dev-only-change-me")
class ProductionSecretGuardTests(SimpleTestCase):
    def test_insecure_secret_rejected_when_debug_false(self):
        from django.core.exceptions import ImproperlyConfigured

        from apps.core.security_checks import assert_secure_settings

        with self.assertRaises(ImproperlyConfigured):
            assert_secure_settings()
