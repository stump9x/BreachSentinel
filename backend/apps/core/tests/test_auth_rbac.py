"""Auth token TTL + staff RBAC regression tests."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from apps.core.crypto import decrypt_secret, encrypt_secret, password_fingerprint


class AuthTokenApiTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("analyst", password="pass12345")
        self.client = APIClient()

    def test_login_returns_token_and_logout_revokes(self):
        res = self.client.post(
            "/api/v1/auth/login/",
            {"username": "analyst", "password": "pass12345"},
            format="json",
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        token = res.data["token"]
        self.assertTrue(token)

        me = APIClient()
        me.credentials(HTTP_AUTHORIZATION=f"Token {token}")
        self.assertEqual(me.get("/api/v1/auth/me/").status_code, status.HTTP_200_OK)

        out = me.post("/api/v1/auth/logout/", {}, format="json")
        self.assertEqual(out.status_code, status.HTTP_200_OK)
        self.assertEqual(me.get("/api/v1/auth/me/").status_code, status.HTTP_401_UNAUTHORIZED)

    @override_settings(AUTH_TOKEN_TTL_HOURS=1)
    def test_expired_token_rejected(self):
        token = Token.objects.create(user=self.user)
        Token.objects.filter(pk=token.pk).update(
            created=timezone.now() - timedelta(hours=2)
        )
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        res = client.get("/api/v1/indicators/?page_size=1")
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class StaffRbacTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.analyst = User.objects.create_user("analyst", password="pass12345")
        self.staff = User.objects.create_user(
            "staffer", password="pass12345", is_staff=True
        )
        self.client = APIClient()

    def test_analyst_cannot_ingest_or_misp(self):
        self.client.force_authenticate(self.analyst)
        ingest = self.client.post(
            "/api/v1/workers/ingest-feeds/",
            {"feeds": ["cve"], "limit": 1, "async_mode": True},
            format="json",
        )
        self.assertEqual(ingest.status_code, status.HTTP_403_FORBIDDEN)
        misp = self.client.post(
            "/api/v1/misp/sync/",
            {"direction": "export", "async_mode": False},
            format="json",
        )
        self.assertEqual(misp.status_code, status.HTTP_403_FORBIDDEN)

    def test_staff_can_queue_ingest(self):
        self.client.force_authenticate(self.staff)
        with patch("apps.workers.views.ingest_cve_feed") as task:
            task.delay.return_value.id = "task-1"
            res = self.client.post(
                "/api/v1/workers/ingest-feeds/",
                {"feeds": ["cve"], "limit": 1, "async_mode": True},
                format="json",
            )
        self.assertEqual(res.status_code, status.HTTP_202_ACCEPTED)


class CryptoHelpersTests(TestCase):
    def test_encrypt_roundtrip_and_fingerprint(self):
        enc = encrypt_secret("hunter2")
        self.assertTrue(enc.startswith("enc:"))
        self.assertEqual(decrypt_secret(enc), "hunter2")
        self.assertEqual(
            password_fingerprint("hunter2"),
            password_fingerprint("hunter2"),
        )
        self.assertNotEqual(password_fingerprint("hunter2"), password_fingerprint("x"))
