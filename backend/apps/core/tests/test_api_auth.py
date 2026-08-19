"""API auth: expiring Token — no SessionAuth / CSRF on SPA POSTs."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient


class ApiAuthCsrfTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.username = "analyst"
        self.password = "test-pass-123"
        self.user = User.objects.create_user(
            username=self.username, password=self.password, is_staff=True
        )

    def test_rest_framework_defaults_use_expiring_token(self):
        from django.conf import settings

        classes = settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]
        self.assertTrue(any("ExpiringTokenAuthentication" in c for c in classes))
        self.assertFalse(any("SessionAuthentication" in c for c in classes))
        self.assertFalse(any("BasicAuthentication" in c for c in classes))

    def test_post_with_token_succeeds_even_when_session_cookie_present(self):
        client = APIClient(enforce_csrf_checks=True)
        self.assertTrue(client.login(username=self.username, password=self.password))
        token = Token.objects.create(user=self.user)
        client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")

        response = client.post(
            "/api/v1/watch-rules/",
            {
                "name": "csrf-regression",
                "keyword": "acme.example",
                "target": "searx",
                "min_severity": "info",
                "is_active": True,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_post_without_credentials_still_rejected(self):
        client = APIClient(enforce_csrf_checks=True)
        response = client.post(
            "/api/v1/watch-rules/",
            {"name": "x", "keyword": "y", "target": "all"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ApiAuthSettingsSmokeTests(TestCase):
    def test_token_auth_get_works(self):
        User = get_user_model()
        user = User.objects.create_user(username="u1", password="p1-secret")
        token = Token.objects.create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        response = client.get("/api/v1/indicators/?page_size=1")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
