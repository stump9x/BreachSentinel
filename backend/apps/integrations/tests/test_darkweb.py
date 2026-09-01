from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import quote

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, override_settings
from rest_framework import status
from rest_framework.test import APITestCase

from apps.integrations.darkweb.engine import (
    _fetch_onion_bytes,
    canonicalize_onion_url,
    extract_search_hits,
    html_to_text,
)
from apps.integrations.models import DarkWebInvestigation


class DarkWebEngineTests(SimpleTestCase):
    onion_host = f"{'a' * 56}.onion"

    def test_canonicalize_accepts_v3_onion_and_removes_fragment(self):
        url = canonicalize_onion_url(
            f"HTTP://{self.onion_host}/report?id=4&utm_source=test#part"
        )
        self.assertEqual(url, f"http://{self.onion_host}/report?id=4")

    def test_canonicalize_rejects_clearnet_v2_credentials_and_custom_port(self):
        self.assertIsNone(canonicalize_onion_url("https://example.com/"))
        self.assertIsNone(canonicalize_onion_url("http://abcdefghijklmnop.onion/"))
        self.assertIsNone(canonicalize_onion_url(f"http://user:pass@{self.onion_host}/"))
        self.assertIsNone(canonicalize_onion_url(f"http://{self.onion_host}:8080/"))

    def test_canonicalize_unwraps_search_redirect(self):
        engine = f"{'b' * 56}.onion"
        target = f"http://{self.onion_host}/claim"
        wrapped = f"http://{engine}/go?url={quote(target, safe='')}"
        self.assertEqual(canonicalize_onion_url(wrapped), target)

    def test_extract_search_hits_deduplicates_and_skips_engine_links(self):
        engine = f"{'b' * 56}.onion"
        target = f"http://{self.onion_host}/claim"
        page = (
            f'<a href="{target}">Claim one</a>'
            f'<a href="{target}#duplicate">Duplicate</a>'
            f'<a href="http://{engine}/about">About</a>'
            '<a href="https://example.com/">Clearnet</a>'
        )
        hits = extract_search_hits(page, engine="Test", base_url=f"http://{engine}/search")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].title, "Claim one")
        self.assertEqual(hits[0].url, target)

    def test_html_to_text_drops_script_and_style_content(self):
        text = html_to_text(
            "<h1>Finding</h1><script>steal()</script><style>.x{}</style><p>Evidence</p>"
        )
        self.assertIn("Finding", text)
        self.assertIn("Evidence", text)
        self.assertNotIn("steal", text)
        self.assertNotIn(".x", text)

    def test_fetch_rejects_redirect_from_onion_to_clearnet(self):
        class RedirectResponse:
            status_code = 302
            headers = {"location": "https://example.com/landing"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class FakeClient:
            def stream(self, method, url):
                self.request = (method, url)
                return RedirectResponse()

        with self.assertRaisesRegex(ValueError, "redirect target"):
            _fetch_onion_bytes(
                FakeClient(), f"http://{self.onion_host}/start", max_bytes=1024
            )


@override_settings(
    DARKWEB_ENABLED=True,
    TOR_ENABLED=True,
    REST_FRAMEWORK={
        "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
        "DEFAULT_AUTHENTICATION_CLASSES": ["apps.core.authentication.ExpiringTokenAuthentication"],
        "DEFAULT_PAGINATION_CLASS": "apps.core.pagination.FlexiblePagination",
        "PAGE_SIZE": 25,
        "DEFAULT_FILTER_BACKENDS": [
            "django_filters.rest_framework.DjangoFilterBackend",
            "rest_framework.filters.SearchFilter",
            "rest_framework.filters.OrderingFilter",
        ],
        "DEFAULT_THROTTLE_CLASSES": [],
    },
)
class DarkWebInvestigationApiTests(APITestCase):
    def setUp(self):
        self.staff = get_user_model().objects.create_user(
            username="darkweb-analyst",
            password="test-password",
            is_staff=True,
        )
        self.client.force_authenticate(self.staff)

    @patch("apps.integrations.views.run_darkweb_investigation_task.delay")
    def test_staff_can_queue_bounded_investigation(self, delay):
        delay.return_value = SimpleNamespace(id="task-1")
        response = self.client.post(
            "/api/v1/darkweb/investigations/",
            {
                "query": "example.org ransomware claim",
                "preset": "ransomware_malware",
                "max_results": 40,
                "max_pages": 5,
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        investigation = DarkWebInvestigation.objects.get(pk=response.data["id"])
        self.assertEqual(investigation.created_by, self.staff)
        self.assertEqual(investigation.parameters["max_pages"], 5)
        delay.assert_called_once_with(investigation.id)

    def test_non_staff_cannot_list_investigations(self):
        user = get_user_model().objects.create_user(
            username="ordinary-user", password="test-password"
        )
        self.client.force_authenticate(user)
        response = self.client.get("/api/v1/darkweb/investigations/")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_create_rejects_control_characters(self):
        response = self.client.post(
            "/api/v1/darkweb/investigations/",
            {"query": "bad\u0007query", "max_results": 40, "max_pages": 5},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
