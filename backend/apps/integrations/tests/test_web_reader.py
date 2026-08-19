"""Tests for web_reader (Jina/httpx) + query packs + enrich."""

from __future__ import annotations

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.intel.models import DataLeak
from apps.integrations.web_reader.enrich import enrich_leak_from_url
from apps.integrations.web_reader.query_packs import build_leak_query_pack
from apps.integrations.web_reader.reader import _is_public_http_url, read_url


class WebReaderSecurityTests(TestCase):
    def test_blocks_private_and_localhost_urls(self):
        self.assertFalse(_is_public_http_url("http://127.0.0.1/secret"))
        self.assertFalse(_is_public_http_url("http://localhost/x"))
        self.assertFalse(_is_public_http_url("http://192.168.1.1/a"))
        self.assertFalse(_is_public_http_url("file:///etc/passwd"))
        self.assertTrue(_is_public_http_url("https://example.com/path"))


class QueryPackTests(TestCase):
    def test_pack_includes_social_and_secret_hints(self):
        pack = build_leak_query_pack("Acme Corp", max_queries=4)
        self.assertEqual(len(pack), 4)
        joined = " ".join(pack)
        self.assertIn("reddit.com", joined)
        self.assertIn("twitter.com", joined)
        self.assertIn("stackoverflow.com", joined)
        self.assertIn("password", joined)


class EnrichLeakTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("analyst", password="pass12345")

    @override_settings(WEB_READER_ENABLED=True, SEARX_LEAK_ENRICH=True)
    @patch("apps.integrations.web_reader.enrich.read_url")
    def test_enrich_attaches_secret_evidence(self, mock_read):
        from apps.integrations.web_reader.reader import ReadResult

        mock_read.return_value = ReadResult(
            True,
            "jina",
            "ORG=Acme\nDB_PASSWORD=SuperSecretPassword123\n",
        )
        leak = DataLeak.objects.create(
            title="hit",
            description="snippet",
            leak_type=DataLeak.LeakType.OTHER,
            severity=DataLeak.Severity.MEDIUM,
            source=DataLeak.Source.SEARX,
            source_url="https://example.com/leak.txt",
            metadata={"keyword": "Acme"},
            created_by=self.user,
        )
        stats = enrich_leak_from_url(leak, keyword="Acme")
        leak.refresh_from_db()
        self.assertTrue(stats["ok"])
        self.assertIn("password", leak.metadata.get("alert_types") or [])
        self.assertIn("SuperSecretPassword123", leak.metadata.get("evidence") or "")
        self.assertTrue(leak.metadata.get("match_snippets"))

    @override_settings(WEB_READER_ENABLED=True)
    def test_read_url_falls_back_when_jina_fails(self):
        from apps.integrations.web_reader.reader import ReadResult

        with patch(
            "apps.integrations.web_reader.reader._read_via_jina",
            return_value=ReadResult(False, "jina", "", "down"),
        ), patch(
            "apps.integrations.web_reader.reader._read_via_httpx",
            return_value=ReadResult(True, "httpx", "plain body"),
        ):
            result = read_url("https://example.com/a")
        self.assertTrue(result.ok)
        self.assertEqual(result.backend, "httpx")
