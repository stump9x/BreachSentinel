"""Unit tests for SearxNG client + leak scan (Watcher-style)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.intel.models import DataLeak, WatchRule
from apps.integrations.searx.client import build_search_term, searx_configured, search_searx
from apps.integrations.searx.leak_scan import ingest_searx_hits, scan_leak_keywords_via_searx


class SearxClientTests(TestCase):
    def test_unconfigured_returns_empty(self):
        with override_settings(SEARXNG_URL=""):
            self.assertFalse(searx_configured())
            self.assertEqual(search_searx("example.com"), [])

    def test_build_search_term_quotes_simple_keywords(self):
        self.assertEqual(build_search_term("acme-corp"), '"acme-corp"')
        self.assertEqual(build_search_term("user@acme.com"), "user@acme.com")

    @override_settings(
        SEARXNG_URL="http://searxng:8080",
        SEARXNG_ENGINES="",
    )
    @patch("apps.integrations.searx.client.httpx.Client")
    def test_search_parses_json_results(self, client_cls):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "results": [
                {
                    "title": "leak paste",
                    "url": "https://pastebin.com/abc123",
                    "content": "api key dumped",
                    "engine": "duckduckgo",
                },
                {
                    "title": "dup",
                    "url": "https://pastebin.com/abc123",
                    "content": "same",
                    "engine": "duckduckgo",
                },
                {
                    "title": "github skip",
                    "url": "https://github.com/foo/bar",
                    "content": "should be ignored",
                    "engine": "duckduckgo",
                },
            ]
        }
        client_cls.return_value.__enter__.return_value.get.return_value = mock_resp

        hits = search_searx("acme", limit=10)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["url"], "https://pastebin.com/abc123")
        self.assertEqual(hits[0]["engine"], "duckduckgo")
        # Default engines must not include github
        engines_param = client_cls.return_value.__enter__.return_value.get.call_args.kwargs[
            "params"
        ]["engines"]
        self.assertNotIn("github", engines_param.split(","))
        for required in ("duckduckgo", "brave", "bing"):
            self.assertIn(required, engines_param)

        call_kwargs = client_cls.return_value.__enter__.return_value.get.call_args
        self.assertIn("/search", call_kwargs.args[0])
        self.assertEqual(call_kwargs.kwargs["params"]["format"], "json")
        # Default SEARX_TIME_RANGE=month biases toward fresher pages
        self.assertEqual(call_kwargs.kwargs["params"].get("time_range"), "month")

    @override_settings(SEARXNG_URL="http://searxng:8080", SEARX_TIME_RANGE="")
    @patch("apps.integrations.searx.client.httpx.Client")
    def test_time_range_omitted_when_empty(self, client_cls):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"results": []}
        client_cls.return_value.__enter__.return_value.get.return_value = mock_resp
        search_searx("acme", limit=5)
        params = client_cls.return_value.__enter__.return_value.get.call_args.kwargs["params"]
        self.assertNotIn("time_range", params)

    @override_settings(SEARXNG_URL="http://searxng:8080")
    def test_query_length_capped(self):
        with patch("apps.integrations.searx.client.httpx.Client") as client_cls:
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"results": []}
            client_cls.return_value.__enter__.return_value.get.return_value = mock_resp
            long_q = "x" * 500
            search_searx(long_q)
            params = client_cls.return_value.__enter__.return_value.get.call_args.kwargs["params"]
            self.assertLessEqual(len(params["q"]), 220)


class SearxLeakScanTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("analyst", password="pass12345")

    @override_settings(SEARX_LEAK_ENRICH=False)
    def test_ingest_creates_leak_and_dedupes(self):
        hits = [
            {
                "title": "Secret in paste for acme",
                "url": "https://pastebin.com/acmeleak",
                "content": "acme password=hunter2",
                "engine": "duckduckgo",
            }
        ]
        stats1 = ingest_searx_hits(hits, keyword="acme", rule=None, recipient=self.user)
        self.assertEqual(stats1["created"], 1)
        stats2 = ingest_searx_hits(hits, keyword="acme", rule=None, recipient=self.user)
        self.assertEqual(stats2["created"], 0)
        self.assertEqual(stats2["duplicates"], 1)
        leak = DataLeak.objects.get(source_url="https://pastebin.com/acmeleak")
        self.assertEqual(leak.source, DataLeak.Source.PASTEBIN)
        self.assertEqual(leak.leak_type, DataLeak.LeakType.PASTE)

    @override_settings(SEARX_LEAK_ENRICH=False)
    def test_ingest_skips_github_urls(self):
        hits = [
            {
                "title": "Secret in repo",
                "url": "https://github.com/acme/leak",
                "content": "password=hunter2",
                "engine": "duckduckgo",
            }
        ]
        stats = ingest_searx_hits(hits, keyword="acme", rule=None, recipient=self.user)
        self.assertEqual(stats["created"], 0)
        self.assertFalse(
            DataLeak.objects.filter(source_url="https://github.com/acme/leak").exists()
        )

    @override_settings(
        SEARXNG_URL="http://searxng:8080",
        SEARX_QUERY_PACKS=False,
        SEARX_LEAK_ENRICH=False,
        EXA_API_KEY="",
    )
    @patch("apps.integrations.searx.leak_scan.search_searx")
    def test_scan_uses_searx_and_leak_target_rules(self, mock_search):
        mock_search.return_value = [
            {
                "title": "GitLab dump acme.internal",
                "url": "https://gitlab.com/x/y",
                "content": "acme.internal token leaked",
                "engine": "gitlab",
            }
        ]
        WatchRule.objects.create(
            name="Acme searx",
            keyword="acme.internal",
            target=WatchRule.Target.SEARX,
            created_by=self.user,
        )
        # Threats-only rule must be ignored by Searx sweep
        WatchRule.objects.create(
            name="Noise",
            keyword="noise",
            target=WatchRule.Target.THREATS,
            created_by=self.user,
        )
        stats = scan_leak_keywords_via_searx()
        self.assertEqual(stats["rules_scanned"], 1)
        self.assertEqual(stats["created"], 1)
        mock_search.assert_called_once()

    @override_settings(
        SEARXNG_URL="http://searxng:8080",
        SEARX_QUERY_PACKS=True,
        SEARX_QUERY_PACK_SIZE=4,
        SEARX_LEAK_ENRICH=False,
        EXA_API_KEY="",
    )
    @patch("apps.integrations.searx.leak_scan.search_searx")
    def test_scan_expands_query_packs(self, mock_search):
        mock_search.return_value = []
        WatchRule.objects.create(
            name="Acme searx",
            keyword="acme",
            target=WatchRule.Target.SEARX,
            created_by=self.user,
        )
        scan_leak_keywords_via_searx(limit_per_keyword=8)
        self.assertGreaterEqual(mock_search.call_count, 2)


class SearxAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("analyst", password="pass12345")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    @override_settings(
        SEARXNG_URL="",
        EXA_API_KEY="",
        X_AUTH_TOKEN="",
        X_CT0="",
        X_TWITTER_ENABLED=False,
        REDDIT_COOKIE="",
        REDDIT_SEARCH_ENABLED=False,
    )
    def test_search_api_reports_unconfigured(self):
        res = self.client.post("/api/v1/searx/search/", {"query": "acme"}, format="json")
        self.assertEqual(res.status_code, 503)

    @override_settings(
        SEARXNG_URL="http://searxng:8080",
        EXA_API_KEY="",
        X_AUTH_TOKEN="",
        X_CT0="",
        X_TWITTER_ENABLED=False,
        REDDIT_COOKIE="",
        REDDIT_SEARCH_ENABLED=False,
    )
    @patch("apps.integrations.views.search_searx")
    def test_search_api_ok(self, mock_search):
        mock_search.return_value = [
            {
                "title": "acme paste dump",
                "url": "https://pastebin.com/a1b2",
                "content": "acme credentials",
                "engine": "duckduckgo",
            }
        ]
        res = self.client.post(
            "/api/v1/searx/search/",
            {"query": "acme", "persist": False},
            format="json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(len(res.data["results"]), 1)
