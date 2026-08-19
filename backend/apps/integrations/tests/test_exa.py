"""Exa channel unit tests."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework.test import APIClient

from apps.integrations.web_reader.exa import (
    build_exa_queries,
    discover_exa_hits,
    search_exa,
    should_call_exa,
)


class ExaQueryPackTests(SimpleTestCase):
    def test_nl_queries_for_keyword(self):
        qs = build_exa_queries("Go2Joy", max_queries=2)
        self.assertEqual(len(qs), 2)
        self.assertIn("Go2Joy", qs[0])
        self.assertTrue(qs[0].lower().startswith("latest news"))
        self.assertNotIn("site:", qs[0])
        self.assertNotIn("OR DATABASE_URL", qs[0])

    def test_strips_quotes(self):
        qs = build_exa_queries('"Acme Corp"', max_queries=1)
        self.assertEqual(qs[0], "Latest news on data breaches Acme Corp")

    def test_nl_queries_avoid_boolean_or(self):
        qs = build_exa_queries("Go2Joy", max_queries=3)
        for q in qs:
            self.assertNotIn(" OR ", q)


class ExaSearchTests(SimpleTestCase):
    @override_settings(EXA_API_KEY="")
    def test_unconfigured_returns_empty(self):
        self.assertEqual(search_exa("Go2Joy"), [])

    @override_settings(
        EXA_API_KEY="test-key",
        EXA_HIGHLIGHTS=True,
        EXA_INCLUDE_TEXT=False,
        EXA_REQUIRE_PHRASE=True,
        EXA_RECENCY_DAYS=90,
        EXA_SEARCH_TYPE="auto",
        EXA_EXCLUDE_DOMAINS="github.com",
        EXA_MAX_AGE_HOURS="",
    )
    @patch("apps.integrations.web_reader.exa.httpx.Client")
    def test_leak_profile_highlights_guide_and_phrase(self, mock_client_cls):
        payload = {
            "results": [
                {
                    "title": "Go2Joy ransomware",
                    "url": "https://breach.house/go2joy",
                    "publishedDate": "2025-06-01T00:00:00.000Z",
                    "score": 0.9,
                    "highlights": [
                        "ransomexx claimed Go2Joy",
                        "data breach in Vietnam",
                    ],
                },
                {
                    "title": "unrelated",
                    "url": "https://example.com/other",
                    "publishedDate": "2025-06-02T00:00:00.000Z",
                    "score": 0.95,
                    "highlights": ["no brand here"],
                },
                {
                    "title": "gh",
                    "url": "https://github.com/foo/bar",
                    "highlights": ["Go2Joy secret"],
                },
            ]
        }
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = payload
        response.raise_for_status = MagicMock()
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = response
        mock_client_cls.return_value = client

        hits = search_exa(
            "Latest news on data breaches Go2Joy",
            limit=10,
            phrase="Go2Joy",
            purpose="leak",
        )
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["url"], "https://breach.house/go2joy")
        self.assertIn("ransomexx", hits[0]["content"])

        body = client.post.call_args.kwargs["json"]
        self.assertEqual(body["type"], "auto")
        self.assertEqual(body["contents"]["highlights"], {"query": "Go2Joy"})
        self.assertNotIn("text", body["contents"])
        self.assertIn("startPublishedDate", body)
        self.assertIn("github.com", body["excludeDomains"])
        self.assertEqual(body.get("includeText"), ["Go2Joy"])
        self.assertNotIn("category", body)
        headers = client.post.call_args.kwargs["headers"]
        self.assertEqual(headers.get("x-api-key"), "test-key")
        self.assertNotIn("Authorization", headers)

    @override_settings(
        EXA_API_KEY="test-key",
        EXA_WIRE_MAX_AGE_DAYS=14,
        EXA_HIGHLIGHTS=True,
        EXA_INCLUDE_TEXT=False,
        EXA_EXCLUDE_DOMAINS="github.com",
    )
    @patch("apps.integrations.web_reader.exa.httpx.Client")
    def test_wire_profile_uses_news_category(self, mock_client_cls):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"results": []}
        response.raise_for_status = MagicMock()
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = response
        mock_client_cls.return_value = client

        search_exa("Latest ransomware attacks", limit=5, purpose="wire")
        body = client.post.call_args.kwargs["json"]
        self.assertEqual(body.get("category"), "news")
        self.assertEqual(body["contents"]["highlights"], True)
        self.assertNotIn("includeText", body)
        self.assertIn("startPublishedDate", body)

    @override_settings(
        EXA_API_KEY="test-key",
        EXA_CATEGORY="company",
        EXA_EXCLUDE_DOMAINS="github.com",
        EXA_RECENCY_DAYS=90,
        EXA_HIGHLIGHTS=True,
        EXA_INCLUDE_TEXT=False,
    )
    @patch("apps.integrations.web_reader.exa.httpx.Client")
    def test_company_category_skips_exclude_and_dates(self, mock_client_cls):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"results": []}
        response.raise_for_status = MagicMock()
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = response
        mock_client_cls.return_value = client

        search_exa("Acme", limit=5, category="company", purpose="leak", require_phrase=False)
        body = client.post.call_args.kwargs["json"]
        self.assertEqual(body.get("category"), "company")
        self.assertNotIn("excludeDomains", body)
        self.assertNotIn("startPublishedDate", body)

    @override_settings(EXA_API_KEY="test-key", EXA_QUERY_COUNT=2, EXA_RECENCY_DAYS=0)
    @patch("apps.integrations.web_reader.exa.search_exa")
    def test_discover_runs_nl_pack(self, mock_search):
        mock_search.side_effect = [
            [
                {
                    "title": "a",
                    "url": "https://a.example/1",
                    "content": "x",
                    "engine": "exa",
                }
            ],
            [
                {
                    "title": "b",
                    "url": "https://b.example/2",
                    "content": "y",
                    "engine": "exa",
                }
            ],
        ]
        hits = discover_exa_hits("Go2Joy", limit=10)
        self.assertEqual(len(hits), 2)
        self.assertEqual(mock_search.call_count, 2)
        first_q = mock_search.call_args_list[0].args[0]
        self.assertIn("Latest news on data breaches", first_q)
        self.assertEqual(mock_search.call_args_list[0].kwargs.get("phrase"), "Go2Joy")
        self.assertEqual(mock_search.call_args_list[0].kwargs.get("purpose"), "leak")

    @override_settings(EXA_API_KEY="test-key", EXA_QUERY_COUNT=1, EXA_RECENCY_DAYS=0)
    @patch("apps.integrations.web_reader.exa.search_exa")
    def test_discover_respects_query_count_one(self, mock_search):
        mock_search.return_value = [
            {
                "title": "a",
                "url": "https://a.example/1",
                "content": "x",
                "engine": "exa",
            }
        ]
        hits = discover_exa_hits("Go2Joy", limit=10)
        self.assertEqual(len(hits), 1)
        self.assertEqual(mock_search.call_count, 1)


class ExaGatingTests(SimpleTestCase):
    def test_fallback_skips_when_enough_hits(self):
        self.assertFalse(
            should_call_exa(
                mode="fallback",
                kept_hits=5,
                min_hits=5,
                configured=True,
            )
        )
        self.assertFalse(
            should_call_exa(
                mode="fallback",
                kept_hits=8,
                min_hits=5,
                configured=True,
            )
        )

    def test_fallback_runs_when_thin(self):
        self.assertTrue(
            should_call_exa(
                mode="fallback",
                kept_hits=4,
                min_hits=5,
                configured=True,
            )
        )
        self.assertTrue(
            should_call_exa(
                mode="fallback",
                kept_hits=0,
                min_hits=5,
                configured=True,
            )
        )

    def test_always_and_off(self):
        self.assertTrue(
            should_call_exa(mode="always", kept_hits=99, min_hits=5, configured=True)
        )
        self.assertFalse(
            should_call_exa(mode="off", kept_hits=0, min_hits=5, configured=True)
        )

    def test_force_overrides_fallback_threshold(self):
        self.assertTrue(
            should_call_exa(
                mode="fallback",
                kept_hits=20,
                min_hits=5,
                configured=True,
                force=True,
            )
        )

    def test_force_does_not_override_off(self):
        self.assertFalse(
            should_call_exa(
                mode="off",
                kept_hits=0,
                min_hits=5,
                configured=True,
                force=True,
            )
        )

    def test_unconfigured_never_calls(self):
        self.assertFalse(
            should_call_exa(
                mode="always",
                kept_hits=0,
                min_hits=5,
                configured=False,
                force=True,
            )
        )

    @override_settings(EXA_OSINT_MODE="fallback", EXA_OSINT_MIN_HITS=5)
    def test_reads_osint_settings_defaults(self):
        self.assertFalse(should_call_exa(kept_hits=5, purpose="osint", configured=True))
        self.assertTrue(should_call_exa(kept_hits=2, purpose="osint", configured=True))

    @override_settings(EXA_LEAK_MODE="off", EXA_LEAK_MIN_HITS=5)
    def test_reads_leak_settings(self):
        self.assertFalse(should_call_exa(kept_hits=0, purpose="leak", configured=True))


class ExaOsintFallbackApiTests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("exa_osint", password="pass12345")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    @override_settings(
        SEARXNG_URL="http://searxng:8080",
        EXA_API_KEY="test-key",
        EXA_OSINT_MODE="fallback",
        EXA_OSINT_MIN_HITS=5,
        X_AUTH_TOKEN="",
        X_CT0="",
        X_TWITTER_ENABLED=False,
        REDDIT_COOKIE="",
        REDDIT_SEARCH_ENABLED=False,
    )
    @patch("apps.integrations.web_reader.exa.discover_exa_hits")
    @patch("apps.integrations.views.search_searx")
    def test_skips_exa_when_searx_has_enough(self, mock_searx, mock_exa):
        mock_searx.return_value = [
            {
                "title": f"acme hit {i}",
                "url": f"https://news.example/acme-{i}",
                "content": "acme credentials leaked",
                "engine": "searx",
            }
            for i in range(6)
        ]
        mock_exa.return_value = [
            {
                "title": "exa acme",
                "url": "https://exa.example/acme",
                "content": "acme",
                "engine": "exa",
            }
        ]
        res = self.client.post(
            "/api/v1/searx/search/",
            {"query": "acme", "persist": False, "limit": 20},
            format="json",
        )
        self.assertEqual(res.status_code, 200)
        mock_exa.assert_not_called()
        channels = res.data.get("channels") or {}
        self.assertTrue(channels.get("exa", {}).get("skipped"))

    @override_settings(
        SEARXNG_URL="http://searxng:8080",
        EXA_API_KEY="test-key",
        EXA_OSINT_MODE="fallback",
        EXA_OSINT_MIN_HITS=5,
        X_AUTH_TOKEN="",
        X_CT0="",
        X_TWITTER_ENABLED=False,
        REDDIT_COOKIE="",
        REDDIT_SEARCH_ENABLED=False,
    )
    @patch("apps.integrations.web_reader.exa.discover_exa_hits")
    @patch("apps.integrations.views.search_searx")
    def test_calls_exa_when_searx_thin(self, mock_searx, mock_exa):
        mock_searx.return_value = [
            {
                "title": "acme only",
                "url": "https://news.example/acme-1",
                "content": "acme credentials",
                "engine": "searx",
            }
        ]
        mock_exa.return_value = [
            {
                "title": "exa acme",
                "url": "https://exa.example/acme",
                "content": "acme breach",
                "engine": "exa",
            }
        ]
        res = self.client.post(
            "/api/v1/searx/search/",
            {"query": "acme", "persist": False},
            format="json",
        )
        self.assertEqual(res.status_code, 200)
        mock_exa.assert_called_once()
        engines = {h.get("engine") for h in res.data["results"]}
        self.assertIn("exa", engines)

    @override_settings(
        SEARXNG_URL="http://searxng:8080",
        EXA_API_KEY="test-key",
        EXA_OSINT_MODE="fallback",
        EXA_OSINT_MIN_HITS=5,
        X_AUTH_TOKEN="",
        X_CT0="",
        X_TWITTER_ENABLED=False,
        REDDIT_COOKIE="",
        REDDIT_SEARCH_ENABLED=False,
    )
    @patch("apps.integrations.web_reader.exa.discover_exa_hits")
    @patch("apps.integrations.views.search_searx")
    def test_use_exa_force_even_with_enough_hits(self, mock_searx, mock_exa):
        mock_searx.return_value = [
            {
                "title": f"acme hit {i}",
                "url": f"https://news.example/acme-{i}",
                "content": "acme credentials leaked",
                "engine": "searx",
            }
            for i in range(6)
        ]
        mock_exa.return_value = [
            {
                "title": "exa acme",
                "url": "https://exa.example/acme",
                "content": "acme",
                "engine": "exa",
            }
        ]
        res = self.client.post(
            "/api/v1/searx/search/",
            {"query": "acme", "persist": False, "use_exa": True},
            format="json",
        )
        self.assertEqual(res.status_code, 200)
        mock_exa.assert_called_once()


class ExaLeakFallbackTests(SimpleTestCase):
    @override_settings(
        SEARXNG_URL="http://searxng:8080",
        EXA_API_KEY="test-key",
        EXA_LEAK_MODE="fallback",
        EXA_LEAK_MIN_HITS=5,
        SEARX_QUERY_PACKS=False,
        X_TWITTER_ENABLED=False,
        X_AUTH_TOKEN="",
        X_CT0="",
        REDDIT_SEARCH_ENABLED=False,
        REDDIT_COOKIE="",
    )
    @patch("apps.integrations.searx.leak_scan.discover_exa_hits")
    @patch("apps.integrations.searx.leak_scan.search_searx")
    def test_leak_skips_exa_when_searx_enough(self, mock_searx, mock_exa):
        from apps.integrations.searx.leak_scan import discover_leak_hits

        mock_searx.return_value = [
            {
                "title": f"acme {i}",
                "url": f"https://a.example/{i}",
                "content": "acme leak dump",
                "engine": "searx",
            }
            for i in range(6)
        ]
        hits = discover_leak_hits("acme", limit=15)
        mock_exa.assert_not_called()
        self.assertGreaterEqual(len(hits), 5)

    @override_settings(
        SEARXNG_URL="http://searxng:8080",
        EXA_API_KEY="test-key",
        EXA_LEAK_MODE="fallback",
        EXA_LEAK_MIN_HITS=5,
        SEARX_QUERY_PACKS=False,
        X_TWITTER_ENABLED=False,
        X_AUTH_TOKEN="",
        X_CT0="",
        REDDIT_SEARCH_ENABLED=False,
        REDDIT_COOKIE="",
    )
    @patch("apps.integrations.searx.leak_scan.discover_exa_hits")
    @patch("apps.integrations.searx.leak_scan.search_searx")
    def test_leak_calls_exa_when_searx_thin(self, mock_searx, mock_exa):
        from apps.integrations.searx.leak_scan import discover_leak_hits

        mock_searx.return_value = [
            {
                "title": "acme only",
                "url": "https://a.example/1",
                "content": "acme leak",
                "engine": "searx",
            }
        ]
        mock_exa.return_value = [
            {
                "title": "exa acme",
                "url": "https://exa.example/1",
                "content": "acme dump",
                "engine": "exa",
            }
        ]
        hits = discover_leak_hits("acme", limit=15)
        mock_exa.assert_called_once()
        engines = {h.get("engine") for h in hits}
        self.assertIn("exa", engines)
