"""Open-web channel registry: X cookie search, Reddit/paste enrich, doctor."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework.test import APIClient

from apps.integrations.searx.leak_scan import merge_hits_balanced
from apps.integrations.web_reader.channels import channel_doctor
from apps.integrations.web_reader.channels.paste import (
    _to_raw_url,
    is_paste_or_raw_url,
    read_paste_raw,
)
from apps.integrations.web_reader.channels.reddit import (
    doctor_reddit_search,
    is_reddit_url,
    read_reddit,
    search_reddit,
)
from apps.integrations.web_reader.channels.x_twitter import (
    doctor_x_twitter,
    is_x_url,
    read_x_status,
    search_x_twitter,
)
from apps.integrations.web_reader.enrich import enrich_leak_from_url
from apps.integrations.web_reader.phrase import (
    contains_phrase,
    social_hit_has_phrase,
)
from apps.integrations.web_reader.reader import ReadResult


class PasteChannelTests(SimpleTestCase):
    def test_allowlist_and_raw_rewrite(self):
        self.assertTrue(is_paste_or_raw_url("https://pastebin.com/AbCdEf12"))
        self.assertTrue(
            is_paste_or_raw_url("https://raw.githubusercontent.com/org/repo/main/a.env")
        )
        self.assertFalse(is_paste_or_raw_url("https://example.com/paste"))
        self.assertEqual(
            _to_raw_url("https://pastebin.com/AbCdEf12"),
            "https://pastebin.com/raw/AbCdEf12",
        )

    @override_settings(PASTE_ENRICH_ENABLED=True)
    @patch("apps.integrations.web_reader.channels.paste.httpx.Client")
    def test_read_paste_raw(self, mock_client_cls):
        response = MagicMock()
        response.status_code = 200
        response.headers = {"content-type": "text/plain"}
        response.content = b"API_KEY=sk-live-abc1234567890\n"
        response.raise_for_status = MagicMock()
        client = MagicMock()
        client.__enter__.return_value = client
        client.get.return_value = response
        mock_client_cls.return_value = client

        result = read_paste_raw("https://pastebin.com/AbCdEf12")
        self.assertTrue(result.ok)
        self.assertEqual(result.backend, "paste")
        self.assertIn("API_KEY", result.text)
        client.get.assert_called()
        self.assertIn("/raw/", client.get.call_args.args[0])


class RedditChannelTests(SimpleTestCase):
    def test_is_reddit_url(self):
        self.assertTrue(
            is_reddit_url("https://www.reddit.com/r/netsec/comments/abc123/title/")
        )
        self.assertFalse(is_reddit_url("https://example.com/r/netsec"))

    @override_settings(REDDIT_ENRICH_ENABLED=True, REDDIT_COOKIE="")
    @patch("apps.integrations.web_reader.channels.reddit.httpx.Client")
    def test_read_reddit_flattens_json(self, mock_client_cls):
        payload = [
            {
                "data": {
                    "children": [
                        {
                            "data": {
                                "title": "leak post",
                                "selftext": "password=Hunter2Secret",
                            }
                        }
                    ]
                }
            },
            {
                "data": {
                    "children": [
                        {"data": {"body": "see pastebin.com/raw/xyz"}},
                    ]
                }
            },
        ]
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = payload
        response.raise_for_status = MagicMock()
        client = MagicMock()
        client.__enter__.return_value = client
        client.get.return_value = response
        mock_client_cls.return_value = client

        result = read_reddit(
            "https://www.reddit.com/r/netsec/comments/abc123/leak_post/"
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.backend, "reddit")
        self.assertIn("Hunter2Secret", result.text)
        self.assertIn("pastebin.com", result.text)


class XTwitterChannelTests(SimpleTestCase):
    @override_settings(X_TWITTER_ENABLED=True, X_AUTH_TOKEN="", X_CT0="")
    def test_doctor_reports_missing(self):
        info = doctor_x_twitter()
        self.assertFalse(info["ok"])
        self.assertIn("X_AUTH_TOKEN", info["detail"])

    @override_settings(
        X_TWITTER_ENABLED=True,
        X_AUTH_TOKEN="tok",
        X_CT0="csrf",
    )
    @patch("apps.integrations.web_reader.channels.x_twitter.httpx.Client")
    def test_search_maps_statuses(self, mock_client_cls):
        gql_payload = {
            "data": {
                "search_by_raw_query": {
                    "search_timeline": {
                        "timeline": {
                            "instructions": [
                                {
                                    "entries": [
                                        {
                                            "entryId": "tweet-123",
                                            "content": {
                                                "itemContent": {
                                                    "tweet_results": {
                                                        "result": {
                                                            "__typename": "Tweet",
                                                            "rest_id": "123",
                                                            "legacy": {
                                                                "id_str": "123",
                                                                "full_text": "Acme password dump",
                                                                "created_at": "Mon Jul 14 12:00:00 +0000 2025",
                                                            },
                                                            "core": {
                                                                "user_results": {
                                                                    "result": {
                                                                        "core": {
                                                                            "screen_name": "leakbot",
                                                                            "name": "Leak Bot",
                                                                        }
                                                                    }
                                                                }
                                                            },
                                                        }
                                                    }
                                                }
                                            },
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            }
        }
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = gql_payload
        response.raise_for_status = MagicMock()
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = response
        mock_client_cls.return_value = client

        hits = search_x_twitter("Acme", limit=5)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["engine"], "x_twitter")
        self.assertEqual(hits[0]["url"], "https://x.com/leakbot/status/123")
        self.assertIn("password dump", hits[0]["content"])
        self.assertTrue(hits[0].get("published"))
        self.assertTrue(client.post.called)

    @override_settings(
        X_TWITTER_ENABLED=True,
        X_AUTH_TOKEN="tok",
        X_CT0="csrf",
    )
    @patch("apps.integrations.web_reader.channels.x_twitter.httpx.Client")
    def test_multiword_x_query_is_quoted(self, mock_client_cls):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {"data": {}}
        response.raise_for_status = MagicMock()
        client = MagicMock()
        client.__enter__.return_value = client
        client.post.return_value = response
        mock_client_cls.return_value = client

        search_x_twitter("Đại học Thăng Long", limit=5)
        self.assertTrue(client.post.called)
        first = client.post.call_args_list[0].kwargs.get("json") or {}
        raw_query = (first.get("variables") or {}).get("rawQuery")
        self.assertEqual(raw_query, '"Đại học Thăng Long"')


class RedditSearchTests(SimpleTestCase):
    @override_settings(REDDIT_SEARCH_ENABLED=True, REDDIT_COOKIE="")
    def test_doctor_reports_missing_cookie(self):
        info = doctor_reddit_search()
        self.assertFalse(info["ok"])
        self.assertIn("REDDIT_COOKIE", info["detail"])

    @override_settings(
        REDDIT_SEARCH_ENABLED=True,
        REDDIT_COOKIE="reddit_session=eyJhbGciOiJS; token_v2=abc; csv=2",
    )
    @patch("apps.integrations.web_reader.channels.reddit.httpx.Client")
    def test_search_maps_listing(self, mock_client_cls):
        payload = {
            "data": {
                "children": [
                    {
                        "data": {
                            "title": "ClickFix incident",
                            "selftext": "details about ClickFix",
                            "permalink": "/r/DefenderATP/comments/1twfqmx/clickfix_incident/",
                            "subreddit_name_prefixed": "r/DefenderATP",
                            "score": 10,
                            "created_utc": 1,
                        }
                    }
                ]
            }
        }
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = payload
        response.raise_for_status = MagicMock()
        client = MagicMock()
        client.__enter__.return_value = client
        client.get.return_value = response
        mock_client_cls.return_value = client

        hits = search_reddit("ClickFix", limit=5)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["engine"], "reddit_search")
        self.assertIn("DefenderATP", hits[0]["url"])
        self.assertIn("ClickFix", hits[0]["title"])
        self.assertEqual(hits[0]["published"], "1")
        params = client.get.call_args.kwargs.get("params") or {}
        self.assertEqual(params.get("sort"), "relevance")
        self.assertEqual(params.get("t"), "all")

    @override_settings(
        REDDIT_SEARCH_ENABLED=True,
        REDDIT_COOKIE="reddit_session=eyJtest",
    )
    def test_pasted_url_returns_single_hit(self):
        url = "https://www.reddit.com/r/DefenderATP/comments/1twfqmx/clickfix_incident/"
        hits = search_reddit(url, limit=5)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["url"], url.rstrip("/"))
        self.assertEqual(hits[0]["engine"], "reddit_search")


class ChannelDoctorTests(SimpleTestCase):
    @override_settings(
        SEARXNG_URL="",
        EXA_API_KEY="",
        X_AUTH_TOKEN="",
        X_CT0="",
        REDDIT_COOKIE="",
        WEB_READER_ENABLED=True,
        REDDIT_ENRICH_ENABLED=True,
        REDDIT_SEARCH_ENABLED=True,
        PASTE_ENRICH_ENABLED=True,
    )
    def test_registry_lists_all_channels(self):
        doc = channel_doctor()
        ids = {c["id"] for c in doc["channels"]}
        self.assertEqual(
            ids,
            {
                "searx",
                "exa",
                "x_twitter",
                "reddit_search",
                "reddit_enrich",
                "paste_raw",
                "web_reader",
            },
        )


class PhraseMatchTests(SimpleTestCase):
    def test_requires_full_phrase(self):
        self.assertTrue(contains_phrase("See ClickFix in the wild", "ClickFix"))
        self.assertFalse(contains_phrase("Click Fix malware", "ClickFix"))
        self.assertTrue(
            contains_phrase("Acme Corp password leak", "Acme Corp")
        )
        self.assertFalse(contains_phrase("Acme password", "Acme Corp"))

    def test_vietnamese_nfc_nfd_and_casefold(self):
        import unicodedata

        phrase = "Đại học Thăng Long"
        nfd_hay = unicodedata.normalize("NFD", "TRƯỜNG ĐẠI HỌC THĂNG LONG hợp tác")
        self.assertTrue(contains_phrase(nfd_hay, phrase))
        self.assertTrue(contains_phrase("trường đại học thăng long", phrase))
        # Diacritic-insensitive: posts often omit tone marks.
        self.assertTrue(contains_phrase("dai hoc thang long breach", phrase))

    def test_social_hit_filter(self):
        ok = {
            "engine": "reddit_search",
            "title": "ClickFix notes",
            "content": "details about ClickFix",
            "url": "https://www.reddit.com/r/x/comments/a/b/",
        }
        bad = {
            "engine": "reddit_search",
            "title": "unrelated post",
            "content": "no match here",
            "url": "https://www.reddit.com/r/x/comments/a/b/",
        }
        self.assertTrue(social_hit_has_phrase(ok, "ClickFix"))
        self.assertFalse(social_hit_has_phrase(bad, "ClickFix"))

    def test_searx_and_exa_also_require_phrase(self):
        from apps.integrations.web_reader.phrase import (
            filter_hits_by_phrase,
            open_web_hit_has_phrase,
        )

        ok_searx = {
            "engine": "duckduckgo",
            "title": "Acme Corp breach report",
            "content": "records exposed",
            "url": "https://news.example/acme",
        }
        bad_searx = {
            "engine": "duckduckgo",
            "title": "Generic ransomware week",
            "content": "unrelated industry roundup",
            "url": "https://news.example/roundup",
        }
        ok_exa = {
            "engine": "exa",
            "title": "RansomEXX hits Acme Corp",
            "content": "claim against Acme Corp",
            "url": "https://breach.house/acme",
        }
        # Phrase only in URL path must not pass.
        url_only = {
            "engine": "exa",
            "title": "Weekly CTI digest",
            "content": "various incidents",
            "url": "https://example.com/acme-corp-notes",
        }
        self.assertTrue(open_web_hit_has_phrase(ok_searx, "Acme Corp"))
        self.assertFalse(open_web_hit_has_phrase(bad_searx, "Acme Corp"))
        self.assertTrue(open_web_hit_has_phrase(ok_exa, '"Acme Corp"'))
        self.assertFalse(open_web_hit_has_phrase(url_only, "Acme Corp"))
        filtered = filter_hits_by_phrase(
            [ok_searx, bad_searx, ok_exa, url_only], "Acme Corp"
        )
        self.assertEqual(
            {h["url"] for h in filtered},
            {ok_searx["url"], ok_exa["url"]},
        )

    def test_empty_social_url_deferred(self):
        from apps.integrations.web_reader.phrase import open_web_hit_has_phrase

        pasted = {
            "engine": "reddit_search",
            "title": "Reddit URL",
            "content": "",
            "url": "https://www.reddit.com/r/x/comments/abc/title/",
        }
        self.assertTrue(open_web_hit_has_phrase(pasted, "ClickFix"))


class BalancedMergeTests(SimpleTestCase):
    def test_round_robin_keeps_social_channels(self):
        searx = [{"url": f"https://a.example/{i}", "engine": "searx"} for i in range(20)]
        x = [{"url": "https://x.com/u/status/1", "engine": "x_twitter"}]
        reddit = [
            {
                "url": "https://www.reddit.com/r/x/comments/abc/t/",
                "engine": "reddit_search",
            }
        ]
        merged = merge_hits_balanced(searx, x, reddit, limit=6)
        engines = {h["engine"] for h in merged}
        self.assertIn("x_twitter", engines)
        self.assertIn("reddit_search", engines)
        self.assertIn("searx", engines)

    def test_newest_published_first(self):
        old = {
            "url": "https://old.example/1",
            "engine": "searx",
            "published": "2020-01-01T00:00:00Z",
        }
        new = {
            "url": "https://new.example/1",
            "engine": "reddit_search",
            "published": "2025-06-01T00:00:00Z",
        }
        mid = {
            "url": "https://x.com/u/status/9",
            "engine": "x_twitter",
            "published": "Wed Jan 15 12:00:00 +0000 2024",
        }
        undated = {"url": "https://nodate.example/1", "engine": "searx"}
        merged = merge_hits_balanced([old, undated], [mid], [new], limit=10)
        urls = [h["url"] for h in merged]
        self.assertEqual(urls[0], new["url"])
        self.assertEqual(urls[1], mid["url"])
        self.assertEqual(urls[2], old["url"])
        self.assertIn(undated["url"], urls)
        self.assertEqual(urls[-1], undated["url"])


class XEnrichTests(SimpleTestCase):
    def test_is_x_url(self):
        self.assertTrue(is_x_url("https://x.com/user/status/123456"))
        self.assertFalse(is_x_url("https://example.com/status/1"))

    @override_settings(
        X_TWITTER_ENABLED=True,
        X_AUTH_TOKEN="tok",
        X_CT0="csrf",
    )
    @patch("apps.integrations.web_reader.channels.x_twitter.httpx.Client")
    def test_read_x_status_includes_replies(self, mock_client_cls):
        tweet_gql = {
            "data": {
                "tweetResult": {
                    "result": {
                        "__typename": "Tweet",
                        "rest_id": "123",
                        "legacy": {
                            "id_str": "123",
                            "full_text": "ClickFix dump password=SuperSecretPassword123",
                        },
                        "core": {
                            "user_results": {
                                "result": {"legacy": {"screen_name": "leakbot"}}
                            }
                        },
                    }
                }
            }
        }
        reply_gql = {
            "data": {
                "search_by_raw_query": {
                    "search_timeline": {
                        "timeline": {
                            "instructions": [
                                {
                                    "entries": [
                                        {
                                            "entryId": "tweet-999",
                                            "content": {
                                                "itemContent": {
                                                    "tweet_results": {
                                                        "result": {
                                                            "__typename": "Tweet",
                                                            "rest_id": "999",
                                                            "legacy": {
                                                                "id_str": "999",
                                                                "full_text": "also API_KEY=sk-live-abcdef123456",
                                                            },
                                                        }
                                                    }
                                                }
                                            },
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            }
        }
        main_resp = MagicMock()
        main_resp.status_code = 200
        main_resp.json.return_value = tweet_gql
        main_resp.raise_for_status = MagicMock()
        reply_resp = MagicMock()
        reply_resp.status_code = 200
        reply_resp.json.return_value = reply_gql
        reply_resp.raise_for_status = MagicMock()
        client = MagicMock()
        client.__enter__.return_value = client
        client.get.side_effect = [main_resp, reply_resp]
        client.post.return_value = reply_resp
        mock_client_cls.return_value = client

        result = read_x_status("https://x.com/leakbot/status/123")
        self.assertTrue(result.ok)
        self.assertIn("SuperSecretPassword123", result.text)
        self.assertIn("sk-live-abcdef123456", result.text)


class EnrichRoutingTests(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        self.user = User.objects.create_user("ch_analyst", password="pass12345")

    @override_settings(WEB_READER_ENABLED=True, SEARX_LEAK_ENRICH=True)
    @patch("apps.integrations.web_reader.enrich.read_paste_raw")
    def test_enrich_prefers_paste_reader(self, mock_paste):
        mock_paste.return_value = ReadResult(
            True, "paste", "DB_PASSWORD=SuperSecretPassword123\n"
        )
        from apps.intel.models import DataLeak

        leak = DataLeak.objects.create(
            title="paste",
            description="hit",
            leak_type=DataLeak.LeakType.OTHER,
            severity=DataLeak.Severity.MEDIUM,
            source=DataLeak.Source.PASTEBIN,
            source_url="https://pastebin.com/AbCdEf12",
            metadata={"keyword": "Acme"},
            created_by=self.user,
        )
        stats = enrich_leak_from_url(leak, keyword="Acme")
        leak.refresh_from_db()
        self.assertTrue(stats["ok"])
        self.assertEqual(stats["backend"], "paste")
        mock_paste.assert_called_once()
        self.assertIn("password", leak.metadata.get("alert_types") or [])

    @override_settings(
        WEB_READER_ENABLED=True,
        SEARX_LEAK_ENRICH=True,
        X_AUTH_TOKEN="tok",
        X_CT0="csrf",
        X_TWITTER_ENABLED=True,
    )
    @patch("apps.integrations.web_reader.enrich.read_x_status")
    def test_enrich_prefers_x_reader(self, mock_x):
        mock_x.return_value = ReadResult(
            True, "x_twitter", "reply: password=SuperSecretPassword123\n"
        )
        from apps.intel.models import DataLeak

        leak = DataLeak.objects.create(
            title="x",
            description="hit",
            leak_type=DataLeak.LeakType.OTHER,
            severity=DataLeak.Severity.MEDIUM,
            source=DataLeak.Source.OTHER,
            source_url="https://x.com/u/status/42",
            metadata={"keyword": "ClickFix"},
            created_by=self.user,
        )
        stats = enrich_leak_from_url(leak, keyword="ClickFix")
        self.assertTrue(stats["ok"])
        self.assertEqual(stats["backend"], "x_twitter")
        mock_x.assert_called_once()


class SearxStatusApiTests(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model

        User = get_user_model()
        self.user = User.objects.create_user("status_u", password="pass12345")
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    @override_settings(
        SEARXNG_URL="",
        EXA_API_KEY="",
        X_AUTH_TOKEN="tok",
        X_CT0="csrf",
        X_TWITTER_ENABLED=True,
        WEB_READER_ENABLED=True,
    )
    def test_status_includes_channels_and_x_ok(self):
        response = self.client.get("/api/v1/searx/status/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data.get("configured"))
        channels = {c["id"]: c for c in data.get("channels") or []}
        self.assertIn("x_twitter", channels)
        self.assertTrue(channels["x_twitter"]["ok"])
        self.assertIn("reddit_enrich", channels)
        self.assertIn("paste_raw", channels)
