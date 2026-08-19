from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.integrations.github.client import GitHubAPIError
from apps.integrations.github.detector import detect_secrets
from apps.integrations.github.scanner import (
    _build_search_lanes,
    _drop_single_txt_only_repos,
    _find_keyword_hits,
    _find_keyword_lines,
    _is_query_parse_error,
    _search_lane_pages,
    _should_fetch_content,
    run_github_scan,
)
from apps.integrations.models import GitHubFinding, GitHubScan
from apps.integrations.tasks import run_github_scan_task
from apps.intel.models import DataLeak


class GitHubLineAndFetchPolicyTests(TestCase):
    def test_find_keyword_lines_returns_absolute_numbers(self):
        content = "alpha\nMinistry of Finance budget\nomega\nMinistry of Finance again\n"
        lines, total = _find_keyword_lines(content, "Ministry of Finance")
        self.assertEqual(lines, [2, 4])
        self.assertEqual(total, 2)
        _lines, _total, snippets = _find_keyword_hits(content, "Ministry of Finance")
        self.assertEqual(
            snippets,
            [
                {"line": 2, "text": "Ministry of Finance budget"},
                {"line": 4, "text": "Ministry of Finance again"},
            ],
        )

    def test_search_lanes_avoid_or_groups_that_break_github_parse(self):
        lanes = _build_search_lanes('"agency"')
        self.assertTrue(lanes[0][2] == "secret")
        self.assertIn("password", lanes[0][0])
        sensitive = [query for query, _pages, kind in lanes if kind == "filename"]
        self.assertGreaterEqual(len(sensitive), 5)
        for query in sensitive:
            self.assertNotIn(" OR ", query)
            self.assertNotIn("(", query)
            self.assertEqual(query.count("filename:"), 1)
        self.assertTrue(any(kind == "non_txt" for _q, _p, kind in lanes))
        self.assertTrue(any(kind == "txt" for _q, _p, kind in lanes))
        # Secret lanes come before bulk non-.txt so Alerts fill early.
        first_non_txt = next(i for i, (_q, _p, kind) in enumerate(lanes) if kind == "non_txt")
        self.assertGreater(first_non_txt, 0)
        self.assertTrue(
            _is_query_parse_error(
                GitHubAPIError(
                    "GitHub API returned HTTP 422: ERROR_TYPE_QUERY_PARSING_FATAL "
                    "unable to parse query!"
                )
            )
        )
        self.assertFalse(
            _is_query_parse_error(GitHubAPIError("GitHub API returned HTTP 403: nope"))
        )

    def test_txt_with_fragments_skips_content_fetch(self):
        self.assertFalse(
            _should_fetch_content(
                is_text_file=True,
                has_fragments=True,
                path="notes.txt",
                content_fetches=0,
                fetch_limit=60,
            )
        )

    def test_non_txt_and_sensitive_files_prefer_fetch(self):
        # Fragment-backed generic code should not burn a content GET.
        self.assertFalse(
            _should_fetch_content(
                is_text_file=False,
                has_fragments=True,
                path="src/app.py",
                content_fetches=0,
                fetch_limit=25,
            )
        )
        # Sensitive filenames always fetch.
        self.assertTrue(
            _should_fetch_content(
                is_text_file=True,
                has_fragments=True,
                path=".env",
                content_fetches=0,
                fetch_limit=25,
            )
        )
        # Config extensions always fetch even when fragments exist.
        self.assertTrue(
            _should_fetch_content(
                is_text_file=False,
                has_fragments=True,
                path="deploy/docker-compose.yml",
                content_fetches=0,
                fetch_limit=25,
            )
        )
        # Document JSON corpora must NOT always fetch (budget burn).
        self.assertFalse(
            _should_fetch_content(
                is_text_file=False,
                has_fragments=True,
                path="documents/legal_30.json",
                content_fetches=0,
                fetch_limit=25,
            )
        )
        # Secret lane force-fetch overrides.
        self.assertTrue(
            _should_fetch_content(
                is_text_file=False,
                has_fragments=True,
                path="documents/legal_30.json",
                content_fetches=0,
                fetch_limit=25,
                force_fetch=True,
            )
        )
        # High-value extension without fragments still fetches.
        self.assertTrue(
            _should_fetch_content(
                is_text_file=False,
                has_fragments=False,
                path="src/app.py",
                content_fetches=0,
                fetch_limit=25,
            )
        )


class GitHubWeakRepoFilterTests(TestCase):
    def test_drops_repo_with_only_one_txt_file(self):
        scan = GitHubScan.objects.create(keyword="agency", max_results=2000)
        GitHubFinding.objects.create(
            scan=scan,
            repository="org/only-txt",
            file_path="notes.txt",
            is_text_file=True,
            html_url="https://github.com/org/only-txt/blob/main/notes.txt",
            score=1,
        )
        GitHubFinding.objects.create(
            scan=scan,
            repository="org/mixed",
            file_path="config/.env",
            is_text_file=False,
            html_url="https://github.com/org/mixed/blob/main/config/.env",
            score=100,
        )
        deleted = _drop_single_txt_only_repos(scan)
        self.assertEqual(deleted, 1)
        self.assertFalse(
            scan.findings.filter(repository="org/only-txt").exists()
        )
        self.assertTrue(scan.findings.filter(repository="org/mixed").exists())


class GitHubSecretDetectorTests(TestCase):
    def test_keeps_password_evidence_as_in_repo(self):
        alerts = detect_secrets("DB_PASSWORD=SuperSecretPassword123\n")

        self.assertEqual(alerts[0].kind, "password")
        self.assertEqual(alerts[0].severity, "high")
        self.assertEqual(alerts[0].line_number, 1)
        self.assertEqual(alerts[0].evidence, "DB_PASSWORD=SuperSecretPassword123")
        self.assertIn("SuperSecretPassword123", alerts[0].evidence)
        self.assertEqual(len(alerts[0].fingerprint), 64)

    def test_detects_database_url_with_credentials_visible(self):
        value = "postgres://admin:VerySecret987@db.example/app"
        alerts = detect_secrets(f"DATABASE_URL={value}")

        self.assertEqual(alerts[0].kind, "database-url")
        self.assertIn(value, alerts[0].evidence)

    def test_detects_account_identifier_as_committed(self):
        alerts = detect_secrets("DB_USERNAME=finance_admin")

        self.assertEqual(alerts[0].kind, "account-identifier")
        self.assertIn("finance_admin", alerts[0].evidence)

    def test_detects_jdbc_and_connection_string(self):
        jdbc = detect_secrets(
            "url=jdbc:postgresql://db.internal:5432/app?user=admin&password=x"
        )
        self.assertEqual(jdbc[0].kind, "jdbc-url")
        self.assertIn("jdbc:postgresql://", jdbc[0].evidence)

        conn = detect_secrets(
            'CONNECTION_STRING="Server=db;User Id=sa;Password=SeCr3t!"'
        )
        self.assertEqual(conn[0].kind, "connection-string")
        self.assertIn("Password=SeCr3t!", conn[0].evidence)

    def test_detects_json_and_sql_password_forms(self):
        json_alerts = detect_secrets('{"password": "SuperSecretPassword123"}')
        self.assertTrue(any(a.kind == "password" for a in json_alerts))
        self.assertIn("SuperSecretPassword123", json_alerts[0].evidence)

        sql_alerts = detect_secrets("CREATE USER app IDENTIFIED BY 'SqlSecret9999';")
        self.assertTrue(any(a.kind == "password" for a in sql_alerts))
        self.assertIn("SqlSecret9999", sql_alerts[0].evidence)

    def test_rejects_password_ui_and_identifier_false_positives(self):
        samples = [
            "password: errorMessage",
            'password: "Show password"',
            'password: "Hide password"',
            'label = "Enter your password"',
            'password: "Password"',
            "password: null",
            "password: undefined",
            'password: "********"',
            'password: "changeme"',
            '{"password": "showPassword"}',
            '{"password": "errorMessage"}',
            "pwd: placeholder",
            "password: true",
            'LBL_SHOW_PASSWORD": "Hiện/ẩn mật khẩu',
            '"LBL_SHOW_PASSWORD": "Hiện/ẩn mật khẩu"',
            '"BTN_HIDE_PASSWORD": "Hide password"',
            "SHOW_PASSWORD_LABEL=Toggle password visibility",
            'MSG_PASSWORD_HINT: "Nhập mật khẩu"',
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                alerts = [a for a in detect_secrets(sample) if a.kind == "password"]
                self.assertEqual(alerts, [], sample)

    def test_rejects_env_var_reference_as_django_secret(self):
        alerts = detect_secrets('secret_key=AWS_SECRET_KEY\n')
        self.assertEqual([a for a in alerts if a.kind == "django-secret"], [])

    def test_still_detects_real_password_secrets(self):
        samples = [
            "DB_PASSWORD=SuperSecretPassword123",
            'password = "P@ssw0rd!2024"',
            '{"password": "hunter2-prod-db"}',
            "MYSQL_ROOT_PASSWORD=Root$ecret99",
            "CREATE USER app IDENTIFIED BY 'SqlSecret9999';",
        ]
        for sample in samples:
            with self.subTest(sample=sample):
                alerts = [a for a in detect_secrets(sample) if a.kind == "password"]
                self.assertTrue(alerts, sample)

    def test_detects_aws_secret_django_and_db_host(self):
        aws = detect_secrets(
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )
        self.assertEqual(aws[0].kind, "aws-secret-key")

        django = detect_secrets('SECRET_KEY="django-insecure-abc123xyz890"')
        self.assertEqual(django[0].kind, "django-secret")

        host = detect_secrets("DB_HOST=prod-db.internal.example")
        self.assertEqual(host[0].kind, "config-host")
        self.assertIn("prod-db.internal.example", host[0].evidence)

    def test_every_alert_keeps_full_source_line(self):
        password = "SuperSecretPassword123"
        token = "ghp_abcdefghijklmnopqrstuvwxyz123456"
        line = f"PASSWORD={password} GITHUB_TOKEN={token}"
        alerts = detect_secrets(line)

        self.assertGreaterEqual(len(alerts), 2)
        for alert in alerts:
            self.assertEqual(alert.evidence, line)
            self.assertIn(password, alert.evidence)
            self.assertIn(token, alert.evidence)

    def test_dedupes_multiple_tokens_but_keeps_plaintext_line(self):
        first = "ghp_abcdefghijklmnopqrstuvwxyz123456"
        second = "ghp_654321zyxwvutsrqponmlkjihgfedcba"
        line = f"TOKEN_A={first} TOKEN_B={second}"
        alerts = detect_secrets(line)

        self.assertEqual(len([a for a in alerts if a.kind == "github-token"]), 2)
        for alert in alerts:
            self.assertIn(first, alert.evidence)
            self.assertIn(second, alert.evidence)


@override_settings(
    GITHUB_TOKEN="test-token",
    GITHUB_CONTENT_FETCH_LIMIT=10,
    GITHUB_MAX_FILE_BYTES=100_000,
)
class GitHubScannerServiceTests(TestCase):
    def setUp(self):
        self.scan = GitHubScan.objects.create(keyword="Ministry of Finance", max_results=10)

    @patch("apps.integrations.github.scanner.GitHubClient")
    def test_non_txt_ranked_first_and_secret_alert_persisted_safely(self, client_cls):
        client = MagicMock()
        client.request_count = 4
        client.rate_limit_remaining = 27
        client.search_rate_limit_remaining = 27
        client.__enter__.return_value = client
        client.__exit__.return_value = False
        non_text = {
            "total_count": 1,
            "items": [
                {
                    "name": ".env",
                    "path": "config/.env",
                    "sha": "abc",
                    "url": "https://api.github.com/repos/acme/leak/contents/config/.env",
                    "html_url": "https://github.com/acme/leak/blob/main/config/.env",
                    "repository": {
                        "full_name": "acme/leak",
                        "html_url": "https://github.com/acme/leak",
                        "owner": {"login": "acme"},
                    },
                }
            ],
        }
        text = {
            "total_count": 1,
            "items": [
                {
                    "name": "notes.txt",
                    "path": "notes.txt",
                    "sha": "def",
                    "url": "https://api.github.com/repos/acme/notes/contents/notes.txt",
                    "html_url": "https://github.com/acme/notes/blob/main/notes.txt",
                    "repository": {
                        "full_name": "acme/notes",
                        "html_url": "https://github.com/acme/notes",
                        "owner": {"login": "acme"},
                    },
                }
            ],
        }
        search_calls = 0
        seen_queries: list[str] = []

        def search_side_effect(query, *_args, **_kwargs):
            nonlocal search_calls
            search_calls += 1
            seen_queries.append(query)
            # Secret co-occurrence lane with password term returns the .env leak.
            if " password " in f" {query} " or query.rstrip().endswith("password in:file"):
                return non_text
            if "-extension:txt" in query:
                return {"total_count": 0, "items": []}
            if query.rstrip().endswith("extension:txt"):
                return text
            return {"total_count": 0, "items": []}

        client.search_code.side_effect = search_side_effect
        client.fetch_text_content.side_effect = [
            "ORG=Ministry of Finance\nDB_PASSWORD=SuperSecretPassword123",
            "Ministry of Finance public notes",
        ]
        client_cls.return_value = client

        run_github_scan(self.scan)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, GitHubScan.Status.COMPLETED)
        # Single-.txt-only repos are pruned after the scan.
        self.assertEqual(self.scan.repository_count, 1)
        self.assertEqual(self.scan.alert_count, 1)
        self.assertTrue(any("password" in q for q in seen_queries))
        self.assertTrue(any("-extension:txt" in q for q in seen_queries))
        rows = list(self.scan.findings.all())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].file_path, "config/.env")
        self.assertIn("password", rows[0].alert_types)
        self.assertEqual(rows[0].match_lines, [1, 2])
        self.assertEqual(
            rows[0].match_snippets,
            [{"line": 1, "text": "ORG=Ministry of Finance"}],
        )
        self.assertTrue(rows[0].html_url.endswith("#L1"))
        self.assertIn("SuperSecretPassword123", rows[0].evidence)
        self.assertIn("DB_PASSWORD=SuperSecretPassword123", rows[0].evidence)
        leak = DataLeak.objects.get(source=DataLeak.Source.GITHUB)
        self.assertIn("SuperSecretPassword123", str(leak.metadata))

    @patch("apps.integrations.github.scanner.GitHubClient")
    def test_txt_lane_uses_fragments_without_content_fetch(self, client_cls):
        client = MagicMock()
        client.request_count = 1
        client.rate_limit_remaining = 40
        client.search_rate_limit_remaining = 40
        client.__enter__.return_value = client
        client.__exit__.return_value = False

        def search_side_effect(query, *_args, **_kwargs):
            if query.rstrip().endswith("extension:txt") and "-extension" not in query:
                return {
                    "total_count": 1,
                    "items": [
                        {
                            "path": "notes.txt",
                            "url": "https://api.github.com/repos/acme/notes/contents/notes.txt",
                            "html_url": "https://github.com/acme/notes/blob/main/notes.txt",
                            "text_matches": [
                                {
                                    "fragment": "Public note about Ministry of Finance"
                                }
                            ],
                            "repository": {
                                "full_name": "acme/notes",
                                "html_url": "https://github.com/acme/notes",
                                "owner": {"login": "acme"},
                            },
                        }
                    ],
                }
            return {"total_count": 0, "items": []}

        client.search_code.side_effect = search_side_effect
        client_cls.return_value = client

        run_github_scan(self.scan)

        self.scan.refresh_from_db()
        # Fragment path avoided a content GET; lone .txt repo is then pruned.
        client.fetch_text_content.assert_not_called()
        self.assertEqual(self.scan.file_count, 0)
        self.assertEqual(self.scan.findings.count(), 0)

    @patch("apps.integrations.github.scanner.GitHubClient")
    def test_unparseable_sensitive_query_is_skipped_not_fatal(self, client_cls):
        client = MagicMock()
        client.request_count = 3
        client.rate_limit_remaining = 40
        client.search_rate_limit_remaining = 40
        client.__enter__.return_value = client
        client.__exit__.return_value = False

        def search_side_effect(query, *_args, **_kwargs):
            if "filename:" in query:
                raise GitHubAPIError(
                    "GitHub API returned HTTP 422: ERROR_TYPE_QUERY_PARSING_FATAL "
                    "unable to parse query!"
                )
            if "-extension:txt" in query:
                return {
                    "total_count": 1,
                    "items": [
                        {
                            "path": "app.py",
                            "url": "https://api.github.com/repos/acme/app/contents/app.py",
                            "html_url": "https://github.com/acme/app/blob/main/app.py",
                            "repository": {
                                "full_name": "acme/app",
                                "html_url": "https://github.com/acme/app",
                                "owner": {"login": "acme"},
                            },
                        }
                    ],
                }
            return {"total_count": 0, "items": []}

        client.search_code.side_effect = search_side_effect
        client.fetch_text_content.return_value = "Ministry of Finance config"
        client_cls.return_value = client

        run_github_scan(self.scan)

        self.scan.refresh_from_db()
        self.assertIn(
            self.scan.status,
            {GitHubScan.Status.COMPLETED, GitHubScan.Status.PARTIAL},
        )
        self.assertEqual(self.scan.findings.count(), 1)
        self.assertEqual(self.scan.findings.get().file_path, "app.py")

    @patch(
        "apps.integrations.github.scanner._persist_leak_alerts",
        side_effect=RuntimeError("notification write failed"),
    )
    @patch("apps.integrations.github.scanner.GitHubClient")
    def test_batch_side_effect_failure_rolls_back_findings_and_counts(
        self, client_cls, _persist
    ):
        client = MagicMock()
        client.request_count = 2
        client.rate_limit_remaining = 20
        client.__enter__.return_value = client
        client.__exit__.return_value = False
        client.search_code.return_value = {
            "total_count": 1,
            "items": [
                {
                    "path": ".env",
                    "url": "https://api.github.com/repos/acme/leak/contents/.env",
                    "html_url": "https://github.com/acme/leak/blob/main/.env",
                    "repository": {
                        "full_name": "acme/leak",
                        "html_url": "https://github.com/acme/leak",
                        "owner": {"login": "acme"},
                    },
                }
            ],
        }
        client.fetch_text_content.return_value = (
            "Ministry of Finance\nPASSWORD=SuperSecretPassword123"
        )
        client_cls.return_value = client

        run_github_scan(self.scan)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.status, GitHubScan.Status.FAILED)
        self.assertEqual(self.scan.file_count, 0)
        self.assertEqual(self.scan.findings.count(), 0)
        self.assertEqual(DataLeak.objects.count(), 0)


class GitHubSearchPaginationTests(TestCase):
    def test_lane_uses_constant_page_size_to_avoid_offset_overlap(self):
        client = MagicMock()
        client.search_code.side_effect = [
            {"total_count": 212, "items": [{"id": i} for i in range(100)]},
            {"total_count": 212, "items": [{"id": i} for i in range(100, 200)]},
            {"total_count": 212, "items": [{"id": i} for i in range(200, 212)]},
        ]

        pages = list(_search_lane_pages(client, '"agency" in:file', remaining=212))

        self.assertEqual([len(rows) for rows, _limited in pages], [100, 100, 12])
        self.assertEqual(
            [call.kwargs["per_page"] for call in client.search_code.call_args_list],
            [100, 100, 100],
        )

    def test_lane_respects_max_pages_cap(self):
        client = MagicMock()
        client.search_code.side_effect = [
            {"total_count": 500, "items": [{"id": i} for i in range(100)]}
            for _ in range(5)
        ]
        pages = list(
            _search_lane_pages(
                client, '"agency" in:file', remaining=500, max_pages=2
            )
        )
        self.assertEqual(len(pages), 2)
        self.assertEqual(client.search_code.call_count, 2)


@override_settings(GITHUB_TOKEN="test-token")
class GitHubClientRateLimitTests(TestCase):
    @patch("apps.integrations.github.client.time.sleep")
    @patch("apps.integrations.github.client.httpx.Client")
    def test_search_waits_and_retries_after_rate_limit(self, client_cls, sleep):
        from apps.integrations.github.client import GitHubClient

        http = MagicMock()
        client_cls.return_value = http
        limited = MagicMock()
        limited.status_code = 403
        limited.headers = {
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": str(int(time.time()) + 1),
            "x-ratelimit-resource": "search",
            "retry-after": "1",
        }
        limited.json.return_value = {"message": "API rate limit exceeded"}
        limited.raise_for_status.side_effect = Exception("should not raise yet")
        ok = MagicMock()
        ok.status_code = 200
        ok.headers = {
            "x-ratelimit-remaining": "29",
            "x-ratelimit-reset": str(int(time.time()) + 60),
            "x-ratelimit-resource": "search",
        }
        ok.json.return_value = {"total_count": 0, "items": []}
        ok.raise_for_status.return_value = None
        http.get.side_effect = [limited, ok]

        with GitHubClient() as client:
            payload = client.search_code('"agency" in:file')

        self.assertEqual(payload["items"], [])
        self.assertEqual(http.get.call_count, 2)
        self.assertTrue(sleep.called)

    @patch("apps.integrations.github.client.time.sleep")
    @patch("apps.integrations.github.client.httpx.Client")
    def test_search_paces_between_requests(self, client_cls, sleep):
        from apps.integrations.github.client import (
            SEARCH_MIN_INTERVAL_SEC,
            GitHubClient,
        )

        http = MagicMock()
        client_cls.return_value = http

        def ok_response():
            response = MagicMock()
            response.status_code = 200
            response.headers = {
                "x-ratelimit-remaining": "20",
                "x-ratelimit-resource": "search",
            }
            response.json.return_value = {"total_count": 0, "items": []}
            response.raise_for_status.return_value = None
            return response

        http.get.side_effect = [ok_response(), ok_response()]
        with GitHubClient() as client:
            client.search_code('"a" in:file')
            client.search_code('"b" in:file')

        paced = [
            call
            for call in sleep.call_args_list
            if call.args and call.args[0] >= SEARCH_MIN_INTERVAL_SEC - 0.05
        ]
        self.assertTrue(paced)


class GitHubScannerAPITests(TestCase):
    def setUp(self):
        User = get_user_model()
        self.staff = User.objects.create_user(
            "staff", password="pass12345", is_staff=True
        )
        self.analyst = User.objects.create_user("analyst", password="pass12345")
        self.client = APIClient()

    @override_settings(GITHUB_TOKEN="")
    def test_status_does_not_expose_token(self):
        self.client.force_authenticate(self.staff)
        response = self.client.get("/api/v1/github/scans/status/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, {"configured": False})

    @override_settings(GITHUB_TOKEN="test-token")
    @patch("apps.integrations.views.run_github_scan_task.delay")
    def test_staff_can_queue_scan(self, delay):
        delay.return_value.id = "task-1"
        self.client.force_authenticate(self.staff)

        response = self.client.post(
            "/api/v1/github/scans/",
            {"keyword": "Bộ Tài chính"},
            format="json",
        )

        self.assertEqual(response.status_code, 202)
        scan = GitHubScan.objects.get()
        self.assertEqual(scan.created_by, self.staff)
        self.assertEqual(scan.status, GitHubScan.Status.QUEUED)
        self.assertEqual(scan.max_results, 1500)
        delay.assert_called_once_with(scan.id)
        self.assertNotIn("test-token", str(response.data))

    @override_settings(GITHUB_TOKEN="test-token")
    def test_non_staff_cannot_start_scan(self):
        self.client.force_authenticate(self.analyst)
        response = self.client.post(
            "/api/v1/github/scans/",
            {"keyword": "government"},
            format="json",
        )
        self.assertEqual(response.status_code, 403)

    @override_settings(GITHUB_TOKEN="test-token")
    @patch("apps.integrations.views.run_github_scan_task.delay")
    def test_rejects_second_active_scan(self, delay):
        GitHubScan.objects.create(keyword="first", status=GitHubScan.Status.RUNNING)
        self.client.force_authenticate(self.staff)

        response = self.client.post(
            "/api/v1/github/scans/",
            {"keyword": "second"},
            format="json",
        )

        self.assertEqual(response.status_code, 409)
        delay.assert_not_called()

    @override_settings(GITHUB_TOKEN="test-token")
    @patch("apps.integrations.views.run_github_scan_task.delay")
    def test_broker_failure_marks_scan_failed(self, delay):
        delay.side_effect = RuntimeError("redis unavailable")
        self.client.force_authenticate(self.staff)

        response = self.client.post(
            "/api/v1/github/scans/",
            {"keyword": "agency"},
            format="json",
        )

        self.assertEqual(response.status_code, 503)
        scan = GitHubScan.objects.get()
        self.assertEqual(scan.status, GitHubScan.Status.FAILED)
        self.assertNotIn("redis", str(response.data).lower())

    @override_settings(GITHUB_TOKEN="test-token", GITHUB_SCAN_STALE_MINUTES=20)
    @patch("apps.integrations.views.run_github_scan_task.delay")
    def test_stale_running_scan_is_failed_before_new_scan_is_queued(self, delay):
        stale = GitHubScan.objects.create(
            keyword="stale",
            status=GitHubScan.Status.RUNNING,
        )
        GitHubScan.objects.filter(pk=stale.pk).update(
            updated_at=timezone.now() - timedelta(minutes=30)
        )
        delay.return_value.id = "task-2"
        self.client.force_authenticate(self.staff)

        response = self.client.post(
            "/api/v1/github/scans/",
            {"keyword": "fresh"},
            format="json",
        )

        self.assertEqual(response.status_code, 202)
        stale.refresh_from_db()
        self.assertEqual(stale.status, GitHubScan.Status.FAILED)
        self.assertIsNone(stale.active_slot)

    def test_findings_api_returns_plaintext_evidence_without_fingerprints(self):
        self.client.force_authenticate(self.staff)
        scan = GitHubScan.objects.create(keyword="agency", created_by=self.staff)
        GitHubFinding.objects.create(
            scan=scan,
            repository="org/repo",
            file_path=".env",
            html_url="https://github.com/org/repo/blob/main/.env",
            severity="critical",
            alert_types=["password"],
            evidence="PASSWORD=SuperSecretPassword123",
            match_lines=[3, 12],
            score=200,
        )

        response = self.client.get(f"/api/v1/github/scans/{scan.id}/findings/")

        self.assertEqual(response.status_code, 200)
        row = response.data["results"][0]
        self.assertNotIn("fingerprint", str(row).lower())
        self.assertEqual(row["evidence"], "PASSWORD=SuperSecretPassword123")
        self.assertEqual(row["match_lines"], [3, 12])

    def test_repositories_rollup_and_findings_filter_non_txt_first(self):
        self.client.force_authenticate(self.staff)
        scan = GitHubScan.objects.create(keyword="agency", created_by=self.staff)
        GitHubFinding.objects.create(
            scan=scan,
            repository="org/repo",
            owner="org",
            repository_url="https://github.com/org/repo",
            file_path="notes.txt",
            is_text_file=True,
            html_url="https://github.com/org/repo/blob/main/notes.txt",
            keyword_matches=2,
            score=10,
        )
        GitHubFinding.objects.create(
            scan=scan,
            repository="org/repo",
            owner="org",
            repository_url="https://github.com/org/repo",
            file_path="config/.env",
            is_text_file=False,
            html_url="https://github.com/org/repo/blob/main/config/.env#L4",
            keyword_matches=5,
            alert_types=["password"],
            severity="high",
            match_lines=[4],
            score=200,
        )

        repos = self.client.get(f"/api/v1/github/scans/{scan.id}/repositories/")
        self.assertEqual(repos.status_code, 200)
        summary = repos.data["results"][0]
        self.assertEqual(summary["repository"], "org/repo")
        self.assertEqual(summary["file_count"], 2)
        self.assertEqual(summary["non_text_count"], 1)
        self.assertEqual(summary["text_count"], 1)
        self.assertEqual(summary["alert_count"], 1)
        self.assertEqual(summary["match_total"], 7)

        findings = self.client.get(
            f"/api/v1/github/scans/{scan.id}/findings/",
            {"repository": "org/repo"},
        )
        self.assertEqual(findings.status_code, 200)
        paths = [row["file_path"] for row in findings.data["results"]]
        self.assertEqual(paths, ["config/.env", "notes.txt"])

    def test_repositories_hides_single_txt_only_repos(self):
        self.client.force_authenticate(self.staff)
        scan = GitHubScan.objects.create(keyword="agency", created_by=self.staff)
        GitHubFinding.objects.create(
            scan=scan,
            repository="org/weak",
            owner="org",
            repository_url="https://github.com/org/weak",
            file_path="a.txt",
            is_text_file=True,
            html_url="https://github.com/org/weak/blob/main/a.txt",
            keyword_matches=1,
            score=1,
        )
        GitHubFinding.objects.create(
            scan=scan,
            repository="org/strong",
            owner="org",
            repository_url="https://github.com/org/strong",
            file_path="app.py",
            is_text_file=False,
            html_url="https://github.com/org/strong/blob/main/app.py",
            keyword_matches=2,
            score=50,
        )

        repos = self.client.get(f"/api/v1/github/scans/{scan.id}/repositories/")
        names = [row["repository"] for row in repos.data["results"]]
        self.assertEqual(names, ["org/strong"])

    def test_repositories_prioritize_alert_repos_first(self):
        self.client.force_authenticate(self.staff)
        scan = GitHubScan.objects.create(keyword="agency", created_by=self.staff)
        GitHubFinding.objects.create(
            scan=scan,
            repository="org/generic",
            owner="org",
            repository_url="https://github.com/org/generic",
            file_path="readme.md",
            extension="md",
            is_text_file=False,
            html_url="https://github.com/org/generic/blob/main/readme.md",
            keyword_matches=3,
            score=40,
        )
        GitHubFinding.objects.create(
            scan=scan,
            repository="org/secrets",
            owner="org",
            repository_url="https://github.com/org/secrets",
            file_path="config/.env",
            extension="env",
            is_text_file=False,
            html_url="https://github.com/org/secrets/blob/main/config/.env",
            keyword_matches=1,
            alert_types=["password"],
            severity="high",
            score=200,
        )

        repos = self.client.get(f"/api/v1/github/scans/{scan.id}/repositories/")
        names = [row["repository"] for row in repos.data["results"]]
        self.assertEqual(names[0], "org/secrets")
        self.assertEqual(repos.data["results"][0]["alert_count"], 1)
        self.assertEqual(repos.data["results"][1]["alert_count"], 0)

    def test_delete_and_bulk_delete_history(self):
        self.client.force_authenticate(self.staff)
        done = GitHubScan.objects.create(
            keyword="done",
            status=GitHubScan.Status.COMPLETED,
            created_by=self.staff,
        )
        other = GitHubScan.objects.create(
            keyword="other",
            status=GitHubScan.Status.FAILED,
            created_by=self.staff,
        )
        active = GitHubScan.objects.create(
            keyword="active",
            status=GitHubScan.Status.RUNNING,
            created_by=self.staff,
        )

        blocked = self.client.delete(f"/api/v1/github/scans/{active.id}/")
        self.assertEqual(blocked.status_code, 409)
        self.assertTrue(GitHubScan.objects.filter(id=active.id).exists())

        deleted = self.client.delete(f"/api/v1/github/scans/{done.id}/")
        self.assertEqual(deleted.status_code, 200)
        self.assertFalse(GitHubScan.objects.filter(id=done.id).exists())

        bulk = self.client.post(
            "/api/v1/github/scans/bulk-delete/",
            {"ids": [other.id, active.id]},
            format="json",
        )
        self.assertEqual(bulk.status_code, 200)
        self.assertEqual(bulk.data["deleted"], [other.id])
        self.assertEqual(bulk.data["blocked"], [active.id])
        self.assertFalse(GitHubScan.objects.filter(id=other.id).exists())
        self.assertTrue(GitHubScan.objects.filter(id=active.id).exists())


class GitHubScannerTaskTests(TestCase):
    @patch("apps.integrations.github.scanner.run_github_scan")
    def test_duplicate_delivery_skips_non_queued_scan(self, run_scan):
        scan = GitHubScan.objects.create(
            keyword="agency",
            status=GitHubScan.Status.RUNNING,
        )

        result = run_github_scan_task(scan.id)

        self.assertTrue(result["skipped"])
        run_scan.assert_not_called()

    def test_database_allows_only_one_active_scan(self):
        GitHubScan.objects.create(keyword="first")
        with self.assertRaises(IntegrityError):
            GitHubScan.objects.create(keyword="second", status=GitHubScan.Status.RUNNING)
