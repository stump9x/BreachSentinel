"""Tests for Logs Scanner upload + keyword scan."""

from __future__ import annotations

import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from apps.workers.log_scanner import run_log_scan, store_upload_bytes
from apps.workers.models import LogScan, LogScanHit


User = get_user_model()


@override_settings(LOG_SCAN_MAX_HITS=100, LOG_SCAN_MAX_FILES_PER_SCAN=10)
class LogScannerServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="analyst", password="x", is_staff=True
        )

    def test_keyword_scan_extracts_url_user_pass(self):
        content = (
            "https://example.com/login:alice:secret1\n"
            "https://portal.gov.vn/auth:bob:GovPass!\n"
            "https://other.com:carol:x\n"
            "not-a-credential-line\n"
        ).encode("utf-8")
        upload = store_upload_bytes(
            original_name="sample.txt", content=content, user=self.user
        )
        scan = LogScan.objects.create(
            keyword=".gov.vn", status=LogScan.Status.QUEUED, created_by=self.user
        )
        scan.uploads.add(upload)
        result = run_log_scan(scan.id)
        scan.refresh_from_db()
        self.assertEqual(scan.status, LogScan.Status.COMPLETED)
        self.assertEqual(result["hit_count"], 1)
        hit = LogScanHit.objects.get(scan=scan)
        self.assertIn("gov.vn", hit.domain)
        self.assertEqual(hit.username, "bob")


class LogScannerAPITests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            username="staff", password="x", is_staff=True
        )
        self.token = Token.objects.create(user=self.staff)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {self.token.key}")

    def test_upload_and_sync_scan(self):
        payload = SimpleUploadedFile(
            "dump.txt",
            b"https://canbo.moit.gov.vn/auth/login:034083023451:010112Kieuduchuynh\n"
            b"https://example.com:user:pass\n",
            content_type="text/plain",
        )
        res = self.client.post(
            "/api/v1/logs/uploads/",
            {"files": payload},
            format="multipart",
        )
        self.assertEqual(res.status_code, 201, res.content)
        upload_id = res.data["created"][0]["id"]

        scan_res = self.client.post(
            "/api/v1/logs/scans/",
            {
                "keyword": "gov.vn",
                "upload_ids": [upload_id],
                "async_mode": False,
            },
            format="json",
        )
        self.assertEqual(scan_res.status_code, 200, scan_res.content)
        self.assertEqual(scan_res.data["status"], "completed")
        self.assertEqual(scan_res.data["hit_count"], 1)

        hits = self.client.get(f"/api/v1/logs/scans/{scan_res.data['id']}/hits/")
        self.assertEqual(hits.status_code, 200)
        rows = hits.data["results"] if isinstance(hits.data, dict) else hits.data
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["password"], "010112Kieuduchuynh")

        keep = self.client.post(f"/api/v1/logs/hits/{rows[0]['id']}/keep/")
        self.assertEqual(keep.status_code, 200)
        kept = self.client.get("/api/v1/logs/hits/kept/")
        kept_rows = kept.data["results"] if isinstance(kept.data, dict) else kept.data
        self.assertEqual(len(kept_rows), 1)

    @override_settings(LOG_SCAN_UPLOAD_CHUNK_BYTES=4)
    def test_chunk_upload_resumes_and_is_idempotent(self):
        upload_id = str(uuid.uuid4())
        fields = {
            "upload_id": upload_id,
            "file_name": "chunked.txt",
            "file_size": "8",
            "total_chunks": "2",
        }
        first = self.client.post(
            "/api/v1/logs/uploads/chunk/",
            {
                **fields,
                "chunk_index": "0",
                "chunk": SimpleUploadedFile("chunk0", b"abcd"),
            },
            format="multipart",
        )
        self.assertEqual(first.status_code, 200, first.content)
        self.assertFalse(first.data["complete"])

        second = self.client.post(
            "/api/v1/logs/uploads/chunk/",
            {
                **fields,
                "chunk_index": "1",
                "chunk": SimpleUploadedFile("chunk1", b"WXYZ"),
            },
            format="multipart",
        )
        self.assertEqual(second.status_code, 201, second.content)
        self.assertTrue(second.data["complete"])
        upload_pk = second.data["upload"]["id"]

        retry = self.client.post(
            "/api/v1/logs/uploads/chunk/",
            {
                **fields,
                "chunk_index": "1",
                "chunk": SimpleUploadedFile("chunk1", b"WXYZ"),
            },
            format="multipart",
        )
        self.assertEqual(retry.status_code, 200, retry.content)
        self.assertEqual(retry.data["upload"]["id"], upload_pk)
