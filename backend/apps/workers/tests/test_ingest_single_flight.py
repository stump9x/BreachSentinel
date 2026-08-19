from unittest.mock import patch

from django.test import SimpleTestCase

from apps.workers.tasks import ingest_cert_rss


class IngestSingleFlightTests(SimpleTestCase):
    @patch("apps.workers.feeds.wordpress.fetch_wordpress_vietnam_backfill", return_value=[])
    @patch("apps.workers.feeds.clients.fetch_cert_rss_feeds", return_value=[])
    @patch("apps.workers.services.ingest_rss_items")
    @patch("apps.core.task_lock.single_flight")
    def test_skips_when_lock_not_acquired(
        self, lock_cm, ingest, _fetch, _backfill
    ):
        lock_cm.return_value.__enter__.return_value = False
        lock_cm.return_value.__exit__.return_value = False

        result = ingest_cert_rss.run(limit_per_feed=10)

        self.assertEqual(result, {"skipped": True, "reason": "already_running"})
        ingest.assert_not_called()
