from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from apps.core.task_lock import single_flight


class SingleFlightLockTests(SimpleTestCase):
    @patch("apps.core.task_lock._redis_client")
    def test_second_caller_is_skipped(self, redis_factory):
        client = MagicMock()
        redis_factory.return_value = client
        client.set.side_effect = [True, False]

        with single_flight("rss-ingest", ttl_sec=60) as first:
            self.assertTrue(first)
        with single_flight("rss-ingest", ttl_sec=60) as second:
            self.assertFalse(second)

        self.assertEqual(client.set.call_count, 2)
        self.assertEqual(client.eval.call_count, 1)

    @patch("apps.core.task_lock._redis_client", side_effect=RuntimeError("redis down"))
    def test_fails_open_when_redis_unavailable(self, _redis_factory):
        with single_flight("translate", ttl_sec=30) as acquired:
            self.assertTrue(acquired)
