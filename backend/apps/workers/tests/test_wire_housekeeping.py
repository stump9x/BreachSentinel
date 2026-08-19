"""Safe Wire housekeeping automation tests."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.intel.models import Threat
from apps.workers.housekeeping import run_wire_housekeeping
from apps.workers.tasks import wire_housekeeping_task
from config.settings import CELERY_BEAT_SCHEDULE, CELERY_RESULT_EXPIRES


class WireHousekeepingConfigTests(SimpleTestCase):
    def test_beat_registers_daily_housekeeping(self):
        entry = CELERY_BEAT_SCHEDULE.get("wire-housekeeping-daily")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["task"], "workers.wire_housekeeping")
        self.assertFalse(entry["kwargs"].get("reset_feed_cache"))

    def test_celery_results_expire(self):
        self.assertGreaterEqual(int(CELERY_RESULT_EXPIRES), 60)


@override_settings(
    WIRE_HOUSEKEEPING_ENABLED=True,
    WIRE_MAX_AGE_DAYS=7,
    WIRE_VIETNAM_MAX_AGE_DAYS=30,
)
class WireHousekeepingRunTests(TestCase):
    def test_run_purges_old_wire(self):
        now = timezone.now()
        old = Threat.objects.create(
            title="Stale foreign wire",
            source=Threat.Source.NEWS,
            wire_relevant=True,
            published_at=now - timedelta(days=10),
            raw_payload={"feed_source": "rss", "discovery": "rss"},
        )
        recent = Threat.objects.create(
            title="Fresh foreign wire",
            source=Threat.Source.NEWS,
            wire_relevant=True,
            published_at=now - timedelta(days=2),
            raw_payload={"feed_source": "rss", "discovery": "rss"},
        )
        stats = run_wire_housekeeping()
        self.assertFalse(stats.get("skipped"))
        self.assertFalse(Threat.objects.filter(pk=old.pk).exists())
        self.assertTrue(Threat.objects.filter(pk=recent.pk).exists())

    @override_settings(WIRE_HOUSEKEEPING_ENABLED=False)
    def test_disabled_skips(self):
        stats = run_wire_housekeeping()
        self.assertTrue(stats["skipped"])


class WireHousekeepingTaskTests(SimpleTestCase):
    @patch("apps.workers.housekeeping.run_wire_housekeeping")
    @patch("apps.core.task_lock.single_flight")
    def test_task_skips_when_lock_not_acquired(self, lock_cm, mock_run):
        lock_cm.return_value.__enter__.return_value = False
        lock_cm.return_value.__exit__.return_value = False
        result = wire_housekeeping_task.run()
        self.assertEqual(result, {"skipped": True, "reason": "already_running"})
        mock_run.assert_not_called()

    @patch(
        "apps.workers.housekeeping.run_wire_housekeeping",
        return_value={"skipped": False, "purge": "ok"},
    )
    @patch("apps.core.task_lock.single_flight")
    def test_task_runs_when_lock_acquired(self, lock_cm, mock_run):
        lock_cm.return_value.__enter__.return_value = True
        lock_cm.return_value.__exit__.return_value = False
        result = wire_housekeeping_task.run(reset_feed_cache=False)
        self.assertEqual(result["skipped"], False)
        mock_run.assert_called_once_with(reset_feed_cache=False)
