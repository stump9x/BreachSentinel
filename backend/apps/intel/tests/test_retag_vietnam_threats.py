from django.core.management import call_command
from django.test import TestCase

from apps.intel.models import Threat
from apps.workers.services import VIETNAM_WIRE_PRIORITY


class RetagVietnamThreatsTests(TestCase):
    def test_backfills_missed_vietnam_ransomware_and_related_news(self):
        ransomware = Threat.objects.create(
            title="Ransomware: Digipro (nova)",
            source=Threat.Source.RANSOMWARE,
            summary="Victim reported by ransomware.live / group=nova",
            severity=Threat.Severity.HIGH,
            wire_priority=0,
            source_url="https://www.ransomware.live/id/digipro-nova",
            raw_payload={
                "victim": "Digipro",
                "group": "nova",
                "domain": "digipro.com.vn",
                "description": (
                    "digipro.com.vn appears to be the website of DIGIPRO TECH JSC "
                    "(Công ty Cổ phần Phát triển Công nghệ DIGIPRO), a Vietnamese IT "
                    "company based in Hanoi, Vietnam."
                ),
            },
        )
        news = Threat.objects.create(
            title="Nova Ransomware Group Claims Digipro as New Victim",
            source=Threat.Source.NEWS,
            summary="Dark web recent claims video about the ransomware group.",
            severity=Threat.Severity.HIGH,
            wire_priority=50,
            source_url="https://undercodenews.com/digipro-claim/",
        )

        call_command("retag_vietnam_threats")

        ransomware.refresh_from_db()
        news.refresh_from_db()
        self.assertIn("vietnam", set(ransomware.tags.values_list("slug", flat=True)))
        self.assertEqual(ransomware.wire_priority, VIETNAM_WIRE_PRIORITY)
        self.assertIn("vietnam", set(news.tags.values_list("slug", flat=True)))
        self.assertEqual(news.wire_priority, VIETNAM_WIRE_PRIORITY)
