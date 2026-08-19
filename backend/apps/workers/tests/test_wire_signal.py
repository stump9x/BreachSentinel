from __future__ import annotations

from datetime import timedelta
from email.utils import format_datetime

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.intel.models import Threat
from apps.workers.services import (
    IMPACT_WIRE_PRIORITY,
    VIETNAM_WIRE_PRIORITY,
    ingest_rss_items,
    is_vietnam_related,
    is_wire_relevant,
)


class WireSignalRelevanceTests(TestCase):
    def test_generic_cybersecurity_blurb_is_irrelevant(self):
        self.assertFalse(
            is_wire_relevant(
                {
                    "title": "Why cybersecurity awareness matters in 2026",
                    "summary": "Tips for employees and information security culture.",
                    "category": "news",
                }
            )
        )

    def test_data_breach_is_relevant(self):
        self.assertTrue(
            is_wire_relevant(
                {
                    "title": "Hospital network hit by data breach",
                    "summary": "Patient records exposed after intrusion.",
                    "category": "news",
                }
            )
        )

    def test_ransomware_against_org_is_relevant(self):
        self.assertTrue(
            is_wire_relevant(
                {
                    "title": "Ransomware group claims attack on city government",
                    "summary": "Operators demand payment after encrypting systems.",
                    "category": "news",
                }
            )
        )

    def test_large_scale_leak_is_relevant(self):
        self.assertTrue(
            is_wire_relevant(
                {
                    "title": "Dark web listing offers 2 million customer records",
                    "summary": "Alleged database leak from a telecom operator.",
                    "category": "news",
                }
            )
        )


class VietnamSignalDetectionTests(TestCase):
    def test_detects_vn_tld_and_vietnamese_company_forms(self):
        self.assertTrue(is_vietnam_related("Target domain digipro.com.vn listed"))
        self.assertTrue(
            is_vietnam_related(
                "Công ty Cổ phần Phát triển Công nghệ DIGIPRO reported a breach"
            )
        )
        self.assertTrue(is_vietnam_related("Incident at a Vietnamese IT firm"))
        self.assertFalse(is_vietnam_related("Retailer in California reports ransomware"))
        self.assertFalse(
            is_vietnam_related("Các công ty báo cáo mô hình OpenAI tấn Hugging Face")
        )
        self.assertFalse(is_vietnam_related("Tập đoàn luật tại Hoa Kỳ bị ransomware"))

    def test_rss_item_with_vn_domain_in_summary_is_tagged(self):
        published = timezone.now() - timedelta(hours=2)
        stats = ingest_rss_items(
            [
                {
                    "title": "Nova claims Digipro as new victim",
                    "link": "https://example.com/digipro-claim",
                    "summary": (
                        "digipro.com.vn appears to be a Vietnamese IT company "
                        "based in Hanoi after a ransomware claim."
                    ),
                    "category": "ransomware",
                    "published": format_datetime(published),
                }
            ]
        )
        self.assertEqual(stats["created"], 1)
        threat = Threat.objects.get(source_url__contains="digipro-claim")
        self.assertIn("vietnam", set(threat.tags.values_list("slug", flat=True)))
        self.assertEqual(threat.wire_priority, VIETNAM_WIRE_PRIORITY)


@override_settings(WIRE_MAX_AGE_DAYS=7, WIRE_VIETNAM_MAX_AGE_DAYS=30)
class WireSevenDayWindowTests(TestCase):
    def test_foreign_breach_older_than_seven_days_is_skipped(self):
        published = timezone.now() - timedelta(days=9)
        stats = ingest_rss_items(
            [
                {
                    "title": "US retailer data breach update",
                    "link": "https://example.com/us-9d",
                    "summary": "Customer records leaked in California.",
                    "category": "news",
                    "published": format_datetime(published),
                }
            ]
        )
        self.assertEqual(stats["created"], 0)
        self.assertEqual(stats["skipped_old"], 1)

    def test_foreign_breach_within_seven_days_is_ingested_with_impact_priority(self):
        published = timezone.now() - timedelta(days=5)
        stats = ingest_rss_items(
            [
                {
                    "title": "Bank hit by ransomware and data leak",
                    "link": "https://example.com/bank-5d",
                    "summary": "Attackers stole customer databases.",
                    "category": "news",
                    "published": format_datetime(published),
                }
            ]
        )
        self.assertEqual(stats["created"], 1)
        t = Threat.objects.get(source_url__contains="bank-5d")
        self.assertEqual(t.wire_priority, IMPACT_WIRE_PRIORITY)
        self.assertLess(t.wire_priority, VIETNAM_WIRE_PRIORITY)

    def test_cyberattack_keyword_is_treated_as_relevant(self):
        self.assertTrue(
            is_wire_relevant(
                {
                    "title": "City government hit by cyberattack",
                    "summary": "Systems offline after intrusion.",
                    "category": "news",
                }
            )
        )

    def test_vietnam_breach_within_month_stays_on_top(self):
        published = timezone.now() - timedelta(days=20)
        stats = ingest_rss_items(
            [
                {
                    "title": "Vietnam ministry reports major data breach",
                    "link": "https://example.com/vn-20d-breach",
                    "summary": "Hanoi confirms leaked citizen records.",
                    "category": "news",
                    "published": format_datetime(published),
                }
            ]
        )
        self.assertEqual(stats["created"], 1)
        t = Threat.objects.get(source_url__contains="vn-20d-breach")
        self.assertEqual(t.wire_priority, VIETNAM_WIRE_PRIORITY)
