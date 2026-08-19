"""Precise Wire topic tagging (avoid generic false positives)."""

from __future__ import annotations

from datetime import timedelta
from email.utils import format_datetime

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.intel.models import Threat
from apps.workers.services import (
    ingest_rss_items,
    is_vietnam_related,
    looks_like_data_breach,
    looks_like_data_leak,
    looks_like_ransomware_topic,
)


class PreciseTopicSignalTests(SimpleTestCase):
    def test_data_breach_requires_explicit_signal(self):
        self.assertTrue(looks_like_data_breach("Major data breach exposes customer emails"))
        self.assertTrue(looks_like_data_breach("2M records leaked from vendor"))
        self.assertTrue(
            looks_like_data_breach("Alleged exfiltration of health data (PHI/PII)")
        )
        self.assertFalse(looks_like_data_breach("Akira ransomware claimed a new victim"))
        self.assertFalse(looks_like_data_breach("Hospital hit by cyberattack"))
        self.assertFalse(looks_like_data_breach("Website defaced overnight"))

    def test_ransomware_and_leak_signals(self):
        self.assertTrue(looks_like_ransomware_topic("Akira ransomware group"))
        self.assertTrue(looks_like_data_leak("database leak on dark web"))
        self.assertFalse(looks_like_data_leak("supply chain leak of patches"))

    def test_translated_foreign_titles_are_not_vietnam(self):
        self.assertFalse(
            is_vietnam_related(
                "Các công ty cho biết các mô hình OpenAI đứng sau việc vi phạm hệ thống Hugging Face"
            )
        )
        self.assertFalse(
            is_vietnam_related(
                "🚨 Cảnh báo về phần mềm tống tiền: us Tập đoàn luật Koshkaryan "
                "(một công ty Luật có trụ sở tại Hoa Kỳ"
            )
        )
        self.assertTrue(
            is_vietnam_related(
                "Công ty Cổ phần Phát triển Công nghệ DIGIPRO reported a breach"
            )
        )


class PreciseTopicIngestTests(TestCase):
    def test_ransomware_claim_not_tagged_data_breach(self):
        now = timezone.now()
        stats = ingest_rss_items(
            [
                {
                    "title": "Akira ransomware claimed a United States food company",
                    "summary": "New victim listed on dark web leak site",
                    "link": "https://example.com/akira-claim",
                    "category": "breach",
                    "discovery": "x-wire",
                    "x_handle": "FalconFeedsio",
                    "published": format_datetime(now - timedelta(hours=1)),
                }
            ],
            source_label="x-wire",
        )
        self.assertEqual(stats["created"], 1)
        slugs = set(
            Threat.objects.get(source_url="https://example.com/akira-claim")
            .tags.values_list("slug", flat=True)
        )
        self.assertIn("ransomware", slugs)
        self.assertNotIn("data-breach", slugs)
        self.assertNotIn("alleged-claim", slugs)
        self.assertIn("geo-united-states", slugs)

    def test_explicit_data_breach_still_tagged(self):
        now = timezone.now()
        stats = ingest_rss_items(
            [
                {
                    "title": "Mexican retailer data breach — emails leaked",
                    "summary": "Customer records exposed after intrusion",
                    "link": "https://example.com/mx-breach",
                    "category": "news",
                    "published": format_datetime(now - timedelta(hours=1)),
                }
            ]
        )
        self.assertEqual(stats["created"], 1)
        slugs = set(
            Threat.objects.get(source_url="https://example.com/mx-breach")
            .tags.values_list("slug", flat=True)
        )
        self.assertIn("data-breach", slugs)
        self.assertIn("geo-mexico", slugs)
