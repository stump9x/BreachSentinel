from datetime import timedelta
from email.utils import format_datetime

from django.test import TestCase
from django.utils import timezone

from apps.intel.models import Threat
from apps.workers.geography import (
    detect_geography_tag_slugs,
    infer_country_from_domain,
    infer_country_from_flag_html,
)
from apps.workers.services import ingest_ransomware_items, ingest_rss_items


class GeographyDetectionTests(TestCase):
    def test_detects_country_and_region_with_word_boundaries(self):
        tags = detect_geography_tag_slugs(
            "Romania agency confirms breach affecting Europe"
        )
        self.assertEqual(tags, ["geo-romania", "geo-europe"])

    def test_does_not_treat_ordinary_us_substring_as_country(self):
        self.assertEqual(
            detect_geography_tag_slugs("Industry discusses ransomware status"),
            [],
        )
        self.assertEqual(
            detect_geography_tag_slugs("Ransomware spreads across Latin America"),
            ["geo-latin-america"],
        )

    def test_detects_flag_emoji_and_cjk_aliases(self):
        self.assertEqual(
            detect_geography_tag_slugs("🚨 CYBER ALERT 🇻🇳 alleged breach"),
            ["vietnam"],
        )
        self.assertIn("geo-japan", detect_geography_tag_slugs("日本の企業でランサムウェア"))
        self.assertIn("geo-romania", detect_geography_tag_slugs("罗马尼亚机构确认数据泄露"))
        self.assertEqual(
            detect_geography_tag_slugs(
                "PREVENTIVE ALERT — CIVIL AVIATION (YEMEN - SANA'A) 🇾🇪"
            ),
            ["geo-yemen"],
        )

    def test_country_code_is_used_when_explicitly_supplied(self):
        self.assertEqual(
            detect_geography_tag_slugs("New victim listed", country_code="US"),
            ["geo-united-states"],
        )

    def test_infer_country_from_vn_domain(self):
        self.assertEqual(
            infer_country_from_domain("https://bank.example.vn/path"),
            ("VN", "Vietnam"),
        )
        self.assertEqual(infer_country_from_domain("example.com"), ("", ""))

    def test_infer_country_from_archive_flag(self):
        html = "<i class='flag flag-us' alt='United States' title='United States'></i>"
        self.assertEqual(infer_country_from_flag_html(html), ("US", "United States"))
        self.assertEqual(infer_country_from_flag_html("no flag here"), ("", ""))


class GeographyIngestTests(TestCase):
    def test_rss_uses_title_and_content_but_not_publisher_country_metadata(self):
        stats = ingest_rss_items(
            [
                {
                    "title": "Romanian ministry hit by ransomware",
                    "summary": "The incident was confirmed in Romania.",
                    "link": "https://example.com/romania",
                    "category": "news",
                    "country_code": "US",
                    "published": format_datetime(timezone.now() - timedelta(hours=1)),
                }
            ]
        )

        self.assertEqual(stats["created"], 1)
        slugs = set(
            Threat.objects.get(source_url="https://example.com/romania")
            .tags.values_list("slug", flat=True)
        )
        self.assertIn("geo-romania", slugs)
        self.assertNotIn("geo-united-states", slugs)

    def test_ransomware_uses_explicit_victim_country(self):
        ingest_ransomware_items(
            [
                {
                    "victim": "Example Corp",
                    "group": "nova",
                    "country_code": "US",
                    "url": "https://example.com/claim",
                }
            ]
        )

        slugs = set(
            Threat.objects.get(title="Ransomware: Example Corp (nova)")
            .tags.values_list("slug", flat=True)
        )
        self.assertIn("geo-united-states", slugs)
