"""Forum enrich + clearnet claim ingest path tests (no session cookies)."""



from __future__ import annotations



from datetime import timedelta

from email.utils import format_datetime



from django.test import TestCase, override_settings

from django.utils import timezone



from apps.intel.models import Threat

from apps.workers.feeds.forum_enrich import classify_forum_title

from apps.workers.services import ingest_rss_items





class ForumEnrichUnitTests(TestCase):

    def test_heuristic_extracts_domain(self):

        data = classify_forum_title("Acme Bank portal example-bank.com sold")

        self.assertTrue(data.get("is_claim"))

        self.assertIn("example-bank.com", data.get("victim_hint") or "")

        self.assertEqual(data.get("provider"), "heuristic")





class ForumWebhookIngestTests(TestCase):

    def test_clearnet_claim_lands_on_wire(self):

        now = timezone.now()

        stats = ingest_rss_items(

            [

                {

                    "title": "Retailer victim.example.com database claim on DarkForums",

                    "link": "https://www.databreaches.net/retailer-claim/",

                    "summary": "",

                    "published": format_datetime(now - timedelta(hours=1)),

                    "feed": "databreaches-net",

                    "feed_url": "https://www.databreaches.net/feed/",

                    "discovery": "forum-claim",

                    "forum_claim": True,

                    "metadata_only": True,

                    "feed_notes": "claim/dark-web news",

                    "category": "news",

                }

            ],

            source_label="claim-news",

        )

        self.assertEqual(stats["created"], 1)

        threat = Threat.objects.get(

            source_url="https://www.databreaches.net/retailer-claim/"

        )

        slugs = set(threat.tags.values_list("slug", flat=True))

        self.assertIn("forum", slugs)

        self.assertNotIn("alleged-claim", slugs)



    @override_settings(FORUM_AI_ENRICH=True, GROQ_API_KEY="")

    def test_enrich_without_groq_uses_heuristic(self):

        from apps.workers.feeds.forum_enrich import enrich_forum_items



        rows = enrich_forum_items(

            [{"title": "hospital records leak claim", "link": "https://example.com/t"}]

        )

        self.assertEqual(rows[0]["forum_enrichment"]["provider"], "heuristic")

        self.assertEqual(rows[0]["forum_enrichment"]["sector"], "healthcare")


