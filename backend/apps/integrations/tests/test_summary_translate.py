from unittest.mock import Mock, patch

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.intel.models import Threat
from apps.integrations.ai.summary_translate import (
    GoogleTranslation,
    normalize_summary,
    summary_hash,
    translate_summary,
)


class SummaryNormalizationTests(SimpleTestCase):
    def test_strips_markup_scripts_decodes_entities_and_caps_input(self):
        source = (
            "<p>Threat&nbsp;<strong>report</strong></p>"
            "<script>ignore me</script><style>.hidden{}</style>"
        )
        self.assertEqual(normalize_summary(source), "Threat report")
        self.assertEqual(normalize_summary("one two three", max_chars=7), "one two")

    def test_hash_uses_canonical_plain_text(self):
        self.assertEqual(
            summary_hash("<p>Threat&nbsp; report</p>"),
            summary_hash(" threat report "),
        )


@override_settings(
    SUMMARY_TRANSLATE_ENABLED=True,
    SUMMARY_TRANSLATE_OLLAMA_FALLBACK=True,
    SUMMARY_TRANSLATE_MAX_ATTEMPTS=3,
    OLLAMA_ENABLED=True,
    OLLAMA_BASE_URL="http://localhost:11434",
)
class SummaryTranslationTests(TestCase):
    def make_threat(self, summary="A hospital disclosed a data breach."):
        return Threat.objects.create(
            title="Hospital breach",
            title_vi="Bệnh viện gặp sự cố lộ dữ liệu",
            title_vi_status=Threat.TitleViStatus.OK,
            summary=summary,
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
        )

    @patch("apps.integrations.ai.summary_translate.google_translate_summary")
    def test_google_auto_detection_translation_is_persisted(self, google):
        google.return_value = GoogleTranslation(
            text="Một bệnh viện công bố sự cố lộ dữ liệu.",
            source_language="en",
        )
        threat = self.make_threat()

        result = translate_summary(threat)

        threat.refresh_from_db()
        self.assertEqual(result["provider"], "google")
        self.assertEqual(threat.summary_vi, google.return_value.text)
        self.assertEqual(threat.summary_source_language, "en")
        self.assertEqual(threat.summary_vi_attempts, 1)

    @patch("apps.integrations.ai.summary_translate.google_translate_summary")
    def test_google_detected_vietnamese_is_saved_without_ai(self, google):
        google.return_value = GoogleTranslation(
            text="Cổng thông tin công bố sự cố dữ liệu.",
            source_language="vi",
        )
        threat = self.make_threat("Cong thong tin cong bo su co du lieu.")

        with patch(
            "apps.integrations.ai.summary_translate.ollama_translate_summary"
        ) as ollama:
            result = translate_summary(threat)

        threat.refresh_from_db()
        ollama.assert_not_called()
        self.assertEqual(result["provider"], "google:detected_vi")
        self.assertEqual(threat.summary_vi_status, Threat.TitleViStatus.SKIPPED)

    @patch("apps.integrations.ai.summary_translate.ollama_translate_summary")
    @patch("apps.integrations.ai.summary_translate.google_translate_summary")
    def test_ai_runs_only_after_google_failure(self, google, ollama):
        from apps.integrations.ai.summary_translate import SummaryTranslateError

        google.side_effect = SummaryTranslateError("Google unavailable")
        ollama.return_value = "Bệnh viện công bố sự cố lộ dữ liệu."
        threat = self.make_threat()

        result = translate_summary(threat)

        threat.refresh_from_db()
        self.assertTrue(result["provider"].startswith("ollama-fallback:"))
        ollama.assert_called_once()
        self.assertEqual(threat.summary_vi_status, Threat.TitleViStatus.OK)

    @patch("apps.integrations.ai.summary_translate.google_translate_summary")
    def test_reuses_exact_summary_hash_without_network(self, google):
        first = self.make_threat()
        first.summary_vi = "Bản dịch đã lưu."
        first.summary_vi_status = Threat.TitleViStatus.OK
        first.summary_vi_provider = "google"
        first.summary_hash = summary_hash(first.summary)
        first.save()
        second = self.make_threat()

        result = translate_summary(second)

        second.refresh_from_db()
        google.assert_not_called()
        self.assertTrue(result["cached"])
        self.assertEqual(second.summary_vi, first.summary_vi)

    @patch("apps.integrations.ai.summary_translate.ollama_translate_summary")
    @patch("apps.integrations.ai.summary_translate.google_translate_summary")
    def test_failures_are_bounded(self, google, ollama):
        from apps.integrations.ai.summary_translate import SummaryTranslateError

        google.side_effect = SummaryTranslateError("down")
        ollama.side_effect = SummaryTranslateError("down")
        threat = self.make_threat()
        threat.summary_vi_attempts = 2
        threat.save(update_fields=["summary_vi_attempts"])

        result = translate_summary(threat)

        threat.refresh_from_db()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(threat.summary_vi_attempts, 3)
        self.assertEqual(threat.summary_vi_status, Threat.TitleViStatus.FAILED)


class GoogleTransportTests(SimpleTestCase):
    @patch("apps.integrations.ai.summary_translate.httpx.Client")
    def test_google_uses_auto_source_detection(self, client_cls):
        from apps.integrations.ai.summary_translate import google_translate_summary

        response = Mock()
        response.json.return_value = [
            [["Bản dịch", "Translation", None, None]],
            None,
            "en",
        ]
        response.raise_for_status.return_value = None
        client = client_cls.return_value.__enter__.return_value
        client.post.return_value = response

        result = google_translate_summary("Translation")

        form = client.post.call_args.kwargs["data"]
        self.assertEqual(form["sl"], "auto")
        self.assertEqual(form["tl"], "vi")
        self.assertEqual(result.source_language, "en")
        self.assertEqual(result.text, "Bản dịch")
