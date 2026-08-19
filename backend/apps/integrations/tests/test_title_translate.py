from unittest.mock import Mock, patch

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.intel.models import Threat
from apps.integrations.ai.translate import (
    TitleTranslateError,
    accept_refine_result,
    apply_inline_rule_translation,
    is_mangled_title_vi,
    looks_vietnamese,
    needs_ai_refine,
    rule_translate_title,
    title_hash,
    translate_threat,
)


class RuleTranslateTests(SimpleTestCase):
    def test_ransomware_structured_title(self):
        self.assertEqual(
            rule_translate_title("Ransomware: Digipro (nova)"),
            "Mã độc tống tiền: Digipro (nova)",
        )

    def test_freeform_titles_are_not_phrase_rewritten(self):
        self.assertIsNone(
            rule_translate_title("Nova has just published a new victim : Digipro")
        )

    def test_vietnamese_title_detected(self):
        self.assertTrue(looks_vietnamese("Lộ dữ liệu tại Hà Nội"))
        self.assertFalse(looks_vietnamese("Hospital data breach in California"))

    def test_title_hash_stable(self):
        self.assertEqual(title_hash("  Foo  Bar "), title_hash("foo bar"))


@override_settings(
    TITLE_TRANSLATE_ENABLED=True,
    TITLE_TRANSLATE_AI_REFINE=False,
    TITLE_TRANSLATE_INLINE_GOOGLE=True,
    TITLE_TRANSLATE_MYMEMORY_FALLBACK=False,
    TITLE_TRANSLATE_OLLAMA_FALLBACK=False,
    TITLE_TRANSLATE_GROQ=False,
    TITLE_TRANSLATE_PREFER_GROQ=False,
    OLLAMA_ENABLED=False,
)
class TranslateThreatPersistenceTests(TestCase):
    def test_inline_rule_sets_title_vi_without_google(self):
        threat = Threat.objects.create(
            title="Ransomware: Digipro (nova)",
            source=Threat.Source.RANSOMWARE,
            published_at=timezone.now(),
        )
        self.assertTrue(apply_inline_rule_translation(threat))
        threat.refresh_from_db()
        self.assertEqual(threat.title_vi, "Mã độc tống tiền: Digipro (nova)")
        self.assertEqual(threat.title_vi_status, Threat.TitleViStatus.RULE)

    def test_cache_reuses_google_translation(self):
        first = Threat.objects.create(
            title="Hospital data breach reported",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi="Báo cáo lộ dữ liệu bệnh viện",
            title_vi_status=Threat.TitleViStatus.OK,
            title_vi_provider="google",
            title_hash=title_hash("Hospital data breach reported"),
        )
        second = Threat.objects.create(
            title="Hospital data breach reported",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
        )
        self.assertTrue(apply_inline_rule_translation(second))
        second.refresh_from_db()
        self.assertEqual(second.title_vi, first.title_vi)
        self.assertTrue(second.title_vi_provider.startswith("cache:"))

    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        return_value="Chiến dịch xâm nhập bệnh viện tinh vi",
    )
    def test_inline_google_sets_title_vi_immediately(self, _mock_google):
        threat = Threat.objects.create(
            title="Hospital network hit by sophisticated intrusion campaign",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
        )
        self.assertTrue(apply_inline_rule_translation(threat))
        threat.refresh_from_db()
        self.assertEqual(threat.title_vi_provider, "google")
        self.assertIn("bệnh viện", threat.title_vi.casefold())

    @override_settings(TITLE_TRANSLATE_INLINE_GOOGLE=False)
    @patch("apps.integrations.ai.translate.google_translate_title")
    def test_ingest_path_defers_google_when_inline_disabled(self, mock_google):
        threat = Threat.objects.create(
            title="Government portal exposes citizen records",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
        )

        self.assertFalse(apply_inline_rule_translation(threat))

        threat.refresh_from_db()
        mock_google.assert_not_called()
        self.assertEqual(threat.title_vi, "")
        self.assertEqual(threat.title_vi_status, Threat.TitleViStatus.PENDING)

    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        return_value="Chiến dịch xâm nhập bệnh viện tinh vi",
    )
    def test_translate_threat_uses_google(self, _mock_google):
        threat = Threat.objects.create(
            title="Hospital network hit by sophisticated intrusion campaign",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(threat.title_vi_provider, "google")
        self.assertIn("bệnh viện", threat.title_vi.casefold())

    def test_translate_threat_stays_pending_when_google_fails(self):
        from apps.integrations.ai.translate import TitleTranslateError

        with patch(
            "apps.integrations.ai.translate.google_translate_title",
            side_effect=TitleTranslateError("network down"),
        ):
            threat = Threat.objects.create(
                title="Hospital network hit by sophisticated intrusion campaign",
                source=Threat.Source.NEWS,
                published_at=timezone.now(),
                title_vi_status=Threat.TitleViStatus.PENDING,
            )
            result = translate_threat(threat)
            threat.refresh_from_db()
            self.assertEqual(result["status"], "pending")
            self.assertEqual(threat.title_vi_provider, "awaiting_google")

    @patch("apps.integrations.ai.translate.google_translate_title")
    def test_translate_threats_skips_valid_ransomware_rule_titles(self, mock_google):
        from apps.integrations.ai.translate import translate_threats

        Threat.objects.create(
            title="Ransomware: Digipro (nova)",
            source=Threat.Source.RANSOMWARE,
            published_at=timezone.now(),
            title_vi="Mã độc tống tiền: Digipro (nova)",
            title_vi_status=Threat.TitleViStatus.RULE,
            title_vi_provider="rule",
            title_hash=title_hash("Ransomware: Digipro (nova)"),
        )
        stats = translate_threats(limit=10)
        self.assertEqual(stats["processed"], 0)
        mock_google.assert_not_called()

    @override_settings(TITLE_TRANSLATE_AI_REFINE=True, TITLE_TRANSLATE_AI_MIN_PRIORITY=50)
    def test_needs_ai_refine_when_flag_enabled(self):
        self.assertTrue(
            needs_ai_refine(
                "Hospital data breach",
                "Lộ dữ liệu bệnh viện",
                wire_priority=50,
            )
        )
        self.assertFalse(
            needs_ai_refine(
                "Low priority fluff",
                "Rác ưu tiên thấp",
                wire_priority=0,
            )
        )

    @override_settings(TITLE_TRANSLATE_AI_REFINE=False)
    def test_needs_ai_refine_off_when_flag_disabled(self):
        self.assertFalse(
            needs_ai_refine(
                "Hospital data breach",
                "Lộ dữ liệu bệnh viện",
            )
        )

    def test_refine_prompt_requests_administrative_style(self):
        from apps.integrations.ai.translate import build_refine_prompt

        prompt = build_refine_prompt(
            "Nova claims Digipro as new victim",
            "Nova tuyên bố Digipro là nạn nhân mới",
        )
        self.assertIn("hành chính", prompt)
        self.assertIn("Nova claims Digipro as new victim", prompt)
        self.assertIn("Nova tuyên bố Digipro là nạn nhân mới", prompt)
        self.assertIn("Google Translate draft", prompt)


class RefineValidationTests(SimpleTestCase):
    def test_detects_mangled_ollama_garble(self):
        bad = (
            "Cơ quotate: Romania's National Land Registry Agency Confirms "
            "Cyberattack After Data Breach Claims Surface on Dark Web"
        )
        self.assertTrue(is_mangled_title_vi(bad, provider="google+ollama:qwen2.5:3b"))

    def test_good_google_draft_not_mangled(self):
        good = (
            "Cơ quan đăng ký đất đai quốc gia Romania xác nhận tấn công mạng "
            "sau khi có cáo buộc lộ dữ liệu trên dark web"
        )
        self.assertFalse(is_mangled_title_vi(good, provider="google"))

    def test_rejects_chinese_mixed_into_vietnamese(self):
        original = "OpenAI GPT Agent used zero-day to breach Hugging Face"
        bad = "GPT Agent của OpenAI利用零日攻击入侵Hugging Face服务器"
        self.assertTrue(
            is_mangled_title_vi(
                bad, provider="ollama-fallback:qwen2.5:3b", original=original
            )
        )

    def test_spanish_accent_is_not_vietnamese(self):
        title = (
            "ASIPONA Mazatlán (Administración del Sistema Portuario Nacional) "
            "alleged data breach"
        )
        self.assertFalse(looks_vietnamese(title))

    def test_threat_actor_leadin_is_mangled(self):
        bad = (
            "Threat Actor Đòi Trợ Giả Thăng Long Đại Học Việt Nam "
            "Là Nạn Nhân Của Sự cố Lộ Dữ Liệu"
        )
        self.assertTrue(
            is_mangled_title_vi(
                bad,
                provider="ollama-fallback:qwen2.5:3b",
                original="Dark web threat actor claims Thang Long University victim",
            )
        )

    def test_question_marks_only_needs_rescue(self):
        from apps.integrations.ai.translate import google_draft_needs_ollama

        self.assertTrue(google_draft_needs_ollama("Saudi cyber alert", "????"))

    def test_reject_refine_with_english_remnants(self):
        original = (
            "Romania's National Land Registry Agency Confirms Cyberattack "
            "After Data Breach Claims Surface on Dark Web"
        )
        google_draft = (
            "Cơ quan đăng ký đất đai quốc gia Romania xác nhận tấn công mạng "
            "sau khi có cáo buộc lộ dữ liệu trên dark web"
        )
        bad_refine = (
            "Cơ quotate: Romania's National Land Registry Agency Confirms "
            "Cyberattack After Data Breach Claims Surface on Dark Web"
        )
        self.assertFalse(accept_refine_result(original, google_draft, bad_refine))

    def test_accept_refine_when_clearly_better(self):
        original = "Hospital data breach reported in California"
        google_draft = "Báo cáo vi phạm dữ liệu bệnh viện ở California"
        good_refine = "Báo cáo sự cố lộ dữ liệu bệnh viện tại California"
        self.assertTrue(accept_refine_result(original, google_draft, good_refine))


@override_settings(
    TITLE_TRANSLATE_ENABLED=True,
    TITLE_TRANSLATE_AI_REFINE=True,
    TITLE_TRANSLATE_INLINE_GOOGLE=True,
    TITLE_TRANSLATE_GROQ=False,
    TITLE_TRANSLATE_PREFER_GROQ=False,
    OLLAMA_ENABLED=True,
    OLLAMA_BASE_URL="http://localhost:11434",
    OLLAMA_TRANSLATE_MODEL="qwen2.5:3b",
)
class GooglePreferredOverRefineTests(TestCase):
    @override_settings(TITLE_TRANSLATE_AI_REFINE=True)
    @patch("apps.integrations.ai.translate.ollama_refine_title")
    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        return_value=(
            "Cơ quan đăng ký đất đai quốc gia Romania xác nhận tấn công mạng "
            "sau khi có cáo buộc lộ dữ liệu trên dark web"
        ),
    )
    def test_bad_ollama_refine_keeps_google(self, _mock_google, mock_refine):
        mock_refine.return_value = (
            "Cơ quotate: Romania's National Land Registry Agency Confirms "
            "Cyberattack After Data Breach Claims Surface on Dark Web"
        )
        threat = Threat.objects.create(
            title=(
                "Romania's National Land Registry Agency Confirms Cyberattack "
                "After Data Breach Claims Surface on Dark Web"
            ),
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(threat.title_vi_provider, "google")
        self.assertIn("Cơ quan", threat.title_vi)
        self.assertNotIn("quotate", threat.title_vi.casefold())


@override_settings(
    TITLE_TRANSLATE_ENABLED=True,
    TITLE_TRANSLATE_AI_REFINE=False,
    TITLE_TRANSLATE_INLINE_GOOGLE=True,
    TITLE_TRANSLATE_OLLAMA_FALLBACK=True,
    TITLE_TRANSLATE_GROQ=False,
    TITLE_TRANSLATE_PREFER_GROQ=False,
    OLLAMA_ENABLED=True,
    OLLAMA_BASE_URL="http://localhost:11434",
    OLLAMA_TRANSLATE_MODEL="qwen2.5:3b",
)
class OllamaFallbackTests(TestCase):
    @patch(
        "apps.integrations.ai.translate.ollama_translate_title",
        return_value="Cơ quan Romania xác nhận sự cố tấn công mạng",
    )
    @patch("apps.integrations.ai.translate.google_translate_title")
    def test_uses_ollama_only_after_google_fails(self, mock_google, _mock_ollama):
        from apps.integrations.ai.translate import TitleTranslateError

        mock_google.side_effect = TitleTranslateError("Google unavailable")
        threat = Threat.objects.create(
            title="Romanian agency confirms cyberattack",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
        )

        self.assertTrue(apply_inline_rule_translation(threat))

        threat.refresh_from_db()
        self.assertEqual(threat.title_vi_status, Threat.TitleViStatus.OK)
        self.assertTrue(threat.title_vi_provider.startswith("ollama-fallback:"))
        self.assertIn("xác nhận", threat.title_vi)

    @patch(
        "apps.integrations.ai.translate.ollama_translate_title",
        return_value="Cơ quotate: Romanian Agency Confirms Cyberattack on Dark Web",
    )
    @patch("apps.integrations.ai.translate.google_translate_title")
    def test_rejects_mangled_ollama_fallback(self, mock_google, _mock_ollama):
        from apps.integrations.ai.translate import TitleTranslateError

        mock_google.side_effect = TitleTranslateError("Google unavailable")
        threat = Threat.objects.create(
            title="Romanian agency confirms cyberattack",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
        )

        self.assertFalse(apply_inline_rule_translation(threat))

        threat.refresh_from_db()
        self.assertEqual(threat.title_vi, "")
        self.assertEqual(threat.title_vi_status, Threat.TitleViStatus.PENDING)

    @override_settings(TITLE_TRANSLATE_AI_REFINE=True, TITLE_TRANSLATE_AI_MIN_PRIORITY=50)
    @patch("apps.integrations.ai.translate.ollama_refine_title")
    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        return_value="Báo cáo vi phạm dữ liệu bệnh viện ở California",
    )
    def test_good_ollama_refine_accepted_when_enabled(self, _mock_google, mock_refine):
        mock_refine.return_value = "Báo cáo sự cố lộ dữ liệu bệnh viện tại California"
        threat = Threat.objects.create(
            title="Hospital data breach reported in California",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
            wire_priority=50,
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        self.assertEqual(result["status"], "ok")
        self.assertTrue(str(threat.title_vi_provider).startswith("google+ollama"))
        self.assertIn("sự cố lộ dữ liệu", threat.title_vi.casefold())

    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        return_value=(
            "Cơ quan đăng ký đất đai quốc gia Romania xác nhận tấn công mạng "
            "sau khi có cáo buộc lộ dữ liệu trên dark web"
        ),
    )
    def test_force_retranslate_mangled_google_ollama(self, _mock_google):
        threat = Threat.objects.create(
            title=(
                "Romania's National Land Registry Agency Confirms Cyberattack "
                "After Data Breach Claims Surface on Dark Web"
            ),
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi=(
                "Cơ quotate: Romania's National Land Registry Agency Confirms "
                "Cyberattack After Data Breach Claims Surface on Dark Web"
            ),
            title_vi_status=Threat.TitleViStatus.OK,
            title_vi_provider="google+ollama:qwen2.5:3b",
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(threat.title_vi_provider, "google")
        self.assertIn("Cơ quan", threat.title_vi)
        self.assertNotIn("quotate", threat.title_vi.casefold())


class GoogleTitleTransportTests(SimpleTestCase):
    @patch("apps.integrations.ai.translate.httpx.Client")
    def test_google_title_uses_post_and_rejects_captcha_redirect(self, client_cls):
        from apps.integrations.ai.translate import (
            TitleTranslateError,
            google_translate_title,
        )
        import httpx as httpx_mod

        client = client_cls.return_value.__enter__.return_value
        captcha = Mock()
        captcha.status_code = 302
        captcha.headers = {"location": "https://www.google.com/sorry/index?q=1"}
        captcha.raise_for_status.side_effect = httpx_mod.HTTPStatusError(
            "redirect",
            request=Mock(),
            response=captcha,
        )
        client.post.return_value = captcha

        with self.assertRaises(TitleTranslateError):
            google_translate_title("Hospital data breach")

        kwargs = client.post.call_args.kwargs
        self.assertEqual(kwargs["data"]["client"], "gtx")
        self.assertEqual(kwargs["data"]["tl"], "vi")
        self.assertFalse(client_cls.call_args.kwargs.get("follow_redirects", True))

    @patch("apps.integrations.ai.translate.httpx.Client")
    def test_google_title_post_success(self, client_cls):
        from apps.integrations.ai.translate import google_translate_title

        response = Mock()
        response.status_code = 200
        response.headers = {"content-type": "application/json"}
        response.json.return_value = [[["Báo cáo lộ dữ liệu", "Data breach report"]]]
        response.raise_for_status.return_value = None
        client = client_cls.return_value.__enter__.return_value
        client.post.return_value = response

        self.assertEqual(
            google_translate_title("Data breach report").text, "Báo cáo lộ dữ liệu"
        )
        self.assertEqual(
            client.post.call_args.kwargs["data"]["q"], "Data breach report"
        )
        self.assertEqual(client.post.call_args.kwargs["data"]["sl"], "auto")
        self.assertEqual(client.post.call_args.kwargs["data"]["tl"], "vi")

    @override_settings(
        TOR_ENABLED=True,
        TOR_SOCKS_PROXY="socks5h://tor:9150",
        GOOGLE_TRANSLATE_TOR_FALLBACK=True,
    )
    @patch("apps.integrations.ai.translate.httpx.Client")
    def test_google_retries_via_tor_after_captcha(self, client_cls):
        from apps.integrations.ai.translate import (
            google_translate_title,
            reset_google_circuit,
        )

        reset_google_circuit()
        captcha = Mock()
        captcha.status_code = 302
        captcha.headers = {"location": "https://www.google.com/sorry/index?q=1"}
        ok = Mock()
        ok.status_code = 200
        ok.headers = {"content-type": "application/json"}
        ok.json.return_value = [
            [["Báo cáo lộ dữ liệu bệnh viện", "Hospital data breach"]],
            None,
            "en",
        ]
        ok.raise_for_status.return_value = None
        client = client_cls.return_value.__enter__.return_value
        client.post.side_effect = [captcha, ok]

        result = google_translate_title("Hospital data breach")
        self.assertEqual(result.text, "Báo cáo lộ dữ liệu bệnh viện")
        self.assertEqual(client.post.call_count, 2)
        self.assertEqual(
            client_cls.call_args_list[-1].kwargs.get("proxy"),
            "socks5h://tor:9150",
        )


class GoogleQualityGateTests(SimpleTestCase):
    def test_rule_title_with_proper_nouns_is_not_mangled(self):
        from apps.integrations.ai.translate import is_mangled_title_vi

        original = "Ransomware: Hillebrand Home Health (qilin)"
        vi = "Mã độc tống tiền: Hillebrand Home Health (qilin)"
        self.assertFalse(is_mangled_title_vi(vi, provider="rule", original=original))

    def test_untranslated_english_needs_ollama(self):
        from apps.integrations.ai.translate import google_draft_needs_ollama

        original = "Hospital network hit by sophisticated intrusion campaign"
        self.assertTrue(google_draft_needs_ollama(original, original))
        self.assertFalse(
            google_draft_needs_ollama(
                original, "Mạng bệnh viện bị chiến dịch xâm nhập tinh vi tấn công"
            )
        )

    def test_hugging_face_not_translated_as_om_mat(self):
        from apps.integrations.ai.translate import (
            google_draft_needs_ollama,
            is_mangled_title_vi,
            normalize_translated_title,
        )

        original = "OpenAI GPT Agents exploit Zero-Days and attack Hugging Face Servers"
        bad = "Các đại lý GPT của OpenAI khai thác Zero-Days và tấn công máy chủ ôm mặt"
        fixed = normalize_translated_title(original, bad)
        self.assertIn("Hugging Face", fixed)
        self.assertNotIn("ôm mặt", fixed.casefold())
        self.assertIn("máy chủ Hugging Face", fixed)
        # After restore, draft is usable — do not force Ollama just for this bug.
        self.assertFalse(google_draft_needs_ollama(original, bad))
        self.assertTrue(is_mangled_title_vi(bad, provider="google", original=original))

    def test_good_google_keeps_proper_nouns_without_ollama(self):
        from apps.integrations.ai.translate import google_draft_needs_ollama

        original = "Nova Ransomware Group Claims Digipro as New Victim"
        draft = "Nhóm Nova Ransomware tuyên bố Digipro là nạn nhân mới"
        self.assertFalse(google_draft_needs_ollama(original, draft))

    def test_cjk_title_detected(self):
        from apps.integrations.ai.translate import is_cjk_title, is_non_english_source

        self.assertTrue(is_cjk_title("OpenAI利用零日攻击入侵Hugging Face服务器"))
        self.assertTrue(is_non_english_source("OpenAI利用零日攻击入侵Hugging Face服务器"))
        self.assertTrue(is_non_english_source("Fuite de données hospitalière", "fr"))
        self.assertFalse(is_non_english_source("Hospital data breach", "en"))

    def test_ollama_beats_poor_google_for_cjk(self):
        from apps.integrations.ai.translate import ollama_beats_google

        original = "勒索软件团伙声称攻击了医院"
        google = "勒索软件团伙声称攻击了医院"  # still Chinese
        ollama = "Nhóm mã độc tống tiền tuyên bố tấn công bệnh viện"
        self.assertTrue(ollama_beats_google(original, google, ollama))

    def test_ollama_does_not_beat_good_english_google(self):
        from apps.integrations.ai.translate import ollama_beats_google

        original = "Hospital data breach reported in California"
        google = "Báo cáo sự cố lộ dữ liệu bệnh viện tại California"
        ollama = "Báo cáo sự cố lộ dữ liệu bệnh viện tại California hôm nay"
        self.assertFalse(ollama_beats_google(original, google, ollama))


@override_settings(
    TITLE_TRANSLATE_ENABLED=True,
    TITLE_TRANSLATE_AI_REFINE=False,
    TITLE_TRANSLATE_MYMEMORY_FALLBACK=False,
    TITLE_TRANSLATE_OLLAMA_FALLBACK=True,
    TITLE_TRANSLATE_GROQ=False,
    TITLE_TRANSLATE_PREFER_GROQ=False,
    OLLAMA_ENABLED=True,
    OLLAMA_BASE_URL="http://localhost:11434",
)
class OllamaRescueOnlyTests(TestCase):
    @patch("apps.integrations.ai.translate.ollama_translate_title")
    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        return_value="Bệnh viện gặp sự cố lộ dữ liệu nghiêm trọng",
    )
    def test_good_google_does_not_call_ollama(self, _google, ollama):
        from apps.integrations.ai.translate import reset_google_circuit

        reset_google_circuit()
        threat = Threat.objects.create(
            title="Hospital disclosed a serious data breach",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        ollama.assert_not_called()
        self.assertEqual(result["provider"], "google")
        self.assertEqual(threat.title_vi_provider, "google")

    @patch(
        "apps.integrations.ai.translate.ollama_translate_title",
        return_value="Mạng bệnh viện bị chiến dịch xâm nhập tinh vi tấn công",
    )
    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        return_value="Hospital network hit by sophisticated intrusion campaign",
    )
    def test_poor_google_triggers_ollama_retranslate(self, _google, ollama):
        from apps.integrations.ai.translate import reset_google_circuit

        reset_google_circuit()
        threat = Threat.objects.create(
            title="Hospital network hit by sophisticated intrusion campaign",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        ollama.assert_called_once()
        self.assertTrue(str(result["provider"]).startswith("ollama-fallback"))
        self.assertIn("bệnh viện", threat.title_vi.casefold())

    @patch("apps.integrations.ai.translate.ollama_translate_title")
    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        return_value="Cổng thông tin công bố sự cố dữ liệu tại Hà Nội",
    )
    def test_detected_vietnamese_source_skips_ollama(self, google, ollama):
        from apps.integrations.ai.translate import (
            GoogleTitleTranslation,
            reset_google_circuit,
        )

        reset_google_circuit()
        google.return_value = GoogleTitleTranslation(
            text="Cổng thông tin công bố sự cố dữ liệu tại Hà Nội",
            source_language="vi",
        )
        threat = Threat.objects.create(
            title="Cổng thông tin công bố sự cố dữ liệu tại Hà Nội",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        ollama.assert_not_called()
        self.assertIn(result["provider"], {"skip_vi", "google:detected_vi"})
        self.assertTrue(looks_vietnamese(threat.title_vi))


@override_settings(
    TITLE_TRANSLATE_ENABLED=True,
    TITLE_TRANSLATE_AI_REFINE=False,
    TITLE_TRANSLATE_MYMEMORY_FALLBACK=True,
    TITLE_TRANSLATE_OLLAMA_FALLBACK=True,
    TITLE_TRANSLATE_GROQ=False,
    TITLE_TRANSLATE_PREFER_GROQ=False,
    OLLAMA_ENABLED=True,
    OLLAMA_BASE_URL="http://localhost:11434",
    OLLAMA_TRANSLATE_MODEL="qwen2.5:3b",
)
class ProviderOrderTests(TestCase):
    @patch(
        "apps.integrations.ai.translate.mymemory_translate_title",
        return_value="Bản dịch MyMemory",
    )
    @patch(
        "apps.integrations.ai.translate.ollama_translate_title",
        return_value="Bệnh viện gặp sự cố lộ dữ liệu",
    )
    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        side_effect=TitleTranslateError("429"),
    )
    def test_ollama_preferred_over_mymemory_after_google(self, google, ollama, mymemory):
        from apps.integrations.ai.translate import reset_google_circuit

        reset_google_circuit()
        threat = Threat.objects.create(
            title="Hospital disclosed a data breach",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        google.assert_called_once()
        ollama.assert_called_once()
        mymemory.assert_not_called()
        self.assertEqual(result["status"], "ok")
        self.assertTrue(str(threat.title_vi_provider).startswith("ollama-fallback"))

    @override_settings(
        TOR_ENABLED=False,
        GOOGLE_TRANSLATE_TOR_FALLBACK=False,
    )
    @patch("apps.integrations.ai.translate.time.sleep")
    @patch(
        "apps.integrations.ai.translate.ollama_translate_title",
        return_value="Bệnh viện gặp sự cố lộ dữ liệu",
    )
    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        side_effect=TitleTranslateError("Google Translate rate limited (429)"),
    )
    def test_google_429_opens_circuit_for_batch(self, google, ollama, _sleep):
        from apps.integrations.ai.translate import (
            reset_google_circuit,
            translate_threats,
        )

        reset_google_circuit()
        Threat.objects.create(
            title="First hospital data breach report",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        Threat.objects.create(
            title="Second hospital data breach report",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        stats = translate_threats(limit=2)
        self.assertEqual(stats["ok"], 2)
        # First call trips the circuit; second title skips Google (no Tor in this test).
        self.assertEqual(google.call_count, 1)
        self.assertEqual(ollama.call_count, 2)


@override_settings(
    TITLE_TRANSLATE_ENABLED=True,
    TITLE_TRANSLATE_AI_REFINE=False,
    TITLE_TRANSLATE_MYMEMORY_FALLBACK=True,
    TITLE_TRANSLATE_OLLAMA_FALLBACK=False,
    TITLE_TRANSLATE_GROQ=False,
    TITLE_TRANSLATE_PREFER_GROQ=False,
    OLLAMA_ENABLED=False,
)
class MyMemoryFallbackTests(TestCase):
    @patch(
        "apps.integrations.ai.translate.mymemory_translate_title",
        return_value="Bệnh viện gặp sự cố lộ dữ liệu",
    )
    @patch(
        "apps.integrations.ai.translate.google_translate_title",
        side_effect=TitleTranslateError("429"),
    )
    def test_mymemory_used_when_google_and_ollama_unavailable(self, _google, mymemory):
        from apps.integrations.ai.translate import reset_google_circuit

        reset_google_circuit()
        threat = Threat.objects.create(
            title="Hospital disclosed a data breach",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        mymemory.assert_called_once()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(threat.title_vi_provider, "mymemory")
        self.assertIn("bệnh viện", threat.title_vi.casefold())


@override_settings(
    TITLE_TRANSLATE_ENABLED=True,
    TITLE_TRANSLATE_GROQ=True,
    TITLE_TRANSLATE_PREFER_GROQ=True,
    TITLE_TRANSLATE_INLINE_GOOGLE=False,
    TITLE_TRANSLATE_OLLAMA_FALLBACK=True,
    TITLE_TRANSLATE_MYMEMORY_FALLBACK=False,
    GROQ_API_KEY="test-key",
    GROQ_MODEL="llama-3.3-70b-versatile",
    OLLAMA_ENABLED=True,
    OLLAMA_BASE_URL="http://localhost:11434",
)
class GroqPreferTests(TestCase):
    @patch("apps.integrations.ai.translate.google_translate_title")
    @patch(
        "apps.integrations.ai.translate.groq_translate_title",
        return_value="Bệnh viện gặp sự cố lộ dữ liệu nghiêm trọng",
    )
    def test_groq_runs_before_google(self, mock_groq, mock_google):
        from apps.integrations.ai.translate import reset_google_circuit, reset_groq_circuit

        reset_google_circuit()
        reset_groq_circuit()
        threat = Threat.objects.create(
            title="Hospital disclosed a serious data breach",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        mock_groq.assert_called_once()
        mock_google.assert_not_called()
        self.assertTrue(str(result["provider"]).startswith("groq:"))
        self.assertIn("bệnh viện", threat.title_vi.casefold())

    @patch(
        "apps.integrations.ai.translate.ollama_translate_title",
        return_value="Bệnh viện gặp sự cố lộ dữ liệu",
    )
    @patch("apps.integrations.ai.translate.google_translate_title")
    @patch(
        "apps.integrations.ai.translate.groq_translate_title",
        side_effect=TitleTranslateError("Groq unavailable"),
    )
    def test_falls_back_to_google_when_groq_fails(
        self, _mock_groq, mock_google, _mock_ollama
    ):
        from apps.integrations.ai.translate import (
            reset_google_circuit,
            reset_groq_circuit,
        )

        reset_google_circuit()
        reset_groq_circuit()
        mock_google.return_value = "Bệnh viện gặp sự cố lộ dữ liệu"
        threat = Threat.objects.create(
            title="Hospital disclosed a data breach",
            source=Threat.Source.NEWS,
            published_at=timezone.now(),
            title_vi_status=Threat.TitleViStatus.PENDING,
        )
        result = translate_threat(threat)
        threat.refresh_from_db()
        mock_google.assert_called()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(threat.title_vi_provider, "google")
