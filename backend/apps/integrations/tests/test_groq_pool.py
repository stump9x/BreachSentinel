"""Unit tests for Groq multi-key pool parsing / rotation helpers."""

from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, override_settings

from apps.integrations.ai.groq_pool import (
    GroqUnavailable,
    clear_groq_key_cooldowns,
    groq_api_keys,
    groq_chat_completion,
    mark_groq_key_cooldown,
    parse_groq_api_keys,
    ready_groq_key_count,
)


class GroqPoolParseTests(SimpleTestCase):
    def test_parse_comma_and_newline_keys(self):
        keys = parse_groq_api_keys("k1", "k2, k3\nk4;k2")
        self.assertEqual(keys, ["k1", "k2", "k3", "k4"])

    @override_settings(GROQ_API_KEY="primary", GROQ_API_KEYS="a,b,c")
    def test_settings_pool(self):
        clear_groq_key_cooldowns()
        self.assertEqual(groq_api_keys(), ["primary", "a", "b", "c"])

    @override_settings(GROQ_POOL_NAMESPACE="breachsentinel")
    def test_cooldown_namespace_is_project_scoped(self):
        from apps.integrations.ai.groq_pool import _cooldown_cache_key, _fingerprint

        fp = _fingerprint("abc")
        self.assertTrue(_cooldown_cache_key(fp).startswith("groq_pool:breachsentinel:"))

    @override_settings(
        GROQ_API_KEY="k1",
        GROQ_API_KEYS="k2,k3",
        GROQ_MIN_INTERVAL_SEC=0,
        GROQ_STOP_ON_FIRST_429=True,
        GROQ_MAX_KEY_ATTEMPTS=6,
        GROQ_KEY_COOLDOWN_SEC=60,
        GROQ_CIRCUIT_TTL_SEC=60,
        GROQ_POOL_NAMESPACE="breachsentinel",
    )
    def test_stop_on_first_429_does_not_cascade_burn(self):
        clear_groq_key_cooldowns()
        response = MagicMock()
        response.status_code = 429
        response.content = b'{"error":{"message":"rate limit"}}'
        response.json.return_value = {"error": {"message": "rate limit"}}
        response.headers = {"retry-after": "30"}

        with patch("apps.integrations.ai.groq_pool.httpx.Client") as client_cls:
            client = client_cls.return_value.__enter__.return_value
            client.post.return_value = response
            with self.assertRaises(GroqUnavailable):
                groq_chat_completion(
                    messages=[{"role": "user", "content": "hi"}],
                    max_tokens=10,
                )
            # Cascade stopped: only one HTTP attempt, not 3/6.
            self.assertEqual(client.post.call_count, 1)
        self.assertEqual(ready_groq_key_count(), 2)

    @override_settings(
        GROQ_API_KEY="only",
        GROQ_API_KEYS="",
        GROQ_MIN_INTERVAL_SEC=0,
        GROQ_POOL_NAMESPACE="breachsentinel",
        GROQ_CIRCUIT_TTL_SEC=60,
    )
    def test_never_retries_cooling_keys(self):
        clear_groq_key_cooldowns()
        mark_groq_key_cooldown("only", seconds=120)
        self.assertEqual(ready_groq_key_count(), 0)
        with self.assertRaises(GroqUnavailable):
            groq_chat_completion(messages=[{"role": "user", "content": "hi"}])
