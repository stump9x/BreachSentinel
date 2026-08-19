from __future__ import annotations

from django.test import SimpleTestCase, override_settings

from apps.core.security import (
    UnsafeURLError,
    is_onion_hostname,
    validate_fetch_http_url,
    validate_onion_http_url,
    validate_public_http_url,
)


class OnionUrlValidationTests(SimpleTestCase):
    def test_detects_onion_hostname(self):
        self.assertTrue(
            is_onion_hostname(
                "dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion"
            )
        )
        self.assertFalse(is_onion_hostname("example.com"))

    def test_validate_onion_accepts_v3_http(self):
        url = (
            "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/"
        )
        self.assertEqual(validate_onion_http_url(url), url)

    def test_validate_onion_rejects_clearnet_and_userinfo(self):
        with self.assertRaises(UnsafeURLError):
            validate_onion_http_url("https://example.com/feed")
        with self.assertRaises(UnsafeURLError):
            validate_onion_http_url(
                "http://user:pass@dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/"
            )

    def test_public_validator_rejects_onion(self):
        with self.assertRaises(UnsafeURLError):
            validate_public_http_url(
                "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/"
            )

    @override_settings(TOR_ENABLED=True, TOR_SOCKS_PROXY="socks5h://tor:9050")
    def test_fetch_validator_routes_onion_when_tor_enabled(self):
        url = (
            "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/rss"
        )
        self.assertEqual(validate_fetch_http_url(url, via_tor=True), url)

    @override_settings(TOR_ENABLED=False)
    def test_fetch_validator_blocks_onion_when_tor_disabled(self):
        with self.assertRaises(UnsafeURLError):
            validate_fetch_http_url(
                "http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/",
                via_tor=True,
            )
