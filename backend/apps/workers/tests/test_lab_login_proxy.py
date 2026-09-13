from django.test import SimpleTestCase

from apps.workers.lab_login_verifier import lab_proxy_display, normalize_lab_proxy


class LabLoginProxyTests(SimpleTestCase):
    def test_normalizes_proxy_and_separate_credentials(self):
        value = normalize_lab_proxy(
            "proxy.internal:8080",
            username="proxy user",
            password="p@ss/word",
        )

        self.assertEqual(
            value,
            "http://proxy%20user:p%40ss%2Fword@proxy.internal:8080",
        )
        self.assertEqual(lab_proxy_display(value), "http://proxy.internal:8080")

    def test_accepts_anonymous_socks_proxy(self):
        self.assertEqual(
            normalize_lab_proxy("socks5://127.0.0.1:1080"),
            "socks5://127.0.0.1:1080",
        )

    def test_rejects_invalid_proxy_shape(self):
        invalid_values = (
            "ftp://proxy.internal:21",
            "http://proxy.internal",
            "http://proxy.internal:8080/path",
        )
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_lab_proxy(value)

    def test_requires_server_when_credentials_are_set(self):
        with self.assertRaisesMessage(
            ValueError,
            "Enter a proxy server before proxy credentials.",
        ):
            normalize_lab_proxy("", username="proxy-user")
