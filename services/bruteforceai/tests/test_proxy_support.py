import pytest

from main import _normalize_proxy_url


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        ("http://proxy.lab:8080", "http://proxy.lab:8080"),
        ("https://10.0.0.8:8443/", "https://10.0.0.8:8443"),
    ],
)
def test_normalize_proxy_url(value, expected):
    assert _normalize_proxy_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "socks5://proxy.lab:1080",
        "http://user:secret@proxy.lab:8080",
        "http://proxy.lab:8080/path",
        "http://proxy.lab:not-a-port",
    ],
)
def test_normalize_proxy_url_rejects_unsafe_or_unsupported_values(value):
    with pytest.raises(ValueError):
        _normalize_proxy_url(value)
