from bs_multisignal_detector import (
    PageSnapshot,
    evaluate_snapshots,
    playwright_proxy_options,
)


def snapshot(**overrides):
    values = {
        "url": "https://lab.internal/login",
        "dom_length": 1000,
        "dom_hash": "dom-a",
        "text_hash": "text-a",
        "login_form_visible": True,
        "success_terms": frozenset(),
        "failure_terms": frozenset(),
        "auth_state": (),
    }
    values.update(overrides)
    return PageSnapshot(**values)


def test_url_change_succeeds_with_same_dom_length():
    result = evaluate_snapshots(
        snapshot(),
        snapshot(
            url="https://lab.internal/dashboard",
            dom_hash="dom-b",
            text_hash="text-b",
            login_form_visible=False,
        ),
        failed_dom_length=1000,
        dom_threshold=100,
    )
    assert result.success is True
    assert result.failed_dom_difference == 0


def test_auth_storage_change_succeeds_for_same_route_spa():
    result = evaluate_snapshots(
        snapshot(),
        snapshot(
            dom_hash="dom-b",
            text_hash="text-b",
            auth_state=(("local:auth-token", "digest"),),
        ),
        failed_dom_length=1000,
        dom_threshold=100,
    )
    assert result.success is True
    assert result.signals["auth_state_changed"] is True


def test_explicit_failure_with_visible_form_fails():
    result = evaluate_snapshots(
        snapshot(),
        snapshot(
            dom_hash="dom-b",
            text_hash="text-b",
            failure_terms=frozenset(("invalid credentials",)),
            dom_length=1250,
        ),
        failed_dom_length=1000,
        dom_threshold=100,
    )
    assert result.success is False
    assert result.signals["failure_text_added"] is True


def test_dom_length_difference_alone_does_not_claim_success():
    result = evaluate_snapshots(
        snapshot(),
        snapshot(dom_hash="dom-b", text_hash="text-b", dom_length=1500),
        failed_dom_length=1000,
        dom_threshold=100,
    )
    assert result.success is False
    assert result.signals["failed_dom_length_differs"] is True


def test_success_text_and_disappeared_form_succeed():
    result = evaluate_snapshots(
        snapshot(),
        snapshot(
            dom_hash="dom-b",
            text_hash="text-b",
            login_form_visible=False,
            success_terms=frozenset(("dashboard", "logout")),
        ),
        failed_dom_length=1000,
        dom_threshold=100,
    )
    assert result.success is True
    assert result.signals["login_form_disappeared"] is True


def test_proxy_options_keep_auth_out_of_server_url():
    assert playwright_proxy_options(
        "http://proxy-user:p%40ss@proxy.internal:8080"
    ) == {
        "server": "http://proxy.internal:8080",
        "username": "proxy-user",
        "password": "p@ss",
    }


def test_proxy_options_support_socks_and_reject_paths():
    assert playwright_proxy_options("socks5://127.0.0.1:1080") == {
        "server": "socks5://127.0.0.1:1080"
    }
    try:
        playwright_proxy_options("http://proxy.internal:8080/not-a-proxy-path")
    except ValueError as exc:
        assert "path" in str(exc)
    else:
        raise AssertionError("Proxy URLs with paths must be rejected")
