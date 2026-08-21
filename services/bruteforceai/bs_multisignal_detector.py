"""Multi-signal result helper for the isolated BruteForceAI lab service.

Only the upstream success decision calls this module. Browser launch, selectors,
retry, delay, persistence, and the analyze/attack workflow remain upstream.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import re
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit


SUCCESS_TERMS = (
    "dashboard", "welcome", "log out", "logout", "sign out",
    "my profile", "my account", "xin chào", "đăng xuất", "trang quản trị",
)
FAILURE_TERMS = (
    "invalid credentials", "incorrect password", "wrong password", "login failed",
    "authentication failed", "access denied", "invalid email or password",
    "không chính xác", "sai mật khẩu", "đăng nhập thất bại",
    "tài khoản hoặc mật khẩu không đúng", "thông tin đăng nhập không hợp lệ",
)
AUTH_NAME_HINTS = (
    "auth", "token", "session", "jwt", "access", "refresh", "supabase",
)


@dataclass(frozen=True)
class PageSnapshot:
    url: str
    dom_length: int
    dom_hash: str
    text_hash: str
    login_form_visible: bool
    success_terms: frozenset[str]
    failure_terms: frozenset[str]
    auth_state: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class DetectionResult:
    success: bool
    score: int
    signals: dict[str, bool]
    current_dom_length: int
    failed_dom_difference: int | None
    safe_before_url: str
    safe_after_url: str


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.casefold()).strip()


def _safe_url(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _meaningful_url(value: str) -> tuple[str, str, str]:
    parsed = urlsplit(value)
    return parsed.netloc.casefold(), parsed.path.rstrip("/") or "/", parsed.query


def _is_visible(page: Any, selector: str | None) -> bool:
    if not selector:
        return False
    try:
        locator = page.locator(selector)
        return any(locator.nth(index).is_visible() for index in range(min(locator.count(), 5)))
    except Exception:
        return False


def _storage_items(page: Any) -> dict[str, str]:
    try:
        result = page.evaluate(
            """
            () => {
              const readStorage = (storage) => {
                const values = {};
                try {
                  for (let index = 0; index < storage.length; index += 1) {
                    const key = storage.key(index);
                    if (key !== null) values[key] = storage.getItem(key) || "";
                  }
                } catch (_) {}
                return values;
              };
              return {
                local: readStorage(window.localStorage),
                session: readStorage(window.sessionStorage),
              };
            }
            """
        )
    except Exception:
        return {}

    values: dict[str, str] = {}
    if isinstance(result, dict):
        for storage_name in ("local", "session"):
            storage = result.get(storage_name)
            if not isinstance(storage, dict):
                continue
            for key, value in storage.items():
                key_text = str(key)
                if any(hint in key_text.casefold() for hint in AUTH_NAME_HINTS):
                    values[f"{storage_name}:{key_text}"] = _digest(str(value))
    return values


def _cookie_items(page: Any) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        cookies = page.context.cookies()
    except Exception:
        return values
    for cookie in cookies:
        name = str(cookie.get("name") or "")
        if any(hint in name.casefold() for hint in AUTH_NAME_HINTS):
            identity = f"cookie:{cookie.get('domain', '')}:{cookie.get('path', '')}:{name}"
            values[identity] = _digest(str(cookie.get("value") or ""))
    return values


def capture_page_snapshot(
    page: Any,
    username_selector: str | None,
    password_selector: str | None,
) -> PageSnapshot:
    html = page.content()
    try:
        visible_text = page.locator("body").inner_text(timeout=3000)
    except Exception:
        visible_text = ""
    normalized_text = _normalize_text(visible_text)
    auth_state = {**_cookie_items(page), **_storage_items(page)}
    return PageSnapshot(
        url=page.url,
        dom_length=len(html),
        dom_hash=_digest(html),
        text_hash=_digest(normalized_text),
        login_form_visible=(
            _is_visible(page, username_selector) or _is_visible(page, password_selector)
        ),
        success_terms=frozenset(term for term in SUCCESS_TERMS if term in normalized_text),
        failure_terms=frozenset(term for term in FAILURE_TERMS if term in normalized_text),
        auth_state=tuple(sorted(auth_state.items())),
    )


def evaluate_snapshots(
    before: PageSnapshot,
    after: PageSnapshot,
    failed_dom_length: int | str | None,
    dom_threshold: int,
) -> DetectionResult:
    try:
        baseline_length = int(failed_dom_length) if failed_dom_length else None
    except (TypeError, ValueError):
        baseline_length = None

    failed_difference = (
        abs(after.dom_length - baseline_length) if baseline_length is not None else None
    )
    signals = {
        "url_changed": _meaningful_url(before.url) != _meaningful_url(after.url),
        "login_form_disappeared": before.login_form_visible and not after.login_form_visible,
        "auth_state_changed": bool(after.auth_state) and before.auth_state != after.auth_state,
        "success_text_added": bool(after.success_terms - before.success_terms),
        "failure_text_added": bool(after.failure_terms - before.failure_terms),
        "dom_hash_changed": before.dom_hash != after.dom_hash,
        "visible_text_changed": before.text_hash != after.text_hash,
        "failed_dom_length_differs": (
            failed_difference is not None and failed_difference >= max(1, dom_threshold)
        ),
        "login_form_still_visible": after.login_form_visible,
    }

    score = 0
    score += 4 if signals["url_changed"] else 0
    score += 4 if signals["login_form_disappeared"] else 0
    score += 4 if signals["auth_state_changed"] else 0
    score += 3 if signals["success_text_added"] else 0
    score += 1 if signals["dom_hash_changed"] else 0
    score += 1 if signals["visible_text_changed"] else 0
    score += 1 if signals["failed_dom_length_differs"] else 0
    score -= 6 if signals["failure_text_added"] else 0
    score -= 2 if signals["login_form_still_visible"] else 0

    strong_success = any(
        signals[name]
        for name in ("url_changed", "login_form_disappeared", "auth_state_changed")
    )
    if signals["failure_text_added"] and not strong_success:
        success = False
    elif strong_success:
        success = score >= 3
    else:
        success = (
            signals["success_text_added"]
            and signals["visible_text_changed"]
            and not signals["login_form_still_visible"]
            and score >= 3
        )

    return DetectionResult(
        success=success,
        score=score,
        signals=signals,
        current_dom_length=after.dom_length,
        failed_dom_difference=failed_difference,
        safe_before_url=_safe_url(before.url),
        safe_after_url=_safe_url(after.url),
    )


def wait_for_spa_result(
    page: Any,
    before: PageSnapshot,
    username_selector: str | None,
    password_selector: str | None,
    failed_dom_length: int | str | None,
    dom_threshold: int,
) -> DetectionResult:
    try:
        page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:
        pass

    settle_seconds = max(
        2.0,
        min(float(os.getenv("BRUTEFORCEAI_SPA_SETTLE_SECONDS", "8")), 30.0),
    )
    deadline = time.monotonic() + settle_seconds
    last_snapshot = capture_page_snapshot(page, username_selector, password_selector)
    result = evaluate_snapshots(before, last_snapshot, failed_dom_length, dom_threshold)

    while time.monotonic() < deadline:
        if result.success or result.signals["failure_text_added"]:
            page.wait_for_timeout(750)
            last_snapshot = capture_page_snapshot(page, username_selector, password_selector)
            result = evaluate_snapshots(before, last_snapshot, failed_dom_length, dom_threshold)
            break
        page.wait_for_timeout(500)
        last_snapshot = capture_page_snapshot(page, username_selector, password_selector)
        result = evaluate_snapshots(before, last_snapshot, failed_dom_length, dom_threshold)
    return result
