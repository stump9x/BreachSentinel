"""Lab-only HTTP wrapper around MorDavid/BruteForceAI.

The upstream project is intentionally kept behind a fail-closed boundary:
targets must be explicitly allowlisted as lab hosts, jobs are single-threaded,
attempts are capped, and passwords never leave this service in responses/logs.
"""

from __future__ import annotations

import asyncio
from contextlib import contextmanager
import ipaddress
import logging
import os
import secrets
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("bruteforceai-wrapper")

REPO = Path(os.getenv("BRUTEFORCEAI_REPO", "/opt/BruteForceAI"))
PATCHED_RUNNER = Path(os.getenv("BRUTEFORCEAI_RUNNER", "/app/patched_runner.py"))
DATA_DIR = Path(os.getenv("BRUTEFORCEAI_DATA_DIR", "/data"))
DATABASE = DATA_DIR / "bruteforce.db"
INTERNAL_TOKEN = os.getenv("BRUTEFORCEAI_INTERNAL_TOKEN", "").strip()
ALLOWED_HOSTS = {
    item.strip().casefold().rstrip(".")
    for item in os.getenv("BRUTEFORCEAI_ALLOWED_HOSTS", "").split(",")
    if item.strip()
}
ALLOW_PUBLIC_TARGETS = os.getenv("BRUTEFORCEAI_ALLOW_PUBLIC_TARGETS", "false").lower() in {
    "1",
    "true",
    "yes",
}
MAX_CREDENTIALS = max(1, min(int(os.getenv("BRUTEFORCEAI_MAX_CREDENTIALS", "20")), 25))
MIN_DELAY_SECONDS = max(2.0, float(os.getenv("BRUTEFORCEAI_MIN_DELAY_SECONDS", "2")))
JOB_TIMEOUT_SECONDS = max(30, min(int(os.getenv("BRUTEFORCEAI_JOB_TIMEOUT_SECONDS", "900")), 1800))
LLM_API_KEY = (
    os.getenv("BRUTEFORCEAI_LLM_API_KEY", "").strip()
    or os.getenv("GROQ_API_KEY", "").strip()
)
LLM_PROVIDER = (
    os.getenv("BRUTEFORCEAI_LLM_PROVIDER", "").strip().lower()
    or os.getenv("LLM_PROVIDER", "").strip().lower()
    or ("groq" if LLM_API_KEY else "")
)
LLM_MODEL = (
    os.getenv("BRUTEFORCEAI_LLM_MODEL", "").strip()
    or os.getenv("GROQ_MODEL", "").strip()
)
OLLAMA_URL = os.getenv("BRUTEFORCEAI_OLLAMA_URL", os.getenv("OLLAMA_URL", "")).strip()
ANALYZE_TIMEOUT_SECONDS = max(60, min(int(os.getenv("BRUTEFORCEAI_ANALYZE_TIMEOUT_SECONDS", "600")), 1800))
SHOW_BROWSER = os.getenv("BRUTEFORCEAI_BROWSER_MODE", "headless").strip().lower() in {
    "headed",
    "visible",
}
AUTO_SELECTOR_FALLBACK = os.getenv("BRUTEFORCEAI_AUTO_SELECTOR_FALLBACK", "true").lower() in {
    "1",
    "true",
    "yes",
}
RUN_LOCK = asyncio.Semaphore(1)

app = FastAPI(title="BreachSentinel BruteForceAI Lab Service", version="1.0.0")


class Credential(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("username", "password")
    @classmethod
    def no_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("NUL bytes are not allowed")
        return value


class ScanRequest(BaseModel):
    target_url: str = Field(min_length=8, max_length=2048)
    credentials: list[Credential] = Field(min_length=1, max_length=25)
    # Backend-managed entries are sent per job so the UI can extend the
    # allowlist without changing the container environment or rebuilding it.
    allowed_hosts: list[str] = Field(default_factory=list, max_length=100)


def _is_lab_host(host: str) -> bool:
    if host in {"localhost", "host.docker.internal"}:
        return True
    if host.endswith((".test", ".localhost", ".local", ".internal")):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    )


def _validate_target(raw_url: str, request_allowed_hosts: list[str] | None = None) -> str:
    parsed = urlsplit(raw_url.strip())
    host = (parsed.hostname or "").casefold().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not host:
        raise HTTPException(status_code=400, detail="target_url must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.fragment:
        raise HTTPException(status_code=400, detail="target_url may not contain credentials or fragments")
    dynamic_hosts = {
        str(item).strip().casefold().rstrip(".")
        for item in (request_allowed_hosts or [])
        if str(item).strip()
    }
    if host not in ALLOWED_HOSTS | dynamic_hosts:
        raise HTTPException(status_code=403, detail="Target host is not in the lab allowlist")
    if not ALLOW_PUBLIC_TARGETS and not _is_lab_host(host):
        raise HTTPException(status_code=403, detail="Public targets are disabled; use a lab host")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _require_internal_token(value: str | None) -> None:
    if not INTERNAL_TOKEN or not value or not secrets.compare_digest(value, INTERNAL_TOKEN):
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Lab service is not configured")


def _redact_database() -> None:
    if not DATABASE.exists():
        return
    try:
        with sqlite3.connect(DATABASE) as connection:
            connection.execute("UPDATE brute_force_attempts SET password='[redacted]'")
            connection.commit()
    except sqlite3.Error:
        logger.exception("Could not redact upstream SQLite attempt records")


def _latest_attempt_id(target_url: str, username: str) -> int:
    if not DATABASE.exists():
        return 0
    try:
        with sqlite3.connect(DATABASE) as connection:
            row = connection.execute(
                """
                SELECT id
                FROM brute_force_attempts
                WHERE url=? AND username_or_email=?
                ORDER BY id DESC LIMIT 1
                """,
                (target_url, username),
            ).fetchone()
    except sqlite3.Error:
        return 0
    return int(row[0]) if row else 0


def _read_latest_result(target_url: str, username: str, after_id: int = 0) -> dict | None:
    if not DATABASE.exists():
        return None
    try:
        with sqlite3.connect(DATABASE) as connection:
            row = connection.execute(
                """
                SELECT success, response_time_ms, timestamp
                FROM brute_force_attempts
                WHERE url=? AND username_or_email=? AND id>?
                ORDER BY id DESC LIMIT 1
                """,
                (target_url, username, after_id),
            ).fetchone()
    except sqlite3.Error:
        return None
    if not row:
        return None
    return {
        "username": username,
        "success": bool(row[0]),
        "response_time_ms": row[1],
        "timestamp": row[2],
    }


def _read_analysis(target_url: str) -> dict | None:
    """Return selectors only after the upstream analyze step succeeds."""
    if not DATABASE.exists():
        return None
    try:
        with sqlite3.connect(DATABASE) as connection:
            row = connection.execute(
                """
                SELECT success, login_username_selector, login_password_selector,
                       login_submit_button_selector, failed_dom_length
                FROM form_analysis
                WHERE url=? AND success=1
                ORDER BY id DESC LIMIT 1
                """,
                (target_url,),
            ).fetchone()
    except sqlite3.Error:
        return None
    if not row or not all(row[index] for index in (1, 2, 3)):
        return None
    return {
        "success": bool(row[0]),
        "has_selectors": True,
        "has_failed_dom_baseline": bool(row[4]),
    }


def _safe_output(output: str, request: ScanRequest) -> str:
    safe = output or ""
    for credential in request.credentials:
        if credential.password:
            safe = safe.replace(credential.password, "[redacted]")
    if LLM_API_KEY:
        safe = safe.replace(LLM_API_KEY, "[redacted]")
    return safe[-4000:]


def _run_command(command: list[str]) -> list[str]:
    """Run Chromium-backed upstream commands in a virtual display when headed."""
    if SHOW_BROWSER:
        return [
            "xvfb-run",
            "--auto-servernum",
            "--server-args=-screen 0 1440x900x24",
            *command,
        ]
    return command


@contextmanager
def _virtual_display():
    """Provide a virtual X display for direct headed Playwright fallback runs."""
    if not SHOW_BROWSER:
        yield
        return
    previous_display = os.environ.get("DISPLAY")
    display = f":{100 + (os.getpid() % 100)}"
    server = subprocess.Popen(
        ["Xvfb", display, "-screen", "0", "1440x900x24", "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.environ["DISPLAY"] = display
    try:
        time.sleep(0.2)
        yield
    finally:
        if previous_display is None:
            os.environ.pop("DISPLAY", None)
        else:
            os.environ["DISPLAY"] = previous_display
        server.terminate()
        try:
            server.wait(timeout=2)
        except subprocess.TimeoutExpired:
            server.kill()


def _first_visible_selector(page, candidates: list[str]) -> str | None:
    for selector in candidates:
        try:
            locator = page.locator(selector)
            for index in range(min(locator.count(), 3)):
                candidate = locator.nth(index)
                if candidate.is_visible() and candidate.is_enabled():
                    return selector
        except Exception:
            continue
    return None


def _fallback_browser_analysis(target_url: str) -> dict | None:
    """Create the same selector/baseline record as stage1 for common forms.

    This is deliberately a fallback for when the configured LLM is unavailable;
    the normal BruteForceAI analyze path still runs first.
    """
    username_candidates = [
        'input[type="email"]',
        'input[name*="email" i]',
        'input[id*="email" i]',
        'input[name*="user" i]',
        'input[id*="user" i]',
        'input[autocomplete="username"]',
        'input[type="text"]',
    ]
    password_candidates = [
        'input[type="password"]',
        'input[autocomplete="current-password"]',
    ]
    submit_candidates = [
        'button[type="submit"]',
        'input[type="submit"]',
        'button[name*="login" i]',
        'button[id*="login" i]',
        'button:has-text("Login")',
        'button:has-text("Sign in")',
        'form button',
    ]
    browser = None
    try:
        with _virtual_display():
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=not SHOW_BROWSER)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.goto(target_url, wait_until="domcontentloaded", timeout=30000)
                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except PlaywrightTimeoutError:
                    pass

                clean_dom_length = len(page.content())
                username_selector = _first_visible_selector(page, username_candidates)
                password_selector = _first_visible_selector(page, password_candidates)
                submit_selector = _first_visible_selector(page, submit_candidates)
                if not username_selector or not password_selector or not submit_selector:
                    logger.warning(
                        "Browser selector fallback incomplete for %s: username=%s password=%s submit=%s",
                        target_url,
                        bool(username_selector),
                        bool(password_selector),
                        bool(submit_selector),
                    )
                    return None

                # Match upstream stage1: one invalid probe establishes the failed DOM baseline.
                probe_username = "bs-probe-" + secrets.token_hex(8) + "@invalid.test"
                probe_password = secrets.token_urlsafe(18)
                page.locator(username_selector).first.fill(probe_username)
                page.locator(password_selector).first.fill(probe_password)
                page.locator(submit_selector).first.click()
                try:
                    page.wait_for_load_state("networkidle", timeout=5000)
                except PlaywrightTimeoutError:
                    time.sleep(2)
                failed_dom_length = len(page.content())

                with sqlite3.connect(DATABASE) as connection:
                    connection.execute("DELETE FROM form_analysis WHERE url=?", (target_url,))
                    connection.execute(
                        """
                        INSERT INTO form_analysis
                        (url, login_username_selector, login_password_selector,
                         login_submit_button_selector, dom_length, failed_dom_length,
                         dom_change, test_username_used, success, attempts,
                         playwright_or_requests)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 'playwright')
                        """,
                        (
                            target_url,
                            username_selector,
                            password_selector,
                            submit_selector,
                            str(clean_dom_length),
                            str(failed_dom_length),
                            failed_dom_length - clean_dom_length,
                            probe_username,
                        ),
                    )
                    connection.commit()
                return {
                    "success": True,
                    "has_selectors": True,
                    "has_failed_dom_baseline": True,
                    "source": "browser_fallback",
                }
    except Exception as exc:
        logger.warning("Browser selector fallback failed for %s: %s", target_url, type(exc).__name__)
        return None
    finally:
        if browser:
            try:
                browser.close()
            except Exception:
                pass


def _run_scan(request: ScanRequest, target_url: str) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    command_path = PATCHED_RUNNER if PATCHED_RUNNER.is_file() else REPO / "BruteForceAI.py"
    if not command_path.is_file():
        return {"status": "failed", "error": "BruteForceAI source is unavailable", "results": []}

    with tempfile.TemporaryDirectory(prefix="bs-bfai-") as temp_dir:
        root = Path(temp_dir)
        urls = root / "urls.txt"
        usernames = root / "usernames.txt"
        passwords = root / "passwords.txt"
        urls.write_text(target_url + "\n", encoding="utf-8")

        analysis = _read_analysis(target_url)
        if not analysis:
            analyzed = None
            if LLM_PROVIDER:
                analyze_command = [
                    "python",
                    str(command_path),
                    "analyze",
                    "--urls",
                    str(urls),
                    "--selector-retry",
                    "3",
                    "--force-reanalyze",
                    "--no-color",
                    "--skip-version-check",
                    "--database",
                    str(DATABASE),
                    "--llm-provider",
                    LLM_PROVIDER,
                ]
                if LLM_MODEL:
                    analyze_command.extend(["--llm-model", LLM_MODEL])
                if LLM_API_KEY:
                    analyze_command.extend(["--llm-api-key", LLM_API_KEY])
                if OLLAMA_URL:
                    analyze_command.extend(["--ollama-url", OLLAMA_URL])
                try:
                    analyzed = subprocess.run(
                        _run_command(analyze_command),
                        cwd=REPO,
                        env={**os.environ, "PYTHONUNBUFFERED": "1"},
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=ANALYZE_TIMEOUT_SECONDS,
                        check=False,
                    )
                except subprocess.TimeoutExpired:
                    analyzed = None
                analysis = _read_analysis(target_url)

            fallback_used = False
            if not analysis and AUTO_SELECTOR_FALLBACK:
                analysis = _fallback_browser_analysis(target_url)
                fallback_used = bool(analysis)
            if not analysis:
                diagnostics = _safe_output(analyzed.stdout if analyzed else "", request)
                if analyzed:
                    logger.warning(
                        "BruteForceAI stage1 failed (exit=%s): %s",
                        analyzed.returncode,
                        diagnostics,
                    )
                reason_code = "stage1_timeout" if LLM_PROVIDER and analyzed is None else (
                    "llm_not_configured" if not LLM_PROVIDER else "stage1_failed"
                )
                error = (
                    "BruteForceAI stage1 timed out; no login attempt was made."
                    if reason_code == "stage1_timeout"
                    else "BruteForceAI could not analyze the login form; no login attempt was made."
                )
                return {
                    "status": "not_attempted",
                    "reason_code": reason_code,
                    "error": error,
                    "diagnostics": diagnostics,
                    "attempt_count": 0,
                    "success_count": 0,
                    "results": [],
                }
            if fallback_used:
                logger.info("Using browser selector fallback for %s", target_url)

        for credential in request.credentials:
            # One pair per subprocess preserves the Log Scanner credential pair
            # and avoids turning this lab check into an uncontrolled cross-product.
            usernames.write_text(credential.username + "\n", encoding="utf-8")
            passwords.write_text(credential.password + "\n", encoding="utf-8")
            previous_attempt_id = _latest_attempt_id(target_url, credential.username)
            command = [
                "python",
                str(command_path),
                "attack",
                "--urls",
                str(urls),
                "--usernames",
                str(usernames),
                "--passwords",
                str(passwords),
                "--threads",
                "1",
                "--retry-attempts",
                "1",
                "--delay",
                str(MIN_DELAY_SECONDS),
                "--jitter",
                "0",
                "--success-exit",
                "--force-retry",
                "--no-color",
                "--skip-version-check",
                "--database",
                str(DATABASE),
            ]
            try:
                completed = subprocess.run(
                    _run_command(command),
                    cwd=REPO,
                    env={**os.environ, "PYTHONUNBUFFERED": "1"},
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=JOB_TIMEOUT_SECONDS,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                _redact_database()
                return {
                    "status": "failed",
                    "reason_code": "attack_timeout",
                    "error": "BruteForceAI login attempt timed out.",
                    "attempt_count": len(results),
                    "success_count": sum(1 for item in results if item["success"]),
                    "results": results,
                }
            result = _read_latest_result(target_url, credential.username, previous_attempt_id)
            if result is None:
                diagnostics = _safe_output(completed.stdout, request)
                logger.warning(
                    "BruteForceAI attack produced no attempt (exit=%s): %s",
                    completed.returncode,
                    diagnostics,
                )
                _redact_database()
                return {
                    "status": "failed",
                    "reason_code": "attack_no_attempt",
                    "error": "BruteForceAI did not record a login attempt.",
                    "diagnostics": diagnostics,
                    "attempt_count": len(results),
                    "success_count": sum(1 for item in results if item["success"]),
                    "results": results,
                }
            results.append(result)
            _redact_database()
            if result["success"]:
                break
            if completed.returncode not in {0, 1}:
                logger.warning(
                    "BruteForceAI exited with code %s: %s",
                    completed.returncode,
                    _safe_output(completed.stdout, request),
                )

    return {
        "status": "completed",
        "attempt_count": len(results),
        "success_count": sum(1 for item in results if item["success"]),
        "analysis": analysis,
        "results": results,
    }


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "bruteforceai",
        "configured": bool(INTERNAL_TOKEN and ALLOWED_HOSTS),
        "lab_only": True,
    }


@app.post("/scan")
async def scan(request: ScanRequest, x_bruteforceai_token: str | None = Header(default=None)) -> dict:
    _require_internal_token(x_bruteforceai_token)
    target_url = _validate_target(request.target_url, request.allowed_hosts)
    if len(request.credentials) > MAX_CREDENTIALS:
        raise HTTPException(status_code=400, detail=f"At most {MAX_CREDENTIALS} credentials per job")
    async with RUN_LOCK:
        return await asyncio.to_thread(_run_scan, request, target_url)
