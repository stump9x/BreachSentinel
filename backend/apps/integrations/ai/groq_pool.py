"""Groq API key pool — rotate carefully on rate limits. Never log raw keys.

Cooldown is namespaced per project (GROQ_POOL_NAMESPACE) so BreachSentinel and
NewsCrawler never share cooldown state even on the same VPS.

Anti-429 design:
- Never hammer cooling keys (old bug: fall back to all keys when all cooling).
- Global min-interval between ANY Groq HTTP calls (cross-process via Redis).
- Cap key attempts; honour Retry-After; stop cascading through the whole pool.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Any

import httpx
from django.conf import settings

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()
_RR_INDEX = 0
# fingerprint -> cooldown-until unix time (process-local fallback)
_COOLDOWN_UNTIL: dict[str, float] = {}
_LAST_CALL_MONO = 0.0


class GroqUnavailable(RuntimeError):
    """Pool exhausted / all keys cooling / circuit open — callers should fall back."""


def _namespace() -> str:
    return (getattr(settings, "GROQ_POOL_NAMESPACE", "") or "breachsentinel").strip()


def _fingerprint(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _cooldown_cache_key(fp: str) -> str:
    return f"groq_pool:{_namespace()}:cooldown:{fp}"


def _pace_cache_key() -> str:
    return f"groq_pool:{_namespace()}:last_call"


def _pool_circuit_cache_key() -> str:
    return f"groq_pool:{_namespace()}:pool_circuit"


def parse_groq_api_keys(
    primary: str = "",
    multi: str = "",
) -> list[str]:
    """Parse GROQ_API_KEY + GROQ_API_KEYS (comma / newline / semicolon)."""
    chunks: list[str] = []
    if primary and str(primary).strip():
        chunks.append(str(primary).strip())
    raw = str(multi or "")
    for part in raw.replace(";", ",").replace("\n", ",").split(","):
        token = part.strip()
        if token:
            chunks.append(token)
    seen: set[str] = set()
    out: list[str] = []
    for key in chunks:
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def groq_api_keys() -> list[str]:
    return parse_groq_api_keys(
        getattr(settings, "GROQ_API_KEY", "") or "",
        getattr(settings, "GROQ_API_KEYS", "") or "",
    )


def groq_keys_configured() -> bool:
    return bool(groq_api_keys())


def mark_groq_key_cooldown(key: str, *, seconds: float | None = None) -> None:
    """Temporarily skip a key after 429 / quota errors (namespaced per project)."""
    ttl = seconds
    if ttl is None:
        ttl = float(getattr(settings, "GROQ_KEY_COOLDOWN_SEC", 120) or 120)
    ttl = max(15.0, float(ttl))
    fp = _fingerprint(key)
    until = time.time() + ttl
    with _LOCK:
        _COOLDOWN_UNTIL[fp] = until
    try:
        from django.core.cache import cache

        cache.set(_cooldown_cache_key(fp), until, timeout=int(ttl) + 5)
    except Exception:  # noqa: BLE001
        logger.debug("groq cooldown cache unavailable", exc_info=True)
    logger.info(
        "groq key cooldown %ss (ns=%s fp=%s)", int(ttl), _namespace(), fp
    )


def clear_groq_key_cooldowns() -> None:
    with _LOCK:
        fps = list(_COOLDOWN_UNTIL.keys())
        _COOLDOWN_UNTIL.clear()
    try:
        from django.core.cache import cache

        for fp in fps:
            cache.delete(_cooldown_cache_key(fp))
        cache.delete(_pool_circuit_cache_key())
    except Exception:  # noqa: BLE001
        return


def trip_groq_pool_circuit(*, seconds: float | None = None, reason: str = "") -> None:
    """Skip Groq entirely for a while after the pool is burned."""
    ttl = float(
        seconds
        if seconds is not None
        else (getattr(settings, "GROQ_CIRCUIT_TTL_SEC", 180) or 180)
    )
    ttl = max(30.0, ttl)
    try:
        from django.core.cache import cache

        cache.set(_pool_circuit_cache_key(), True, timeout=int(ttl))
    except Exception:  # noqa: BLE001
        pass
    logger.warning(
        "groq pool circuit open %.0fs ns=%s%s",
        ttl,
        _namespace(),
        f" ({reason})" if reason else "",
    )


def is_groq_pool_circuit_open() -> bool:
    try:
        from django.core.cache import cache

        return bool(cache.get(_pool_circuit_cache_key()))
    except Exception:  # noqa: BLE001
        return False


def _key_cooling(fp: str, now: float) -> bool:
    with _LOCK:
        local_until = _COOLDOWN_UNTIL.get(fp, 0.0)
    if local_until > now:
        return True
    try:
        from django.core.cache import cache

        cached = cache.get(_cooldown_cache_key(fp))
        if cached and float(cached) > now:
            with _LOCK:
                _COOLDOWN_UNTIL[fp] = float(cached)
            return True
    except Exception:  # noqa: BLE001
        return False
    return False


def _available_keys(now: float | None = None) -> list[str]:
    """Keys that are NOT cooling. Empty when the whole pool needs rest."""
    now = time.time() if now is None else now
    keys = groq_api_keys()
    return [key for key in keys if not _key_cooling(_fingerprint(key), now)]


def ready_groq_key_count() -> int:
    return len(_available_keys())


def acquire_groq_api_key() -> str | None:
    """Round-robin among keys not in cooldown. None if all cooling."""
    global _RR_INDEX
    ready = _available_keys()
    if not ready:
        return None
    with _LOCK:
        idx = _RR_INDEX % len(ready)
        _RR_INDEX += 1
        return ready[idx]


def _parse_retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("retry-after") or response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(15.0, float(str(raw).strip()))
    except ValueError:
        return None


def _is_rate_limit_status(status_code: int, payload: Any) -> bool:
    if status_code in {429, 503}:
        return True
    text = str(payload or "").casefold()
    return any(
        token in text
        for token in (
            "rate limit",
            "rate_limit",
            "too many requests",
            "quota",
            "tokens per day",
            "tpm",
            "rpm",
        )
    )


def _wait_global_pace() -> None:
    """Enforce min interval between Groq calls (local + Redis for multi-worker)."""
    global _LAST_CALL_MONO
    interval = float(getattr(settings, "GROQ_MIN_INTERVAL_SEC", 1.25) or 1.25)
    interval = max(0.0, interval)
    if interval <= 0:
        return

    # Process-local floor.
    with _LOCK:
        now_m = time.monotonic()
        wait_local = (_LAST_CALL_MONO + interval) - now_m
        if wait_local > 0:
            time.sleep(wait_local)
        _LAST_CALL_MONO = time.monotonic()

    try:
        from django.core.cache import cache

        key = _pace_cache_key()
        now = time.time()
        last = cache.get(key)
        if last is not None:
            wait = float(last) + interval - now
            if wait > 0:
                time.sleep(min(wait, interval * 3))
        cache.set(key, time.time(), timeout=int(interval) + 120)
    except Exception:  # noqa: BLE001
        return


def groq_chat_completion(
    *,
    messages: list[dict[str, str]],
    max_tokens: int = 200,
    temperature: float = 0.1,
    model: str | None = None,
    timeout: float | None = None,
    max_attempts: int | None = None,
) -> dict[str, Any]:
    """
    Call Groq chat completions with careful key rotation.

    Returns {text, model, key_fp, raw_id, namespace}.
    Raises GroqUnavailable when the pool should not be hammered further.
    """
    keys = groq_api_keys()
    if not keys:
        raise GroqUnavailable("No Groq API keys configured")
    if is_groq_pool_circuit_open():
        raise GroqUnavailable("Groq pool circuit open")

    ready = _available_keys()
    if not ready:
        trip_groq_pool_circuit(reason="all keys cooling")
        raise GroqUnavailable("all Groq keys cooling")

    model = model or (
        getattr(settings, "GROQ_MODEL", "llama-3.3-70b-versatile")
        or "llama-3.3-70b-versatile"
    )
    timeout = float(
        timeout
        if timeout is not None
        else (getattr(settings, "GROQ_TIMEOUT_SEC", 12) or 12)
    )
    attempt_cap = int(
        max_attempts
        if max_attempts is not None
        else (getattr(settings, "GROQ_MAX_KEY_ATTEMPTS", 2) or 2)
    )
    # Never burn the whole pool in one request.
    attempt_cap = max(1, min(attempt_cap, len(ready), 3))
    stop_on_429 = bool(getattr(settings, "GROQ_STOP_ON_FIRST_429", True))
    url = "https://api.groq.com/openai/v1/chat/completions"
    body = {
        "model": model,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "messages": messages,
    }

    errors: list[str] = []
    attempted: set[str] = set()
    rate_limited = 0
    for _ in range(attempt_cap):
        api_key = acquire_groq_api_key()
        if not api_key:
            break
        if api_key in attempted:
            remaining = [k for k in _available_keys() if k not in attempted]
            if not remaining:
                break
            api_key = remaining[0]
        attempted.add(api_key)
        fp = _fingerprint(api_key)
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        _wait_global_pace()
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(url, headers=headers, json=body)
                data = response.json() if response.content else {}
        except httpx.HTTPError as exc:
            errors.append(f"{fp}: network {exc}")
            mark_groq_key_cooldown(api_key, seconds=30)
            continue

        if response.status_code >= 400:
            err = data.get("error", data) if isinstance(data, dict) else data
            errors.append(f"{fp}: HTTP {response.status_code}")
            if _is_rate_limit_status(response.status_code, err):
                rate_limited += 1
                retry_after = _parse_retry_after(response)
                cooldown = retry_after or float(
                    getattr(settings, "GROQ_KEY_COOLDOWN_SEC", 120) or 120
                )
                # Cap absurd Retry-After values but stay long enough to clear RPM.
                cooldown = max(30.0, min(float(cooldown), 600.0))
                mark_groq_key_cooldown(api_key, seconds=cooldown)
                if stop_on_429:
                    # One 429 often means org/IP RPM pressure — do not cascade-burn
                    # the rest of the pool within the same call.
                    trip_groq_pool_circuit(
                        reason=f"429 on {fp}; stopping cascade"
                    )
                    raise GroqUnavailable(
                        f"Groq rate limited (HTTP {response.status_code})"
                    )
                continue
            if response.status_code in {401, 403}:
                mark_groq_key_cooldown(api_key, seconds=3600)
                continue
            raise RuntimeError(f"Groq HTTP {response.status_code}: {err}")

        choices = data.get("choices") or []
        text = ""
        if choices:
            message = choices[0].get("message") or {}
            text = str(message.get("content") or "").strip()
        return {
            "text": text,
            "model": model,
            "key_fp": fp,
            "raw_id": data.get("id"),
            "namespace": _namespace(),
        }

    if rate_limited or not _available_keys():
        trip_groq_pool_circuit(reason="exhausted key attempts")
    raise GroqUnavailable(
        "Groq exhausted API key attempts: " + "; ".join(errors[:6])
    )
