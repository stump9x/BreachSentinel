"""LLM providers — keys only from settings/env. Never log secrets."""

from __future__ import annotations

import logging
from typing import Any

import httpx
from django.conf import settings

logger = logging.getLogger(__name__)


class AIProviderError(Exception):
    pass


def generate_briefing_text(prompt: str, *, max_tokens: int = 1200) -> dict[str, Any]:
    """
    Prefer Groq (free-tier friendly), then Anthropic, then Hugging Face, else local.
    Returns {provider, text, raw}.
    """
    from apps.integrations.ai.groq_pool import groq_keys_configured

    if groq_keys_configured():
        return groq_complete(prompt, max_tokens=max_tokens)

    anthropic_key = getattr(settings, "ANTHROPIC_API_KEY", "") or ""
    if anthropic_key:
        return _anthropic_complete(prompt, anthropic_key, max_tokens=max_tokens)

    hf_token = getattr(settings, "HUGGINGFACE_API_TOKEN", "") or ""
    if hf_token:
        model = getattr(
            settings,
            "HUGGINGFACE_SUMMARIZE_MODEL",
            "google/flan-t5-base",
        )
        return _huggingface_complete(prompt, hf_token, model=model)

    return {
        "provider": "local",
        "text": _local_briefing(prompt),
        "raw": {"mode": "local_fallback"},
    }


def groq_complete(prompt: str, *, max_tokens: int = 400) -> dict[str, Any]:
    """OpenAI-compatible Groq chat completions with shared multi-key rotation."""
    from apps.integrations.ai.groq_pool import groq_chat_completion, groq_keys_configured

    if not groq_keys_configured():
        raise AIProviderError("GROQ_API_KEY / GROQ_API_KEYS is not configured")
    model = (
        getattr(settings, "GROQ_MODEL", "llama-3.3-70b-versatile")
        or "llama-3.3-70b-versatile"
    )
    try:
        result = groq_chat_completion(
            messages=[
                {
                    "role": "system",
                    "content": "You assist defensive cyber threat intelligence. Be concise.",
                },
                {"role": "user", "content": prompt[:6000]},
            ],
            max_tokens=max_tokens,
            temperature=0.1,
            model=model,
            timeout=float(getattr(settings, "GROQ_TIMEOUT_SEC", 45) or 45),
        )
    except Exception as exc:
        from apps.integrations.ai.groq_pool import GroqUnavailable

        if isinstance(exc, (GroqUnavailable, RuntimeError)):
            raise AIProviderError(str(exc)) from exc
        raise
    return {
        "provider": "groq",
        "text": str(result.get("text") or "").strip(),
        "raw": {
            "id": result.get("raw_id"),
            "model": result.get("model") or model,
            "key_fp": result.get("key_fp"),
        },
    }


def _anthropic_complete(prompt: str, api_key: str, *, max_tokens: int) -> dict[str, Any]:
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": getattr(settings, "ANTHROPIC_MODEL", "claude-3-haiku-20240307"),
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.post(url, headers=headers, json=body)
    except httpx.HTTPError as exc:
        raise AIProviderError(f"Anthropic request failed: {exc}") from exc

    data = response.json() if response.content else {}
    if response.status_code >= 400:
        # Do not include API key; message may contain provider error only
        raise AIProviderError(
            f"Anthropic HTTP {response.status_code}: {data.get('error', data)}"
        )

    parts = data.get("content") or []
    text = ""
    for part in parts:
        if isinstance(part, dict) and part.get("type") == "text":
            text += part.get("text", "")
    return {"provider": "anthropic", "text": text.strip(), "raw": {"id": data.get("id")}}


def _huggingface_complete(prompt: str, token: str, *, model: str) -> dict[str, Any]:
    url = f"https://api-inference.huggingface.co/models/{model}"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        with httpx.Client(timeout=90.0) as client:
            response = client.post(
                url,
                headers=headers,
                json={"inputs": prompt[:4000], "parameters": {"max_new_tokens": 512}},
            )
    except httpx.HTTPError as exc:
        raise AIProviderError(f"Hugging Face request failed: {exc}") from exc

    data = response.json() if response.content else {}
    if response.status_code >= 400:
        raise AIProviderError(f"Hugging Face HTTP {response.status_code}: {data}")

    text = ""
    if isinstance(data, list) and data:
        first = data[0]
        if isinstance(first, dict):
            text = first.get("summary_text") or first.get("generated_text") or ""
    elif isinstance(data, dict):
        text = data.get("summary_text") or data.get("generated_text") or str(data)

    return {
        "provider": "huggingface",
        "text": str(text).strip(),
        "raw": {"model": model},
    }


def _local_briefing(prompt: str) -> str:
    """Deterministic offline briefing when no AI keys are configured."""
    return (
        "# BreachSentinel Daily Briefing (local template)\n\n"
        "No GROQ_API_KEY / ANTHROPIC_API_KEY / HUGGINGFACE_API_TOKEN configured — "
        "generated a structured local summary from collected intel.\n\n"
        f"{prompt}\n\n"
        "## Analyst notes\n"
        "- Prioritize critical/high Wire items and KEV-linked CVEs.\n"
        "- Validate new stealer domains against monitored assets.\n"
        "- Export confirmed IOCs to MISP when connectivity allows.\n"
    )
