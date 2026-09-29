"""Lane 2/3 — LLM proposers, behind the same contract."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from inv4r.ai.settings import AISettings
from inv4r.core.facts import CANONICAL_FACTS
from inv4r.core.localhost_guard import is_loopback_url

import logging
logger = logging.getLogger(__name__)

_warned: set[str] = set()


def _warn_once(key: str, message: str) -> None:
    """Operational failures are reported once per endpoint, not once per fragment."""
    if key not in _warned:
        _warned.add(key)
        logger.warning(f"{message} (further failures for this endpoint suppressed)")

_VOCAB_LINES = "\n".join(f"- {k} ({t}): {d}" for k, (t, d) in sorted(CANONICAL_FACTS.items()))

_SYSTEM = (
    "You are a network-security configuration analyst. You map raw configuration "
    "statements to canonical security facts from a CLOSED vocabulary. "
    "Rules: (1) choose ONLY from the listed fact names; (2) if nothing fits "
    "confidently, reply with null; (3) never invent new fact names; "
    "(4) respond with strict JSON only: {\"fact\": string|null, \"confidence\": number}."
)


def _user_prompt(path: str, value: str, few_shot: list[tuple[str, str, str]]) -> str:
    examples = "\n".join(f"  {p!r} -> {f}" for p, _v, f in few_shot[:6])
    return (
        f"Closed vocabulary:\n{_VOCAB_LINES}\n\n"
        f"Examples approved by human auditors (vendor X):\n{examples or '  (none yet)'}\n\n"
        f"Map this configuration statement:\n  path: {path!r}\n  value: {value!r}\n"
        f"JSON response:"
    )


def _parse_response(text: str) -> tuple[str, float] | None:
    """Extract strict JSON from the model output; validate against vocabulary."""
    try:
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            return None
        data = json.loads(text[start:end + 1])
    except (json.JSONDecodeError, ValueError):
        return None
    fact = data.get("fact")
    if not fact or fact not in CANONICAL_FACTS:
        return None
    try:
        conf = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
    except (TypeError, ValueError):
        return None
    if conf < 0.3:
        return None
    return fact, conf


def _post_json(url: str, payload: dict[str, Any], timeout: float,
               headers: dict[str, str] | None = None) -> dict[str, Any]:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def propose_local(path: str, value: str, settings: AISettings,
                  few_shot: list[tuple[str, str, str]]) -> tuple[str, float, dict[str, Any]] | None:
    """Ollama-native chat API. Refused for non-loopback endpoints under air gap."""
    if settings.air_gapped and not is_loopback_url(settings.local_llm_base):
        logger.debug(f"local_llm refused: air_gapped=True and base URL '{settings.local_llm_base}' is not loopback")
        return None
    try:
        data = _post_json(
            f"{settings.local_llm_base.rstrip('/')}/api/chat",
            {"model": settings.local_llm_model, "stream": False,
             "messages": [{"role": "system", "content": _SYSTEM},
                          {"role": "user", "content": _user_prompt(path, value, few_shot)}],
             "options": {"temperature": 0}},
            settings.local_llm_timeout)
        content = (data.get("message") or {}).get("content", "")
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError) as exc:
        _warn_once(f"local_llm:{settings.local_llm_base}",
                   f"local_llm endpoint call failed for {settings.local_llm_base}: {exc}")
        return None
    parsed = _parse_response(content)
    if not parsed:
        return None
    fact, conf = parsed
    return fact, conf, {"model": f"local_llm:{settings.local_llm_model}",
                        "raw_confidence": conf}


def propose_cloud(path: str, value: str, settings: AISettings,
                  few_shot: list[tuple[str, str, str]]) -> tuple[str, float, dict[str, Any]] | None:
    """OpenAI-compatible chat completion. Caller must have verified air-gap+key."""
    if settings.air_gapped or not settings.cloud_api_key:
        logger.debug(f"cloud_llm refused: air_gapped={settings.air_gapped}, "
                     f"has_key={bool(settings.cloud_api_key)}")
        return None
    try:
        data = _post_json(
            f"{settings.cloud_llm_base.rstrip('/')}/v1/chat/completions",
            {"model": settings.cloud_llm_model, "temperature": 0,
             "messages": [{"role": "system", "content": _SYSTEM},
                          {"role": "user", "content": _user_prompt(path, value, few_shot)}]},
            settings.cloud_llm_timeout,
            headers={"Authorization": f"Bearer {settings.cloud_api_key}"})
        content = data["choices"][0]["message"]["content"]
    except (urllib.error.URLError, OSError, json.JSONDecodeError, KeyError, IndexError) as exc:
        _warn_once(f"cloud_llm:{settings.cloud_llm_base}",
                   f"cloud_llm endpoint call failed for {settings.cloud_llm_base}: {exc}")
        return None
    parsed = _parse_response(content)
    if not parsed:
        return None
    fact, conf = parsed
    return fact, conf, {"model": f"cloud_llm:{settings.cloud_llm_model}",
                        "raw_confidence": conf}
