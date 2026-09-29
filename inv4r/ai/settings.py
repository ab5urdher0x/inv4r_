"""AI lane settings: which proposer may run, and whether we may leave the box."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

MODES = ("rules", "learned", "local_llm", "cloud_llm", "auto")
_DEFAULT_CONFIG_PATHS = ("inv4r.yaml", "inv4r.yml")


@dataclass
class AISettings:
    mode: str = "learned"
    air_gapped: bool = True
    mappings_dir: str = "mappings"
    min_confidence: float = 0.45
    local_llm_model: str = "llama3.2"
    local_llm_base: str = "http://localhost:11434"
    local_llm_timeout: float = 20.0
    cloud_llm_base: str = "https://api.openai.com"
    cloud_llm_model: str = "gpt-4o-mini"
    cloud_llm_timeout: float = 30.0
    cloud_llm_provider: str = "openai"
    cloud_api_key: str = ""
    last_fallback_note: str = ""

    def to_json(self) -> dict[str, Any]:
        """Serializable view. The API key is never included — only whether one
        is configured and a masked tail for operator confirmation."""
        from inv4r.ai.secrets import mask_key

        return {
            "mode": self.mode,
            "air_gapped": self.air_gapped,
            "mappings_dir": self.mappings_dir,
            "min_confidence": self.min_confidence,
            "local_llm": {"model": self.local_llm_model, "base_url": self.local_llm_base},
            "cloud_llm": {"model": self.cloud_llm_model, "base_url": self.cloud_llm_base,
                          "provider": self.cloud_llm_provider,
                          "api_key_set": bool(self.cloud_api_key),
                          "api_key_masked": mask_key(self.cloud_api_key)},
            "note": self.last_fallback_note,
        }


def load_settings(root: str | Path = ".") -> AISettings:
    """Load settings from inv4r.yaml, then apply env overrides."""
    s = AISettings()
    for name in _DEFAULT_CONFIG_PATHS:
        p = Path(root) / name
        if p.exists():
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            except Exception:
                data = {}
            ai = data.get("ai") or {}
            s.mode = ai.get("mode", s.mode)
            s.air_gapped = bool(ai.get("air_gapped", s.air_gapped))
            s.mappings_dir = ai.get("mappings_dir", s.mappings_dir)
            s.min_confidence = float(ai.get("min_confidence", s.min_confidence))
            local = ai.get("local_llm") or {}
            s.local_llm_model = local.get("model", s.local_llm_model)
            s.local_llm_base = local.get("base_url", s.local_llm_base)
            cloud = ai.get("cloud_llm") or {}
            s.cloud_llm_base = cloud.get("base_url", s.cloud_llm_base)
            s.cloud_llm_model = cloud.get("model", s.cloud_llm_model)
            key_env = cloud.get("api_key_env", "INV4R_LLM_API_KEY")
            s.cloud_api_key = os.environ.get(key_env, "")
            break

    if os.environ.get("INV4R_AI_MODE"):
        s.mode = os.environ["INV4R_AI_MODE"]
    if os.environ.get("INV4R_AIR_GAPPED") is not None:
        s.air_gapped = os.environ["INV4R_AIR_GAPPED"].lower() not in ("0", "false", "no")
    if os.environ.get("INV4R_LLM_API_KEY"):
        s.cloud_api_key = os.environ["INV4R_LLM_API_KEY"]

    # Fall back to a key submitted through the API and encrypted at rest.
    if not s.cloud_api_key:
        try:
            from inv4r.ai.secrets import load_cloud_key
            stored, provider = load_cloud_key()
            if stored:
                s.cloud_api_key = stored
                s.cloud_llm_provider = provider or s.cloud_llm_provider
        except Exception:  # noqa: BLE001 - a missing/corrupt store must not break startup
            pass

    s = resolve(s)
    return s


def resolve(s: AISettings) -> AISettings:
    """Enforce the air-gap invariant. cloud_llm + air_gapped is a hard refusal,"""
    s.last_fallback_note = ""
    if s.mode not in MODES:
        s.last_fallback_note = f"unknown mode '{s.mode}' -> learned"
        s.mode = "learned"
    if s.mode == "cloud_llm" and s.air_gapped:
        s.last_fallback_note = "cloud_llm refused under air_gapped=true -> learned"
        s.mode = "learned"
    if s.mode == "cloud_llm" and not s.cloud_api_key:
        s.last_fallback_note = "cloud_llm selected but no API key -> learned"
        s.mode = "learned"
    if s.mode == "auto":
        s.mode = "learned" if s.air_gapped else ("cloud_llm" if s.cloud_api_key else "learned")
    return s


_active: AISettings | None = None


def get_settings() -> AISettings:
    global _active
    if _active is None:
        _active = load_settings()
    return _active


def set_settings(s: AISettings) -> None:
    global _active
    _active = resolve(s)


def set_overrides(mode: str | None = None, mappings_dir: str | None = None,
                  air_gapped: bool | None = None) -> AISettings:
    """Apply CLI overrides on top of the loaded config."""
    s = load_settings()
    if mode:
        s.mode = mode.replace("-", "_")
    if mappings_dir:
        s.mappings_dir = mappings_dir
    if air_gapped is not None:
        s.air_gapped = air_gapped
    set_settings(s)
    return s
