"""Runtime configuration for the INV4R API: repo paths + env overrides."""

from __future__ import annotations

import os
from pathlib import Path


def repo_root() -> Path:
    """inv4r/api/config.py -> repo root is two parents up."""
    return Path(__file__).resolve().parent.parent.parent


def _resolve(env_var: str, default: Path) -> Path:
    env = os.environ.get(env_var, "").strip()
    p = Path(env) if env else default
    return p if p.is_absolute() else (repo_root() / p)


def configs_dir() -> Path:
    return _resolve("INV4R_CONFIGS_DIR", repo_root() / "configs")


def mappings_dir() -> Path:
    return _resolve("INV4R_MAPPINGS_DIR", repo_root() / "mappings")


def controls_dir() -> Path:
    return _resolve("INV4R_CONTROLS_DIR", repo_root() / "controls")


def artifacts_dir() -> Path:
    return _resolve("INV4R_OUT_DIR", repo_root() / "out")


def ensure_dirs() -> None:
    for d in (configs_dir(), mappings_dir(), artifacts_dir()):
        d.mkdir(parents=True, exist_ok=True)
