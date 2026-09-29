"""AI candidate-mapping proposer — lane orchestrator."""

from __future__ import annotations

import os
import pathlib
import re
import logging
logger = logging.getLogger(__name__)
from typing import Any

from inv4r.ai import learned
from inv4r.ai.llm import propose_cloud, propose_local
from inv4r.ai.settings import get_settings
from inv4r.core.facts import CANONICAL_FACTS


_RULES: list[dict] = [
    {"fact": "management.ssh.enabled", "on": ["ssh"], "enable_words": ["enable", "on", "yes", "true"]},
    {"fact": "management.ssh.version", "path_regex": r"ssh.*(version|protocol)",
     "value_regex": r"^(v)?([0-9])$", "value_group": 2},
    {"fact": "management.telnet.enabled", "on": ["telnet"], "enable_words": ["enable", "on", "yes", "true"]},
    {"fact": "management.http.enabled", "on": ["http"], "exclude": ["https"],
     "enable_words": ["enable", "on", "yes", "true"]},
    {"fact": "management.https.enabled", "on": ["https"], "enable_words": ["enable", "on", "yes", "true"]},
    {"fact": "management.session_timeout", "path_regex": r"(timeout|idle)",
     "value_regex": r"^(\d+)$", "value_group": 1},
    {"fact": "authentication.aaa.enabled", "on": ["aaa"], "enable_words": ["enable", "on", "yes", "enterprise", "true"]},
    {"fact": "logging.remote.enabled", "path_regex": r"(logging|syslog).*(remote|host|server)|remote.*host"},
    {"fact": "snmp.v1.v2c.enabled", "path_regex": r"snmp.*(community|v2)", "value_regex": r"(?i)v2c|public|private"},
    {"fact": "snmp.v3.enabled", "path_regex": r"snmp.*(v3|user|group)"},
    {"fact": "network.route.present", "path_regex": r"(route|gateway)"},
    {"fact": "network.interface.present", "path_regex": r"(interface|ifname|port-channel)"},
    {"fact": "acl.present", "path_regex": r"(acl|access[-_]?list)"},
    {"fact": "management.acl.present", "path_regex": r"(source[-_]?filter|permitted|access[-_]?class|restrict)"},
]

_NUM_WORDS = {"on", "enable", "enabled", "yes", "true", "active"}
_OFF_WORDS = {"off", "disable", "disabled", "no", "false", "inactive"}


def _propose_rules(path: str, value: str) -> tuple[str, float, dict[str, Any]] | None:
    joined = f"{path} {value}".lower()
    value_l = (value or "").strip().lower()

    best: tuple[str, float] | None = None
    for rule in _RULES:
        fact = rule["fact"]
        if fact not in CANONICAL_FACTS:
            continue
        conf = 0.0
        on = rule.get("on") or []
        if on and any(k in joined for k in on):
            conf = max(conf, 0.55)
        prx = rule.get("path_regex")
        if prx and re.search(prx, joined):
            conf = max(conf, 0.6)
        if conf == 0.0:
            continue
        excl = rule.get("exclude")
        if excl and any(k in joined for k in excl):
            continue
        if any(w in value_l for w in _OFF_WORDS):
            conf = min(conf, 0.45)
        elif any(w in value_l for w in _NUM_WORDS):
            conf = min(0.85, conf + 0.15)
        vrx = rule.get("value_regex")
        if vrx:
            m = re.search(vrx, value_l)
            if m:
                conf = min(0.9, conf + 0.2)
            else:
                conf = min(conf, 0.4)
        if best is None or conf > best[1]:
            best = (fact, conf)

    if best and best[1] >= 0.45:
        return best[0], round(best[1], 3), {"model": "rules"}
    return None


_model_cache: dict[tuple[str, float, int], learned.LearnedModel] = {}


def _registry_fingerprint(mappings_dir: str) -> int:
    """Cheap change signal: newest mtime among packs AND decision ledgers.

    Including the decision ledgers means an approval invalidates the cached
    model without a restart even if the explicit reset is ever missed.
    """
    try:
        base = pathlib.Path(mappings_dir)
        files = list(base.glob("*.yaml"))
        files += [base / "fragment_decisions.json", base / "decisions.json"]
        mtimes = [p.stat().st_mtime_ns for p in files if p.exists()]
        return max(mtimes) if mtimes else 0
    except OSError:
        return 0


def get_learned_model(min_confidence: float | None = None) -> learned.LearnedModel:
    from inv4r.ai.settings import get_settings
    from inv4r.mapping.registry import MappingRegistry

    s = get_settings()
    mdir = s.mappings_dir
    # The AI settings default to a literal "mappings"; honour the deployment's
    # configured directory (the same one approval writes to) when unset.
    if mdir in ("", "mappings"):
        mdir = os.environ.get("INV4R_MAPPINGS_DIR", mdir)
    min_conf = s.min_confidence if min_confidence is None else min_confidence
    fp = _registry_fingerprint(mdir)
    key = (mdir, min_conf, fp)
    if key not in _model_cache:
        registry = MappingRegistry(mdir)
        examples = learned.examples_from_registry(registry)
        # Approvals made in the review queue live in the decision ledger, not
        # in mapping packs; include them so approving a mapping actually
        # teaches the learned lane.
        examples = examples + learned.examples_from_decisions(mdir)
        _model_cache[key] = learned.LearnedModel(min_confidence=min_conf).fit(examples)
        for k in [k for k in _model_cache if k[0] == mdir and k != key]:
            del _model_cache[k]
    return _model_cache[key]


def reset_model_cache() -> None:
    _model_cache.clear()


def propose_mapping(path: str, value: str) -> tuple[str, float] | None:
    """Legacy 2-tuple contract (used by the generic structural adapter)."""
    r = propose(path, value)
    return (r[0], r[1]) if r else None


def propose(path: str, value: str) -> tuple[str, float, dict[str, Any]] | None:
    """Full proposal with provenance: (fact, confidence, explanation) or None."""
    s = get_settings()
    mode = s.mode

    attempts: list[str] = {
        "rules": ["rules"],
        "learned": ["learned", "rules"],
        "local_llm": ["learned", "rules", "local_llm"],
        "cloud_llm": ["learned", "rules", "cloud_llm"],
    }.get(mode, ["learned", "rules"])

    few_shot: list[tuple[str, str, str]] = []
    for lane in attempts:
        if lane == "rules":
            r = _propose_rules(path, value)
            if r:
                logger.debug(f"Lane 'rules' suggestion: {r}")
                return r
        elif lane == "learned":
            model = get_learned_model()
            r = model.propose(path, value)
            if r:
                logger.debug(f"Lane 'learned' suggestion: {r}")
                return r
            few_shot = [(nb.example_path, "", nb.fact) for nb in model.neighbors(path, value)]
        elif lane == "local_llm":
            r = propose_local(path, value, s, few_shot)
            if r:
                logger.debug(f"Lane 'local_llm' suggestion: {r}")
                return r
        elif lane == "cloud_llm":
            r = propose_cloud(path, value, s, few_shot)
            if r:
                logger.debug(f"Lane 'cloud_llm' suggestion: {r}")
                return r

    logger.debug(f"No suggestion generated for path='{path}' value='{value}' (mode={mode})")
    return None
