"""Deterministic, control-specific remediation composition.

This module explains a control result in human language. It is intentionally
deterministic: the narrative is *derived* from control metadata (the ``expect``
block, the canonical fact names, the observed values and the recorded impact
catalog), and executable / vendor-specific configuration is **only** ever read
from validated policy data (a control's ``remediation:`` map or the profile's
``remediation_by_fact:`` table).

It never invents commands and it never calls an AI lane or Batfish. Batfish is a
parsing/behavioural-verification component; it is not a remediation generator.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

# YAML include (leading underscore keeps it out of ControlEngine's profile glob).
IMPACT_FILENAME = "_impact_shared.yaml"

_OPERATOR_WORDS = {
    "==": "must equal",
    "in": "must be one of",
    "<=": "must be at most",
    ">=": "must be at least",
    "contains": "must contain",
}


def load_impacts(controls_dir: str | Path) -> dict[str, str]:
    """Load the fact -> human-impact catalog. Missing/corrupt file = empty."""
    p = Path(controls_dir) / IMPACT_FILENAME
    if not p.is_file():
        return {}
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    impacts = data.get("impacts") if isinstance(data, dict) else None
    if not isinstance(impacts, dict):
        return {}
    return {str(k): str(v) for k, v in impacts.items() if v}


def _human_fact(name: str) -> str:
    return str(name or "").replace(".", " ")


def _expect_sentence(group: dict[str, Any]) -> str:
    """One human sentence describing the required state of a single fact block."""
    name = str(group.get("fact") or "")
    expect = group.get("expect") or {}
    status = expect.get("status", "PRESENT")
    operator = expect.get("operator")
    value = expect.get("value")

    if status == "ABSENT":
        return f"{_human_fact(name)} must be absent (the insecure setting disabled)"
    if status == "PRESENT" and operator and value is not None:
        word = _OPERATOR_WORDS.get(operator, str(operator))
        if operator == "in" and isinstance(value, list):
            return f"{_human_fact(name)} {word} {', '.join(str(v) for v in value)}"
        return f"{_human_fact(name)} {word} {value!r}"
    if status == "PRESENT" and value is True:
        return f"{_human_fact(name)} must be present and enabled"
    return f"{_human_fact(name)} must be present"


def expected_state(group: dict[str, Any]) -> str:
    """Human expected state for a control (its ``expect`` / group structure)."""
    if not isinstance(group, dict):
        return ""
    if "fact" in group:
        return _expect_sentence(group)
    for key, joiner in (("all_of", " and "), ("any_of", " or ")):
        parts = group.get(key) or []
        sentences = [_expect_sentence(p) for p in parts if isinstance(p, dict) and "fact" in p]
        if sentences:
            return joiner.join(sentences)
    applicable = group.get("applicable_when")
    if isinstance(applicable, dict):
        return expected_state(applicable)
    return ""


def observed_state(detail: str, fact_values: dict[str, Any] | None = None) -> str:
    """Human observed state. Uses the evaluator's detail plus reported values."""
    values = fact_values or {}
    rendered = ", ".join(f"{_human_fact(k)}={v!r}" for k, v in values.items())
    detail = (detail or "").strip()
    if detail and rendered:
        return f"{detail} (observed: {rendered})"
    return detail or rendered or "No evidence was reported for this control."


def why_it_matters(facts_used: list[str], impacts: dict[str, str],
                   rationale: str | None = None,
                   title: str = "", severity: str = "") -> str:
    """Human 'why this matters'. Deterministic metadata only, never generated CLI."""
    if rationale:
        return str(rationale).strip()
    for name in facts_used or []:
        text = impacts.get(name)
        if text:
            return text
    sev = (severity or "security").lower()
    return (f"This control protects the device's {sev}-severity security posture"
            + (f" ({title.strip()})." if title else "."))
