"""Multi-framework control engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from inv4r.controls.remediation import (
    expected_state,
    load_impacts,
    observed_state,
    why_it_matters,
)
from inv4r.core.facts import FactStatus, SecurityFact

# Files in controls/ that are YAML includes rather than loadable profiles.
_OVERLAY_SUFFIX = "__user.yaml"

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_EXPECT_OPERATORS = frozenset({"==", "in", "<=", ">=", "contains"})
VALID_EXPECT_STATUSES = frozenset({"PRESENT", "ABSENT"})


@dataclass
class ControlResult:
    control_id: str
    title: str
    severity: str
    result: str
    detail: str = ""
    evidence_lines: list[int] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    facts_used: list[str] = field(default_factory=list)
    fact_values: dict[str, Any] = field(default_factory=dict)
    weight: float = 0.0
    # Control-specific context used by the Evidence & Remediation view. All
    # deterministic: derived from the control definition and observed facts.
    framework: str = ""
    expected: str = ""
    observed: str = ""
    reason: str = ""

    @property
    def remediation_cli_sequence(self) -> list[str]:
        """PS-facing name for the ordered remediation commands."""
        return self.remediation

    @property
    def has_remediation(self) -> bool:
        """True only when validated policy data provides vendor-specific config."""
        return bool(self.remediation)

    def to_json(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "severity": self.severity,
            "result": self.result,
            "detail": self.detail,
            "evidence_lines": self.evidence_lines,
            "remediation": self.remediation,
            "remediation_cli_sequence": self.remediation_cli_sequence,
            "has_remediation": self.has_remediation,
            "facts_used": self.facts_used,
            "fact_values": self.fact_values,
            "weight": self.weight,
            "framework": self.framework,
            "expected": self.expected,
            "observed": self.observed,
            "reason": self.reason,
        }


class ProfileError(ValueError):
    pass


def control_category(control_id: str) -> str:
    """Group a control id into its framework family for roll-ups."""
    cid = (control_id or "").strip()
    if not cid:
        return "general"
    prefix, _, rest = cid.partition("-")
    if not rest:
        return prefix

    dotted = rest.split(".")
    family = dotted[0].split("-")[0]
    if len(dotted) >= 2 and re.fullmatch(r"[A-Za-z]+", family):
        family = f"{family}.{dotted[1].split('-')[0]}"
    return f"{prefix}-{family}"


DEFAULT_APPLICABILITY = {
    "snmp.v1.v2c.enabled": "snmp",
    "snmp.v3.enabled": "snmp",
    "management.http.enabled": "http",
    "management.https.enabled": "http",
}


def _facts_named(facts: list[SecurityFact], name: str,
                 scope: str | None = None, entity: str | None = None) -> list[SecurityFact]:
    return [f for f in facts if f.name == name
            and (scope is None or f.scope == scope)
            and (entity is None or f.entity == entity)]


def _check_expect(name: str, group_facts: list[SecurityFact],
                  expect: dict[str, Any],
                  entity_scope: dict[str, str] | None = None) -> tuple[str, str, list[SecurityFact]]:
    """Evaluate an expect{} against facts reported for a name."""
    if not group_facts:
        return "UNKNOWN", f"fact '{name}' not reported by any adapter", []

    want_status = expect.get("status", "PRESENT")
    present = [f for f in group_facts if f.status == "PRESENT"]

    if want_status == "ABSENT":
        if present:
            vals = ", ".join(str(f.value) for f in present[:3])
            return "FAIL", f"evidence found: {vals}", present
        if any(f.status == "UNKNOWN" for f in group_facts):
            return "UNKNOWN", "adapter could not determine state", []
        return "PASS", "no evidence of the insecure service", []

    if not present:
        if any(f.status == "UNKNOWN" for f in group_facts):
            return "UNKNOWN", "adapter could not determine state", []
        if any(f.status == "NOT_APPLICABLE" for f in group_facts):
            return "NOT_APPLICABLE", f"'{name}' not present in this configuration", []
        return "FAIL", f"'{name}' reported ABSENT or missing", []

    op = expect.get("operator", "==")
    want = expect.get("value")
    values = [f.value for f in present]

    def _vals() -> str:
        return ", ".join(repr(v) for v in values[:4])

    if op == "in":
        allowed = [str(v).lower() for v in (want or [])]
        bad = [(f, v) for f, v in zip(present, values) if str(v).lower() not in allowed]
        if bad:
            return "FAIL", (f"non-compliant values: "
                            f"{', '.join(repr(b) for _, b in bad[:3])}"), [f for f, _ in bad]
        return "PASS", f"all values compliant ({_vals()})", present

    if op == "==":
        if want is None:
            return "PASS", f"present ({_vals()})", present
        ok = [f for f in present if str(f.value).lower() == str(want).lower()]
        if len(ok) == len(present):
            return "PASS", f"value matches {want!r}", present
        if ok:
            return "FAIL", f"expected {want!r} for all entities, got {_vals()}", [
                f for f in present if str(f.value).lower() != str(want).lower()]
        return "FAIL", f"expected {want!r}, got {_vals()}", present

    if op in ("<=", ">="):
        nums: list[float] = []
        per: list[tuple[SecurityFact, float]] = []
        for f in present:
            try:
                n = float(f.value)
                nums.append(n)
                per.append((f, n))
            except (TypeError, ValueError):
                return "UNKNOWN", f"non-numeric value {f.value!r} for numeric control", []
        if not nums:
            return "UNKNOWN", "no numeric values reported", []
        if op == "<=":
            worst = max(nums)
            viol = [f for f, n in per if n > float(want)]
        else:
            worst = min(nums)
            viol = [f for f, n in per if n < float(want)]
        if not viol:
            return "PASS", f"worst value {worst:g} satisfies {op} {want}", present
        return "FAIL", f"worst value {worst:g} violates {op} {want}", viol

    if op == "contains":
        bad = [f for f in present
               if str(want).lower() not in " ".join(str(v) for v in
                                                    (f.value if isinstance(f.value, list) else [f.value])).lower()]
        if bad:
            return "FAIL", f"value missing {want!r}", bad
        return "PASS", f"all values contain {want!r}", present

    return "PASS", f"present ({_vals()})", present


def _eval_group(group: dict[str, Any], facts: list[SecurityFact]) -> tuple[str, str, list[SecurityFact]]:
    """Evaluate a fact/any_of/all_of block. Returns (result, detail, facts_used)."""
    if "fact" in group:
        scope = group.get("scope")
        entity = group.get("entity")
        return _check_expect(group["fact"], _facts_named(facts, group["fact"], scope, entity),
                             group.get("expect") or {})

    parts = group.get("any_of") or group.get("all_of") or []
    if not parts:
        return "UNKNOWN", "empty control group", []
    mode = "any" if "any_of" in group else "all"
    results = [_eval_group(p, facts) for p in parts]
    used = [f for _, _, fs in results for f in fs]
    if mode == "all":
        fails = [d for r, d, _ in results if r == "FAIL"]
        if fails:
            return "FAIL", "; ".join(fails), used
        unknowns = [d for r, d, _ in results if r == "UNKNOWN"]
        if unknowns:
            return "UNKNOWN", "; ".join(unknowns), used
        nas = [r for r, _, _ in results if r == "NOT_APPLICABLE"]
        if nas and len(nas) == len(results):
            return "NOT_APPLICABLE", "all conditions not applicable", []
        return "PASS", "all conditions satisfied", used
    else:
        if any(r == "PASS" for r, _, _ in results):
            return "PASS", next(d for r, d, _ in results if r == "PASS"), used
        fails = [d for r, d, _ in results if r == "FAIL"]
        if fails:
            return "FAIL", "; ".join(fails), used
        if any(r == "NOT_APPLICABLE" for r, _, _ in results):
            return "NOT_APPLICABLE", "; ".join(d for r, d, _ in results if r == "NOT_APPLICABLE"), []
        return "UNKNOWN", "; ".join(d for _, d, _ in results), []


class ControlEngine:
    def __init__(self, controls_dir: str | Path = "controls") -> None:
        self.controls_dir = Path(controls_dir)
        self._profiles: dict[str, dict[str, Any]] = {}
        self._impacts: dict[str, str] = {}
        self.reload()

    def reload(self) -> None:
        self._profiles = {}
        for p in sorted(self.controls_dir.glob("*.yaml")):
            # Skip YAML includes (leading underscore) and user overlays; those
            # are merged below so shipped profile files are never rewritten.
            if p.name.startswith("_") or p.name.endswith(_OVERLAY_SUFFIX):
                continue
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            pid = data.get("profile_id", p.stem)
            self._profiles[pid] = data
        self._merge_overlays()
        self._impacts = load_impacts(self.controls_dir)

    def _merge_overlays(self) -> None:
        """Merge validated user-added controls from ``*__user.yaml`` overlays.

        Invalid or duplicate entries are skipped so a malformed overlay can
        never break the engine or shadow a shipped control.
        """
        for p in sorted(self.controls_dir.glob(f"*{_OVERLAY_SUFFIX}")):
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                continue
            if not isinstance(data, dict):
                continue
            target = str(data.get("profile_id") or p.name[: -len(_OVERLAY_SUFFIX)])
            prof = self._profiles.get(target)
            if prof is None:
                continue
            base = prof.setdefault("controls", []) or []
            shown = {c.get("id") for c in base if isinstance(c, dict)}
            for ctrl in data.get("controls") or []:
                if not isinstance(ctrl, dict):
                    continue
                cid = ctrl.get("id")
                if not cid or cid in shown:
                    continue
                if validate_control_definition(ctrl, action="add"):
                    continue  # never load an invalid definition
                base.append(ctrl)
                shown.add(cid)
            prof["controls"] = base

    def profiles(self) -> list[dict[str, Any]]:
        return list(self._profiles.values())

    def get_profile(self, profile_id: str) -> dict[str, Any]:
        aliases = {
            "cis": "cis-network-baseline",
            "cis-baseline": "cis-network-baseline",
            "cis_network_baseline": "cis-network-baseline",
            "nist": "nist-800-53-network",
            "nist-800-53": "nist-800-53-network",
            "nist_800_53": "nist-800-53-network",
            "stig": "disa-stig-network",
            "disa-stig": "disa-stig-network",
            "disa_stig": "disa-stig-network",
            "iso": "iso27001-network",
            "iso27001": "iso27001-network",
            "iso-27001": "iso27001-network",
        }
        pid_norm = profile_id.lower().strip()
        target_id = aliases.get(pid_norm, aliases.get(pid_norm.replace("_", "-"), profile_id))
        if target_id not in self._profiles:
            raise ProfileError(
                f"unknown profile '{profile_id}'. available: {', '.join(sorted(self._profiles))}")
        return self._profiles[target_id]

    def evaluate(self, facts: list[SecurityFact], vendor: str,
                 profile_id: str) -> list[ControlResult]:
        """Evaluate a single profile (thin wrapper over ``evaluate_profiles``)."""
        return self.evaluate_profiles(facts, vendor, [profile_id])

    def evaluate_profiles(self, facts: list[SecurityFact], vendor: str,
                          profile_ids: list[str],
                          control_ids: list[str] | None = None,
                          controls_by_profile: dict[str, list[str]] | None = None
                          ) -> list[ControlResult]:
        """Evaluate one or more profiles, optionally limited to control ids.

        ``control_ids`` is a global filter that applies to every profile;
        ``controls_by_profile`` scopes ids to one framework. A profile is
        filtered only when at least one entry applies to it, so a control
        subset chosen for one framework never hides another framework's
        controls.

        The returned list carries the profile id on each result so callers can
        group aggregate counts per framework without re-evaluating.
        """
        shared = {c.strip() for c in (control_ids or []) if c and c.strip()}
        scoped = {pid: {c.strip() for c in ids if c and c.strip()}
                  for pid, ids in (controls_by_profile or {}).items()}
        results: list[ControlResult] = []
        for profile_id in profile_ids:
            prof = self.get_profile(profile_id)
            picked = self._evaluate_profile(facts, vendor, prof)
            wanted = shared | scoped.get(profile_id, set())
            if wanted:
                picked = [r for r in picked if r.control_id in wanted]
            results.extend(picked)
        return results

    def _evaluate_profile(self, facts: list[SecurityFact], vendor: str,
                          prof: dict[str, Any]) -> list[ControlResult]:
        results: list[ControlResult] = []
        profile_id = prof.get("profile_id", "")
        impacts = self._impacts

        for ctrl in prof.get("controls") or []:
            applicable = ctrl.get("applicable_when")
            if applicable:
                ok = bool(_eval_group(applicable, facts)[0] == "PASS")
                if not ok:
                    names = _fact_names(ctrl)
                    detail = _applicability_sentence(applicable)
                    results.append(ControlResult(
                        control_id=ctrl.get("id", "?"),
                        title=ctrl.get("title", ""),
                        severity=ctrl.get("severity", "medium"),
                        result="NOT_APPLICABLE",
                        # Never surface a raw dict into a report: derive a human
                        # sentence from the applicable_when precondition.
                        detail=detail,
                        facts_used=names,
                        framework=profile_id,
                        expected=expected_state(applicable) or expected_state(ctrl),
                        observed=observed_state(detail),
                        reason=why_it_matters(names, impacts, ctrl.get("rationale"),
                                              ctrl.get("title", ""), ctrl.get("severity", ""))))
                    continue

            result, detail, used = _eval_group(ctrl, facts)
            fail_closed = bool(ctrl.get("fail_closed"))
            if result == "UNKNOWN" and fail_closed:
                result = "FAIL"
                detail = f"fail-closed: {detail}"

            lines: list[int] = []
            for f in used:
                lines.extend(s.get("line_start", 0) for s in f.evidence_spans)

            rem_map = ctrl.get("remediation") or {}
            rem = rem_map.get(vendor) or rem_map.get("default") or []
            if not rem:
                names = _fact_names(ctrl)
                by_fact = prof.get("remediation_by_fact") or {}
                for n in names:
                    tbl = by_fact.get(n) or {}
                    rem = tbl.get(vendor) or tbl.get("default") or []
                    if rem:
                        break
            # An UNKNOWN result means we do not yet know what the configuration
            # means, so no definitive vendor fix is offered — the training loop
            # resolves it first. (FAIL uses validated policy remediation only.)
            if result == "UNKNOWN":
                rem = []

            names = sorted({f.name for f in used}) or _fact_names(ctrl)
            results.append(ControlResult(
                control_id=ctrl.get("id", "?"),
                title=ctrl.get("title", ""),
                severity=ctrl.get("severity", "medium"),
                result=result,
                detail=detail,
                evidence_lines=sorted(set(lines))[:8],
                remediation=[str(x) for x in rem],
                facts_used=names,
                fact_values={f.name: f.value for f in used[:6]},
                weight=0.0,
                framework=profile_id,
                expected=expected_state(ctrl),
                observed=observed_state(detail, {f.name: f.value for f in used[:6]}),
                reason=why_it_matters(names, impacts, ctrl.get("rationale"),
                                      ctrl.get("title", ""), ctrl.get("severity", "")),
            ))
        return results


def validate_control_definition(ctrl: dict[str, Any],
                                action: str = "add") -> list[str]:
    """Validate a complete control definition before it is persisted/loaded.

    Returns a list of human-readable errors; an empty list means valid. The
    same validator guards the admin Add-Control endpoint and the overlay merge,
    so an invalid control can never reach the evaluation engine.
    """
    from inv4r.core.facts import CANONICAL_FACTS, FACT_NAME_RE

    errors: list[str] = []
    if not isinstance(ctrl, dict):
        return ["control must be a mapping"]

    cid = str(ctrl.get("id") or "").strip()
    if not cid:
        errors.append("id is required")
    elif not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", cid):
        errors.append(f"id {cid!r} must be alphanumeric with ., _, or -")

    if not str(ctrl.get("title") or "").strip():
        errors.append("title is required")

    severity = str(ctrl.get("severity") or "").lower()
    if severity not in VALID_SEVERITIES:
        errors.append(f"severity must be one of {', '.join(sorted(VALID_SEVERITIES))}")

    if not any(k in ctrl for k in ("fact", "any_of", "all_of")):
        errors.append("a control requires one of: fact, any_of, all_of")

    for group in _walk_groups(ctrl):
        name = str(group.get("fact") or "")
        if not name:
            errors.append("every fact block requires 'fact'")
            continue
        if not FACT_NAME_RE.fullmatch(name):
            errors.append(f"fact {name!r} is not a valid canonical fact name")
        elif name not in CANONICAL_FACTS:
            errors.append(f"fact {name!r} is outside the closed vocabulary")
        expect = group.get("expect") or {}
        status = expect.get("status", "PRESENT")
        if status not in VALID_EXPECT_STATUSES:
            errors.append(f"expect.status {status!r} must be PRESENT or ABSENT")
        operator = expect.get("operator")
        if operator is not None and operator not in VALID_EXPECT_OPERATORS:
            errors.append(
                f"expect.operator {operator!r} must be one of "
                f"{', '.join(sorted(VALID_EXPECT_OPERATORS))}")
    return errors


def _walk_groups(group: dict[str, Any]) -> list[dict[str, Any]]:
    """Yield every fact block in a control (or nested any_of/all_of)."""
    out: list[dict[str, Any]] = []
    if not isinstance(group, dict):
        return out
    if "fact" in group:
        out.append(group)
    for key in ("any_of", "all_of"):
        for part in group.get(key) or []:
            out.extend(_walk_groups(part))
    return out


def _applicability_sentence(group: dict[str, Any]) -> str:
    """Readable NOT_APPLICABLE reason (never a raw dict/template)."""
    if "fact" in group:
        name = str(group.get("fact"))
        expect = group.get("expect") or {}
        status = expect.get("status", "PRESENT")
        value = expect.get("value")
        human = name.replace(".", " ")
        if status == "PRESENT" and value is True:
            return f"Not applicable: {human} is not present on this device"
        if status == "ABSENT":
            return f"Not applicable: {human} is already absent on this device"
        return (f"Not applicable: the precondition {human} = {status}"
                + (f" {value!r}" if value is not None else "") + " is not met")
    for key in ("any_of", "all_of"):
        parts = group.get(key) or []
        if parts:
            return _applicability_sentence(parts[0])
    if group.get("applicable_when"):
        return _applicability_sentence(group["applicable_when"])
    return "Not applicable: the precondition for this control is not met on this device"


def _fact_names(group: dict[str, Any]) -> list[str]:
    if "fact" in group:
        return [group["fact"]]
    names: list[str] = []
    for part in (group.get("any_of") or []) + (group.get("all_of") or []) + \
                ([group.get("applicable_when")] if group.get("applicable_when") else []):
        if isinstance(part, dict):
            names.extend(_fact_names(part))
    return names


def summarize(results: list[ControlResult]) -> dict[str, int]:
    s = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0, "NOT_APPLICABLE": 0}
    for r in results:
        s[r.result] = s.get(r.result, 0) + 1
    return s


def severity_weights(profile: dict[str, Any] | None = None) -> dict[str, float]:
    """Configurable severity weights — data, not code."""
    w = {"critical": 30.0, "high": 20.0, "medium": 12.0, "low": 6.0}
    if profile:
        w.update({str(k).lower(): float(v)
                  for k, v in (profile.get("severity_weights") or {}).items()})
    return w


def risk_score(results: list[ControlResult], profile: dict[str, Any] | None = None) -> tuple[int | str, str]:
    """Weighted posture score over APPLICABLE controls only."""
    applicable = [r for r in results if r.result != "NOT_APPLICABLE"]
    if not applicable:
        return "N/A", "no applicable controls"

    weights = severity_weights(profile)
    default_w = weights.get("default", 10)
    for r in applicable:
        r.weight = weights.get(r.severity.lower(), default_w)

    total = sum(r.weight for r in applicable) or 1.0
    lost = 0.0
    for r in applicable:
        if r.result == "FAIL":
            lost += r.weight
        elif r.result == "UNKNOWN":
            lost += r.weight * 0.5
    score = max(0, round(100 - 100 * lost / total))
    band = ("strong" if score >= 85 else "moderate" if score >= 65 else
            "weak" if score >= 40 else "critical")
    return score, band
