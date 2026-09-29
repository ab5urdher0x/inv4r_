"""Coverage levels: how far a device's evidence progressed through the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

LEVEL_NAMES = {
    0: "Raw ingestion",
    1: "Structural parsing",
    2: "Platform identification",
    3: "Resource normalization",
    4: "Security-fact normalization",
    5: "Compliance-ready",
    6: "Behavior-ready",
    7: "Full assurance",
}


@dataclass
class CoverageReport:
    achieved_level: int = 0
    reasons: list[str] = field(default_factory=list)

    def level_name(self) -> str:
        return LEVEL_NAMES.get(self.achieved_level, "Unknown")

    def to_json(self) -> dict[str, Any]:
        return {
            "achieved_level": self.achieved_level,
            "level_name": self.level_name(),
            "scale": {str(k): v for k, v in LEVEL_NAMES.items()},
            "reasons": self.reasons,
        }


def compute_coverage(
    has_envelope: bool,
    has_structure: bool,
    vendor_identified: bool,
    resources_count: int,
    facts_count: int,
    controls_evaluated: bool,
) -> CoverageReport:
    """Derive the highest honest coverage level from pipeline artifacts."""
    reasons: list[str] = []
    level = 0
    if has_envelope:
        level = 0
        reasons.append("evidence stored and hashed")
    if has_structure:
        level = 1
        reasons.append("structural tree extracted")
    if vendor_identified:
        level = 2
        reasons.append("vendor/platform identified")
    if resources_count > 0:
        level = 3
        reasons.append(f"{resources_count} resource(s) normalized")
    if facts_count > 0:
        level = 4
        reasons.append(f"{facts_count} canonical security fact(s) extracted")
    if facts_count > 0 and controls_evaluated:
        level = 5
        reasons.append("controls evaluated against facts")
    return CoverageReport(achieved_level=level, reasons=reasons)


@dataclass
class RemediationCoverage:
    """How many FAILED controls have a device-specific CLI remediation path."""

    failed_controls: int = 0
    with_remediation: int = 0
    without_remediation: int = 0

    @property
    def coverage_pct(self) -> float:
        if self.failed_controls == 0:
            return 100.0
        return round(100.0 * self.with_remediation / self.failed_controls, 1)

    def to_json(self) -> dict[str, Any]:
        return {
            "failed_controls": self.failed_controls,
            "with_remediation": self.with_remediation,
            "without_remediation": self.without_remediation,
            "coverage_pct": self.coverage_pct,
            "note": ("every failed control has a device-specific CLI remediation path"
                     if self.without_remediation == 0 else
                     f"{self.without_remediation} failed control(s) have no remediation "
                     "path for this vendor yet"),
        }


def remediation_coverage(controls) -> RemediationCoverage:
    """Remediation-path coverage over failed controls."""
    rc = RemediationCoverage()
    for c in controls:
        if str(getattr(c, "result", "")).upper() != "FAIL":
            continue
        rc.failed_controls += 1
        if getattr(c, "remediation", None):
            rc.with_remediation += 1
        else:
            rc.without_remediation += 1
    return rc
