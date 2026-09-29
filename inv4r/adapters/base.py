"""Adapter contract: every ingestion path implements UniversalAdapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from inv4r.core.envelope import EvidenceEnvelope
from inv4r.core.model import StructuralNode
from inv4r.detection import DetectionResult


@dataclass
class AdapterMatch:
    adapter_id: str
    tier: int
    confidence: float
    reason: str = ""

    def to_json(self) -> dict[str, Any]:
        return {"adapter_id": self.adapter_id, "tier": self.tier,
                "confidence": round(float(self.confidence), 3), "reason": self.reason}


@dataclass
class AdapterCapabilities:
    parses_format: str
    normalizes_to_resources: bool = False
    produces_security_facts: bool = False
    requires_human_mapping: bool = False
    requires_external_engine: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "parses_format": self.parses_format,
            "normalizes_to_resources": self.normalizes_to_resources,
            "produces_security_facts": self.produces_security_facts,
            "requires_human_mapping": self.requires_human_mapping,
            "requires_external_engine": self.requires_external_engine,
        }


@dataclass
class Limitation:
    code: str
    description: str

    def to_json(self) -> dict[str, Any]:
        return {"code": self.code, "description": self.description}


@dataclass
class ParsedRepresentation:
    """Universal parsed representation: structural tree + vendor extras."""

    evidence_id: str
    adapter_id: str
    tier: int
    root: StructuralNode
    warnings: list[str] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "adapter_id": self.adapter_id,
            "tier": self.tier,
            "warnings": self.warnings,
            "notes": self.notes,
            "root": self.root.to_json(),
        }


@dataclass
class NormalizationOutput:
    """Canonical model output of an adapter's normalize() step."""

    resources: list[Any] = field(default_factory=list)
    relationships: list[Any] = field(default_factory=list)
    facts: list[Any] = field(default_factory=list)
    unknown_fragments: list[Any] = field(default_factory=list)
    normalization_status: str = "PARTIAL"

    def to_json(self) -> dict[str, Any]:
        return {
            "resources": [r.to_json() for r in self.resources],
            "relationships": [r.to_json() for r in self.relationships],
            "facts": [f.to_json() for f in self.facts],
            "unknown_fragments": [u.to_json() for u in self.unknown_fragments],
            "normalization_status": self.normalization_status,
        }


@runtime_checkable
class UniversalAdapter(Protocol):
    adapter_id: str
    adapter_version: str
    tier: int

    def can_handle(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> AdapterMatch: ...
    def parse(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> ParsedRepresentation: ...
    def normalize(self, parsed: ParsedRepresentation, detection: DetectionResult) -> NormalizationOutput: ...
    def capabilities(self) -> AdapterCapabilities: ...
    def limitations(self) -> list[Limitation]: ...
