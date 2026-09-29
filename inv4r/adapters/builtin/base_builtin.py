"""Shared helpers for tier-2 deterministic parsers."""

from __future__ import annotations

import re
from typing import Any, Callable

from inv4r.adapters.base import (
    AdapterCapabilities,
    AdapterMatch,
    Limitation,
    NormalizationOutput,
    ParsedRepresentation,
)
from inv4r.adapters.generic_structural import GenericStructuralAdapter
from inv4r.core.envelope import EvidenceEnvelope
from inv4r.core.facts import CANONICAL_FACTS, FactStatus, SecurityFact
from inv4r.core.model import CanonicalRelationship, CanonicalResource, SourceSpan, StructuralNode
from inv4r.core.unknown import UnknownFragment, guess_category
from inv4r.detection import DetectionResult


def make_fact(name: str, status: str, value: Any, line: int | None,
              adapter_id: str, notes: str = "", confidence: float = 1.0,
              entity: str | None = None) -> SecurityFact | None:
    """Create a validated canonical fact; drop anything non-canonical (guard rail)."""
    if name not in CANONICAL_FACTS:
        return None
    span = SourceSpan(line, line) if line else None
    fact = SecurityFact(
        fact_id=f"sf-{abs(hash((name, str(value), line, entity))) % 10_000_000:07d}",
        name=name,
        status=status,
        value=value,
        confidence=confidence,
        evidence_spans=[{"line_start": span.line_start, "line_end": span.line_end}] if span else [],
        source_adapter=adapter_id,
        notes=notes,
        entity=entity,
    )
    return fact if not fact.validate() else None


def hash_strength(secret_line: str) -> str:
    """Classify password storage from a config line (device-type agnostic)."""
    s = secret_line.lower()
    if "$9$" in s or "scrypt" in s:
        return "scrypt"
    if "$6$" in s or "sha512" in s or "sha-512" in s:
        return "sha512"
    if "$5$" in s or "sha256" in s:
        return "sha256"
    if type9(s):
        return "scrypt"
    if "$1$" in s or "md5" in s:
        return "md5"
    if re.search(r"\bpassword\b", s) and "secret" not in s and "encrypted" not in s and "phash" not in s:
        return "plaintext"
    return "unknown"


def type9(s: str) -> bool:
    return bool(re.search(r"secret\s+9\s+", s))


class BuiltinParser:
    """Base for tier-2 parsers. Subclasses set identity fields and implement"""

    adapter_id: str = "builtin-base"
    adapter_version: str = "1.0.0"
    tier: int = 2
    vendor: str = ""
    platform: str = ""
    formats: tuple[str, ...] = ()

    def __init__(self) -> None:
        self._generic = GenericStructuralAdapter()


    def can_handle(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> AdapterMatch:
        if detection.vendor == self.vendor and detection.input_format in self.formats:
            return AdapterMatch(self.adapter_id, self.tier, 0.9,
                                f"built-in deterministic parser for {self.vendor}")
        return AdapterMatch(self.adapter_id, self.tier, 0.0, "not this vendor/format")

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(parses_format=self.formats[0],
                                   normalizes_to_resources=True,
                                   produces_security_facts=True)

    def limitations(self) -> list[Limitation]:
        return [Limitation("deterministic_subset",
                           "Covers common hardening-relevant statements; exotic features are "
                           "reported as unknown fragments.")]

    def parse(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> ParsedRepresentation:
        parsed = self._generic.parse(evidence, detection)
        parsed.adapter_id = self.adapter_id
        parsed.tier = self.tier
        parsed.warnings = parsed.warnings[:0]
        parsed.notes["evidence_text"] = evidence.content
        return parsed

    def normalize(self, parsed: ParsedRepresentation, detection: DetectionResult) -> NormalizationOutput:
        out = NormalizationOutput()
        self.extract(parsed, detection, out)
        out.normalization_status = "FULL" if not out.unknown_fragments else "PARTIAL"
        return out


    def extract(self, parsed: ParsedRepresentation, detection: DetectionResult,
                out: NormalizationOutput) -> None:
        raise NotImplementedError


    @staticmethod
    def add_fragment(out: NormalizationOutput, path: str, raw_text: str, line: int) -> None:
        """Preserve an unmapped line AND ask the AI lane chain for a candidate.

        Without the proposer call here, every tier-2 fragment reached the review
        queue with a blank suggestion, forcing 100% manual mapping.
        """
        frag = UnknownFragment(
            fragment_id=f"uf-{abs(hash((path, line))) % 10_000_000:07d}",
            category=guess_category(path),
            reason="Not covered by deterministic parser; requires mapping",
            raw_path=path, raw_text=raw_text, source_span=SourceSpan(line, line),
        )
        try:
            from inv4r.adapters.generic_structural import propose_for_fragment
            proposal = propose_for_fragment(path, raw_text)
        except Exception:
            proposal = None
        if proposal:
            frag.suggested_fact = proposal[0]
            frag.suggestion_confidence = proposal[1]
            frag.suggested_by = (proposal[2].get("model", "rules")
                                 if len(proposal) > 2 else "rules")
        out.unknown_fragments.append(frag)

    @staticmethod
    def add_resource(out: NormalizationOutput, rid: str, rtype: str, name: str,
                     vendor: str, platform: str, attrs: dict[str, Any],
                     line: int | None = None, raw_text: str = "") -> CanonicalResource:
        return CanonicalResource(
            resource_id=rid,
            resource_type=rtype if rtype in {
                "interface", "route", "acl", "acl_rule", "service", "management_service",
                "user", "snmp_community", "ntp_server", "syslog_server", "security_group",
                "certificate", "banner", "other"} else "other",
            name=name, vendor=vendor, platform=platform,
            attributes=attrs,
            source_span=SourceSpan(line, line) if line else None,
            raw_text=raw_text,
        )
