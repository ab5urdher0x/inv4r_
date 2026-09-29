"""Tier-4 runtime-approved mapping adapter."""

from __future__ import annotations

from inv4r.adapters.base import (
    AdapterCapabilities,
    AdapterMatch,
    Limitation,
    NormalizationOutput,
    ParsedRepresentation,
)
from inv4r.adapters.generic_structural import GenericStructuralAdapter
from inv4r.core.envelope import EvidenceEnvelope
from inv4r.core.facts import FactStatus, SecurityFact
from inv4r.core.model import SourceSpan
from inv4r.core.unknown import UnknownFragment, guess_category
from inv4r.detection import DetectionResult
from inv4r.mapping.registry import MappingRegistry, fact_from_rule


class RuntimeMappingAdapter:
    adapter_id = "runtime-mapping"
    adapter_version = "1.0.0"
    tier = 4

    def __init__(self, registry: MappingRegistry) -> None:
        self._registry = registry
        self._generic = GenericStructuralAdapter()

    def can_handle(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> AdapterMatch:
        packs = self._registry.packs_for(detection.vendor, detection.platform, evidence.content)
        if packs:
            ids = ",".join(p.map_id for p in packs[:3])
            return AdapterMatch(self.adapter_id, self.tier, 0.9,
                                f"approved mapping pack(s): {ids}")
        return AdapterMatch(self.adapter_id, self.tier, 0.0, "no approved mapping pack")

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            parses_format="any (via generic structural parser)",
            normalizes_to_resources=False,
            produces_security_facts=True,
            requires_human_mapping=False,
        )

    def limitations(self) -> list[Limitation]:
        return [
            Limitation("mapping_scoped", "Facts only for rules a human approved."),
            Limitation("structural_base", "Inherits generic parser block heuristics."),
        ]

    def parse(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> ParsedRepresentation:
        parsed = self._generic.parse(evidence, detection)
        parsed.adapter_id = self.adapter_id
        parsed.tier = self.tier
        parsed.warnings = [w for w in parsed.warnings if "semantics" not in w]
        parsed.warnings.append("Normalized via human-approved mapping pack (deterministic).")
        parsed.notes["evidence_text"] = evidence.content
        return parsed

    def normalize(self, parsed: ParsedRepresentation, detection: DetectionResult) -> NormalizationOutput:
        out = NormalizationOutput(normalization_status="PARTIAL")
        packs = self._registry.packs_for(detection.vendor, detection.platform,
                                         parsed.notes.get("evidence_text", ""))
        rules = [r for p in packs for r in p.rules]

        fragments: list[UnknownFragment] = []
        matched_paths: set[str] = set()

        for node in parsed.root.walk():
            if node.node_type in ("comment",) or node is parsed.root:
                continue
            path = ".".join(node.path)
            if not path:
                continue
            hit = None
            for rule in rules:
                if rule.matches(path, node.value):
                    hit = rule
                    break
            if hit:
                matched_paths.add(path)
                fact = fact_from_rule(hit, path, node.value, node.source_span, self.adapter_id)
                if fact:
                    out.facts.append(fact)
            else:
                frag = UnknownFragment(
                    fragment_id=f"uf-{abs(hash(path)) % 10_000_000:07d}",
                    category=guess_category(path),
                    reason="No approved mapping rule for this path",
                    raw_path=path,
                    raw_text=node.raw_text or path,
                    source_span=node.source_span or SourceSpan(0),
                )
                try:
                    from inv4r.adapters.generic_structural import propose_for_fragment
                    proposal = propose_for_fragment(path, node.value or "")
                except Exception:
                    proposal = None
                if proposal:
                    frag.suggested_fact = proposal[0]
                    frag.suggestion_confidence = proposal[1]
                    frag.suggested_by = (proposal[2].get("model", "rules")
                                         if len(proposal) > 2 else "rules")
                fragments.append(frag)

        out.unknown_fragments = fragments[:400]
        out.normalization_status = "FULL" if not fragments else "PARTIAL"
        return out
