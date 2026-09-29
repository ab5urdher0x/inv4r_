"""Pipeline orchestrator — the vendor-independent core engine."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from inv4r.adapters import AdapterResolver, Resolution
from inv4r.adapters.base import NormalizationOutput, ParsedRepresentation
from inv4r.adapters.builtin import default_adapters
from inv4r.adapters.builtin.batfish_bridge import (BatfishBridgeAdapter,
                                                   merge_secondary_batfish_facts)
from inv4r.adapters.external_engine import ExternalEngineAdapter
from inv4r.adapters.generic_structural import GenericStructuralAdapter
from inv4r.adapters.runtime_mapping import RuntimeMappingAdapter
from inv4r.core.coverage import CoverageReport, compute_coverage
from inv4r.core.evidence_store import EvidenceStore
from inv4r.core.envelope import EvidenceEnvelope, discover_evidence
from inv4r.core.facts import FACT_VERSION, SecurityFact
from inv4r.detection.universal import detection_version
from inv4r.core.model import CanonicalRelationship, CanonicalResource
from inv4r.core.provenance import ProvenanceChain
from inv4r.core.registry import ArtifactRegistry
from inv4r.core.unknown import UnknownFragment
from inv4r.detection import DetectionResult, detect
from inv4r.mapping.registry import MappingRegistry


@dataclass
class DeviceResult:
    """Everything the pipeline learned about one evidence file."""

    envelope: EvidenceEnvelope
    detection: DetectionResult
    resolution: Resolution
    parsed: ParsedRepresentation | None
    normalization: NormalizationOutput | None
    coverage: CoverageReport
    provenance: ProvenanceChain
    errors: list[str] = field(default_factory=list)

    @property
    def facts(self) -> list[SecurityFact]:
        """Live facts, or the rehydrated facts from a loaded assessment."""
        if self.normalization is not None:
            return list(self.normalization.facts)
        return list(getattr(self, "_facts_json", []) or [])

    @property
    def vendor(self) -> str:
        return self.detection.vendor

    @property
    def platform(self) -> str:
        return self.detection.platform

    def to_json(self) -> dict[str, Any]:
        return {
            "envelope": self.envelope.to_json(),
            "detection": self.detection.to_json(),
            "resolution": self.resolution.to_json() if self.resolution else None,
            "parsed": self.parsed.to_json() if self.parsed else None,
            "normalization": self.normalization.to_json() if self.normalization else None,
            "coverage": self.coverage.to_json(),
            "provenance": self.provenance.to_json(),
            "errors": self.errors,
        }


def _dedupe_facts(facts: list[SecurityFact]) -> list[SecurityFact]:
    """Collapse duplicate (name, status, value) facts, keeping all evidence spans."""
    seen: dict[tuple[str, str, Any], SecurityFact] = {}
    for f in facts:
        key = (f.name, f.status, f.value if isinstance(f.value, (str, int, float, bool)) else str(f.value))
        if key in seen:
            seen[key].evidence_spans.extend(f.evidence_spans)
            seen[key].evidence_spans = seen[key].evidence_spans[:12]
        else:
            seen[key] = f
    return list(seen.values())


class Engine:
    """Universal processing pipeline. Knows nothing about specific vendors."""

    def __init__(self, mapping_dir: str = "mappings", artifact_dir: str = "out",
                 evidence_dir: str | None = None,
                 include_pending: bool = False) -> None:
        # ``include_pending`` powers the provisional preview path: PENDING_REVIEW
        # mapping packs may be replayed so the operator sees a predicted result
        # immediately, while the authoritative assessment still uses ACTIVE only.
        self.mapping_registry = MappingRegistry(mapping_dir, include_pending=include_pending)
        self.registry = ArtifactRegistry(artifact_dir)
        self.evidence_store = EvidenceStore(evidence_dir or (Path(artifact_dir) / "evidence"))
        adapters = default_adapters()
        adapters.append(RuntimeMappingAdapter(self.mapping_registry))
        adapters.append(ExternalEngineAdapter())
        adapters.append(GenericStructuralAdapter())
        self.resolver = AdapterResolver(adapters)
        # One long-lived bridge instance so the per-content Batfish cache is
        # reused across the files of a batch instead of re-parsing each file.
        self.batfish = BatfishBridgeAdapter()

    def process_file(self, path: str) -> DeviceResult:
        ref = self.evidence_store.ingest_bytes(Path(path).read_bytes(), str(path))
        return self.process_envelope(ref.envelope, duplicate=ref.duplicate,
                                     duplicate_of=ref.duplicate_of)

    def process_envelope(self, env: EvidenceEnvelope, duplicate: bool = False,
                         duplicate_of: str = "") -> DeviceResult:
        prov = ProvenanceChain(evidence_id=env.evidence_id)
        prov.add("ingest", "engine", "duplicate" if duplicate else "stored",
                 f"sha256={env.raw_bytes_sha256[:16]}" +
                 (f" duplicate_of={duplicate_of}" if duplicate else ""))

        detection = detect(env.content, env.source_path.rsplit("/", 1)[-1])
        prov.add("detect", "detection", detection.vendor,
                 f"format={detection.input_format} conf={detection.confidence}")

        resolution = self.resolver.resolve(env, detection)
        prov.add("resolve", "resolver",
                 resolution.chosen.adapter_id if resolution.chosen else "none",
                 resolution.match.reason if resolution.match else "no adapter matched")

        parsed: ParsedRepresentation | None = None
        normalization: NormalizationOutput | None = None
        errors: list[str] = []

        if resolution.chosen:
            try:
                parsed = resolution.chosen.parse(env, detection)
                prov.add("parse", f"adapter:{resolution.chosen.adapter_id}", "ok",
                         f"nodes={parsed.notes.get('node_count', '?')}")
            except Exception as exc:
                errors.append(f"parse failed: {exc}")
                prov.add("parse", f"adapter:{resolution.chosen.adapter_id}", "error", str(exc))

            if parsed is not None:
                try:
                    normalization = resolution.chosen.normalize(parsed, detection)
                    normalization.facts = _dedupe_facts(normalization.facts)
                    prov.add("normalize", f"adapter:{resolution.chosen.adapter_id}",
                             normalization.normalization_status,
                             f"facts={len(normalization.facts)} unknown={len(normalization.unknown_fragments)}")
                except Exception as exc:
                    errors.append(f"normalize failed: {exc}")
                    prov.add("normalize", f"adapter:{resolution.chosen.adapter_id}", "error", str(exc))
                    normalization = None

            if parsed is not None and normalization is not None:
                # The tier-3 adapter already ran the bridge during normalize().
                chosen_id = resolution.chosen.adapter_id if resolution.chosen else ""
                # Never enrich a tier-4 structural parse of an UNKNOWN config:
                # Batfish-derived facts for unidentifiable input would let an
                # unknown device PASS controls (P0 regression). Tier-3
                # 'external-engine' already ran the bridge during normalize().
                if chosen_id not in ("external-engine", "generic-structural"):
                    try:
                        parsed.notes.setdefault("evidence_text", env.content)
                        parsed.notes.setdefault("filename", Path(env.source_path).name)
                        bf_out = NormalizationOutput()
                        if self.batfish.extract(parsed, detection, bf_out):
                            before = len(normalization.facts)
                            normalization.facts = merge_secondary_batfish_facts(
                                normalization.facts, bf_out.facts)
                            known_ids = {r.resource_id for r in normalization.resources}
                            normalization.resources.extend(
                                r for r in bf_out.resources if r.resource_id not in known_ids)
                            normalization.facts = _dedupe_facts(normalization.facts)
                            prov.add("enrich", "adapter:builtin-batfish-bridge", "merged",
                                     f"batfish_facts={len(bf_out.facts)} "
                                     f"total={before}->{len(normalization.facts)}")
                    except Exception as exc:
                        logger.warning(f"Batfish secondary enrichment skipped: {exc}")

        coverage = compute_coverage(
            has_envelope=True,
            has_structure=parsed is not None,
            vendor_identified=detection.vendor != "unknown",
            resources_count=len(normalization.resources) if normalization else 0,
            facts_count=len(normalization.facts) if normalization else 0,
            controls_evaluated=False,
        )
        prov.add("coverage", "engine", f"level={coverage.achieved_level}", "; ".join(coverage.reasons))

        resolved_pack_version = self.resolved_pack_version(detection, env.content)
        prov.add("logic_versions", "engine", "recorded",
                 f"adapter={resolution.chosen.adapter_id}@{resolution.chosen.adapter_version} "
                 f"detection={detection_version()} "
                 f"facts_vocabulary={FACT_VERSION} "
                 + (f"pack={resolved_pack_version}" if resolved_pack_version else ""))

        result = DeviceResult(
            envelope=env, detection=detection, resolution=resolution,
            parsed=parsed, normalization=normalization,
            coverage=coverage, provenance=prov, errors=errors,
        )
        self._persist(result)
        return result

    def process_path(self, path: str) -> list[DeviceResult]:
        return [self.process_file(str(p)) for p in discover_evidence(path)]

    def _persist(self, r: DeviceResult) -> None:
        eid = r.envelope.evidence_id
        self.registry.save_envelope(eid, r.envelope.to_json())
        self.registry.save_detection(eid, r.detection.to_json())
        self.registry.save_parsed(eid, r.parsed.to_json() if r.parsed else {"evidence_id": eid})
        self.registry.save_facts(eid, {
            "evidence_id": eid,
            "vendor": r.vendor,
            "platform": r.platform,
            "coverage": r.coverage.to_json(),
            "resources": [x.to_json() for x in r.normalization.resources] if r.normalization else [],
            "relationships": [x.to_json() for x in r.normalization.relationships] if r.normalization else [],
            "facts": [x.to_json() for x in r.facts],
        })
        unknown_payload = {
            "evidence_id": eid,
            "vendor": r.vendor,
            "unknown_fragments": [x.to_json() for x in r.normalization.unknown_fragments] if r.normalization else [],
            "normalization_status": r.normalization.normalization_status if r.normalization else "NONE",
        }
        self.registry.save_unknown(eid, unknown_payload)
        self.registry.append_audit(eid, r.provenance)

    def resolved_pack_version(self, detection: DetectionResult, evidence_text: str) -> str:
        """Version stamp of the ACTIVE pack(s) consulted for this evidence."""
        packs = self.mapping_registry.packs_for(detection.vendor, detection.platform, evidence_text)
        return "+".join(f"{p.map_id}@v{p.version}" for p in packs)
