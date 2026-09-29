"""Core vendor-independent data model. Everything here is vendor-agnostic."""

from inv4r.core.coverage import CoverageReport, compute_coverage, LEVEL_NAMES
from inv4r.core.envelope import EvidenceEnvelope, envelope_from_file, make_envelope, discover_evidence
from inv4r.core.facts import (
    CANONICAL_FACTS,
    FACT_VERSION,
    FactStatus,
    SecurityFact,
    is_well_formed_name,
    normalize_fact_name,
    vocabulary_json,
)
from inv4r.core.model import (
    CanonicalRelationship,
    CanonicalResource,
    RELATIONSHIP_TYPES,
    RESOURCE_TYPES,
    SourceSpan,
    StructuralNode,
)
from inv4r.core.provenance import ProvenanceChain, ProvenanceEvent
from inv4r.core.registry import ArtifactRegistry

__all__ = [
    "CANONICAL_FACTS", "CoverageReport", "EvidenceEnvelope", "FACT_VERSION",
    "FactStatus", "LEVEL_NAMES", "ProvenanceChain", "ProvenanceEvent",
    "RELATIONSHIP_TYPES", "RESOURCE_TYPES", "SecurityFact", "SourceSpan",
    "StructuralNode", "ArtifactRegistry", "canonical_fact_type", "compute_coverage",
    "discover_evidence", "envelope_from_file", "is_well_formed_name",
    "make_envelope", "normalize_fact_name", "vocabulary_json",
]


def canonical_fact_type(name: str) -> str:
    return CANONICAL_FACTS.get(name, ("string", ""))[0]
