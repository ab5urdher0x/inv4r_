"""Mapping package: runtime-approved packs, proposals, decisions."""

from inv4r.mapping.registry import (
    MappingDecision,
    MappingPack,
    MappingProposal,
    MappingRegistry,
    MappingRule,
    build_proposals,
    fact_from_rule,
)

__all__ = [
    "MappingDecision", "MappingPack", "MappingProposal", "MappingRegistry",
    "MappingRule", "build_proposals", "fact_from_rule",
]
