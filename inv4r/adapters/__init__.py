"""Adapter package: base contract, resolver, generic parser, built-ins, mapping adapter."""

from inv4r.adapters.base import (
    AdapterCapabilities,
    AdapterMatch,
    Limitation,
    NormalizationOutput,
    ParsedRepresentation,
    UniversalAdapter,
)
from inv4r.adapters.resolver import AdapterResolver, Resolution

__all__ = [
    "AdapterCapabilities", "AdapterMatch", "AdapterResolver", "Limitation",
    "NormalizationOutput", "ParsedRepresentation", "Resolution", "UniversalAdapter",
]
