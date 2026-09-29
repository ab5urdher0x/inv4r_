"""Universal adapter resolver — picks the best adapter by tier and match score."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from inv4r.adapters.base import AdapterMatch, UniversalAdapter
from inv4r.core.envelope import EvidenceEnvelope
from inv4r.detection import DetectionResult

TIER_ORDER = [1, 2, 3, 4, 5, 6, 7]

MIN_CONFIDENCE = 0.25


@dataclass
class Resolution:
    chosen: UniversalAdapter | None
    match: AdapterMatch | None
    considered: list[dict[str, Any]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "chosen_adapter": self.chosen.adapter_id if self.chosen else None,
            "match": self.match.to_json() if self.match else None,
            "considered": self.considered,
        }


class AdapterResolver:
    def __init__(self, adapters: list[UniversalAdapter]) -> None:
        self._adapters = list(adapters)

    def register(self, adapter: UniversalAdapter) -> None:
        self._adapters.append(adapter)

    def adapters(self) -> list[UniversalAdapter]:
        return list(self._adapters)

    def resolve(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> Resolution:
        candidates: list[tuple[UniversalAdapter, AdapterMatch]] = []
        considered: list[dict[str, Any]] = []

        for ad in self._adapters:
            try:
                m = ad.can_handle(evidence, detection)
            except Exception as exc:
                considered.append({"adapter_id": getattr(ad, "adapter_id", "?"),
                                   "error": str(exc)})
                continue
            considered.append(m.to_json())
            if m.confidence >= MIN_CONFIDENCE:
                candidates.append((ad, m))

        if not candidates:
            return Resolution(chosen=None, match=None, considered=considered)

        def sort_key(item: tuple[UniversalAdapter, AdapterMatch]):
            ad, m = item
            tier_boost = -0.5 if ad.tier == 4 else 0.0
            return (ad.tier, -(m.confidence + tier_boost))

        candidates.sort(key=sort_key)
        ad, m = candidates[0]
        return Resolution(chosen=ad, match=m, considered=considered)
