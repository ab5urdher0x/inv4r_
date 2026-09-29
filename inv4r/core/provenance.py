"""Provenance chain: append-only record of what happened to evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ProvenanceEvent:
    stage: str
    actor: str
    decision: str
    detail: str = ""
    timestamp: str = field(default_factory=_now)

    def to_json(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "stage": self.stage,
            "actor": self.actor,
            "decision": self.decision,
            "detail": self.detail,
        }


@dataclass
class ProvenanceChain:
    evidence_id: str
    events: list[ProvenanceEvent] = field(default_factory=list)

    def add(self, stage: str, actor: str, decision: str, detail: str = "") -> None:
        self.events.append(ProvenanceEvent(stage, actor, decision, detail))

    def to_json(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "events": [e.to_json() for e in self.events],
        }
