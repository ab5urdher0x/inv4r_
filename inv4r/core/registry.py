"""Artifact registry: writes/loads pipeline artifacts under an output directory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ArtifactRegistry:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _write(self, name: str, payload: dict[str, Any]) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    def save_envelope(self, eid: str, payload: dict[str, Any]) -> Path:
        return self._write(f"envelope-{eid}.json", payload)

    def save_detection(self, eid: str, payload: dict[str, Any]) -> Path:
        return self._write(f"detection-{eid}.json", payload)

    def save_parsed(self, eid: str, payload: dict[str, Any]) -> Path:
        return self._write(f"parsed-{eid}.json", payload)

    def save_facts(self, eid: str, payload: dict[str, Any]) -> Path:
        return self._write(f"facts-{eid}.json", payload)

    def save_unknown(self, eid: str, payload: dict[str, Any]) -> Path:
        return self._write(f"unknown-{eid}.json", payload)

    def append_audit(self, eid: str, provenance) -> Path:
        """Append-only provenance artifact (audit-<eid>.json)."""
        import hashlib

        def fp(ev: dict[str, Any]) -> str:
            return hashlib.sha256(json.dumps(ev, sort_keys=True, default=str).encode()).hexdigest()[:16]

        name = f"audit-{eid}.json"
        path = self.root / name
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                existing = {"evidence_id": eid, "events": [], "integrity_notes": []}
        else:
            existing = {"evidence_id": eid, "events": [], "integrity_notes": []}

        events = list(existing.get("events") or [])
        seen_fps = {fp(e) for e in events}
        notes = list(existing.get("integrity_notes") or [])
        added = 0
        for ev in provenance.events:
            evj = ev.to_json()
            f = fp(evj)
            if f in seen_fps:
                continue
            key4 = (evj["stage"], evj["actor"], evj["decision"], evj["timestamp"])
            conflict = next((x for x in events
                             if (x["stage"], x["actor"], x["decision"], x["timestamp"]) == key4
                             and x["detail"] != evj["detail"]), None)
            if conflict:
                notes.append({"reason": "event_conflict", "preserved": conflict,
                              "incoming": evj})
                continue
            events.append(evj)
            seen_fps.add(f)
            added += 1

        existing["events"] = events
        existing["integrity_notes"] = notes
        existing["event_count"] = len(events)
        path.write_text(json.dumps(existing, indent=2, default=str), encoding="utf-8")
        return path

    def save_assessment(self, payload: dict[str, Any]) -> Path:
        return self._write("assessment.json", payload)

    def save_session(self, payload: dict[str, Any]) -> Path:
        return self._write("session.json", payload)

    def read_json(self, name: str) -> dict[str, Any]:
        return json.loads((self.root / name).read_text(encoding="utf-8"))

    def exists(self, name: str) -> bool:
        return (self.root / name).exists()

    def evidence_ids(self) -> list[str]:
        ids: set[str] = set()
        for p in self.root.glob("detection-*.json"):
            ids.add(p.stem.removeprefix("detection-"))
        return sorted(ids)

    def load_all(self, eid: str) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for prefix in ("envelope", "detection", "parsed", "facts", "unknown"):
            name = f"{prefix}-{eid}.json"
            if self.exists(name):
                out[prefix] = self.read_json(name)
        return out
