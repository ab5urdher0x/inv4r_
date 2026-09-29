"""Evidence store: deterministic content-hash deduplication."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from inv4r.core.envelope import EvidenceEnvelope, make_envelope


class EvidenceIntegrityError(RuntimeError):
    """Raised when a stored evidence record would be mutated."""


@dataclass
class EvidenceRef:
    envelope: EvidenceEnvelope
    duplicate: bool
    duplicate_of: str


class EvidenceStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _dir_for(self, sha256: str) -> Path:
        return self.root / sha256[:16]

    def _record_path(self, sha256: str) -> Path:
        return self._dir_for(sha256) / "evidence.json"

    def lookup(self, sha256: str) -> EvidenceEnvelope | None:
        p = self._record_path(sha256)
        if not p.exists():
            return None
        return self._envelope_from_record(json.loads(p.read_text(encoding="utf-8")))

    def _envelope_from_record(self, rec: dict[str, Any]) -> EvidenceEnvelope:
        return EvidenceEnvelope(
            evidence_id=rec["evidence_id"],
            source_path=rec.get("source_path", ""),
            content=rec.get("content", ""),
            raw_bytes_sha256=rec["hashes"]["sha256"],
            raw_bytes_md5=rec["hashes"]["md5"],
            size_bytes=rec.get("size_bytes", 0),
            line_count=rec.get("line_count", 0),
            metadata=rec.get("metadata") or {},
        )

    def ingest_bytes(self, data: bytes, source_path: str,
                     metadata: dict[str, Any] | None = None) -> EvidenceRef:
        """Deduplicating ingest. Same bytes => same envelope, duplicate=True."""
        import hashlib

        sha = hashlib.sha256(data).hexdigest()
        existing = self.lookup(sha)
        if existing is not None:
            return EvidenceRef(envelope=existing, duplicate=True,
                               duplicate_of=existing.evidence_id)

        env = make_envelope(data, source_path, metadata)
        d = self._dir_for(sha)
        d.mkdir(parents=True, exist_ok=True)
        record = {
            "evidence_id": env.evidence_id,
            "source_path": source_path,
            "hashes": {"sha256": env.raw_bytes_sha256, "md5": env.raw_bytes_md5},
            "size_bytes": env.size_bytes,
            "line_count": env.line_count,
            "metadata": env.metadata,
            "content": env.content,
        }
        rec_path = self._record_path(sha)
        if rec_path.exists():
            raise EvidenceIntegrityError(
                f"evidence record for {sha[:16]} already exists; raw evidence is immutable")
        rec_path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        return EvidenceRef(envelope=env, duplicate=False, duplicate_of="")
