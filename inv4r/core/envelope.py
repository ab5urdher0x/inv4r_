"""Universal evidence envelope: the immutable container for any ingested input."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SUPPORTED_SUFFIXES = {
    ".cfg", ".conf", ".txt", ".log", ".json", ".xml", ".yaml", ".yml",
    ".set", ".boot", ".rsc", ".unf", ".bat", ".py",
}


def _hash(data: bytes) -> dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
    }


@dataclass
class EvidenceEnvelope:
    """Level-0 container. Raw bytes are never mutated; everything downstream"""

    evidence_id: str
    source_path: str
    content: str
    raw_bytes_sha256: str
    raw_bytes_md5: str
    size_bytes: int
    line_count: int
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def lines(self) -> list[str]:
        return self.content.splitlines()

    def to_json(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_path": self.source_path,
            "hashes": {"sha256": self.raw_bytes_sha256, "md5": self.raw_bytes_md5},
            "size_bytes": self.size_bytes,
            "line_count": self.line_count,
            "metadata": self.metadata,
        }


def make_envelope(data: bytes, source_path: str, metadata: dict[str, Any] | None = None) -> EvidenceEnvelope:
    """Build an envelope from raw bytes. Preserves Level-0 guarantees."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    return EvidenceEnvelope(
        evidence_id=uuid.uuid4().hex[:16],
        source_path=source_path,
        content=text,
        raw_bytes_sha256=_hash(data)["sha256"],
        raw_bytes_md5=_hash(data)["md5"],
        size_bytes=len(data),
        line_count=text.count("\n") + (0 if text.endswith("\n") or not text else 1),
        metadata=dict(metadata or {}),
    )


def envelope_from_file(path: str | Path, metadata: dict[str, Any] | None = None) -> EvidenceEnvelope:
    p = Path(path)
    return make_envelope(p.read_bytes(), str(p), metadata)


def discover_evidence(root: str | Path) -> list[Path]:
    """Find candidate evidence files under a file or directory."""
    root = Path(root)
    if root.is_file():
        return [root]
    files: list[Path] = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and (p.suffix.lower() in SUPPORTED_SUFFIXES or not p.suffix):
            files.append(p)
    return files
