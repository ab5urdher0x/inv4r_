"""Universal vendor profile format."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class VendorProfile:
    profile_id: str
    vendor: str
    platform: str
    version_range: dict[str, str] = field(default_factory=dict)
    input_formats: list[str] = field(default_factory=list)
    structural_parser: str = "generic_hierarchical_cli"
    grammar: str | None = None
    schemas: list[str] = field(default_factory=list)
    mappings: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    security_fact_coverage: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    source_path: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id, "vendor": self.vendor, "platform": self.platform,
            "version_range": self.version_range, "input_formats": self.input_formats,
            "structural_parser": self.structural_parser, "grammar": self.grammar,
            "schemas": self.schemas, "mappings": self.mappings,
            "capabilities": self.capabilities,
            "security_fact_coverage": self.security_fact_coverage,
            "limitations": self.limitations, "source_path": self.source_path,
        }


class ProfileLoader:
    def __init__(self, directory: str | Path = "profiles") -> None:
        self.directory = Path(directory)
        self.profiles: dict[str, VendorProfile] = {}
        if self.directory.exists():
            self.reload()

    def reload(self) -> None:
        self.profiles = {}
        for p in sorted(self.directory.glob("*.yaml")):
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            if not data.get("profile_id") or not data.get("vendor"):
                continue
            prof = VendorProfile(
                profile_id=data["profile_id"],
                vendor=data["vendor"],
                platform=data.get("platform", data["vendor"]),
                version_range=data.get("version_range") or {},
                input_formats=list(data.get("input_formats") or []),
                structural_parser=data.get("structural_parser", "generic_hierarchical_cli"),
                grammar=data.get("grammar"),
                schemas=list(data.get("schemas") or []),
                mappings=list(data.get("mappings") or []),
                capabilities=list(data.get("capabilities") or []),
                security_fact_coverage=list(data.get("security_fact_coverage") or []),
                limitations=list(data.get("limitations") or []),
                source_path=str(p),
            )
            self.profiles[prof.profile_id] = prof

    def for_detection(self, vendor: str, platform: str) -> VendorProfile | None:
        for prof in self.profiles.values():
            if prof.vendor == vendor or (platform and prof.platform == platform):
                return prof
        return None
