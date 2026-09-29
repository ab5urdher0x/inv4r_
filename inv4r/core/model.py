"""Canonical vendor-neutral model: resources, relationships, states."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SourceSpan:
    """Line provenance back to the raw evidence file."""

    __slots__ = ("line_start", "line_end")

    def __init__(self, line_start: int, line_end: int | None = None) -> None:
        self.line_start = int(line_start)
        self.line_end = int(line_end if line_end is not None else line_start)

    def to_json(self) -> dict[str, int]:
        return {"line_start": self.line_start, "line_end": self.line_end}


@dataclass
class StructuralNode:
    """Tier-5 universal structural representation: blocks/keys/values with"""

    node_type: str
    name: str
    path: list[str] = field(default_factory=list)
    value: str | None = None
    raw_text: str = ""
    source_span: SourceSpan | None = None
    children: list["StructuralNode"] = field(default_factory=list)

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()

    def find(self, path: list[str]) -> "StructuralNode | None":
        """Find the first descendant whose path equals `path`."""
        target = list(path)
        for n in self.walk():
            if n.path == target:
                return n
        return None

    def to_json(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "node_type": self.node_type,
            "name": self.name,
            "path": self.path,
        }
        if self.value is not None:
            d["value"] = self.value
        if self.raw_text:
            d["raw_text"] = self.raw_text
        if self.source_span:
            d["source_span"] = self.source_span.to_json()
        if self.children:
            d["children"] = [c.to_json() for c in self.children]
        return d


@dataclass
class CanonicalResource:
    """A normalized network resource (interface, route, ACL, service, object...)."""

    resource_id: str
    resource_type: str
    name: str
    vendor: str
    platform: str
    attributes: dict[str, Any] = field(default_factory=dict)
    source_span: SourceSpan | None = None
    raw_text: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "name": self.name,
            "vendor": self.vendor,
            "platform": self.platform,
            "attributes": self.attributes,
            "source_span": self.source_span.to_json() if self.source_span else None,
            "raw_text": self.raw_text,
        }


@dataclass
class CanonicalRelationship:
    """Edge between resources: acl applied_on interface, route via interface..."""

    relationship_type: str
    source_id: str
    target_id: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "relationship_type": self.relationship_type,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "attributes": self.attributes,
        }


RESOURCE_TYPES = {
    "interface", "route", "acl", "acl_rule", "service", "management_service",
    "user", "snmp_community", "ntp_server", "syslog_server", "security_group",
    "certificate", "banner", "other",
}

RELATIONSHIP_TYPES = {"applied_on", "member_of", "via", "connects", "uses", "references"}
