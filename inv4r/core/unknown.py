"""UnknownFragment: preserves structurally-parsed but semantically unmapped content."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from inv4r.core.model import SourceSpan, StructuralNode

CATEGORIES = [
    "management_access", "authentication", "logging", "snmp", "network_services",
    "firewall_policy", "crypto", "routing", "interfaces", "other",
]


@dataclass
class UnknownFragment:
    """A fragment whose security semantics could not be mapped. Raw text is"""

    fragment_id: str
    category: str
    status: str = "UNKNOWN"
    reason: str = "No approved semantic mapping"
    raw_path: str = ""
    raw_text: str = ""
    source_span: SourceSpan | None = None
    suggested_fact: str | None = None
    suggestion_confidence: float = 0.0
    suggested_by: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "fragment_id": self.fragment_id,
            "category": self.category,
            "status": self.status,
            "reason": self.reason,
            "raw_path": self.raw_path,
            "raw_text": self.raw_text,
            "source_span": self.source_span.to_json() if self.source_span else None,
            "suggested_fact": self.suggested_fact,
            "suggestion_confidence": round(float(self.suggestion_confidence), 3),
            "suggested_by": self.suggested_by,
        }


def fragment_from_node(node: StructuralNode, category: str = "other",
                       reason: str = "No approved semantic mapping") -> UnknownFragment:
    span = node.source_span or SourceSpan(0, 0)
    return UnknownFragment(
        fragment_id=f"uf-{abs(hash((node.name, span.line_start))) % 10_000_000:07d}",
        category=category,
        reason=reason,
        raw_path=".".join(node.path) if node.path else node.name,
        raw_text=node.raw_text or node.name,
        source_span=span,
    )


def guess_category(path: str) -> str:
    """Cheap heuristic bucketing for display purposes only — never a semantic claim."""
    p = path.lower()
    if any(k in p for k in ("ssh", "telnet", "web", "http", "vty", "service", "management")):
        return "management_access"
    if any(k in p for k in ("aaa", "auth", "login", "user", "password", "secret")):
        return "authentication"
    if "log" in p:
        return "logging"
    if "snmp" in p:
        return "snmp"
    if any(k in p for k in ("acl", "access-list", "policy", "firewall", "zone")):
        return "firewall_policy"
    if any(k in p for k in ("route", "ospf", "bgp", "eigrp")):
        return "routing"
    if any(k in p for k in ("interface", "vlan", "port")):
        return "interfaces"
    if any(k in p for k in ("crypto", "cert", "key")):
        return "crypto"
    if any(k in p for k in ("ntp", "snmp", "dns")):
        return "network_services"
    return "other"
