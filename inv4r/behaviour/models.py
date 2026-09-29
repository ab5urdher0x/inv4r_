"""Behaviour query contracts: the intermediate object between natural"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

QUERY_TYPES = (
    "reachability",
    "path_trace",
    "route_check",
    "acl_check",
    "segmentation",
    "network_health",
)

# Configurable security invariants. Each is a (source, destination, expected
# action) definition evaluated by Batfish — not a hardcoded copy of one check.
# Extend this list rather than adding bespoke verification logic per page.
INVARIANTS: list[dict[str, Any]] = [
    {
        "id": "NET-001",
        "title": "Internet must not reach management",
        "description": "Management-plane interfaces must not be reachable from the internet.",
        "source": "0.0.0.0/0",
        "destination": "management",
        "destination_hint": "management subnet, e.g. 10.10.10.0/24",
        "protocol": "tcp",
        "port": 22,
        "expected": "DENIED",
    },
    {
        "id": "NET-002",
        "title": "Guest network must not reach internal segment",
        "description": "The guest VLAN must be segmented from internal corporate segments.",
        "source": "guest",
        "source_hint": "guest VLAN subnet, e.g. 192.168.50.0/24",
        "destination": "internal",
        "destination_hint": "internal segment subnet, e.g. 10.20.0.0/16",
        "protocol": "tcp",
        "port": 443,
        "expected": "DENIED",
    },
    {
        "id": "NET-003",
        "title": "Internet must not reach OT/ICS VLAN",
        "description": "Operational-technology / ICS VLANs must not be reachable from the internet.",
        "source": "0.0.0.0/0",
        "destination": "ot-vlan",
        "destination_hint": "OT/ICS VLAN subnet, e.g. 10.30.30.0/24",
        "protocol": "tcp",
        "port": 102,
        "expected": "DENIED",
    },
]


def invariant_by_id(invariant_id: str) -> dict[str, Any] | None:
    for inv in INVARIANTS:
        if inv["id"] == invariant_id:
            return inv
    return None


def invariant_needs_endpoints(inv: dict[str, Any]) -> list[dict[str, str]]:
    """Which endpoints of this invariant the operator must supply.

    A symbolic endpoint such as "management" documents the intent but is not
    an ipSpace Batfish can evaluate, so the UI must ask for the real subnet
    instead of the backend silently widening it to 0.0.0.0/0.
    """
    from inv4r.behaviour.engine import endpoint_spec

    needed: list[dict[str, str]] = []
    for role in ("source", "destination"):
        value = inv.get(role)
        _spec, err = endpoint_spec(value)
        if err:
            needed.append({"role": role, "value": str(value or ""),
                           "hint": str(inv.get(f"{role}_hint") or err)})
    return needed


def invariant_to_query(inv: dict[str, Any], source: str | None = None,
                       destination: str | None = None, protocol: str | None = None,
                       port: int | None = None, node: str | None = None,
                       qtype: str = "reachability") -> "BehaviourQuery":
    """Build the query that decides an invariant, with operator overrides."""
    return BehaviourQuery(
        type=qtype,
        source=source if source is not None else inv.get("source"),
        destination=(destination if destination is not None
                     else inv.get("destination")),
        protocol=protocol or inv.get("protocol"),
        destination_port=port if port is not None else inv.get("port"),
        node=node,
        raw_text=inv.get("title", ""),
    )


def invariant_verdict(expected: str, behaviour_status: str) -> str:
    """Map a Batfish reachability status to PASS/FAIL for the expected action.

    ``expected=DENIED`` means PASS when traffic cannot flow (Batfish FAIL) and
    FAIL when it can flow (Batfish PASS). UNKNOWN stays UNKNOWN — never guessed.
    """
    if behaviour_status == "UNKNOWN":
        return "UNKNOWN"
    reachable = behaviour_status == "PASS"
    if str(expected).upper() == "DENIED":
        return "FAIL" if reachable else "PASS"
    if str(expected).upper() in ("ALLOWED", "PERMITTED"):
        return "PASS" if reachable else "FAIL"
    return "UNKNOWN"

FAIL_REASONS = {
    "no_route": "No route to destination",
    "acl_denial": "Denied by access control list",
    "unreachable_next_hop": "Next-hop is unreachable",
    "incorrect_forwarding": "Forwarded to the wrong next-hop/interface",
    "missing_path": "No complete forwarding path exists",
    "denied": "Traffic denied by policy",
    "no_path": "No path found between source and destination",
}


@dataclass
class BehaviourQuery:
    type: str
    source: str | None = None
    destination: str | None = None
    protocol: str | None = None
    destination_port: int | None = None
    prefix: str | None = None
    node: str | None = None
    raw_text: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "destination_port": self.destination_port,
            "prefix": self.prefix,
            "node": self.node,
            "raw_text": self.raw_text,
        }

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "BehaviourQuery":
        t = str(d.get("type", "")).strip().lower()
        if t not in QUERY_TYPES:
            raise ValueError(f"query type must be one of {QUERY_TYPES}")
        port = d.get("destination_port")
        return cls(
            type=t,
            source=(d.get("source") or None),
            destination=(d.get("destination") or None),
            protocol=(d.get("protocol") or None),
            destination_port=int(port) if port not in (None, "") else None,
            prefix=(d.get("prefix") or None),
            node=(d.get("node") or None),
            raw_text=d.get("raw_text", ""),
        )


@dataclass
class Evidence:
    """One auditable piece of engine evidence attached to a result."""

    kind: str
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "summary": self.summary, "detail": self.detail}


@dataclass
class NetworkHop:
    node: str
    interface: str | None = None
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        d = {"node": self.node}
        if self.interface:
            d["interface"] = self.interface
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class BehaviourResult:
    type: str
    status: str
    summary: str
    source: str | None = None
    destination: str | None = None
    protocol: str | None = None
    destination_port: int | None = None
    prefix: str | None = None
    node: str | None = None
    fail_reason: str | None = None
    path: list[NetworkHop] = field(default_factory=list)
    relevant_devices: list[str] = field(default_factory=list)
    explanation: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    batfish_result: Any = None
    query: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "status": self.status,
            "summary": self.summary,
            "source": self.source,
            "destination": self.destination,
            "protocol": self.protocol,
            "destination_port": self.destination_port,
            "prefix": self.prefix,
            "node": getattr(self, "node", None),
            "fail_reason": self.fail_reason,
            "path": [h.to_json() for h in self.path],
            "relevant_devices": self.relevant_devices,
            "explanation": self.explanation,
            "evidence": [e.to_json() for e in self.evidence],
            "batfish_result": self.batfish_result,
            "query": self.query,
        }


@dataclass
class NetworkSituationReport:
    """Deterministic suite of checks — no vague AI verdicts, just per-check status."""

    checks: list[BehaviourResult] = field(default_factory=list)
    snapshot: str = ""
    batfish_available: bool = False

    def to_json(self) -> dict[str, Any]:
        passed = sum(1 for c in self.checks if c.status == "PASS")
        failed = sum(1 for c in self.checks if c.status == "FAIL")
        unknown = sum(1 for c in self.checks if c.status == "UNKNOWN")
        return {
            "snapshot": self.snapshot,
            "batfish_available": self.batfish_available,
            "summary": {
                "total": len(self.checks),
                "passed": passed,
                "failed": failed,
                "unknown": unknown,
            },
            "checks": [c.to_json() for c in self.checks],
        }


_PORT_MAP = {
    "ssh": 22, "telnet": 23, "http": 80, "https": 443, "dns": 53,
    "postgres": 5432, "postgresql": 5432, "mysql": 3306, "sql": 1433,
    "redis": 6379, "smtp": 25, "web": 80, "database": 5432, "db": 5432,
}

_IP_PREFIX_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
_NAME_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_-]{1,31})\b")
_ENDPOINT_WORDS = {"internet", "server", "firewall", "router", "switch",
                   "host", "vlan", "workstation", "management"}
_STOPWORDS = {
    "can", "the", "why", "how", "is", "are", "there", "a", "an", "to", "from",
    "reach", "reaches", "connect", "connects", "connectivity", "traffic",
    "show", "me", "trace", "path", "route", "routing", "check", "does",
    "device", "devices", "please",
    "what", "which", "block", "blocked", "blocking", "blocks",
    "acl", "access", "list", "segmentation", "segmented", "and", "with",
    "via", "port", "protocol", "tcp", "udp", "icmp", "get", "on", "of",
    "in", "my", "our", "all", "between", "for", "it", "be", "should",
    "network", "everything", "ok",
}


def _extract_endpoint(token: str, hints: set[str]) -> str | None:
    t = token.strip(" '\".,?")
    if not t:
        return None
    if _IP_PREFIX_RE.fullmatch(t):
        return t
    if t.lower() in hints:
        return t
    if t.lower() in _ENDPOINT_WORDS:
        return t
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*-?\d*", t) and any(c.isdigit() for c in t):
        return t
    return None


def _known_names(text: str) -> set[str]:
    """Best-effort endpoint-name extraction: capitalized tokens, tokens with"""
    names: set[str] = set()
    for m in _NAME_RE.finditer(text):
        t = m.group(1)
        low = t.lower()
        if low in _STOPWORDS:
            continue
        if any(c.isdigit() for c in t) or t[0].isupper():
            names.add(t)
    return names


def interpret(query: str) -> BehaviourQuery:
    """Convert natural language into a BehaviourQuery. Pure syntax heuristics —"""
    q = (query or "").strip()
    low = q.lower()
    names = _known_names(q)
    ips = _IP_PREFIX_RE.findall(q)
    hints = {n.lower() for n in names} | {i for i in ips}

    protocol, port = None, None
    pm = re.search(r"\b(tcp|udp|icmp)\b", low)
    if pm:
        protocol = pm.group(1)
    for proto_name, p in _PORT_MAP.items():
        if re.search(rf"(?<![\w-]){proto_name}(?![\w-])", low):
            port = p
            if protocol is None and proto_name not in ("web", "database", "db"):
                protocol = "tcp"
            break
    pm2 = re.search(r"port\s+(\d{1,5})", low)
    if pm2:
        port = int(pm2.group(1))

    endpoints: list[str] = []
    prev_raw = ""
    for tok in q.replace("?", " ").replace(".", " ").split():
        ep = _extract_endpoint(tok, hints)
        if ep is None:
            prev_raw = tok
            continue
        if (endpoints and ep.lower() in _ENDPOINT_WORDS
                and ep.lower() not in ("internet", "vlan")
                and prev_raw and prev_raw.isalpha() and prev_raw.islower()
                and prev_raw.lower() not in _STOPWORDS):
            endpoints[-1] = f"{prev_raw}-{ep}"
        else:
            endpoints.append(ep)
        prev_raw = tok

    src = dst = None
    if len(endpoints) >= 2:
        src, dst = endpoints[0], endpoints[1]
    elif len(endpoints) == 1:
        src = endpoints[0]

    prefix = next((i for i in ips if "/" in i), None)

    def has(*words: str) -> bool:
        return any(w in low for w in words)

    if has("segment", "isolated", "segmentation", "separated"):
        qtype = "segmentation"
        if src and dst:
            return BehaviourQuery(type=qtype, source=src, destination=dst,
                                  protocol=protocol, destination_port=port,
                                  raw_text=q)
        return BehaviourQuery(type=qtype, raw_text=q)
    if has("trace", "path from", "path between", "follow"):
        qtype = "path_trace"
    elif has("route", "routing"):
        qtype = "route_check"
    elif has("acl", "access-list", "access list", "firewall rule", "blocked by"):
        qtype = "acl_check"
    elif has("health", "situation", "everything ok", "network ok", "unreachable"):
        qtype = "network_health"
    else:
        qtype = "reachability"

    return BehaviourQuery(type=qtype, source=src, destination=dst,
                          protocol=protocol, destination_port=port,
                          prefix=prefix, raw_text=q)


SUGGESTED_QUERIES = [
    "Is the network reachable?",
    "Check internet connectivity",
    "Find unreachable devices",
    "Check routing",
    "Check ACL blocking",
    "Trace traffic",
    "Check network segmentation",
]
