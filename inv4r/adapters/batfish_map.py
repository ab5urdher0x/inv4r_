"""Map Batfish question output to INV4R canonical facts and resources.

Batfish parses every supported vendor configuration into one vendor-neutral
model. INV4R consumes that model through the documented *configuration
properties* questions and maps the results onto the closed canonical fact
vocabulary. Deterministic tier-2 parsers keep primacy for values only they can
see; the Batfish layer fills gaps and, for vendors INV4R has no dedicated
parser, becomes the primary normalization source.

Only ``nodeProperties`` and ``interfaceProperties`` are used here, because
their columns are stable and documented. Every emitted fact is validated
against :data:`inv4r.core.facts.CANONICAL_FACTS` — Batfish may never invent
vocabulary. Negative (ABSENT) evidence is emitted too, so controls resolve to
PASS/FAIL instead of UNKNOWN whenever Batfish can actually prove a value.

Documented columns consumed (pybatfish configProperties):
- nodeProperties:      Logging_Servers, NTP_Servers, TACACS_Servers,
                       IP_Access_Lists, Zones, Default_Cross_Zone_Action,
                       Interfaces, Hostname, Domain_Name
- interfaceProperties: Interface, Active, Admin_Up, Incoming_Filter_Name,
                       Outgoing_Filter_Name, Primary_Address, VRF, Zone_Name,
                       Description
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from inv4r.core.facts import (CANONICAL_FACTS, FactStatus, SecurityFact,
                              stable_fact_id)
from inv4r.core.model import CanonicalResource

BATFISH_SOURCE = "builtin-batfish-bridge"


@dataclass
class Mapped:
    """Canonical facts + resources extracted from one Batfish answer."""

    facts: list[SecurityFact] = field(default_factory=list)
    resources: list[CanonicalResource] = field(default_factory=list)


def make_batfish_fact(name: str, status: str, value: Any, notes: str = "",
                      entity: str | None = None, line: int | None = None,
                      confidence: float = 1.0) -> SecurityFact | None:
    """Build a canonical fact, or return None if the name is not in vocabulary.

    Returning None (rather than emitting an unvalidated fact) keeps Batfish
    inside the closed-vocabulary invariant that the rest of the engine follows.
    """
    if name not in CANONICAL_FACTS:
        return None
    fact = SecurityFact(
        fact_id=stable_fact_id(name, value, line, entity),
        name=name,
        status=status,
        value=value,
        confidence=confidence,
        source_adapter=BATFISH_SOURCE,
        notes=notes or "extracted via batfish model",
        scope="interface" if entity and name.startswith("network.interface") else "device",
        entity=entity,
        derivation="derived",
    )
    return fact


def _as_list(value: Any) -> list[str]:
    """Normalize a Batfish set/list/None column into a list of strings."""
    if value in (None, "", []):
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [str(k) for k in value.keys()]
    try:
        return [str(v) for v in value if str(v) not in ("", "None")]
    except TypeError:
        return [str(value)]


def _truthy(value: Any) -> bool:
    return str(value).lower() in ("true", "1", "yes")


def map_node_properties(row: dict[str, Any]) -> Mapped:
    """Map one ``nodeProperties`` row to canonical facts + ACL/zone resources."""
    out = Mapped()

    logging_servers = _as_list(row.get("Logging_Servers"))
    f = make_batfish_fact(
        "logging.remote.enabled", FactStatus.PRESENT if logging_servers else FactStatus.ABSENT,
        bool(logging_servers),
        notes=(f"syslog servers: {logging_servers}" if logging_servers
               else "no logging servers in Batfish model"))
    if f:
        out.facts.append(f)
    for server in logging_servers:
        f = make_batfish_fact("logging.remote.servers", FactStatus.PRESENT, server,
                              notes="syslog server from Batfish model", entity=server)
        if f:
            out.facts.append(f)

    ntp_servers = _as_list(row.get("NTP_Servers"))
    for server in ntp_servers:
        f = make_batfish_fact("ntp.servers", FactStatus.PRESENT, server,
                              notes="NTP server from Batfish model", entity=server)
        if f:
            out.facts.append(f)

    tacacs = _as_list(row.get("TACACS_Servers"))
    if tacacs:
        f = make_batfish_fact("authentication.aaa.enabled", FactStatus.PRESENT, True,
                              notes=f"TACACS servers: {tacacs}")
        if f:
            out.facts.append(f)

    acls = _as_list(row.get("IP_Access_Lists"))
    if acls:
        f = make_batfish_fact("acl.present", FactStatus.PRESENT, True,
                              notes=f"{len(acls)} IPv4 filter(s) in Batfish model")
        if f:
            out.facts.append(f)
        for name in acls:
            out.resources.append(CanonicalResource(
                resource_id=f"bf-acl-{abs(hash(name)) % 10_000_000:07d}",
                resource_type="acl", name=name, vendor="", platform="",
                attributes={"source": "batfish", "family": "ipv4"},
                raw_text=f"acl {name}"))

    zones = _as_list(row.get("Zones"))
    cross_zone = row.get("Default_Cross_Zone_Action")
    if zones or cross_zone:
        f = make_batfish_fact(
            "firewall.policy.present", FactStatus.PRESENT, True,
            notes=(f"firewall zones: {zones}" if zones
                   else f"cross-zone action {cross_zone}"))
        if f:
            out.facts.append(f)

    interfaces = _as_list(row.get("Interfaces"))
    f = make_batfish_fact(
        "network.interface.present",
        FactStatus.PRESENT if interfaces else FactStatus.ABSENT,
        bool(interfaces),
        notes=(f"{len(interfaces)} interface(s) in Batfish model" if interfaces
               else "no interfaces in Batfish model"))
    if f:
        out.facts.append(f)

    return out


def _interface_parts(row: dict[str, Any]) -> tuple[str, str]:
    """Return (hostname, interface_name) from the polymorphic Interface column."""
    raw = row.get("Interface")
    if isinstance(raw, dict):
        return str(raw.get("hostname") or ""), str(raw.get("interface") or "")
    text = str(raw or "")
    if "[" in text and text.endswith("]"):
        host, _, iface = text.partition("[")
        return host, iface[:-1]
    return "", text


def map_interface_properties(rows: list[dict[str, Any]]) -> Mapped:
    """Map ``interfaceProperties`` rows to facts, interface and ACL resources."""
    out = Mapped()
    if not rows:
        return out

    has_active = False
    has_filter = False
    has_zone = False
    seen_ifaces: set[str] = set()
    seen_filters: set[str] = set()

    for r in rows:
        host, iface = _interface_parts(r)
        if r.get("Active"):
            has_active = True
        if r.get("Zone_Name"):
            has_zone = True

        for key, direction in (("Incoming_Filter_Name", "in"),
                               ("Outgoing_Filter_Name", "out")):
            name = r.get(key)
            if name:
                has_filter = True
                if name not in seen_filters:
                    seen_filters.add(name)
                    out.resources.append(CanonicalResource(
                        resource_id=f"bf-acl-{abs(hash(name)) % 10_000_000:07d}",
                        resource_type="acl", name=str(name), vendor="", platform="",
                        attributes={"source": "batfish", "applied_on": iface,
                                    "direction": direction},
                        raw_text=f"filter {name} {direction} {iface}"))

        if iface and iface not in seen_ifaces:
            seen_ifaces.add(iface)
            out.resources.append(CanonicalResource(
                resource_id=f"bf-if-{abs(hash((host, iface))) % 10_000_000:07d}",
                resource_type="interface", name=iface, vendor="", platform="",
                attributes={
                    "source": "batfish",
                    "hostname": host,
                    "active": bool(r.get("Active")),
                    "admin_up": bool(r.get("Admin_Up")),
                    "primary_address": r.get("Primary_Address") or "",
                    "vrf": r.get("VRF") or "",
                    "zone": r.get("Zone_Name") or "",
                    "description": r.get("Description") or "",
                },
                raw_text=f"interface {iface}"))

    if seen_ifaces:
        f = make_batfish_fact(
            "network.interface.present", FactStatus.PRESENT, True,
            notes=(f"{len(seen_ifaces)} interface(s)"
                   + (", at least one active" if has_active else "")))
        if f:
            out.facts.append(f)

    if has_filter:
        f = make_batfish_fact(
            "acl.present", FactStatus.PRESENT, True,
            notes="interface ACL filters in Batfish model")
        if f:
            out.facts.append(f)

    if has_zone:
        f = make_batfish_fact(
            "firewall.policy.present", FactStatus.PRESENT, True,
            notes="interfaces bound to firewall zones in Batfish model")
        if f:
            out.facts.append(f)

    return out
