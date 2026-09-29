"""Canonical security-fact vocabulary — a CLOSED, versioned set."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

FACT_VERSION = "1.2.0"

CANONICAL_FACTS: dict[str, tuple[str, str]] = {
    "management.ssh.enabled":            ("bool", "SSH management service enabled"),
    "management.ssh.version":            ("string", "SSH protocol version (e.g. '2')"),
    "management.ssh.timeout":            ("number", "SSH idle timeout (minutes)"),
    "management.ssh.acl.present":        ("bool", "ACL restricting SSH management access"),
    "management.telnet.enabled":         ("bool", "Telnet management service enabled (insecure)"),
    "management.http.enabled":           ("bool", "Plain-HTTP management enabled (insecure)"),
    "management.https.enabled":          ("bool", "HTTPS management enabled"),
    "management.http.authentication":    ("string", "HTTP management authentication method"),
    "management.https.authentication":   ("string", "HTTPS management authentication method"),
    "management.http.acl":               ("string", "ACL applied to the HTTP management server"),
    "management.https.acl":              ("string", "ACL applied to the HTTPS management server"),
    "management.ftp.enabled":            ("bool", "FTP management service enabled (insecure)"),
    "management.console.authentication": ("string", "Console line authentication method"),
    "management.vty.authentication":     ("string", "VTY authentication method"),
    "management.vty.transport":          ("string", "Permitted VTY transport protocols"),
    "management.vty.acl":                ("string", "ACL applied to VTY lines (ipv4)"),
    "management.vty.acl.ipv6":           ("string", "ACL applied to VTY lines (ipv6)"),
    "management.session_timeout":        ("number", "Management session idle timeout (minutes)"),
    "management.acl.present":            ("bool", "ACL restricting management plane access"),
    "management.acl.applied":            ("bool", "An ACL is attached to a management surface"),
    "management.acl.terminal_action":    ("string", "Terminal behavior of the management-bound ACL"),
    "management.acl.binding":            ("string", "Management ACL binding (acl/direction)"),
    "authentication.aaa.enabled":        ("bool", "AAA (authentication/authorization/accounting) enabled"),
    "authentication.password.hashing":   ("string", "DEPRECATED global alias — see credential.* facts"),
    "credential.storage_type":           ("string", "Per-credential storage/encoding mechanism"),
    "credential.algorithm_class":        ("string", "Credential algorithm class (scrypt, md5, reversible, plaintext, unknown)"),
    "credential.type9.present":          ("bool", "At least one type-9 (scrypt) credential exists"),
    "credential.reversible.present":     ("bool", "At least one reversible-encoded credential exists"),
    "credential.plaintext.present":      ("bool", "At least one plaintext credential exists"),
    "snmp.v1.v2c.enabled":               ("bool", "SNMP v1/v2c communities in use (insecure)"),
    "snmp.v3.enabled":                   ("bool", "SNMPv3 enabled"),
    "snmp.community.acl":                ("string", "ACL restricting an SNMP community"),
    "snmp.version":                      ("string", "SNMP version in use for a configured SNMP principal (one fact per principal)"),
    "snmp.communities_restricted":       ("bool", "SNMP community bounded by a source ACL (one fact per community)"),
    "logging.remote.enabled":            ("bool", "Remote syslog configured"),
    "logging.local.enabled":             ("bool", "Local logging (buffered/file) enabled"),
    "logging.remote.servers":            ("string", "Remote syslog server address (one fact per configured server)"),
    "ntp.servers":                       ("string", "NTP server address (one fact per configured server)"),
    "network.route.present":             ("bool", "At least one route (static or learned) configured"),
    "network.interface.present":         ("bool", "At least one interface configured (derived compat fact)"),
    "acl.present":                       ("bool", "At least one ACL/firewall rule set defined"),
    "acl.default_action":                ("string", "DEPRECATED global alias — see acl.terminal_action"),
    "acl.terminal_action":               ("string", "Per-ACL terminal behavior (explicit_deny | explicit_permit | implicit_deny)"),
    "acl.rule_count":                    ("number", "Number of rules in a specific ACL"),
    "acl.binding":                       ("string", "Where an ACL is applied (surface/direction/owner)"),
    "firewall.policy.present":           ("bool", "Firewall/security policy set present"),
    "vendor_extension":                  ("string", "Unmapped vendor-specific feature (status UNKNOWN)"),
}

_ALIASES = {
    "admin.ssh.enabled": "management.ssh.enabled",
    "admin.telnet.enabled": "management.telnet.enabled",
    "admin.http.enabled": "management.http.enabled",
    "admin.https.enabled": "management.https.enabled",
    "admin.acl.present": "management.acl.present",
    "admin.session_timeout": "management.session_timeout",
}

FACT_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")

_REDACT_MARKERS = ("REDACTED", "redacted")
_REDACT_MIN_LEN = 8


def redact(value: Any) -> Any:
    """Redact credential material from a value while keeping typed metadata."""
    if not isinstance(value, str):
        return value
    if any(m in value for m in _REDACT_MARKERS):
        return "<redacted>"
    if value.startswith("$") and len(value) >= _REDACT_MIN_LEN:
        return "<redacted>"
    if len(value) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=$._-]+", value):
        return "<redacted>"
    return value


class FactStatus:
    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Derivation:
    """How a fact was obtained. Extraction certainty, NOT security quality."""
    DIRECT = "direct"
    DERIVED = "derived"
    AGGREGATED = "aggregated"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


@dataclass
class SecurityFact:
    """A typed, scoped fact with evidence and provenance."""

    fact_id: str
    name: str
    status: str
    value: Any = None
    confidence: float = 1.0
    evidence_spans: list[dict[str, Any]] = field(default_factory=list)
    source_adapter: str = "unknown"
    notes: str = ""
    scope: str = "device"
    entity: str | None = None
    derivation: str = Derivation.DIRECT
    evidence_texts: list[str] = field(default_factory=list)

    def validate(self) -> list[str]:
        errs: list[str] = []
        if self.name not in CANONICAL_FACTS:
            errs.append(f"non-canonical fact name: {self.name}")
        if self.status not in (FactStatus.PRESENT, FactStatus.ABSENT,
                               FactStatus.UNKNOWN, FactStatus.NOT_APPLICABLE):
            errs.append(f"invalid status: {self.status}")
        if not 0.0 <= float(self.confidence) <= 1.0:
            errs.append(f"confidence out of range: {self.confidence}")
        if self.derivation not in (Derivation.DIRECT, Derivation.DERIVED,
                                   Derivation.AGGREGATED, Derivation.INFERRED,
                                   Derivation.UNKNOWN):
            errs.append(f"invalid derivation: {self.derivation}")
        return errs

    def to_json(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "name": self.name,
            "status": self.status,
            "value": redact(self.value),
            "confidence": round(float(self.confidence), 3),
            "evidence_spans": self.evidence_spans,
            "source_adapter": self.source_adapter,
            "notes": self.notes,
            "scope": self.scope,
            "entity": self.entity,
            "derivation": self.derivation,
            "evidence_texts": list(self.evidence_texts)[:4],
        }

    def to_legacy_json(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "name": self.name,
            "status": self.status,
            "value": redact(self.value),
            "confidence": round(float(self.confidence), 3),
            "evidence_spans": self.evidence_spans,
            "source_adapter": self.source_adapter,
            "notes": self.notes,
        }


def stable_fact_id(name: str, value: Any, line: int | None, entity: str | None) -> str:
    """Deterministic fact id (hash()-salted ids broke cross-run stability)."""
    raw = f"{name}|{value!r}|{line}|{entity or ''}"
    return f"sf-{hashlib.sha1(raw.encode()).hexdigest()[:10]}"


def normalize_fact_name(name: str) -> str:
    """Validate a fact name against the closed vocabulary."""
    n = (name or "").strip()
    n = _ALIASES.get(n, n)
    if n not in CANONICAL_FACTS:
        raise ValueError(f"non-canonical fact name: {name!r}")
    return n


def is_well_formed_name(name: str) -> bool:
    return bool(FACT_NAME_RE.match(name or ""))


def vocabulary_json() -> dict[str, Any]:
    """Machine-readable view of the closed vocabulary (versioned)."""
    return {
        "fact_version": FACT_VERSION,
        "count": len(CANONICAL_FACTS),
        "facts": {k: {"type": t, "description": d} for k, (t, d) in CANONICAL_FACTS.items()},
        "aliases": dict(_ALIASES),
    }
