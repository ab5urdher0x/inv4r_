"""Tier-1 structured model adapter: OpenConfig / YANG-shaped JSON (and NETCONF XML)."""

from __future__ import annotations

import json

from inv4r.adapters.base import (
    AdapterCapabilities,
    AdapterMatch,
    Limitation,
    NormalizationOutput,
    ParsedRepresentation,
)
from inv4r.adapters.generic_structural import GenericStructuralAdapter
from inv4r.adapters.builtin.base_builtin import BuiltinParser, make_fact
from inv4r.core.envelope import EvidenceEnvelope
from inv4r.core.facts import FactStatus
from inv4r.detection import DetectionResult


class OpenConfigAdapter(BuiltinParser):
    """Tier 1 — standards-based structured model. Parses OC JSON payloads."""

    adapter_id = "openconfig-yang"
    adapter_version = "1.0.0"
    tier = 1
    vendor = "openconfig-yang"
    platform = "openconfig"
    formats = ("json_structured",)

    def can_handle(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> AdapterMatch:
        if detection.input_format == "json_structured" and (
                "openconfig" in evidence.content[:4000].lower()
                or detection.vendor == "openconfig-yang"):
            return AdapterMatch(self.adapter_id, self.tier, 0.95,
                                "OpenConfig/YANG structured payload")
        return AdapterMatch(self.adapter_id, self.tier, 0.0, "not an OpenConfig payload")

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(parses_format="json_structured",
                                   normalizes_to_resources=True,
                                   produces_security_facts=True)

    def limitations(self) -> list[Limitation]:
        return [Limitation("model_subset", "Covers openconfig-system and openconfig-interfaces subtrees.")]

    def extract(self, parsed: ParsedRepresentation, detection: DetectionResult,
                out: NormalizationOutput) -> None:
        text = parsed.notes.get("evidence_text", "")
        vid = self.adapter_id

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return

        sysroot = None
        for k, v in data.items():
            if "openconfig-system:system" in k or k == "system":
                sysroot = v
                break

        if not sysroot:
            return

        ssh = ((sysroot.get("ssh-server") or {}).get("config") or {})
        out.facts.append(make_fact("management.ssh.enabled",
                                   FactStatus.PRESENT if ssh.get("enable") else FactStatus.ABSENT,
                                   bool(ssh.get("enable")), None, vid))
        if ssh.get("protocol-version"):
            out.facts.append(make_fact("management.ssh.version", FactStatus.PRESENT,
                                       str(ssh["protocol-version"]), None, vid))
        if ssh.get("timeout") is not None:
            try:
                out.facts.append(make_fact("management.session_timeout", FactStatus.PRESENT,
                                           int(ssh["timeout"]), None, vid))
            except (TypeError, ValueError):
                pass

        telnet = ((sysroot.get("telnet-server") or {}).get("config") or {})
        out.facts.append(make_fact("management.telnet.enabled",
                                   FactStatus.PRESENT if telnet.get("enable") else FactStatus.ABSENT,
                                   bool(telnet.get("enable")), None, vid))

        aaa = ((sysroot.get("aaa") or {}).get("authentication") or {}).get("config") or {}
        out.facts.append(make_fact("authentication.aaa.enabled",
                                   FactStatus.PRESENT if aaa else FactStatus.ABSENT,
                                   bool(aaa), None, vid))

        syslog = (sysroot.get("syslog") or {})
        remotes = ((syslog.get("remote-servers") or {}).get("remote-server")) or []
        out.facts.append(make_fact("logging.remote.enabled",
                                   FactStatus.PRESENT if remotes else FactStatus.ABSENT,
                                   bool(remotes), None, vid))

        ifaces = ((data.get("openconfig-interfaces:interfaces") or data.get("interfaces")) or {})
        ilist = ifaces.get("interface") or []
        resources: list = []
        for i, ifc in enumerate(ilist, start=1):
            cfg = ifc.get("config") or {}
            resources.append(self.add_resource(
                out, f"if-{i}", "interface", ifc.get("name") or cfg.get("name", f"if{i}"),
                self.vendor, self.platform,
                {"enabled": cfg.get("enabled"), "mtu": cfg.get("mtu")}, 0, ""))
        out.facts.append(make_fact("network.interface.present",
                                   FactStatus.PRESENT if ilist else FactStatus.ABSENT,
                                   bool(ilist), None, vid))
        out.resources = resources
