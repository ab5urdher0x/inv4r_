"""Tier-2 deterministic parser for SONiC config_db JSON."""

from __future__ import annotations

import json
import re

from inv4r.adapters.base import NormalizationOutput, ParsedRepresentation
from inv4r.adapters.builtin.base_builtin import BuiltinParser, make_fact
from inv4r.core.facts import FactStatus
from inv4r.detection import DetectionResult


class SonicAdapter(BuiltinParser):
    adapter_id = "builtin-sonic"
    vendor = "sonic"
    platform = "sonic"
    formats = ("json_structured",)

    def extract(self, parsed: ParsedRepresentation, detection: DetectionResult,
                out: NormalizationOutput) -> None:
        text = parsed.notes.get("evidence_text", "")
        vid = self.adapter_id

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return

        resources: list = []
        ridx = 0

        md = (data.get("DEVICE_METADATA") or {}).get("localhost", {})
        parsed.notes["hostname"] = md.get("hostname", "")
        parsed.notes["sw_version"] = md.get("os_version", "")

        ifaces = data.get("INTERFACE") or {}
        for name in ifaces:
            ridx += 1
            resources.append(self.add_resource(
                out, f"if-{ridx}", "interface", name, self.vendor, self.platform, {}, 0, ""))
        out.facts.append(make_fact("network.interface.present",
                                   FactStatus.PRESENT if ifaces else FactStatus.ABSENT,
                                   bool(ifaces), None, vid))

        telnet = data.get("TELNET_SERVER") or {}
        telnet_on = str(telnet.get("listening_mode", "disabled")).lower() == "enabled"
        out.facts.append(make_fact("management.telnet.enabled",
                                   FactStatus.PRESENT if telnet_on else FactStatus.ABSENT,
                                   telnet_on, None, vid))
        if "inactivity_timeout" in telnet:
            try:
                out.facts.append(make_fact("management.session_timeout", FactStatus.PRESENT,
                                           int(telnet["inactivity_timeout"]), None, vid))
            except (TypeError, ValueError):
                pass

        ssh = data.get("SSH_SERVER") or {}
        ssh_on = bool(ssh)
        out.facts.append(make_fact("management.ssh.enabled",
                                   FactStatus.PRESENT if ssh_on else FactStatus.UNKNOWN,
                                   ssh_on, None, vid))

        syslog = data.get("SYSLOG_SERVER") or {}
        out.facts.append(make_fact("logging.remote.enabled",
                                   FactStatus.PRESENT if syslog else FactStatus.ABSENT,
                                   bool(syslog), None, vid))
        for host in syslog:
            ridx += 1
            resources.append(self.add_resource(
                out, f"sys-{ridx}", "syslog_server", host, self.vendor, self.platform, {}, 0, ""))

        ntp = data.get("NTP_SERVER") or {}
        for host in ntp:
            ridx += 1
            resources.append(self.add_resource(
                out, f"ntp-{ridx}", "ntp_server", host, self.vendor, self.platform, {}, 0, ""))

        snmp = data.get("SNMP") or {}
        communities = (snmp.get("Community") or {})
        for cname, cval in communities.items():
            ridx += 1
            resources.append(self.add_resource(
                out, f"snmp-{ridx}", "snmp_community", cname, self.vendor, self.platform,
                {"type": (cval or {}).get("TYPE", "")}, 0, ""))
        out.facts.append(make_fact("snmp.v1.v2c.enabled",
                                   FactStatus.PRESENT if communities else FactStatus.ABSENT,
                                   bool(communities), None, vid))
        out.facts.append(make_fact("snmp.v3.enabled", FactStatus.UNKNOWN, None, None, vid,
                                   "not represented in config_db sample"))

        routes = data.get("STATIC_ROUTE") or {}
        out.facts.append(make_fact("network.route.present",
                                   FactStatus.PRESENT if routes else FactStatus.UNKNOWN,
                                   bool(routes), None, vid))
