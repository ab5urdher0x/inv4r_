"""Tier-2 deterministic parser for AWS Security Group JSON exports."""

from __future__ import annotations

import json
import ipaddress

from inv4r.adapters.base import NormalizationOutput, ParsedRepresentation
from inv4r.adapters.builtin.base_builtin import BuiltinParser, make_fact
from inv4r.core.facts import FactStatus
from inv4r.detection import DetectionResult

_ADMIN_PORTS = {22: "ssh", 23: "telnet", 80: "http", 3389: "rdp", 5985: "winrm-http", 5986: "winrm-https"}


class AwsSecurityGroupAdapter(BuiltinParser):
    adapter_id = "builtin-aws-sg"
    vendor = "aws-security-group"
    platform = "aws-security-group"
    formats = ("json_structured",)

    def extract(self, parsed: ParsedRepresentation, detection: DetectionResult,
                out: NormalizationOutput) -> None:
        text = parsed.notes.get("evidence_text", "")
        vid = self.adapter_id

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return

        groups = data.get("security_groups") if isinstance(data, dict) else data
        if not isinstance(groups, list):
            groups = [groups] if isinstance(groups, dict) else []

        resources: list = []
        ridx = 0
        open_admin_ports: list[str] = []
        open_to_world = 0

        for g in groups:
            ridx += 1
            gid = g.get("GroupId", f"sg-{ridx}")
            resources.append(self.add_resource(
                out, f"sg-{ridx}", "security_group", g.get("GroupName", gid), self.vendor,
                self.platform, {"group_id": gid, "vpc": g.get("VpcId", "")}, 0, ""))

            for perm in g.get("IpPermissions", []) or []:
                proto = perm.get("IpProtocol", "-1")
                lo = perm.get("FromPort")
                hi = perm.get("ToPort")
                for r in perm.get("IpRanges", []) or []:
                    cidr = r.get("CidrIp", "")
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                    except ValueError:
                        continue
                    world = net.prefixlen == 0
                    if world:
                        open_to_world += 1
                    if lo is not None and (world or (lo in _ADMIN_PORTS)):
                        label = _ADMIN_PORTS.get(lo, f"port{lo}")
                        if world:
                            open_admin_ports.append(f"{gid}:{label}")
                ridx += 1
                resources.append(self.add_resource(
                    out, f"rule-{ridx}", "acl_rule",
                    f"{gid}-{proto}-{lo}-{hi}", self.vendor, self.platform,
                    {"protocol": proto, "from_port": lo, "to_port": hi}, 0, ""))

        out.facts.append(make_fact("firewall.policy.present",
                                   FactStatus.PRESENT if groups else FactStatus.ABSENT,
                                   bool(groups), None, vid))
        out.facts.append(make_fact("acl.present",
                                   FactStatus.PRESENT if groups else FactStatus.ABSENT,
                                   bool(groups), None, vid))
        out.facts.append(make_fact("network.interface.present", FactStatus.UNKNOWN, None, None, vid,
                                   "ENI inventory not part of SG export"))
        parsed.notes["open_admin_ports_world"] = sorted(set(open_admin_ports))
        parsed.notes["rules_open_to_world"] = open_to_world
