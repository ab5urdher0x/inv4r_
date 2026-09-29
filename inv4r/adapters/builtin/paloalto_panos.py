"""Tier-2 deterministic parser for Palo Alto PAN-OS (XML config)."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from inv4r.adapters.base import NormalizationOutput, ParsedRepresentation
from inv4r.adapters.builtin.base_builtin import BuiltinParser, make_fact
from inv4r.core.facts import FactStatus
from inv4r.detection import DetectionResult

_RE_ENTRY = ".//entry"


class PaloAltoPanosAdapter(BuiltinParser):
    adapter_id = "builtin-paloalto-panos"
    vendor = "paloalto-panos"
    platform = "panos"
    formats = ("xml_structured",)

    def extract(self, parsed: ParsedRepresentation, detection: DetectionResult,
                out: NormalizationOutput) -> None:
        text = parsed.notes.get("evidence_text", "")
        vid = self.adapter_id

        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            out.unknown_fragments.append(
                self.add_fragment(out, "xml", "unparseable XML document", 0))
            return

        services = root.findall(".//deviceconfig/system/services")
        ssh_on = telnet_on = http_on = https_on = False
        permitted_ips: list[str] = []
        if services is not None:
            for svc in services:
                for name, on_flag in (("ssh", "ssh"), ("telnet", "telnet"),
                                      ("http", "http"), ("https", "https")):
                    el = svc.find(name)
                    if el is not None:
                        if name == "ssh":
                            ssh_on = True
                        elif name == "telnet":
                            telnet_on = True
                        elif name == "http":
                            http_on = True
                        elif name == "https":
                            https_on = True
                        for ip in el.findall("permitted-ip"):
                            v = ip.findtext("value") or ip.findtext("permitted-ip")
                            if v:
                                permitted_ips.append(v)

        out.facts.append(make_fact("management.ssh.enabled",
                                   FactStatus.PRESENT if ssh_on else FactStatus.ABSENT, ssh_on, None, vid))
        out.facts.append(make_fact("management.telnet.enabled",
                                   FactStatus.PRESENT if telnet_on else FactStatus.ABSENT, telnet_on, None, vid))
        out.facts.append(make_fact("management.http.enabled",
                                   FactStatus.PRESENT if http_on else FactStatus.ABSENT, http_on, None, vid))
        out.facts.append(make_fact("management.https.enabled",
                                   FactStatus.PRESENT if https_on else FactStatus.ABSENT, https_on, None, vid))
        if permitted_ips:
            out.facts.append(make_fact("management.acl.present", FactStatus.PRESENT, True, None, vid,
                                       notes="permitted-ip management ACL"))

        for phash in root.findall(".//mgt-config/users/entry/phash"):
            h = (phash.text or "").strip()
            algo = "md5" if h.startswith("$1$") else ("sha512" if h.startswith("$6$") else "unknown")
            out.facts.append(make_fact("authentication.password.hashing", FactStatus.PRESENT,
                                       algo, None, vid))

        syslog_hosts = [e.text for e in root.findall(".//log-settings/system/entry") if e.text]
        for s in root.iter("server"):
            pass
        out.facts.append(make_fact("logging.remote.enabled",
                                   FactStatus.PRESENT if syslog_hosts else FactStatus.ABSENT,
                                   bool(syslog_hosts), None, vid))

        ridx = 0
        resources: list = []
        ifaces = root.findall(".//network/interface/ethernet/entry")
        for e in ifaces:
            ridx += 1
            name = e.get("name") or f"eth{ridx}"
            resources.append(self.add_resource(
                out, f"if-{ridx}", "interface", name, self.vendor, self.platform,
                {"layer3": e.find(".//layer3") is not None}, 0, ""))
        out.facts.append(make_fact("network.interface.present",
                                   FactStatus.PRESENT if ifaces else FactStatus.ABSENT,
                                   bool(ifaces), None, vid))

        rules = root.findall(".//rulebase/security/rules/entry")
        for e in rules:
            ridx += 1
            action = (e.findtext("action") or "unknown").strip()
            resources.append(self.add_resource(
                out, f"pol-{ridx}", "acl_rule", e.get("name") or f"rule-{ridx}",
                self.vendor, self.platform, {"action": action}, 0, ""))
        out.facts.append(make_fact("firewall.policy.present",
                                   FactStatus.PRESENT if rules else FactStatus.ABSENT,
                                   bool(rules), None, vid))
        out.facts.append(make_fact("acl.present",
                                   FactStatus.PRESENT if rules else FactStatus.ABSENT,
                                   bool(rules), None, vid))

        m = re.search(r"<sw-version>([^<]+)</sw-version>", text)
        if m:
            parsed.notes["sw_version"] = m.group(1)

        out.resources = resources

        for tag in ("profile-group", "server-profile", "certificate"):
            for el in root.iter(tag):
                self.add_fragment(out, tag, f"<{tag} name=\"{el.get('name', '')}\">", 0)

