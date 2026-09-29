"""Tier-2 deterministic parser for Fortinet FortiGate configs."""

from __future__ import annotations

import re

from inv4r.adapters.base import NormalizationOutput, ParsedRepresentation
from inv4r.adapters.builtin.base_builtin import BuiltinParser, make_fact
from inv4r.core.facts import FactStatus
from inv4r.detection import DetectionResult

_RE_EDIT = re.compile(r'^\s*edit\s+"?(\S+?)"?\s*$', re.I)
_RE_NEXT = re.compile(r"^\s*next\s*$", re.I)
_RE_SET = re.compile(r"^\s*set\s+(\S+)\s+(.+?)\s*$", re.I)
_RE_SECTION = re.compile(r"^\s*config\s+(.+?)\s*$", re.I)
_RE_END = re.compile(r"^\s*end\s*$", re.I)


def _walk(lines: list[str]) -> list[tuple[str, str, str | None, int]]:
    """Yield (section_path, key, value, lineno)."""
    out: list[tuple[str, str, str | None, int]] = []
    stack: list[str] = []
    current_entry: str | None = None
    for i, raw in enumerate(lines, start=1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = _RE_SECTION.match(s)
        if m:
            stack.append(m.group(1).replace(" ", "."))
            current_entry = None
            continue
        if _RE_END.match(s):
            if stack:
                stack.pop()
            current_entry = None
            continue
        m = _RE_EDIT.match(s)
        if m:
            current_entry = m.group(1).strip('"')
            continue
        if _RE_NEXT.match(s):
            current_entry = None
            continue
        m = _RE_SET.match(s)
        if m and stack:
            path = ".".join(stack + ([current_entry] if current_entry else []))
            out.append((path, m.group(1), m.group(2), i))
    return out


class FortinetFortigateAdapter(BuiltinParser):
    adapter_id = "builtin-fortinet-fortigate"
    vendor = "fortinet-fortigate"
    platform = "fortigate"
    formats = ("hierarchical_cli",)

    def extract(self, parsed: ParsedRepresentation, detection: DetectionResult,
                out: NormalizationOutput) -> None:
        text = parsed.notes.get("evidence_text", "")
        vid = self.adapter_id
        entries = _walk(text.splitlines())

        hostname = None
        admintimeout = None
        allowaccess: dict[str, list[str]] = {}
        snmp_communities: list[tuple[str, str]] = []  # (entry_id, name)
        syslog_servers: list[str] = []
        static_routes = 0
        policies: list[str] = []
        resources: list = []
        ridx = 0

        ssh_v2 = False
        syslog_enabled = False
        password_hashing = None
        mgmt_acl = False

        for path, key, value, lineno in entries:
            pl = path.lower()
            kl = key.lower()
            vl = value.strip('"').lower()

            if pl == "system.global":
                if kl == "hostname":
                    hostname = value.strip('"')
                    continue
                if kl == "admintimeout":
                    try:
                        admintimeout = int(value)
                    except ValueError:
                        pass
                    continue
                if (kl == "admin-ssh-v1" and vl == "disable") or (kl == "strong-crypto" and vl == "enable"):
                    ssh_v2 = True
                    continue

            if pl.startswith("system.interface") and kl == "allowaccess":
                iface = path.split(".")[-1]
                allowaccess[iface] = [p.strip() for p in value.split()]
                continue
            if pl.startswith("system.snmp.community") and kl == "name":
                # Keep the entry id ('edit 1') alongside the community name so
                # remediation can target the community that actually exists
                # instead of hard-coding 'delete 1'.
                snmp_communities.append((path.split(".")[-1], value.strip('"')))
                continue
            if pl.startswith("router.static") and kl in ("dst", "gateway"):
                if kl == "gateway":
                    static_routes += 1
                continue
            if pl.startswith("firewall.policy") and kl == "name":
                policies.append(value.strip('"'))
                continue
            if pl.startswith("firewall.local-in-policy"):
                mgmt_acl = True
                continue
            if pl.startswith("system.admin"):
                if kl == "password-hash" and vl in ("sha256", "sha512", "scrypt"):
                    password_hashing = vl
                    continue
                if kl == "password":
                    password_hashing = password_hashing or "sha256"
                    out.facts.append(make_fact("authentication.password.hashing",
                                               FactStatus.PRESENT, password_hashing, lineno, vid,
                                               notes="vendor-encapsulated password hash"))
                    continue
                if kl.startswith("trusthost"):
                    mgmt_acl = True
                    continue
            if pl.startswith("log.syslogd") and kl == "status" and vl == "enable":
                syslog_enabled = True
                continue
            if pl.startswith("log.syslogd") and kl == "server":
                syslog_servers.append(value.strip('"'))
                continue

            self.add_fragment(out, f"{path}.{key}", f"set {key} {value}", lineno)

        ssh_any = telnet_any = http_any = https_any = False
        for iface, protos in allowaccess.items():
            ssh_any = ssh_any or "ssh" in protos
            telnet_any = telnet_any or "telnet" in protos
            http_any = http_any or "http" in protos
            https_any = https_any or "https" in protos
            ridx += 1
            resources.append(self.add_resource(
                out, f"if-{ridx}", "interface", iface, self.vendor, self.platform,
                {"allowaccess": protos}, 0, ""))

        out.facts.append(make_fact("management.ssh.enabled",
                                   FactStatus.PRESENT if ssh_any else FactStatus.ABSENT,
                                   ssh_any, None, vid, "from allowaccess"))
        if ssh_any or ssh_v2:
            out.facts.append(make_fact("management.ssh.version",
                                       FactStatus.PRESENT if ssh_v2 else FactStatus.UNKNOWN,
                                       "2" if ssh_v2 else None, None, vid))
        out.facts.append(make_fact("management.telnet.enabled",
                                   FactStatus.PRESENT if telnet_any else FactStatus.ABSENT,
                                   telnet_any, None, vid, "from allowaccess"))
        out.facts.append(make_fact("management.http.enabled",
                                   FactStatus.PRESENT if http_any else FactStatus.ABSENT,
                                   http_any, None, vid, "from allowaccess"))
        out.facts.append(make_fact("management.https.enabled",
                                   FactStatus.PRESENT if https_any else FactStatus.ABSENT,
                                   https_any, None, vid, "from allowaccess"))
        if admintimeout is not None:
            out.facts.append(make_fact("management.session_timeout", FactStatus.PRESENT,
                                       admintimeout, None, vid))
        out.facts.append(make_fact("snmp.v1.v2c.enabled",
                                   FactStatus.PRESENT if snmp_communities else FactStatus.ABSENT,
                                   bool(snmp_communities), None, vid))
        out.facts.append(make_fact("logging.remote.enabled",
                                   FactStatus.PRESENT if syslog_enabled else FactStatus.ABSENT,
                                   syslog_enabled, None, vid))
        out.facts.append(make_fact("management.acl.present",
                                   FactStatus.PRESENT if mgmt_acl else FactStatus.ABSENT,
                                   mgmt_acl, None, vid))
        if password_hashing and not any(f.name == "authentication.password.hashing" for f in out.facts):
            out.facts.append(make_fact("authentication.password.hashing",
                                       FactStatus.PRESENT, password_hashing, None, vid))
        for entry_id, c in snmp_communities:
            ridx += 1
            resources.append(self.add_resource(
                out, f"snmp-{ridx}", "snmp_community", c, self.vendor, self.platform,
                {"version": "v2c", "entry_id": entry_id}, 0, ""))
        for server in syslog_servers:
            out.facts.append(make_fact("logging.remote.servers", FactStatus.PRESENT,
                                       server, None, vid, "from log syslogd setting"))
        out.facts.append(make_fact("network.route.present",
                                   FactStatus.PRESENT if static_routes else FactStatus.ABSENT,
                                   bool(static_routes), None, vid))
        out.facts.append(make_fact("firewall.policy.present",
                                   FactStatus.PRESENT if policies else FactStatus.ABSENT,
                                   bool(policies), None, vid))
        out.facts.append(make_fact("network.interface.present",
                                   FactStatus.PRESENT if allowaccess else FactStatus.ABSENT,
                                   bool(allowaccess), None, vid))
        out.facts.append(make_fact("acl.present", FactStatus.UNKNOWN, None, None, vid,
                                   "fortigate local-in policies not parsed"))
        if hostname:
            parsed.notes["hostname"] = hostname
        out.resources = resources
