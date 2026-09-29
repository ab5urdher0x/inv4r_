"""Tier-2 deterministic parser for Juniper Junos (braced hierarchy or set-style)."""

from __future__ import annotations

import re

from inv4r.adapters.base import NormalizationOutput, ParsedRepresentation
from inv4r.adapters.builtin.base_builtin import BuiltinParser, hash_strength, make_fact
from inv4r.core.facts import FactStatus
from inv4r.detection import DetectionResult

_RE_SET = re.compile(r"^\s*set\s+(.+)$")
_RE_SSH_PROTO = re.compile(r"^\s*set\s+system services ssh protocol-version\s+v?(\d+)", re.I)
_RE_SSH_ON = re.compile(r"^\s*set\s+system services ssh(\s|$)", re.I)
_RE_TELNET = re.compile(r"^\s*set\s+system services telnet\b", re.I)
_RE_WEB_HTTP = re.compile(r"^\s*set\s+system services web-management http\b", re.I)
_RE_WEB_HTTPS = re.compile(r"^\s*set\s+system services web-management https\b", re.I)
_RE_ROOT_LOGIN = re.compile(r"^\s*set\s+system services ssh root-login\s+(\S+)", re.I)
_RE_SYSLOG_HOST = re.compile(r"^\s*set\s+system syslog host\s+(\S+)", re.I)
_RE_SYSLOG_BRACED = re.compile(r"^\s*host\s+(\d+\.\d+\.\d+\.\d+|\S+)\s*\{", re.I)
_RE_NTP = re.compile(r"^\s*set\s+system ntp server\s+(\S+)", re.I)
_RE_NTP_BRACED = re.compile(r"^\s*server\s+(\d+\.\d+\.\d+\.\d+|\S+);", re.I)
_RE_ENC_PASSWORD = re.compile(r"encrypted-password\s+(\S+)", re.I)
_RE_HOSTNAME = re.compile(r"host-name\s+(\S+);", re.I)
_RE_IFACE_UNIT = re.compile(r"^\s*(?:set\s+)?(ge|xe|et|fe|ae|em|fxp)-\d/\d/\d(?:\.\d+)?", re.I)
_RE_ZONE_IFACE = re.compile(r"^\s*(?:set\s+)?(\S+)\s*;", re.I)
_RE_SSH_VERSION_VALUE = re.compile(r"v?(\d+)")

# trailing `system syslog host` path tokens that carry no hostname information
_SYSLOG_QUALIFIERS = frozenset((
    "any", "all", "authorization", "change-log", "conflict-log", "dfc-log",
    "firewall", "ftp", "interactive-commands", "kernel", "ntp", "pfe",
    "security", "user", "emergency", "alert", "critical", "error",
    "warning", "notice", "info", "debug", "none",
))


def _syslog_host(path: str) -> str:
    """Host of a flattened `system syslog host <host> ...` path ('' when unknown)."""
    rest = path.split("system.syslog.host", 1)[-1].lstrip(".")
    if not rest:
        return ""
    toks = rest.split(".")
    while toks and toks[-1] in _SYSLOG_QUALIFIERS:
        toks.pop()
    return ".".join(toks)


def _walk_set_style(lines: list[str]) -> list[tuple[str, str | None, int]]:
    """Flatten 'set a b c' into (path, value, lineno) tuples."""
    out: list[tuple[str, str | None, int]] = []
    for i, raw in enumerate(lines, start=1):
        m = _RE_SET.match(raw)
        if m:
            parts = m.group(1).split()
            if len(parts) >= 2:
                out.append((".".join(parts[:-1]), parts[-1], i))
            elif parts:
                out.append((parts[0], None, i))
    return out


class JuniperJunosAdapter(BuiltinParser):
    adapter_id = "builtin-juniper-junos"
    vendor = "juniper-junos"
    platform = "junos"
    formats = ("junos_braced", "set_commands")

    def extract(self, parsed: ParsedRepresentation, detection: DetectionResult,
                out: NormalizationOutput) -> None:
        text = parsed.notes.get("evidence_text", "")
        lines = text.splitlines()
        vid = self.adapter_id
        stmts = _walk_set_style(lines)

        for node in parsed.root.walk():
            if node.node_type not in ("block", "statement") or not node.raw_text:
                continue
            if node.raw_text.startswith("set "):
                continue
            p = ".".join(node.path)
            if not p:
                continue
            lineno = node.source_span.line_start if node.source_span else 0
            if node.value:
                stmts.append((p, node.value, lineno))
            elif p.startswith("system.services.telnet"):
                stmts.append((p, None, lineno))  # bare `telnet;` carries no value

        ssh_on = False
        ssh_version = None
        telnet_on = False
        http_on = False
        https_on = False
        syslog_host = None
        syslog_servers: list[str] = []
        ntp_servers: list[str] = []
        snmp_communities: dict[str, bool] = {}
        snmp_v3 = False
        hashing: set[str] = set()
        ifaces: list[str] = []
        ridx = 0
        resources: list = []

        for path, value, lineno in stmts:
            pl = path.lower()
            v = (value or "").strip()

            if pl.startswith("system.services.ssh") or (pl == "system.services" and v.lower() == "ssh"):
                ssh_on = True
                if "protocol-version" in pl:
                    m = _RE_SSH_VERSION_VALUE.search(v)
                    if m:
                        ssh_version = m.group(1)
                continue
            if "system.services.telnet" in pl or (pl == "system.services" and v.lower() == "telnet"):
                telnet_on = True
                continue
            if "web-management.http" in pl:
                http_on = True
                continue
            if "web-management.https" in pl:
                https_on = True
                continue
            if "system.syslog.host" in pl or (pl == "system.syslog" and v):
                host = _syslog_host(pl) or v
                if host and host not in syslog_servers:
                    syslog_servers.append(host)
                syslog_host = host or syslog_host
                continue
            if "system.ntp.server" in pl:
                server = v.rstrip(";").strip()
                if server and server not in ntp_servers:
                    ntp_servers.append(server)
                continue
            if pl.startswith("snmp.community."):
                parts = pl.split(".")
                if len(parts) > 2 and parts[2]:
                    name = parts[2]
                    restricted = snmp_communities.get(name, False) or "clients" in pl
                    snmp_communities[name] = restricted
                continue
            if pl.startswith("snmp.v3."):
                snmp_v3 = True
                continue
            if "encrypted-password" in pl or "encrypted-password" in v:
                hashing.add(hash_strength(v))
                continue
            if re.match(r"^host-name", pl):
                continue
            if re.match(r"^(ge|xe|et|fe|ae|em|fxp)-", pl):
                name = pl.split(".")[0]
                if name not in ifaces:
                    ifaces.append(name)
                    ridx += 1
                    resources.append(self.add_resource(
                        out, f"if-{ridx}", "interface", name, self.vendor, self.platform, {}, lineno, ""))
                continue
            if "security-zone" in pl:
                continue

            self.add_fragment(out, path, f"{path} {value}".strip(), lineno)

        out.facts.append(make_fact("management.ssh.enabled",
                                   FactStatus.PRESENT if ssh_on else FactStatus.ABSENT,
                                   ssh_on, None, vid))
        if ssh_version:
            out.facts.append(make_fact("management.ssh.version", FactStatus.PRESENT, ssh_version, None, vid))
        out.facts.append(make_fact("management.telnet.enabled",
                                   FactStatus.PRESENT if telnet_on else FactStatus.ABSENT,
                                   telnet_on, None, vid))
        out.facts.append(make_fact("management.http.enabled",
                                   FactStatus.PRESENT if http_on else FactStatus.ABSENT,
                                   http_on, None, vid))
        out.facts.append(make_fact("management.https.enabled",
                                   FactStatus.PRESENT if https_on else FactStatus.ABSENT,
                                   https_on, None, vid))
        out.facts.append(make_fact("logging.remote.enabled",
                                   FactStatus.PRESENT if syslog_servers else FactStatus.ABSENT,
                                   bool(syslog_servers), None, vid))
        for host in syslog_servers:
            out.facts.append(make_fact("logging.remote.servers", FactStatus.PRESENT,
                                       host, None, vid, entity=host))
        for server in ntp_servers:
            out.facts.append(make_fact("ntp.servers", FactStatus.PRESENT,
                                       server, None, vid, entity=server))
        for name, restricted in snmp_communities.items():
            out.facts.append(make_fact("snmp.version", FactStatus.PRESENT, "v2c", None, vid,
                                       entity=name))
            out.facts.append(make_fact(
                "snmp.communities_restricted",
                FactStatus.PRESENT if restricted else FactStatus.ABSENT,
                restricted, None, vid, entity=name,
                notes="" if restricted else "community has no client address restriction"))
        if snmp_v3:
            out.facts.append(make_fact("snmp.version", FactStatus.PRESENT, "v3", None, vid,
                                       entity="v3"))
        out.facts.append(make_fact("network.route.present", FactStatus.UNKNOWN, None, None, vid,
                                   "junos routes not covered by this parser"))
        if ntp_servers:
            for n in ntp_servers:
                ridx += 1
                resources.append(self.add_resource(
                    out, f"ntp-{ridx}", "ntp_server", n, self.vendor, self.platform, {}, 0, ""))
        for h in hashing:
            out.facts.append(make_fact("authentication.password.hashing", FactStatus.PRESENT, h, None, vid))
        out.facts.append(make_fact("network.interface.present",
                                   FactStatus.PRESENT if ifaces else FactStatus.ABSENT,
                                   bool(ifaces), None, vid))

        out.resources = resources
