"""Tier-2 deterministic parser for Arista EOS configs."""

from __future__ import annotations

import re

from inv4r.adapters.base import NormalizationOutput, ParsedRepresentation
from inv4r.adapters.builtin.base_builtin import BuiltinParser, hash_strength, make_fact
from inv4r.core.facts import FactStatus
from inv4r.detection import DetectionResult

_RE_API_HTTP = re.compile(r"^\s*management api http-commands\s*$", re.I)
_RE_API_SHUTDOWN = re.compile(r"^\s*(no\s+)?shutdown\s*$", re.I)
_RE_SSH_IDLE = re.compile(r"^\s*management ssh\s*$", re.I)
_RE_IDLE_TIMEOUT = re.compile(r"^\s*idle-timeout\s+(\d+)", re.I)
_RE_LOG_HOST = re.compile(r"^\s*logging host\s+(\S+)", re.I)
_RE_LOG_BUF = re.compile(r"^\s*logging buffered\s+(\d+)", re.I)
_RE_SECRET = re.compile(r"^\s*(?:enable|username|aaa root)\s+secret\s+(\S+)\s+(\S+)", re.I)
_RE_ROUTE = re.compile(r"^\s*ip route\s+(\S+)\s+(\S+)", re.I)
_RE_IFACE = re.compile(r"^\s*interface\s+(\S+)", re.I)
_RE_AAA = re.compile(r"^\s*aaa authentication login\b", re.I)


class AristaEOSAdapter(BuiltinParser):
    adapter_id = "builtin-arista-eos"
    vendor = "arista-eos"
    platform = "eos"
    formats = ("hierarchical_cli",)

    def extract(self, parsed: ParsedRepresentation, detection: DetectionResult,
                out: NormalizationOutput) -> None:
        text = parsed.notes.get("evidence_text", "")
        lines = text.splitlines()
        vid = self.adapter_id

        api_enabled = False
        in_api = False
        in_ssh_mgmt = False
        ssh_idle: int | None = None
        syslog_host = None
        log_buffered = False
        hashing: set[str] = set()
        routes = 0
        ifaces: list[str] = []
        aaa = False
        resources: list = []
        ridx = 0

        for i, raw in enumerate(lines, start=1):
            line = raw.rstrip()

            if _RE_API_HTTP.match(line):
                in_api = True
                continue
            if _RE_SSH_IDLE.match(line):
                in_ssh_mgmt = True
                continue
            if _RE_IFACE.match(line):
                in_api = in_ssh_mgmt = False
                m = _RE_IFACE.match(line)
                ifaces.append(m.group(1))
                ridx += 1
                resources.append(self.add_resource(
                    out, f"if-{ridx}", "interface", m.group(1), self.vendor, self.platform, {}, i, line.strip()))
                continue

            m = _RE_API_SHUTDOWN.match(line)
            if m and in_api:
                api_enabled = bool(m.group(1))
                continue
            m = _RE_IDLE_TIMEOUT.match(line)
            if m and in_ssh_mgmt:
                ssh_idle = int(m.group(1))
                continue
            m = _RE_LOG_HOST.match(line)
            if m:
                syslog_host = m.group(1)
                continue
            if _RE_LOG_BUF.match(line):
                log_buffered = True
                continue
            m = _RE_SECRET.match(line)
            if m:
                hashing.add(hash_strength(line))
                continue
            m = _RE_ROUTE.match(line)
            if m:
                routes += 1
                continue
            if _RE_AAA.match(line):
                aaa = True
                continue

            s = line.strip()
            if s and not s.startswith(("!", "#")) and s not in ("end",) and not s.startswith("description"):
                self.add_fragment(out, s.split()[0], s, i)

        out.facts.append(make_fact("management.https.enabled",
                                   FactStatus.PRESENT if api_enabled else FactStatus.ABSENT,
                                   api_enabled, None, vid, "management api http-commands (https)"))
        out.facts.append(make_fact("management.ssh.enabled", FactStatus.PRESENT, True, None, vid,
                                   "ssh mgmt implied by management ssh block"))
        if ssh_idle is not None:
            out.facts.append(make_fact("management.session_timeout", FactStatus.PRESENT,
                                       ssh_idle, None, vid))
        out.facts.append(make_fact("logging.remote.enabled",
                                   FactStatus.PRESENT if syslog_host else FactStatus.ABSENT,
                                   bool(syslog_host), None, vid))
        out.facts.append(make_fact("logging.local.enabled",
                                   FactStatus.PRESENT if log_buffered else FactStatus.ABSENT,
                                   log_buffered, None, vid))
        for h in hashing:
            out.facts.append(make_fact("authentication.password.hashing", FactStatus.PRESENT, h, None, vid))
        out.facts.append(make_fact("network.route.present",
                                   FactStatus.PRESENT if routes else FactStatus.ABSENT, routes > 0, None, vid))
        out.facts.append(make_fact("authentication.aaa.enabled",
                                   FactStatus.PRESENT if aaa else FactStatus.ABSENT, aaa, None, vid))
        out.facts.append(make_fact("network.interface.present",
                                   FactStatus.PRESENT if ifaces else FactStatus.ABSENT, bool(ifaces), None, vid))

        out.resources = resources
