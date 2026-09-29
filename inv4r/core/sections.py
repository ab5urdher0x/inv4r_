"""Vendor-neutral intermediate representation for IOS-style hierarchical CLI."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_RE_SECTION = re.compile(
    r"^(?P<head>line|interface|router|ip access-list|access-list|aaa|snmp-server|"
    r"username|enable|ip http|logging|ntp|banner|bridge|controller|voice-service|"
    r"policy-map|class-map|crypto|ip route|hostname|service|no\s+ip http)\b.*$",
    re.I,
)
_RE_LINE_HEAD = re.compile(r"^line\s+(vty|con|console|aux|telnet|ssh|\d+)\b(?P<rest>.*)$", re.I)
_RE_ACL_NAMED = re.compile(r"^(?:ip\s+|ipv6\s+)?access-list\s+(?P<type>standard|extended)\s+(?P<name>\S+)", re.I)
_RE_ACL_NUMBERED = re.compile(r"^access-list\s+(?P<num>\d+)\s+(?P<action>permit|deny)\b.*$", re.I)
_RE_ACL_RULE = re.compile(r"^\s*(?:\d+\s+)?(?P<action>permit|deny)\b(?P<rest>.*)$", re.I)
_RE_IFACE_HEAD = re.compile(r"^interface\s+(?P<name>\S+)", re.I)
_RE_LOGGING_HEAD = re.compile(r"^logging\s+(host|buffered|trap|monitor)\b", re.I)


@dataclass
class Statement:
    """One config line inside a section, tokenized into a field + values."""

    raw: str
    line_no: int
    field: str
    values: list[str] = field(default_factory=list)
    negated: bool = False

    def to_json(self) -> dict[str, Any]:
        return {"field": self.field, "values": self.values, "raw": self.raw,
                "line_no": self.line_no, "negated": self.negated}


_NOISE = {"ip", "no", "service"}

_FIELD_ALIASES = {
    "secure-server": "secure_server",
    "access-class": "access_class",
    "password-encryption": "password_encryption",
    "new-model": "new_model",
    "exec-timeout": "exec_timeout",
    "time-out": "time-out",
    "input": "input",
}


def _shape(toks: list[str]) -> tuple[str, list[str]]:
    """Deterministically shape tokens into (field, values)."""
    t = list(toks)
    if t and t[0].lower() == "ip" and len(t) > 1:
        t = t[1:]
    if not t:
        return "", []
    head = t[0].lower()
    second = t[1].lower() if len(t) > 1 else ""

    if head == "transport" and second in ("input", "output", "preferred"):
        return f"transport_{second}", t[2:]
    if head == "http":
        if second == "server":
            return "http_server", t[2:]
        if second == "secure-server":
            return "secure_server", t[2:]
        return _FIELD_ALIASES.get(second, second), t[2:]
    if head == "ssh" and second in ("version", "time-out", "authentication-retries"):
        return f"ssh_{second}", t[2:]
    if head == "ssh" and second == "server":
        return "ssh_server", t[2:]
    if head == "ssh" and second == "server":
        return "ssh_server", t[2:]
    if head == "server" and second == "algorithm":
        return "server_algorithm", t[2:]
    if head == "telnet" and second == "server":
        return "telnet_server", t[2:]
    if head == "exec" and second == "timeout":
        return "exec_timeout", t[2:]
    if head == "service" and second == "password-encryption":
        return "password_encryption", t[2:]
    if head == "aaa" and second in ("new-model", "new_model"):
        return "new_model", t[2:]
    if head == "access" and second == "class":
        return "access_class", t[2:]
    if head == "access" and second == "group":
        return "access_group", t[2:]
    if head == "ipv6" and second == "access-class":
        return "ipv6_access_class", t[2:]
    if head in ("snmp-server",) and second:
        return _FIELD_ALIASES.get(second, second), t[2:]
    if head == "logging" and second:
        return _FIELD_ALIASES.get(second, second), t[2:]
    if head in ("username", "enable"):
        for j, tok in enumerate(t[1:], start=1):
            if tok.lower() in ("secret", "password"):
                return tok.lower(), t[j + 1:]
        return head, t[1:]
    if head == "wpa-psk":
        return "psk", t[1:]
    if head in ("tacacs-server", "radius-server") and second == "key":
        return "key", t[2:]
    if head == "ppp" and second == "chap" and len(t) > 2 and t[2].lower() == "password":
        return "password", t[3:]
    if head == "chap" and second == "password":
        return "password", t[2:]
    if head == "access-list" and second and len(t) > 2 and t[2].lower() in ("permit", "deny"):
        return t[2].lower(), t[3:]
    return _FIELD_ALIASES.get(head, head), t[1:]


@dataclass
class Section:
    """A structural section of the configuration."""

    kind: str
    entity: str
    line_no: int
    raw_text: str
    statements: list[Statement] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "entity": self.entity, "line_no": self.line_no,
            "raw_text": self.raw_text, "attributes": self.attributes,
            "statements": [s.to_json() for s in self.statements],
        }


def _mk_stmt(line_no: int, raw: str) -> Statement:
    negated = bool(re.match(r"^\s*no\s+\S", raw, re.I))
    body = re.sub(r"^\s*no\s+", "", raw, flags=re.I) if negated else raw
    body = body.strip()
    toks = body.split()
    if not toks:
        return Statement(raw=raw.strip(), line_no=line_no, field="", values=[])
    if toks and toks[0].isdigit() and len(toks) > 1 and toks[1].lower() in ("permit", "deny"):
        toks = toks[1:]
    field_name, values = _shape(toks)
    return Statement(raw=raw.strip(), line_no=line_no, field=field_name, values=values,
                     negated=negated)


def parse_sections(text: str) -> list[Section]:
    """Parse IOS-style text into structural sections preserving context."""
    sections: list[Section] = []
    current: Section | None = None

    def _close():
        nonlocal current
        if current is not None:
            sections.append(current)
            current = None

    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith(("!", "#")):
            continue

        m = _RE_LINE_HEAD.match(stripped)
        if m:
            _close()
            rest = m.group("rest") or ""
            kind_map = {"vty": "line_vty", "con": "line_console", "console": "line_console",
                        "aux": "line_aux", "telnet": "line_telnet", "ssh": "line_ssh"}
            word = m.group(1).lower()
            kind = kind_map.get(word, "line_other")
            entity = f"{word} {rest.strip()}".strip()
            current = Section(kind=kind, entity=entity, line_no=i, raw_text=stripped)
            continue

        m = _RE_ACL_NAMED.match(stripped)
        if m:
            _close()
            fam = "ipv6" if stripped.lower().startswith("ipv6") else "ipv4"
            current = Section(kind="acl", entity=m.group("name"), line_no=i, raw_text=stripped,
                              attributes={"family": fam, "type": m.group("type")})
            continue

        m = _RE_ACL_NUMBERED.match(stripped)
        if m:
            num = m.group("num")
            entity = f"acl-{num}"
            if current is not None and current.kind == "acl" and current.entity == entity:
                if not re.match(r"^\s*access-list\s+\d+\s+remark\b", stripped, re.I):
                    current.statements.append(_mk_stmt(i, stripped))
                continue
            _close()
            fam = "mac" if 700 <= int(num) < 799 else "ipv4"
            current = Section(kind="acl", entity=entity, line_no=i, raw_text=stripped,
                              attributes={"family": fam, "type": "numbered", "number": int(num)})
            if not re.match(r"^\s*access-list\s+\d+\s+remark\b", stripped, re.I):
                current.statements.append(_mk_stmt(i, stripped))
            continue

        m = _RE_IFACE_HEAD.match(stripped)
        if m:
            _close()
            current = Section(kind="interface", entity=m.group("name"), line_no=i, raw_text=stripped)
            continue

        if current is not None and current.kind == "acl":
            mr = _RE_ACL_RULE.match(stripped)
            if mr:
                current.statements.append(_mk_stmt(i, stripped))
                continue

        hm = _RE_SECTION.match(stripped)
        if hm:
            head = hm.group("head").lower()
            if (head == "logging" and current is not None
                    and current.kind in ("line_vty", "line_console", "line_aux",
                                         "line_telnet", "line_ssh", "line_other", "interface")
                    and not _RE_LOGGING_HEAD.match(stripped)):
                current.statements.append(_mk_stmt(i, stripped))
                continue
            _close()
            if head == "username" or head == "enable":
                ename = stripped.split()[1] if len(stripped.split()) > 1 else stripped
                label = f"enable {ename}" if head == "enable" else f"username {ename}"
                current = Section(kind="credential", entity=label, line_no=i, raw_text=stripped)
                current.statements.append(_mk_stmt(i, stripped))
                _close()
                continue
            if head == "snmp-server":
                current = Section(kind="snmp", entity=stripped.split()[1] if len(stripped.split()) > 1 else stripped,
                                  line_no=i, raw_text=stripped)
                current.statements.append(_mk_stmt(i, stripped))
                _close()
                continue
            if head in ("ip http", "no ip http"):
                current = Section(kind="http_server", entity="http", line_no=i, raw_text=stripped)
                current.statements.append(_mk_stmt(i, stripped))
                _close()
                continue
            if head == "logging" and _RE_LOGGING_HEAD.match(stripped):
                current = Section(kind="logging", entity="logging", line_no=i, raw_text=stripped)
                current.statements.append(_mk_stmt(i, stripped))
                _close()
                continue
            if head == "aaa":
                current = Section(kind="aaa", entity="aaa", line_no=i, raw_text=stripped)
                current.statements.append(_mk_stmt(i, stripped))
                _close()
                continue
            current = Section(kind="global", entity="global", line_no=i, raw_text=stripped)
            current.statements.append(_mk_stmt(i, stripped))
            _close()
            continue

        if current is None:
            current = Section(kind="global", entity="global", line_no=i, raw_text=stripped)
        current.statements.append(_mk_stmt(i, stripped))

    _close()
    return sections


def sections_to_json(sections: list[Section]) -> list[dict[str, Any]]:
    return [s.to_json() for s in sections]
