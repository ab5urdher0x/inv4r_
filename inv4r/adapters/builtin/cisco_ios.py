"""Tier-2 deterministic parser for Cisco IOS / IOS-XE style configs."""

from __future__ import annotations

from pathlib import Path

from inv4r.adapters.base import NormalizationOutput, ParsedRepresentation
from inv4r.adapters.builtin.base_builtin import BuiltinParser
from inv4r.core.facts import FactStatus, SecurityFact, stable_fact_id
from inv4r.core.sections import Section, parse_sections
from inv4r.core.semantic import SemanticEngine, resolve_conflicts
from inv4r.detection import DetectionResult

_SEMANTIC_DIR = Path(__file__).resolve().parents[1] / "semantic"

_LEGACY_HTTP_ABSENT = ("no `ip http server` configured",
                       "no `ip http secure-server` configured")


class CiscoIOSAdapter(BuiltinParser):
    adapter_id = "builtin-cisco-ios"
    vendor = "cisco-ios"
    platform = "ios"
    formats = ("hierarchical_cli", "flat_cli")

    def __init__(self) -> None:
        super().__init__()
        self._engine = SemanticEngine(_SEMANTIC_DIR)

    def extract(self, parsed: ParsedRepresentation, detection: DetectionResult,
                out: NormalizationOutput) -> None:
        text = parsed.notes.get("evidence_text", "")
        sections = parse_sections(text)

        facts = resolve_conflicts(self._engine.apply(sections))

        facts.extend(self._acl_existence(sections))

        facts.extend(self._compat_facts(facts, sections))

        out.facts = facts

        resources: list = []
        ridx = 0
        for sec in sections:
            if sec.kind == "interface":
                ridx += 1
                resources.append(self.add_resource(
                    out, f"if-{ridx}", "interface", sec.entity,
                    self.vendor, self.platform, {}, sec.line_no, sec.raw_text))
            elif sec.kind == "acl":
                ridx += 1
                resources.append(self.add_resource(
                    out, f"acl-{ridx}", "acl", sec.entity,
                    self.vendor, self.platform, dict(sec.attributes), sec.line_no, sec.raw_text))
            elif sec.kind == "credential":
                ridx += 1
                resources.append(self.add_resource(
                    out, f"cred-{ridx}", "user", sec.entity,
                    self.vendor, self.platform, {}, sec.line_no, sec.raw_text))
            elif sec.kind == "snmp" and sec.statements:
                st = sec.statements[0]
                ridx += 1
                resources.append(self.add_resource(
                    out, f"snmp-{ridx}", "snmp_community", sec.entity,
                    self.vendor, self.platform, {"version": "v2c"}, st.line_no, st.raw))
            elif sec.kind == "global" and sec.statements:
                st = sec.statements[0]
                if st.field == "host" and sec.raw_text.lower().startswith("logging host"):
                    ridx += 1
                    resources.append(self.add_resource(
                        out, f"sys-{ridx}", "syslog_server", st.values[0] if st.values else "",
                        self.vendor, self.platform, {}, st.line_no, st.raw))
                elif st.field == "route":
                    ridx += 1
                    resources.append(self.add_resource(
                        out, f"rt-{ridx}", "route",
                        f"{st.values[0]} via {st.values[-1]}" if len(st.values) >= 3 else sec.raw_text,
                        self.vendor, self.platform, {}, st.line_no, st.raw))
        out.resources = resources

        mapped_lines = {ln for f in facts for s in f.evidence_spans
                        for ln in (s.get("line_start"),)}
        for sec in sections:
            for st in sec.statements:
                if st.line_no in mapped_lines or not st.raw or len(st.raw) <= 3:
                    continue
                if st.raw.strip().startswith(("!", "#")):
                    continue
                self.add_fragment(out, st.field or "unmapped", st.raw, st.line_no)

        parsed.notes["semantic_trace"] = self._engine.trace[:400]
        parsed.notes["sections_parsed"] = len(sections)


    @staticmethod
    def _acl_existence(sections: list[Section]) -> list[SecurityFact]:
        acl_secs = [s for s in sections if s.kind == "acl"]
        if not acl_secs:
            return [SecurityFact(
                fact_id=stable_fact_id("acl.present", False, None, None),
                name="acl.present", status=FactStatus.ABSENT, value=False,
                confidence=1.0, source_adapter="builtin-cisco-ios",
                notes="no ACL objects defined", scope="device",
                derivation="derived")]
        return [SecurityFact(
            fact_id=stable_fact_id("acl.present", True, s.line_no, s.entity),
            name="acl.present", status=FactStatus.PRESENT, value=True,
            confidence=1.0, evidence_spans=[{"line_start": s.line_no, "line_end": s.line_no}],
            source_adapter="builtin-cisco-ios", notes="ACL object defined",
            scope="acl", entity=s.entity, derivation="direct",
            evidence_texts=[s.raw_text]) for s in acl_secs]

    def _compat_facts(self, facts: list[SecurityFact], sections: list[Section]) -> list[SecurityFact]:
        """Derive the pre-existing global fact names the dashboard/controls"""
        derived: list[SecurityFact] = []

        def _has(name: str, status: str = FactStatus.PRESENT) -> bool:
            return any(f.name == name and f.status == status for f in facts)

        def _val(name: str):
            for f in facts:
                if f.name == name and f.status == FactStatus.PRESENT:
                    return f.value
            return None

        mgmt_acl = _has("management.acl.applied")
        derived.append(SecurityFact(
            fact_id=stable_fact_id("management.acl.present", mgmt_acl, None, None),
            name="management.acl.present",
            status=FactStatus.PRESENT if mgmt_acl else FactStatus.ABSENT,
            value=mgmt_acl, confidence=1.0,
            source_adapter="builtin-cisco-ios",
            notes="derived: ACL bound to a management surface (vty/http)" if mgmt_acl
                  else "no ACL bound to any management surface",
            scope="device", derivation="derived"))

        for name, note in (("management.http.enabled", _LEGACY_HTTP_ABSENT[0]),
                           ("management.https.enabled", _LEGACY_HTTP_ABSENT[1])):
            if not any(f.name == name for f in facts):
                derived.append(SecurityFact(
                    fact_id=stable_fact_id(name, False, None, None),
                    name=name, status=FactStatus.ABSENT, value=False, confidence=1.0,
                    source_adapter="builtin-cisco-ios", notes=note,
                    scope="device", derivation="inferred"))

        if not any(f.name == "snmp.v1.v2c.enabled" for f in facts):
            derived.append(SecurityFact(
                fact_id=stable_fact_id("snmp.v1.v2c.enabled", False, None, None),
                name="snmp.v1.v2c.enabled", status=FactStatus.ABSENT, value=False,
                confidence=1.0, source_adapter="builtin-cisco-ios",
                notes="no snmp-server community configured",
                scope="device", derivation="inferred"))

        local_types = {str(f.value) for f in facts
                       if f.name == "credential.storage_type" and f.scope == "credential"}
        if local_types:
            order = ["type9", "type8", "type5", "type7", "plaintext", "unknown"]
            best = next((t for t in order if t in local_types), "unknown")
            derived.append(SecurityFact(
                fact_id=stable_fact_id("authentication.password.hashing", best, None, None),
                name="authentication.password.hashing", status=FactStatus.PRESENT,
                value=best, confidence=1.0,
                source_adapter="builtin-cisco-ios",
                notes=f"legacy alias of strongest local credential class {sorted(local_types)}",
                scope="device", derivation="aggregated"))

        term = [f for f in facts if f.name == "acl.terminal_action" and f.scope == "acl"]
        if term:
            explicit_denies = {f.entity for f in term if f.value == "explicit_deny"}
            value = "deny" if explicit_denies else "permit"
            derived.append(SecurityFact(
                fact_id=stable_fact_id("acl.default_action", value, None, None),
                name="acl.default_action", status=FactStatus.PRESENT, value=value,
                confidence=0.9, source_adapter="builtin-cisco-ios",
                notes=f"legacy alias; ACLs with explicit terminal deny: {sorted(explicit_denies) or 'none'}",
                scope="device", derivation="aggregated"))

        has_if = any(s.kind == "interface" for s in sections)
        derived.append(SecurityFact(
            fact_id=stable_fact_id("network.interface.present", has_if, None, None),
            name="network.interface.present",
            status=FactStatus.PRESENT if has_if else FactStatus.ABSENT,
            value=True, confidence=1.0, source_adapter="builtin-cisco-ios",
            notes="derived compatibility fact; per-interface objects are resources",
            scope="device", derivation="derived"))
        return derived
