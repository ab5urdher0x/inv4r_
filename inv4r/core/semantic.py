"""Declarative semantic-mapping engine."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from inv4r.core.facts import (CANONICAL_FACTS, Derivation, FactStatus,
                              SecurityFact, stable_fact_id)
from inv4r.core.sections import Section, Statement


class SemanticEngine:
    def __init__(self, semantic_dir: str | Path) -> None:
        self.semantic_dir = Path(semantic_dir)
        self.rules: list[dict[str, Any]] = []
        self.aggregations: list[dict[str, Any]] = []
        self.acl_semantics = False
        self.trace: list[dict[str, Any]] = []
        self.reload()

    def reload(self) -> None:
        self.rules, self.aggregations = [], []
        self.acl_semantics = False
        for p in sorted(self.semantic_dir.glob("*.yaml")):
            if p.name.startswith("_"):
                continue
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            self.rules.extend(data.get("mappings") or [])
            self.aggregations.extend(data.get("aggregations") or [])
            if data.get("acl_semantics"):
                self.acl_semantics = True


    @staticmethod
    def _section_matches(spec: Any, sec: Section) -> bool:
        kinds = spec if isinstance(spec, list) else [spec]
        return sec.kind in {str(k).lower() for k in kinds}

    @staticmethod
    def _stmt_matches(m: dict[str, Any], sec: Section, stmt: Statement) -> bool:
        if "section" in m and not SemanticEngine._section_matches(m["section"], sec):
            return False
        if "field" in m:
            fields = m["field"] if isinstance(m["field"], list) else [m["field"]]
            if stmt.field not in {str(f).lower() for f in fields}:
                return False
        if "contains" in m:
            joined = " ".join(v.lower() for v in stmt.values)
            needle = m["contains"]
            needles = needle if isinstance(needle, list) else [needle]
            if not all(str(n).lower() in joined for n in needles):
                return False
        if "negated" in m and bool(m["negated"]) != stmt.negated:
            return False
        if m.get("terminal") and stmt is not sec.statements[-1]:
            return False
        if "regex" in m and not re.search(str(m["regex"]), stmt.raw, re.I):
            return False
        return True


    def _emit(self, rule: dict[str, Any], sec: Section,
              stmt: Statement | None) -> SecurityFact | None:
        emit = rule.get("emit") or {}
        fact_name = emit.get("fact")
        if fact_name not in CANONICAL_FACTS:
            return None

        rx = rule.get("regex") or (rule.get("match") or {}).get("regex")
        groups: list[str] = []
        if rx and stmt is not None:
            mm = re.search(str(rx), stmt.raw, re.I)
            if mm:
                groups = list(mm.groups())

        value: Any = emit.get("value")
        if emit.get("value_template"):
            tmpl = str(emit["value_template"])
            if "{" in tmpl and not groups:
                return None
            value = tmpl.format(*groups) if groups else tmpl
            if value in ("true", "false"):
                value = value == "true"

        status = str(emit.get("status") or FactStatus.PRESENT)
        try:
            num = float(value)
            if status == FactStatus.PRESENT and emit.get("value_template") and num == int(num):
                value = num if "." in str(emit["value_template"]) else int(num)
        except (TypeError, ValueError):
            pass

        ev = rule.get("evidence") or {}
        texts: list[str] = []
        if stmt is not None:
            texts.append(stmt.raw)
        if ev.get("include_context"):
            texts.insert(0, sec.raw_text)
        spans: list[dict[str, Any]] = []
        if stmt is not None:
            spans.append({"line_start": stmt.line_no, "line_end": stmt.line_no})

        scope = str(emit.get("scope") or sec.kind)  # noqa: kept for rules
        entity: Any = None
        if emit.get("entity_template"):
            tmpl = str(emit["entity_template"])
            if tmpl.strip().lower() == "true":
                entity = sec.entity
            else:
                entity = tmpl.format(*groups) if groups else tmpl
        elif emit.get("entity") is not None:
            entity = emit.get("entity")
        elif scope not in ("device", "global"):
            entity = sec.entity

        return SecurityFact(
            fact_id=stable_fact_id(fact_name, value, stmt.line_no if stmt else sec.line_no, entity),
            name=fact_name, status=status, value=value,
            confidence=float(emit.get("confidence", 1.0)),
            evidence_spans=spans,
            source_adapter=f"semantic:{self.semantic_dir.name}",
            notes=str(emit.get("notes") or rule.get("notes") or ""),
            scope=scope, entity=entity,
            derivation=str(emit.get("derivation") or Derivation.DIRECT),
            evidence_texts=texts,
        )


    def _acl_facts(self, sections: list[Section]) -> list[SecurityFact]:
        """Terminal behavior per ACL object. This is ACL *protocol* logic"""
        if not self.acl_semantics:
            return []
        facts: list[SecurityFact] = []
        for sec in sections:
            if sec.kind != "acl":
                continue
            rules = [s for s in sec.statements if s.field in ("permit", "deny")]
            if rules and rules[-1].field == "deny":
                value, conf = "explicit_deny", 1.0
                last = rules[-1]
            else:
                value, conf = "implicit_deny", 0.9
                last = rules[-1] if rules else None
            texts = [last.raw] if last else []
            spans = [{"line_start": last.line_no, "line_end": last.line_no}] if last else []
            facts.append(SecurityFact(
                fact_id=stable_fact_id("acl.terminal_action", value, sec.line_no, sec.entity),
                name="acl.terminal_action", status=FactStatus.PRESENT, value=value,
                confidence=conf, evidence_spans=spans,
                source_adapter="semantic:acl-protocol",
                notes="terminal behavior of the ACL object",
                scope="acl", entity=sec.entity, derivation=Derivation.DIRECT,
                evidence_texts=[sec.raw_text] + texts,
            ))
            facts.append(SecurityFact(
                fact_id=stable_fact_id("acl.rule_count", len(rules), sec.line_no, sec.entity),
                name="acl.rule_count", status=FactStatus.PRESENT if rules else FactStatus.ABSENT,
                value=len(rules), confidence=1.0, evidence_spans=spans,
                source_adapter="semantic:acl-protocol", notes="",
                scope="acl", entity=sec.entity, derivation=Derivation.DIRECT,
                evidence_texts=[sec.raw_text],
            ))
        return facts


    def apply(self, sections: list[Section]) -> list[SecurityFact]:
        facts: list[SecurityFact] = []
        self.trace = []
        for sec in sections:
            for stmt in sec.statements:
                for rule in self.rules:
                    if not self._stmt_matches(rule.get("match") or {}, sec, stmt):
                        continue
                    f = self._emit(rule, sec, stmt)
                    if f is None:
                        continue
                    facts.append(f)
                    self.trace.append({
                        "raw": stmt.raw, "line_no": stmt.line_no,
                        "section": {"kind": sec.kind, "entity": sec.entity},
                        "parsed": stmt.to_json(),
                        "rule": rule.get("id") or "?",
                        "fact": f.to_json(),
                    })
        facts.extend(self._acl_facts(sections))
        facts.extend(self._aggregate(facts))
        return facts


    def _agg_match(self, spec: dict[str, Any], facts: list[SecurityFact]) -> list[SecurityFact]:
        out = []
        want = spec.get("fact")
        scopes = spec.get("scope")
        want_status = spec.get("status")
        bound_surfaces = spec.get("bound_surface")
        bound_names: set[str] | None = None
        if bound_surfaces:
            surfaces = bound_surfaces if isinstance(bound_surfaces, list) else [bound_surfaces]
            bound_names = set()
            for f in facts:
                if f.name != "acl.binding" or not f.value:
                    continue
                parts = str(f.value).split(":")
                if len(parts) >= 2 and parts[0] in {str(s) for s in surfaces}:
                    bound_names.add(parts[1])
        for f in facts:
            if f.name != want:
                continue
            if scopes and f.scope not in {str(s) for s in scopes}:
                continue
            if want_status and f.status not in {str(s) for s in want_status}:
                continue
            if bound_names is not None:
                ent = f.entity or ""
                if ent not in bound_names and ent.replace("acl-", "", 1) not in bound_names:
                    continue
            if "equals" in spec and f.value != spec["equals"]:
                continue
            if "equals_prefix" in spec and not str(f.value or "").startswith(str(spec["equals_prefix"])):
                continue
            if "contains" in spec:
                joined = " ".join(str(v).lower() for v in
                                  (f.value if isinstance(f.value, list) else [f.value]))
                needles = spec["contains"] if isinstance(spec["contains"], list) else [spec["contains"]]
                if not all(str(n).lower() in joined for n in needles):
                    continue
            out.append(f)
        return out

    def _aggregate(self, facts: list[SecurityFact]) -> list[SecurityFact]:
        produced: list[SecurityFact] = []
        for agg in self.aggregations:
            spec = agg.get("when_any") or agg.get("when_all") or {}
            emit = agg.get("emit") or {}
            fact_name = emit.get("fact")
            if fact_name not in CANONICAL_FACTS:
                continue
            matches = self._agg_match(spec, facts)
            ok = bool(matches)
            default = emit.get("default") or agg.get("default")
            if not ok and not default:
                continue

            if ok and agg.get("reduce") == "min":
                nums: list[float] = []
                for f in matches:
                    try:
                        nums.append(float(f.value))
                    except (TypeError, ValueError):
                        continue
                if not nums:
                    continue
                mn = min(nums)
                value: Any = int(mn) if mn == int(mn) else mn
                status = FactStatus.PRESENT
            elif ok and emit.get("value") is None:
                vals = {str(f.value) for f in matches}
                if len(vals) == 1:
                    value = matches[0].value
                else:
                    top = max(matches, key=lambda f: f.confidence)
                    value = top.value
                status = emit.get("status", FactStatus.PRESENT)
            elif ok:
                value = emit.get("value", True)
                status = emit.get("status", FactStatus.PRESENT)
            else:
                d = default or {}
                value = d.get("value")
                status = d.get("status", FactStatus.ABSENT)
                if str(value).lower() in ("true", "false") and status == FactStatus.ABSENT:
                    value = str(value).lower() == "true"

            lines = sorted({ln for f in matches for s in f.evidence_spans
                            for ln in (s.get("line_start"),) if ln})[:8]
            texts = [t for f in matches for t in f.evidence_texts][:4]
            notes_src = emit if ok else (default or {})
            if ok and len({str(f.value) for f in matches}) > 1 and emit.get("value") is None:
                notes_src = dict(notes_src or {})
                notes_src["notes"] = (str(notes_src.get("notes") or "") +
                                      " | mixed entity values: " +
                                      ", ".join(sorted({str(f.value) for f in matches}))).strip()
            produced.append(SecurityFact(
                fact_id=stable_fact_id(fact_name, value, lines[0] if lines else None, None),
                name=fact_name, status=status, value=value,
                confidence=float(notes_src.get("confidence", 1.0)),
                evidence_spans=[{"line_start": ln, "line_end": ln} for ln in lines],
                source_adapter="semantic:aggregation",
                notes=str(notes_src.get("notes") or ""),
                scope=str(emit.get("scope") or "device"), entity=None,
                derivation=Derivation.DERIVED,
                evidence_texts=texts,
            ))
            self.trace.append({
                "raw": "(aggregation)", "line_no": None,
                "section": {"kind": "device", "entity": None},
                "parsed": {"when": spec, "matched_entities": len(matches)},
                "rule": f"aggregation:{fact_name}",
                "fact": produced[-1].to_json(),
            })
        return produced


def resolve_conflicts(facts: list[SecurityFact]) -> list[SecurityFact]:
    """Deterministic fact resolution keyed on (scope, entity, fact name)."""
    best: dict[tuple, SecurityFact] = {}
    order: list[tuple] = []
    for f in facts:
        key = (f.scope, f.entity or "", f.name)
        if key not in best:
            best[key] = f
            order.append(key)
            continue
        cur = best[key]
        if str(f.value) == str(cur.value):
            cur.evidence_spans = (cur.evidence_spans + f.evidence_spans)[:8]
            cur.evidence_texts = (cur.evidence_texts + f.evidence_texts)[:4]
            cur.confidence = max(cur.confidence, f.confidence)
        else:
            if f.confidence > cur.confidence:
                cur, f = f, cur
                best[key] = cur
            cur.evidence_spans = (cur.evidence_spans + f.evidence_spans)[:8]
            cur.evidence_texts = (cur.evidence_texts + f.evidence_texts)[:4]
            cur.notes = (f"{cur.notes} | conflicting candidate {f.value!r} "
                         f"(conf={f.confidence:.2f})").strip(" |")
    return [best[k] for k in order]
