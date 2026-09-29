"""Tier-5 generic structural parser."""

from __future__ import annotations

import re
from typing import Any

from inv4r.adapters.base import (
    AdapterCapabilities,
    AdapterMatch,
    Limitation,
    NormalizationOutput,
    ParsedRepresentation,
)
from inv4r.core.envelope import EvidenceEnvelope
from inv4r.core.model import SourceSpan, StructuralNode
from inv4r.core.unknown import fragment_from_node, guess_category
from inv4r.detection import DetectionResult

_INDENT_RE = re.compile(r"^(\s*)(.*)$")
_SET_RE = re.compile(r"^(set\s+.+)$")
_COMMENT_RE = re.compile(r"^\s*[#!;]|^\s*//")


def _split_statement(line: str) -> tuple[str | None, str | None]:
    """Split 'key value' -> (key, value); dotted paths become keys."""
    parts = line.split()
    if not parts:
        return None, None
    if len(parts) == 1:
        return parts[0], None
    return parts[0], " ".join(parts[1:])


def _looks_like_block_open(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    if s.endswith("{"):
        return True
    if s.endswith(":") and not s.endswith("::"):
        return True
    return False


def _is_dotted(key: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][\w-]*(\.[\w-]+)+$", key))


class GenericStructuralAdapter:
    """Tier 5 — universal structural ingestion with UNKNOWN semantics."""

    adapter_id = "generic-structural"
    adapter_version = "1.0.0"
    tier = 5

    FORMATS = {
        "hierarchical_cli", "flat_cli", "set_commands", "junos_braced",
        "dotted_path_cli", "yaml_structured", "xml_structured",
        "json_structured", "unknown",
    }

    def can_handle(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> AdapterMatch:
        if detection.input_format in self.FORMATS:
            conf = 0.3 if detection.vendor in ("unknown", "unknown-vendorx") else 0.28
            return AdapterMatch(self.adapter_id, self.tier, conf,
                                "universal structural fallback: preserves syntax, semantics UNKNOWN")
        return AdapterMatch(self.adapter_id, self.tier, 0.0, "format not attemptable")

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            parses_format="any textual/structured",
            normalizes_to_resources=False,
            produces_security_facts=False,
            requires_human_mapping=True,
        )

    def limitations(self) -> list[Limitation]:
        return [
            Limitation("no_semantics", "Structure only; security facts require human-approved mapping."),
            Limitation("heuristic_blocks", "Block boundaries inferred from indentation/braces; may merge sibling blocks."),
        ]


    def parse(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> ParsedRepresentation:
        text = evidence.content
        fmt = detection.input_format
        root = StructuralNode(node_type="root", name="configuration", path=[])

        if fmt == "json_structured":
            self._parse_json(text, root)
        elif fmt == "xml_structured":
            self._parse_xml(text, root)
        elif fmt == "yaml_structured":
            self._parse_yaml(text, root)
        elif fmt == "junos_braced":
            self._parse_braced(text, root)
        else:
            self._parse_line_based(text, root, fmt)

        warnings: list[str] = [
            "Structural parse only: no security semantics were applied.",
        ]
        if detection.vendor == "unknown":
            warnings.append("Vendor unidentified; platform-specific parsing skipped.")

        return ParsedRepresentation(
            evidence_id=evidence.evidence_id,
            adapter_id=self.adapter_id,
            tier=self.tier,
            root=root,
            warnings=warnings,
            notes={"input_format": fmt, "node_count": sum(1 for _ in root.walk())},
        )

    def _parse_line_based(self, text: str, root: StructuralNode, fmt: str) -> None:
        scanned: list[tuple[int, str, int]] = []
        for idx, raw in enumerate(text.splitlines(), start=1):
            m = _INDENT_RE.match(raw)
            body = m.group(2).strip()
            if not body or _COMMENT_RE.match(body):
                if body and _COMMENT_RE.match(body):
                    root.children.append(StructuralNode(
                        node_type="comment", name=body[:60], path=[f"comment{idx}"],
                        raw_text=body, source_span=SourceSpan(idx)))
                continue
            scanned.append((len(m.group(1).expandtabs(2)), body, idx))

        stack: list[tuple[int, StructuralNode]] = [(-1, root)]
        for pos, (indent, body, idx) in enumerate(scanned):
            next_indent = scanned[pos + 1][0] if pos + 1 < len(scanned) else -1

            if fmt == "set_commands" and body.startswith("set "):
                parts = body[4:].split()
                key, value = parts[0], (" ".join(parts[1:]) or None)
            else:
                key, value = _split_statement(body)
            if key is None:
                continue
            key = str(key)

            is_block = _looks_like_block_open(body) or next_indent > indent
            segments = key.split(".") if _is_dotted(key) else [key]

            while stack and indent <= stack[-1][0] and len(stack) > 1:
                stack.pop()

            parent = stack[-1][1]
            path = parent.path + segments
            node = StructuralNode(
                node_type="block" if is_block else "statement",
                name=segments[-1],
                path=path,
                value=None if is_block else value,
                raw_text=body,
                source_span=SourceSpan(idx),
            )
            parent.children.append(node)
            if is_block:
                stack.append((indent, node))

    def _parse_braced(self, text: str, root: StructuralNode) -> None:
        stack: list[StructuralNode] = [root]
        for idx, raw in enumerate(text.splitlines(), start=1):
            s = raw.strip()
            if not s or s.startswith("#") or s.startswith("/*"):
                continue
            if s == "}":
                if len(stack) > 1:
                    stack.pop()
                continue
            if s.endswith("{"):
                name = s[:-1].strip() or "anon"
                parts = name.split()
                node = StructuralNode(node_type="block", name=parts[0],
                                      path=stack[-1].path + [parts[0]] + parts[1:],
                                      raw_text=name, source_span=SourceSpan(idx))
                stack[-1].children.append(node)
                stack.append(node)
            else:
                parts = s.split()
                key = parts[0] if parts else s
                val = " ".join(parts[1:]) if len(parts) > 1 else None
                node = StructuralNode(node_type="statement", name=key,
                                      path=stack[-1].path + [key], value=val,
                                      raw_text=s, source_span=SourceSpan(idx))
                stack[-1].children.append(node)

    def _parse_json(self, text: str, root: StructuralNode) -> None:
        import json

        def walk(obj: Any, parent: StructuralNode, path: list[str]) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    node = StructuralNode(node_type="block" if isinstance(v, (dict, list)) else "statement",
                                          name=str(k), path=path + [str(k)],
                                          raw_text=f"{k}: {v}" if not isinstance(v, (dict, list)) else str(k))
                    parent.children.append(node)
                    walk(v, node, path + [str(k)])
            elif isinstance(obj, list):
                for i, v in enumerate(obj):
                    walk(v, parent, path + [str(i)])
            else:
                parent.value = None if parent.value in (None, "None") else parent.value

        walk(json.loads(text), root, [])

    def _parse_yaml(self, text: str, root: StructuralNode) -> None:
        import yaml as _yaml

        self._parse_json(_yaml.safe_dump(_yaml.safe_load(text), default_flow_style=False), root)

    def _parse_xml(self, text: str, root: StructuralNode) -> None:
        import xml.etree.ElementTree as ET

        def walk(elem: ET.Element, parent: StructuralNode, path: list[str]) -> None:
            node = StructuralNode(node_type="block", name=elem.tag, path=path + [elem.tag],
                                  raw_text=f"<{elem.tag}>")
            parent.children.append(node)
            text_val = (elem.text or "").strip()
            if text_val:
                node.children.append(StructuralNode(node_type="value", name="#text",
                                                    path=path + [elem.tag, "#text"], value=text_val))
            for child in elem:
                walk(child, node, path + [elem.tag])

        try:
            walk(ET.fromstring(text), root, [])
        except ET.ParseError as exc:
            root.children.append(StructuralNode(node_type="comment", name=f"xml parse error: {exc}",
                                                path=["error"]))


    def normalize(self, parsed: ParsedRepresentation, detection: DetectionResult) -> NormalizationOutput:
        """Extract known resources/values where possible; semantics stay UNKNOWN."""
        out = NormalizationOutput(normalization_status="PARTIAL")

        for node in parsed.root.walk():
            if node.node_type == "comment" or node is parsed.root:
                continue
            path = ".".join(node.path)
            if not path:
                continue
            frag = fragment_from_node(node, guess_category(path))
            proposal = propose_for_fragment(path, node.value or "")
            if proposal:
                frag.suggested_fact, frag.suggestion_confidence = proposal[0], proposal[1]
                frag.suggested_by = proposal[2].get("model", "") if len(proposal) > 2 else ""
            out.unknown_fragments.append(frag)

        if len(out.unknown_fragments) > 400:
            out.unknown_fragments = out.unknown_fragments[:400]

        return out


def propose_for_fragment(path: str, value: str):
    """Ask the AI lane orchestrator for a candidate mapping."""
    from inv4r.ai.proposer import propose

    return propose(path, value)
