"""Universal detection engine: format, vendor, platform, OS version."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_DATA = Path(__file__).resolve().parents[1] / "data" / "detection_signatures.yaml"


@dataclass
class DetectionResult:
    input_format: str
    vendor: str = "unknown"
    platform: str = "unknown"
    os_version: str = ""
    model_hint: str = ""
    hostname: str = ""
    serial: str = ""
    confidence: float = 0.0
    reasons: list[str] = field(default_factory=list)
    candidate_vendors: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "input_format": self.input_format,
            "vendor": self.vendor,
            "platform": self.platform,
            "os_version": self.os_version,
            "model_hint": self.model_hint,
            "hostname": self.hostname,
            "serial": self.serial,
            "confidence": round(float(self.confidence), 3),
            "reasons": self.reasons,
            "candidate_vendors": self.candidate_vendors,
        }


def detect_format(text: str) -> tuple[str, list[str]]:
    """Detect the structural input format from content only."""
    reasons: list[str] = []
    stripped = text.strip()
    if not stripped:
        return "unknown", ["empty input"]

    if stripped.startswith("{") or stripped.startswith("["):
        try:
            import json

            json.loads(text)
            return "json_structured", ["content parses as JSON"]
        except Exception:
            reasons.append("looks like JSON but does not parse")

    if stripped.startswith("<"):
        if re.search(r"<[a-zA-Z_][\w.-]*[\s>]", stripped):
            return "xml_structured", ["content starts with XML tags"]

    first_line = stripped.splitlines()[0]
    if not re.match(r"^[#!<\s{[]", first_line) and re.match(r"^[A-Za-z_][\w.-]*\s*:\s+\S", first_line):
        try:
            import yaml as _yaml

            if isinstance(_yaml.safe_load(text), dict):
                return "yaml_structured", ["content parses as YAML mapping"]
        except Exception:
            pass

    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return "unknown", ["blank input"]

    brace = any(ln.strip().endswith("{") for ln in lines)
    closing_brace = any(ln.strip() == "}" for ln in lines)
    set_cmds = sum(1 for ln in lines if ln.startswith(("set ", "delete ", "deactivate ")))
    bang = sum(1 for ln in lines if ln.startswith("!"))
    angle_sections = sum(1 for ln in lines if re.match(r"^config(-\w+)*\b", ln.strip()) or ln.strip() == "end")
    prompts = sum(1 for ln in lines if ln.startswith("<") and ln.endswith(">"))

    if brace and closing_brace and set_cmds:
        return "junos_braced", ["brace-delimited hierarchy with set/delete statements"]
    if brace and closing_brace and sum(1 for ln in lines if ln.strip().endswith("{")) >= 2:
        return "junos_braced", ["brace-delimited hierarchy without set statements"]
    dotted = sum(1 for ln in lines if re.match(r"^[a-z][\w-]*(\.[\w-]+){1,}[\s\d]", ln.strip(), re.I))
    if dotted >= 3 and dotted / max(len(lines), 1) > 0.2:
        return "dotted_path_cli", [f"{dotted} dotted-path statements"]
    if set_cmds >= 1 and set_cmds / max(len(lines), 1) > 0.5:
        return "set_commands", [f"{set_cmds} set/delete statements"]
    if prompts:
        return "hierarchical_cli", ["device prompt lines detected"]
    if angle_sections:
        return "hierarchical_cli", ["config/end section blocks detected"]
    if bang:
        return "flat_cli", [f"{bang} comment separators (IOS-style)"]
    return "unknown", ["no format signature matched"]


def _load_table() -> dict[str, Any]:
    try:
        with open(_DATA, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {"vendors": {}, "defaults": []}


def detection_version() -> str:
    """Version stamp of the signature table used for traceability."""
    return str(_load_table().get("version", "1"))


def detect_vendor(text: str, fmt: str, filename: str = "") -> DetectionResult:
    """Score every vendor signature; pick the winner with a confidence score."""
    table = _load_table()
    scores: dict[str, float] = {}
    matched: dict[str, list[str]] = {}

    for vid, spec in (table.get("vendors") or {}).items():
        score = 0.0
        hits: list[str] = []
        for sig in spec.get("signature_regexes") or []:
            n = len(re.findall(sig, text, re.IGNORECASE | re.MULTILINE))
            if n:
                score += min(n, 3) * 2.0
                hits.append(f"signature:{sig[:40]}")
        for sig in spec.get("weak_signature_regexes") or []:
            n = len(re.findall(sig, text, re.IGNORECASE | re.MULTILINE))
            if n:
                score += min(n, 3) * 0.5
                hits.append(f"weak:{sig[:40]}")
        for feat, rx in (spec.get("features") or {}).items():
            if re.search(rx, text, re.IGNORECASE | re.MULTILINE):
                score += float(spec.get("feature_weight", 5.0))
                hits.append(f"feature:{feat}")
        for rx in spec.get("negative_regexes") or []:
            if re.search(rx, text, re.IGNORECASE | re.MULTILINE):
                score -= 20.0
                hits.append(f"negative:{rx[:40]}")
        if hits and score > 0:
            scores[vid] = score
            matched[vid] = hits

    scores = {vid: s for vid, s in scores.items() if s >= 2.0}
    best = max(scores, key=scores.get) if scores else None
    platform = "unknown"
    version = model = ""
    hostname = serial = ""
    conf = 0.0
    candidates: list[str] = []

    if best is None and filename:
        fn = filename.lower()
        for vid, spec in (table.get("vendors") or {}).items():
            hint = spec.get("filename_hint")
            if hint and re.search(hint, fn):
                best = vid
                scores[vid] = 1.0
                matched[vid] = [f"filename hint: {hint}"]
                break

    if best is None:
        for rule in table.get("defaults") or []:
            if fmt == rule.get("format") and re.search(rule["require_regex"], text, re.IGNORECASE):
                best = rule["vendor"]
                scores[best] = float(rule.get("confidence", 0.5))
                matched[best] = [f"default rule: {rule.get('note', '')}"]
                break

    if best:
        spec = table["vendors"][best]
        conf = min(0.99, 0.3 + scores[best] / (scores[best] + 8.0))
        candidates = sorted(scores, key=scores.get, reverse=True)[:5]
        m = re.search(spec.get("version_regex") or r"(?!x)x", text, re.IGNORECASE | re.MULTILINE)
        if m:
            version = m.group(1)
        m2 = re.search(spec.get("model_regex") or r"(?!x)x", text, re.IGNORECASE | re.MULTILINE)
        if m2:
            model = m2.group(1)
        mh = re.search(spec.get("hostname_regex") or r"(?!x)x", text, re.IGNORECASE | re.MULTILINE)
        if mh:
            hostname = mh.group(1).strip().strip('"')
        ms = re.search(spec.get("serial_regex") or r"(?!x)x", text, re.IGNORECASE | re.MULTILINE)
        if ms:
            serial = ms.group(1).strip().strip('"')
        platform = spec.get("platform", best)

    if best is None:
        best = "unknown"

    return DetectionResult(
        input_format=fmt,
        vendor=best,
        platform=platform,
        os_version=version,
        model_hint=model,
        hostname=hostname,
        serial=serial,
        confidence=round(conf, 3) if best != "unknown" else 0.0,
        reasons=matched.get(best, ["no signature matched"]),
        candidate_vendors=candidates,
    )


def detect(text: str, filename: str = "") -> DetectionResult:
    fmt, _ = detect_format(text)
    return detect_vendor(text, fmt, filename)


def detect_file(path: str | Path) -> DetectionResult:
    p = Path(path)
    text = p.read_text(encoding="utf-8", errors="replace")
    fmt, _ = detect_format(text)
    return detect_vendor(text, fmt, p.name)
