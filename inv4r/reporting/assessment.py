"""Assessment assembly and reporting (JSON + PDF)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import xml.sax.saxutils as _sax


def _esc(value: Any) -> str:
    """XML-escape any value for use inside a ReportLab Paragraph."""
    return _sax.escape("" if value is None else str(value))

from inv4r.controls.engine import ControlEngine, ControlResult, risk_score, summarize
from inv4r.core.coverage import remediation_coverage
from inv4r.core.facts import redact
from inv4r.core.provenance import ProvenanceChain
from inv4r.engine import DeviceResult, Engine


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class DeviceAssessment:
    device_result: DeviceResult
    controls: list[ControlResult] = field(default_factory=list)
    profile_id: str = ""
    score: int = 0
    band: str = ""

    def to_json(self) -> dict[str, Any]:
        r = self.device_result
        return {
            "source_path": r.envelope.source_path,
            "evidence_id": r.envelope.evidence_id,
            "hashes": {"sha256": r.envelope.raw_bytes_sha256, "md5": r.envelope.raw_bytes_md5},
            "detection": r.detection.to_json(),
            "device_metadata": dict(getattr(r.envelope, "metadata", None) or {}),
            "adapter": (r.resolution.chosen.adapter_id if r.resolution and r.resolution.chosen
                        else getattr(r, "_adapter_id", None)),
            "tier": (r.resolution.chosen.tier if r.resolution and r.resolution.chosen
                     else getattr(r, "_tier", None)),
            "coverage": r.coverage.to_json(),
            "normalization_status": (r.normalization.normalization_status
                                     if r.normalization else "NONE"),
            "resource_count": len(r.normalization.resources) if r.normalization else 0,
            "unknown_fragment_count": (len(r.normalization.unknown_fragments)
                                       if r.normalization else 0),
            "unknown_fragments": ([u.to_json() for u in r.normalization.unknown_fragments]
                                  if r.normalization else []),
            "resources": ([x.to_json() for x in r.normalization.resources]
                          if r.normalization else []),
            "facts": [f.to_json() for f in r.facts],
            "profile_id": self.profile_id,
            "score": self.score,
            "band": self.band,
            "controls": [c.to_json() for c in self.controls],
            "errors": r.errors,
        }


@dataclass
class Assessment:
    run_id: str
    created_at: str
    framework_profile: str
    devices: list[DeviceAssessment] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "created_at": self.created_at,
            "framework_profile": self.framework_profile,
            "summary": self.summary(),
            "devices": [d.to_json() for d in self.devices],
        }

    def summary(self) -> dict[str, Any]:
        agg = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0, "NOT_APPLICABLE": 0}
        for d in self.devices:
            s = summarize(d.controls)
            for k in agg:
                agg[k] += s.get(k, 0)
        return {
            "devices": len(self.devices),
            "controls_passed": agg["PASS"],
            "controls_failed": agg["FAIL"],
            "controls_unknown": agg["UNKNOWN"],
            "controls_not_applicable": agg["NOT_APPLICABLE"],
            "avg_score": (round(sum(d.score for d in self.devices) / len(self.devices), 1)
                          if self.devices else 0),
            "remediation": remediation_coverage(
                [c for d in self.devices for c in d.controls]).to_json(),
        }

    def save_json(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_json(), indent=2, default=str), encoding="utf-8")
        return p

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Assessment":
        """Rehydrate an assessment (enough fidelity to render the PDF)."""
        from inv4r.controls.engine import ControlResult
        from inv4r.core.coverage import CoverageReport
        from inv4r.core.envelope import EvidenceEnvelope
        from inv4r.core.facts import SecurityFact
        from inv4r.core.unknown import UnknownFragment
        from inv4r.core.model import SourceSpan
        from inv4r.detection import DetectionResult

        ass = cls(run_id=data.get("run_id", "run"),
                  created_at=data.get("created_at", ""),
                  framework_profile=data.get("framework_profile", ""))
        for dv in data.get("devices") or []:
            det = dv.get("detection") or {}
            detection = DetectionResult(
                input_format=det.get("input_format", "unknown"),
                vendor=det.get("vendor", "unknown"),
                platform=det.get("platform", "unknown"),
                os_version=det.get("os_version", ""),
                model_hint=det.get("model_hint", ""),
                hostname=det.get("hostname", ""),
                serial=det.get("serial", ""),
                confidence=det.get("confidence", 0.0),
            )
            env = EvidenceEnvelope(
                evidence_id=dv.get("evidence_id", ""),
                source_path=dv.get("source_path", ""),
                content="", raw_bytes_sha256=(dv.get("hashes") or {}).get("sha256", ""),
                raw_bytes_md5=(dv.get("hashes") or {}).get("md5", ""),
                size_bytes=0, line_count=0,
                metadata=dv.get("device_metadata") or {},
            )
            cov = dv.get("coverage") or {}
            coverage = CoverageReport(achieved_level=cov.get("achieved_level", 0),
                                      reasons=cov.get("reasons", []))
            facts = [SecurityFact(fact_id=f.get("fact_id", ""), name=f.get("name", ""),
                                  status=f.get("status", "UNKNOWN"), value=f.get("value"),
                                  confidence=f.get("confidence", 1.0),
                                  evidence_spans=f.get("evidence_spans") or [],
                                  source_adapter=f.get("source_adapter", ""))
                     for f in dv.get("facts") or []]
            unk = [UnknownFragment(fragment_id=u.get("fragment_id", ""),
                                   category=u.get("category", "other"),
                                   raw_path=u.get("raw_path", ""),
                                   raw_text=u.get("raw_text", ""))
                   for u in (dv.get("unknown_fragments") or [])]
            dr = DeviceResult(envelope=env, detection=detection,
                              resolution=None, parsed=None, normalization=None,
                              coverage=coverage,
                              provenance=ProvenanceChain(evidence_id=env.evidence_id),
                              errors=dv.get("errors") or [])
            dr._facts_json = facts
            dr._unknown_json = unk
            dr._resources_json = dv.get("resources") or []
            dr._adapter_id = dv.get("adapter")
            dr._tier = dv.get("tier")
            dr._normalization_status = dv.get("normalization_status", "NONE")
            controls = [ControlResult(control_id=c.get("control_id", ""),
                                      title=c.get("title", ""),
                                      severity=c.get("severity", "medium"),
                                      result=c.get("result", "UNKNOWN"),
                                      detail=c.get("detail", ""),
                                      evidence_lines=c.get("evidence_lines") or [],
                                      remediation=c.get("remediation") or [])
                        for c in dv.get("controls") or []]
            ass.devices.append(DeviceAssessment(device_result=dr, controls=controls,
                                                profile_id=dv.get("profile_id", ""),
                                                score=dv.get("score", 0),
                                                band=dv.get("band", "")))
        return ass


def run_assessment(engine: Engine, paths: list[str], profile_id: str,
                   control_engine: ControlEngine | None = None) -> Assessment:
    ce = control_engine or ControlEngine()
    ass = Assessment(run_id=f"run-{_now().replace(':', '')}", created_at=_now(),
                     framework_profile=profile_id)
    for path in paths:
        for result in engine.process_path(path):
            controls = ce.evaluate(result.facts, result.vendor, profile_id) if result.facts else []
            if controls:
                score, band = risk_score(controls, ce.get_profile(profile_id))
                if score == "N/A":
                    score, band = 0, "no applicable controls"
            else:
                score, band = 0, "insufficient evidence"
            ass.devices.append(DeviceAssessment(device_result=result, controls=controls,
                                                profile_id=profile_id, score=score, band=band))
    return ass


def _device_identity(r: DeviceResult) -> dict[str, str]:
    """Device identification for the report."""
    det = getattr(r, "detection", None)
    meta = dict(getattr(r.envelope, "metadata", None) or {})

    def pick(key: str, auto: str = "") -> str:
        user = meta.get(key)
        if user not in (None, ""):
            return str(user)
        return str(auto or "")

    return {
        "hostname": pick("hostname", getattr(det, "hostname", "")),
        "device_model": pick("device_model", getattr(det, "model_hint", "")),
        "serial": pick("serial", getattr(det, "serial", "")),
        "ip_address": pick("ip_address"),
        "site": pick("site"),
        "notes": pick("notes"),
    }


def _framework_label(profile_id: str) -> str:
    """Human framework name, never a slug like cis-network-baseline."""
    known = {
        "cis-network-baseline": "CIS Network Device Baseline",
        "nist-800-53-network": "NIST SP 800-53 Network Controls",
        "disa-stig-network": "DISA STIG Network Devices",
        "iso27001-network": "ISO/IEC 27001 Network Controls",
    }
    if profile_id in known:
        return known[profile_id]
    return (profile_id or "unknown").replace("-", " ").replace("_", " ").title()


# --------------------------------------------------------------------------- #
# Remediation value resolution
# --------------------------------------------------------------------------- #

# Command placeholders -> the visible uppercase hint shown when a value cannot
# be derived from the device's own evidence. Keeping commands as *values* that
# are XML-escaped at render time means nothing is ever dropped as markup.
_PLACEHOLDER_LABELS: dict[str, str] = {
    "iface": "INTERFACE_NAME",
    "iface-name": "INTERFACE_NAME",
    "interface": "INTERFACE_NAME",
    "syslog-ip": "SYSLOG_SERVER_IP",
    "community": "SNMP_COMMUNITY",
    "community-id": "SNMP_COMMUNITY_ID",
    "admin": "ADMIN_USER",
    "admin-name": "ADMIN_USER",
    "mgmt-net": "MANAGEMENT_SUBNET",
    "management-subnet": "MANAGEMENT_SUBNET",
    "wildcard": "SUBNET_WILDCARD",
    "mask": "SUBNET_MASK",
    "allowed-services": "ALLOWED_SERVICES",
    "new-secret": "NEW_SECRET",
    "user": "USERNAME",
    "minutes": "MINUTES",
    "hash": "PASSWORD_HASH",
    "gw": "GATEWAY_IP",
    "profile": "SYSLOG_PROFILE",
    "acl": "ACL_NAME",
    "vsys": "VSYS_ID",
    "authpw": "SNMPV3_AUTH_PASSWORD",
    "privpw": "SNMPV3_PRIV_PASSWORD",
    "key": "ENCRYPTION_KEY",
    "none": "NONE",
}


def _device_facts(r: DeviceResult) -> list[Any]:
    try:
        return list(r.facts)
    except Exception:  # pragma: no cover - defensive
        return []


def _device_resources(r: DeviceResult) -> list[dict[str, Any]]:
    res = getattr(r, "_resources_json", None)
    if res is not None:
        return list(res)
    norm = getattr(r, "normalization", None)
    if norm is not None and getattr(norm, "resources", None):
        return [x.to_json() for x in norm.resources]
    return []


def _remediation_context(d: DeviceAssessment) -> dict[str, str]:
    """Real values, taken from the device's own facts/resources.

    Only values we can actually see are substituted; everything else stays a
    visible placeholder. Nothing here is guessed.
    """
    r = d.device_result
    ctx: dict[str, str] = {}
    resources = _device_resources(r)

    insecure: list[tuple[dict[str, Any], list[str]]] = []
    for x in resources:
        if x.get("resource_type") != "interface":
            continue
        svcs = [str(s) for s in ((x.get("attributes") or {}).get("allowaccess") or [])]
        if any(s.lower() in ("telnet", "http") for s in svcs):
            insecure.append((x, svcs))
    if insecure:
        x, svcs = insecure[0]
        ctx["iface"] = str(x.get("name") or "")
        remaining = [s for s in svcs if s.lower() not in ("telnet", "http")]
        ctx["allowed-services"] = " ".join(remaining) if remaining else "https ssh"

    snmp = [x for x in resources if x.get("resource_type") == "snmp_community"]
    if snmp:
        ctx["community"] = str(snmp[0].get("name") or "")
        entry_id = (snmp[0].get("attributes") or {}).get("entry_id") or snmp[0].get("name")
        ctx["community-id"] = str(entry_id or "")

    for f in _device_facts(r):
        if getattr(f, "name", "") == "logging.remote.servers" and \
                getattr(f, "status", "") == "PRESENT" and f.value not in (None, ""):
            ctx["syslog-ip"] = str(f.value)
            break

    admins = [x for x in resources if x.get("resource_type") == "admin"]
    if admins:
        ctx["admin"] = str(admins[0].get("name") or "")
    return {k: v for k, v in ctx.items() if v}


def _resolve_command(cmd: str, ctx: dict[str, str]) -> tuple[str, list[str]]:
    """Substitute known values; return (command, unresolved placeholder hints)."""
    resolved = cmd
    unresolved: list[str] = []
    for tag, label in _PLACEHOLDER_LABELS.items():
        token = f"<{tag}>"
        if token not in resolved:
            continue
        value = ctx.get(tag)
        if value:
            resolved = resolved.replace(token, value)
        else:
            resolved = resolved.replace(token, f"<{label}>")
            if label not in unresolved:
                unresolved.append(label)
    return resolved, unresolved


def _line_texts(r: DeviceResult) -> dict[int, str]:
    """Map of line number -> redacted source text (live assessments only)."""
    content = getattr(getattr(r, "envelope", None), "content", "") or ""
    out: dict[int, str] = {}
    for i, line in enumerate(content.splitlines(), start=1):
        out[i] = str(redact(line.strip()))
    return out


def _evidence_text(control: ControlResult, facts: list[Any],
                   lines: dict[int, str], limit: int = 3) -> str:
    """Config line numbers + redacted line text, or the UNKNOWN reason."""
    if control.result == "UNKNOWN":
        reason = control.detail or "insufficient evidence"
        if "not reported" in reason or "could not determine" in reason:
            return "insufficient evidence: fact not reported by parser"
        return f"insufficient evidence: {reason}"
    parts: list[str] = []
    raw_lines: list[str] = []
    for f in facts:
        if getattr(f, "name", "") in set(control.facts_used or []):
            for span in getattr(f, "evidence_spans", []) or []:
                ln = span.get("line_start")
                if ln not in (None, 0):
                    raw_lines.append(str(ln))
            for t in getattr(f, "evidence_texts", []) or []:
                parts.append(str(redact(t)))
    lines_seen: list[str] = []
    for ln in control.evidence_lines or []:
        txt = lines.get(ln, "")
        lines_seen.append(f"L{ln}: {txt}" if txt else f"L{ln}")
    for raw in raw_lines:
        if f"L{raw}" not in " ".join(lines_seen):
            txt = lines.get(int(raw), "")
            if txt:
                lines_seen.append(f"L{raw}: {txt}")
    out = "; ".join(lines_seen[:limit])
    if not out:
        out = "; ".join(parts[:limit])
    if not out:
        out = "no evidence line recorded"
    return out


def _frag_lines(r: DeviceResult, limit: int = 12) -> list[tuple[Any, str, str]]:
    """(line, category, redacted raw text) for unknown fragments."""
    frags = getattr(r, "_unknown_json", None)
    if frags is None:
        norm = getattr(r, "normalization", None)
        frags = norm.unknown_fragments if norm else []
    out: list[tuple[Any, str, str]] = []
    for f in (frags or [])[:limit]:
        if isinstance(f, dict):
            span = f.get("source_span") or {}
            out.append((span.get("line_start", "?"), f.get("category", "other"),
                        str(redact(f.get("raw_text") or ""))))
        else:
            line = f.source_span.line_start if getattr(f, "source_span", None) else "?"
            out.append((line, getattr(f, "category", "other"),
                        str(redact(getattr(f, "raw_text", "")))))
    return out


def _unknown_count(r: DeviceResult) -> int:
    frags = getattr(r, "_unknown_json", None)
    if frags is None:
        norm = getattr(r, "normalization", None)
        frags = norm.unknown_fragments if norm else []
    return len(frags or [])


# --------------------------------------------------------------------------- #
# PDF rendering
# --------------------------------------------------------------------------- #

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_RESULT_ORDER = {"FAIL": 0, "UNKNOWN": 1, "PASS": 2, "NOT_APPLICABLE": 3}
_RESULT_COLORS = {"FAIL": "#b00020", "UNKNOWN": "#8a6d00", "PASS": "#2e7d32",
                  "NOT_APPLICABLE": "#607d8b"}
_SEV_COLORS = {"critical": "#b00020", "high": "#e65100", "medium": "#f9a825",
               "low": "#2e7d32"}


def _result_label(result: str) -> str:
    """Short labels so the Result column never wraps ('NOT_APPLICABLE' -> 'N/A')."""
    return "N/A" if result == "NOT_APPLICABLE" else result


def render_pdf(ass: Assessment, out_path: str | Path, kind: str = "device",
               preliminary: bool = False,
               suggestions: dict[str, dict[int, dict[str, Any]]] | None = None,
               ) -> Path:
    """Render the report.

    ``preliminary`` marks a report generated while unresolved fragments remain,
    so the cover says so and ``suggestions`` (node -> line -> proposed mapping)
    is printed next to each unmapped line: an operator sees what the pipeline
    *would* map the line to. A preliminary report never pretends to be final.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.pdfgen import canvas as _canvas
        from reportlab.platypus import (KeepTogether, PageBreak, Paragraph,
                                        SimpleDocTemplate, Spacer, Table, TableStyle)
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PDF support requires: pip install reportlab") from exc

    Path(out_path).parent.mkdir(parents=True, exist_ok=True)

    base = getSampleStyleSheet()
    title_style = base["Title"]
    h1 = ParagraphStyle("h1", parent=base["Heading1"], fontSize=14, spaceBefore=6,
                        spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=base["Heading2"], fontSize=11, spaceBefore=8,
                        spaceAfter=4)
    body = base["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10)
    muted = ParagraphStyle("muted", parent=small, textColor=colors.grey)
    mono = ParagraphStyle("mono", parent=small, fontName="Courier", fontSize=7.5,
                          leading=9.5)
    score_style = ParagraphStyle("score", parent=base["Title"], fontSize=40,
                                 leading=44, spaceBefore=4, spaceAfter=0)

    scope_note = ("static configuration analysis only — UNKNOWN means the control "
                  "could not be verified from the provided evidence")
    header_text = f"INV4R Network Compliance Report · run {ass.run_id}"

    class _Chrome(_canvas.Canvas):
        """Header on every page, footer with page X of Y on every page."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._saved: list[dict[str, Any]] = []

        def showPage(self) -> None:  # noqa: N802 (reportlab API)
            self._saved.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            total = len(self._saved)
            for state in self._saved:
                self.__dict__.update(state)
                self._draw_chrome(total)
                super().showPage()
            super().save()

        def _draw_chrome(self, total: int) -> None:
            w, h = A4
            self.setFont("Helvetica", 7)
            self.setFillColor(colors.HexColor("#607d8b"))
            self.drawString(0.7 * inch, h - 0.5 * inch, header_text)
            self.drawRightString(w - 0.7 * inch, h - 0.5 * inch,
                                 _framework_label(ass.framework_profile))
            self.setStrokeColor(colors.HexColor("#dfe3e8"))
            self.line(0.7 * inch, h - 0.56 * inch, w - 0.7 * inch, h - 0.56 * inch)
            self.setFillColor(colors.grey)
            self.drawString(0.7 * inch, 0.45 * inch, f"Page {self._pageNumber} of {total}")
            self.drawRightString(w - 0.7 * inch, 0.45 * inch, scope_note)

    story: list[Any] = []
    s = ass.summary()
    rem_cov = remediation_coverage([c for d in ass.devices for c in d.controls])
    unreviewed = sum(_unknown_count(d.device_result) for d in ass.devices)

    # ---- Cover / summary ------------------------------------------------- #
    story.append(Paragraph("INV4R — Network Compliance Report", title_style))
    story.append(Paragraph(
        f"{_esc(_framework_label(ass.framework_profile))} · "
        f"run <b>{_esc(ass.run_id)}</b> · generated {_esc(_now())}",
        body))
    story.append(Paragraph(
        f"Scope: {s['devices']} device(s) · framework profile "
        f"<b>{_esc(_framework_label(ass.framework_profile))}</b>", small))
    if preliminary:
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph(
            f"<font color='#b00020'><b>PRELIMINARY — not a final result.</b></font> "
            f"This report was generated with {unreviewed} unresolved fragment(s). "
            "The “suggested mapping” column shows what the pipeline proposes for "
            "each unmapped line; nothing has been applied yet, so UNKNOWN rows may "
            "still change. Resolve the lines, then download the final report.",
            small))
    if unreviewed:
        story.append(Paragraph(
            f"<font color='#b00020'><b>Generated with {unreviewed} unreviewed "
            f"fragment(s).</b></font> Map them on the Knowledge &amp; Learning page.",
            small))
    story.append(Spacer(1, 0.15 * inch))

    score_tbl = Table(
        [[Paragraph(f"<b>{s['avg_score']}</b>", score_style),
          Paragraph(f"<b>Average posture score</b> / 100<br/>band: {_esc(str(_band_for(s['avg_score'])))}",
                    body)]],
        colWidths=[1.6 * inch, 5.0 * inch])
    score_tbl.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(score_tbl)
    story.append(Spacer(1, 0.1 * inch))

    counts = Table([[
        Paragraph(f"<b>Fail</b><br/>{s['controls_failed']}", small),
        Paragraph(f"<b>Unknown</b><br/>{s['controls_unknown']}", small),
        Paragraph(f"<b>Pass</b><br/>{s['controls_passed']}", small),
        Paragraph(f"<b>Not applicable</b><br/>{s['controls_not_applicable']}", small),
    ]], colWidths=[1.65 * inch] * 4)
    counts.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#fdeaea")),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#fdf5e2")),
        ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#eaf6ec")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.append(counts)
    story.append(Spacer(1, 0.12 * inch))

    sev = _severity_breakdown(ass)
    sev_rows = [[Paragraph("<b>Severity</b>", small), Paragraph("<b>Failures</b>", small)]]
    for name in ("critical", "high", "medium", "low"):
        sev_rows.append([Paragraph(name, small), Paragraph(str(sev.get(name, 0)), small)])
    sev_tbl = Table(sev_rows, colWidths=[1.5 * inch, 1.5 * inch])
    sev_tbl.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                                 ("FONTSIZE", (0, 0), (-1, -1), 8)]))
    story.append(Paragraph("Failure breakdown by severity", h2))
    story.append(sev_tbl)
    story.append(Spacer(1, 0.1 * inch))

    top = _top_risks(ass, limit=5)
    story.append(Paragraph("Top risks", h2))
    if top:
        rows = [[Paragraph("<b>Device</b>", small), Paragraph("<b>Control</b>", small),
                 Paragraph("<b>Severity</b>", small)]]
        for device, c in top:
            rows.append([Paragraph(_esc(device), small),
                         Paragraph(f"{_esc(c.control_id)}: "
                                   f"{_esc(c.title)}", small),
                         Paragraph(f"<font color='{_SEV_COLORS.get(c.severity, '#607d8b')}'>"
                                   f"{_esc(c.severity)}</font>", small)])
        t = Table(rows, colWidths=[1.6 * inch, 4.2 * inch, 0.8 * inch])
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
    else:
        story.append(Paragraph("No failed controls across the scope.", small))
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph(
        f"Remediation CLI coverage: <b>{rem_cov.coverage_pct}%</b> of failed controls "
        f"({rem_cov.with_remediation} with an ordered device-specific command sequence, "
        f"{rem_cov.without_remediation} without a visible path). "
        f"Review status: {unreviewed} unmapped fragment(s) awaiting review.",
        small))
    story.append(Paragraph(
        "Scope note: " + scope_note + ".", muted))

    if kind == "fleet":
        story.append(PageBreak())
        story.extend(_fleet_pages(ass, h1, small, mono, colors, Table, TableStyle,
                                  Paragraph))

    for d in ass.devices:
        story.append(PageBreak())
        story.extend(_device_pages(d, small, mono, muted, h1, h2, body, colors,
                                   Table, TableStyle, Paragraph, Spacer, KeepTogether,
                                   suggestions))

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        topMargin=0.8 * inch, bottomMargin=0.7 * inch,
        title=f"INV4R compliance report {ass.run_id}",
        pageCompression=0,
    )
    doc.build(story, canvasmaker=_Chrome)
    return Path(out_path)


def _band_for(score: float) -> str:
    try:
        v = float(score)
    except (TypeError, ValueError):
        return "unknown"
    return ("strong" if v >= 85 else "moderate" if v >= 65 else
            "weak" if v >= 40 else "critical")


def _severity_breakdown(ass: Assessment) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for d in ass.devices:
        for c in d.controls:
            if c.result == "FAIL":
                key = (c.severity or "medium").lower()
                if key not in out:
                    key = "medium"
                out[key] += 1
    return out


def _top_risks(ass: Assessment, limit: int = 5) -> list[tuple[str, ControlResult]]:
    items: list[tuple[str, ControlResult]] = []
    for d in ass.devices:
        name = Path(d.device_result.envelope.source_path).name
        for c in d.controls:
            if c.result == "FAIL":
                items.append((name, c))
    items.sort(key=lambda x: _SEV_ORDER.get((x[1].severity or "medium").lower(), 9))
    return items[:limit]


def _device_pages(d: DeviceAssessment, small: Any, mono: Any, muted: Any, h1: Any,
                  h2: Any, body: Any, colors: Any, Table: Any, TableStyle: Any,
                  Paragraph: Any, Spacer: Any, KeepTogether: Any,
                  suggestions: dict[str, dict[int, dict[str, Any]]] | None = None,
                  ) -> list[Any]:
    from reportlab.lib.units import inch

    r = d.device_result
    story: list[Any] = []
    name = Path(r.envelope.source_path).name
    sugg = (suggestions or {}).get(name) or {}
    story.append(Paragraph(f"Device: {_esc(name)}", h1))

    chosen = getattr(r, "resolution", None)
    chosen = chosen.chosen if chosen else None
    adapter_id = getattr(r, "_adapter_id", None) or (chosen.adapter_id if chosen else "none")
    tier = getattr(r, "_tier", None)
    if tier is None:
        tier = chosen.tier if chosen else "—"
    ident_fields = _device_identity(r)
    _np = "not provided"
    sha = r.envelope.raw_bytes_sha256 or ""
    ident = Table([
        ["Hostname", _esc(ident_fields["hostname"] or _np)],
        ["Model", _esc(ident_fields["device_model"] or _np)],
        ["Serial", _esc(ident_fields["serial"] or _np)],
        ["IP address", _esc(ident_fields["ip_address"] or _np)],
        ["Site", _esc(ident_fields["site"] or _np)],
        ["Vendor", _esc(r.detection.vendor or _np)],
        ["Platform / OS", _esc(f"{r.detection.platform} "
                                      f"{r.detection.os_version}".strip() or _np)],
        ["Adapter (tier)", _esc(f"{adapter_id} (tier {tier})")],
        ["Evidence ID", _esc(r.envelope.evidence_id or _np)],
        ["SHA-256", Paragraph(_esc(sha or _np), mono)],
        ["Analysis timestamp", _esc(str((r.envelope.metadata or {}).get("timestamp")
                                              or _np))],
    ], colWidths=[1.5 * inch, 5.2 * inch])
    ident.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(ident)
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph(
        f"Posture score: <b>{d.score}/100</b> ({_esc(d.band)}) · "
        f"per-device counts — FAIL {sum(1 for c in d.controls if c.result == 'FAIL')}, "
        f"UNKNOWN {sum(1 for c in d.controls if c.result == 'UNKNOWN')}, "
        f"PASS {sum(1 for c in d.controls if c.result == 'PASS')}, "
        f"N/A {sum(1 for c in d.controls if c.result == 'NOT_APPLICABLE')}", small))
    story.append(Spacer(1, 0.1 * inch))

    if not d.controls:
        story.append(Paragraph(
            "No canonical security facts were extracted — controls cannot be "
            "evaluated. Map this configuration on the Knowledge &amp; Learning page "
            "or ingest a richer export.", body))
        story.extend(_fragment_section(r, h2, small, mono, colors, Table, TableStyle,
                                       Paragraph, Spacer, sugg))
        return story

    facts = _device_facts(r)
    lines = _line_texts(r)
    story.append(KeepTogether([Paragraph("Compliance findings", h2)]))
    ordered = sorted(d.controls, key=lambda c: (
        _RESULT_ORDER.get(c.result, 9), _SEV_ORDER.get((c.severity or "medium").lower(), 9),
        c.control_id))
    rows: list[Any] = [[
        Paragraph("<b>ID</b>", small), Paragraph("<b>Requirement</b>", small),
        Paragraph("<b>Severity</b>", small), Paragraph("<b>Result</b>", small),
        Paragraph("<b>Evidence</b>", small)]]
    for c in ordered:
        rows.append([
            Paragraph(_esc(c.control_id), small),
            Paragraph(_esc(c.title), small),
            Paragraph(f"<font color='{_SEV_COLORS.get((c.severity or '').lower(), '#607d8b')}'>"
                      f"{_esc(c.severity)}</font>", small),
            Paragraph(f"<font color='{_RESULT_COLORS.get(c.result, '#607d8b')}'>"
                      f"<b>{_result_label(c.result)}</b></font>", small),
            Paragraph(_esc(_evidence_text(c, facts, lines)), small),
        ])
    ft = Table(rows, colWidths=[0.7 * inch, 1.7 * inch, 0.7 * inch, 0.7 * inch, 2.9 * inch],
               repeatRows=1)
    # The whole row is tinted by its own result (rather than hardcoded zebra
    # stripes) so a FAIL / UNKNOWN finding is visible at a glance.
    result_tint = {"FAIL": "#fdecec", "UNKNOWN": "#fdf4e3",
                   "PASS": "#eef8f1", "NOT_APPLICABLE": "#f4f6f8"}
    findings_style: list[Any] = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff4")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
    ]
    for i, c in enumerate(ordered, start=1):
        findings_style.append(("BACKGROUND", (0, i), (-1, i),
                               colors.HexColor(result_tint.get(c.result, "#ffffff"))))
    ft.setStyle(TableStyle(findings_style))
    story.append(ft)

    fails = [c for c in d.controls if c.result == "FAIL"]
    if fails:
        ctx = _remediation_context(d)
        fails.sort(key=lambda c: _SEV_ORDER.get((c.severity or "medium").lower(), 9))
        story.append(Spacer(1, 0.1 * inch))
        story.append(KeepTogether([
            Paragraph("Remediation — device-specific CLI commands (FAIL only)", h2)]))
        story.append(Paragraph(
            "Caution: review and apply these commands in a maintenance window, "
            "and validate against the vendor CLI reference for this platform and version.",
            muted))
        for idx, c in enumerate(fails, start=1):
            block: list[Any] = [Paragraph(
                f"<b>{_esc(c.control_id)}</b> — {_esc(c.title)} "
                f"<font color='{_SEV_COLORS.get((c.severity or '').lower(), '#607d8b')}'>"
                f"({_esc(c.severity)})</font>", body)]
            if c.remediation_cli_sequence:
                unresolved: list[str] = []
                cmd_rows: list[Any] = []
                for step, cmd in enumerate(c.remediation_cli_sequence, start=1):
                    resolved, missing = _resolve_command(cmd, ctx)
                    unresolved.extend(m for m in missing if m not in unresolved)
                    cmd_rows.append([Paragraph(f"{idx}.{step}", mono),
                                     Paragraph(_esc(resolved), mono)])
                cmds = Table(cmd_rows, colWidths=[0.4 * inch, 6.0 * inch])
                cmds.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f6f8")),
                    ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#cfd8e3")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 1),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]))
                block.append(cmds)
                block.append(Paragraph(
                    "Filled in from the device config: "
                    + (", ".join(f"{k}={v}" for k, v in ctx.items()) or "none")
                    + ". Must be replaced by the operator: "
                    + (", ".join(f"<{u}>" for u in unresolved) or "none") + ".", muted))
            else:
                block.append(Paragraph(
                    "No device-specific remediation path for this vendor yet — "
                    "contribute one via the mapping governance workflow.", small))
            story.append(KeepTogether(block))
            story.append(Spacer(1, 0.08 * inch))
        d_cov = remediation_coverage(fails)
        story.append(Paragraph(
            f"Device remediation CLI coverage: {d_cov.with_remediation}/"
            f"{d_cov.failed_controls} failed control(s) have an ordered sequence"
            + (f" ({d_cov.without_remediation} without — visible gap, not silent)."
               if d_cov.without_remediation else "."), muted))
    else:
        story.append(Paragraph("No failed controls — no remediation required.", body))

    story.extend(_fragment_section(r, h2, small, mono, colors, Table, TableStyle,
                                   Paragraph, Spacer, sugg))
    return story


def _fragment_section(r: DeviceResult, h2: Any, small: Any, mono: Any, colors: Any,
                      Table: Any, TableStyle: Any, Paragraph: Any,
                      Spacer: Any,
                      suggestions: dict[int, dict[str, Any]] | None = None,
                      ) -> list[Any]:
    from reportlab.lib.units import inch

    story: list[Any] = []
    sugg = suggestions or {}
    n = _unknown_count(r)
    story.append(Spacer(1, 0.1 * inch))
    story.append(Paragraph(f"Unmapped fragments requiring review: {n}", h2))
    if not n:
        return story
    frags = _frag_lines(r)
    show_suggestions = bool(sugg)
    head: list[Any] = [Paragraph("<b>Line</b>", small),
                       Paragraph("<b>Category</b>", small),
                       Paragraph("<b>Raw text</b>", small)]
    if show_suggestions:
        head.append(Paragraph("<b>Suggested mapping (proposed)</b>", small))
    rows: list[Any] = [head]
    for line, cat, text in frags:
        row: list[Any] = [Paragraph(_esc(line), mono),
                          Paragraph(_esc(cat), small),
                          Paragraph(_esc(text), small)]
        if show_suggestions:
            s = sugg.get(_as_int(line)) or {}
            fact = str(s.get("fact") or "")
            if fact:
                conf = float(s.get("confidence") or 0.0)
                src = str(s.get("source") or "")
                label = f"<b>{_esc(fact)}</b>"
                if conf:
                    label += f" ({round(conf * 100)}%)"
                if src:
                    label += f"<br/><font color='#607d8b'>{_esc(src)}</font>"
                if s.get("resolved"):
                    label += "<br/><font color='#607d8b'>(already decided)</font>"
            else:
                label = ("<font color='#8a6d00'>no closed-vocabulary "
                         "suggestion — needs a human decision</font>")
            row.append(Paragraph(label, small))
        rows.append(row)
    widths = ([0.6 * inch, 1.2 * inch, 3.2 * inch, 1.7 * inch] if show_suggestions
              else [0.6 * inch, 1.4 * inch, 4.7 * inch])
    t = Table(rows, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff4")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)
    if show_suggestions:
        story.append(Paragraph(
            "The suggested mapping column is a proposal only — nothing here has "
            "been applied, and no UNKNOWN row may be read as a verified result.",
            small))
    story.append(Paragraph(
        "These lines were structurally preserved but could not be mapped to canonical "
        "security facts. Resolve them on the Knowledge &amp; Learning page.", small))
    return story


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _fleet_pages(ass: Assessment, h1: Any, small: Any, mono: Any, colors: Any,
                 Table: Any, TableStyle: Any, Paragraph: Any) -> list[Any]:
    from reportlab.lib.units import inch

    story: list[Any] = [Paragraph("Fleet overview", h1)]
    rows: list[Any] = [[Paragraph("<b>Device</b>", small), Paragraph("<b>Vendor</b>", small),
                        Paragraph("<b>Score</b>", small), Paragraph("<b>Band</b>", small),
                        Paragraph("<b>FAIL</b>", small), Paragraph("<b>UNKNOWN</b>", small),
                        Paragraph("<b>PASS</b>", small)]]
    for d in sorted(ass.devices, key=lambda x: x.score):
        r = d.device_result
        rows.append([
            Paragraph(_esc(Path(r.envelope.source_path).name), small),
            Paragraph(_esc(r.detection.vendor), small),
            Paragraph(str(d.score), small),
            Paragraph(_esc(d.band), small),
            Paragraph(str(sum(1 for c in d.controls if c.result == "FAIL")), small),
            Paragraph(str(sum(1 for c in d.controls if c.result == "UNKNOWN")), small),
            Paragraph(str(sum(1 for c in d.controls if c.result == "PASS")), small),
        ])
    t = Table(rows, colWidths=[1.9 * inch, 1.4 * inch, 0.7 * inch, 1.0 * inch,
                               0.6 * inch, 0.8 * inch, 0.6 * inch], repeatRows=1)
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eceff4")),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)
    s = ass.summary()
    total = max(1, s["controls_failed"] + s["controls_unknown"] + s["controls_passed"])
    story.append(Paragraph(
        f"Framework pass rate — {_esc(_framework_label(ass.framework_profile))}: "
        f"{round(100 * s['controls_passed'] / total)}% "
        f"({s['controls_passed']}/{total} applicable controls)", small))
    return story
