"""Tier-3 external modeling engine adapter (Batfish).

Selected when INV4R has no dedicated tier-2 parser for a vendor but a Batfish
service is reachable and the input is a vendor CLI format Batfish understands.
The adapter reuses the universal structural parse to preserve syntax, then
leans on Batfish's vendor-neutral model to produce canonical facts via
:class:`~inv4r.adapters.builtin.batfish_bridge.BatfishBridgeAdapter`.

If Batfish cannot parse the input, the structural parse (with UNKNOWN
semantics) is still returned honestly — never a guessed compliance verdict.
"""

from __future__ import annotations

import os
import shutil
import urllib.request

from inv4r.adapters.base import (
    AdapterCapabilities,
    AdapterMatch,
    Limitation,
    NormalizationOutput,
    ParsedRepresentation,
)
from inv4r.adapters.builtin.batfish_bridge import BatfishBridgeAdapter
from inv4r.adapters.generic_structural import GenericStructuralAdapter
from inv4r.core.envelope import EvidenceEnvelope
from inv4r.detection import DetectionResult

#: Configuration formats Batfish is able to parse.
_BATFISH_FORMATS = ("hierarchical_cli", "flat_cli", "junos_braced")

_DEFAULT_HOST = "localhost"
_DEFAULT_PORT = 9996


def _service_host_port() -> tuple[str, int]:
    host = os.environ.get("INV4R_BATFISH_HOST", "") or _DEFAULT_HOST
    try:
        port = int(os.environ.get("INV4R_BATFISH_PORT", "") or _DEFAULT_PORT)
    except ValueError:
        port = _DEFAULT_PORT
    return host, port


class ExternalEngineAdapter:
    adapter_id = "external-engine"
    adapter_version = "1.1.0"
    tier = 3

    def __init__(self) -> None:
        self._generic = GenericStructuralAdapter()
        self._bridge = BatfishBridgeAdapter()

    @staticmethod
    def engine_available() -> bool:
        """Feature-detect a Batfish service (env host, Docker port, or CLI).

        The probe uses the *same* host/port the REST client uses
        (``INV4R_BATFISH_HOST`` / ``INV4R_BATFISH_PORT``). The previous
        implementation hard-coded port 9997, which never matched the client's
        9996 default and made availability detection disagree with the client.
        """
        if shutil.which("batfish") is not None:
            return True
        host, port = _service_host_port()
        try:
            req = urllib.request.Request(f"http://{host}:{port}/v2/networks", method="GET")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                return resp.status < 500
        except Exception:
            return False

    def can_handle(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> AdapterMatch:
        if (self.engine_available()
                and detection.input_format in _BATFISH_FORMATS
                and detection.vendor not in ("", "unknown")):
            return AdapterMatch(self.adapter_id, self.tier, 0.6,
                                "Batfish model available for this vendor CLI")
        if self.engine_available() and detection.input_format in _BATFISH_FORMATS:
            return AdapterMatch(self.adapter_id, self.tier, 0.55,
                                "Batfish model available (vendor not identified)")
        return AdapterMatch(self.adapter_id, self.tier, 0.0,
                            "no external engine available")

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(parses_format="vendor CLI (via Batfish model)",
                                   normalizes_to_resources=True,
                                   produces_security_facts=True,
                                   requires_external_engine=True)

    def limitations(self) -> list[Limitation]:
        return [Limitation("engine_required",
                           "Requires a running Batfish service; if it is absent or cannot "
                           "parse the vendor, only structural UNKNOWN output is produced."),
                Limitation("no_credential_semantics",
                           "Batfish does not expose credential encoding, so credential.* "
                           "facts are left to the deterministic parsers.")]

    def parse(self, evidence: EvidenceEnvelope, detection: DetectionResult) -> ParsedRepresentation:
        parsed = self._generic.parse(evidence, detection)
        parsed.adapter_id = self.adapter_id
        parsed.tier = self.tier
        parsed.notes["evidence_text"] = evidence.content
        parsed.notes["filename"] = evidence.source_path.rsplit("/", 1)[-1] or "device.cfg"
        parsed.warnings.append(
            "Normalization is delegated to the Batfish model; syntax is preserved.")
        return parsed

    def normalize(self, parsed: ParsedRepresentation, detection: DetectionResult) -> NormalizationOutput:
        # Start from the honest structural baseline: every unmapped line is a
        # reviewable unknown fragment, so behaviour is safe if Batfish fails.
        out = self._generic.normalize(parsed, detection)

        try:
            contributed = self._bridge.extract(parsed, detection, out)
        except Exception:
            contributed = False

        if contributed:
            out.normalization_status = "FULL" if not out.unknown_fragments else "PARTIAL"
        else:
            out.normalization_status = "PARTIAL"
        return out
