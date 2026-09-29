"""Batfish Bridge — maps Batfish's vendor-neutral model onto INV4R facts.

Batfish parses the configuration languages of many vendors (Cisco IOS/IOS-XE/
NX-OS/ASA, Juniper, Arista, Palo Alto, Fortinet, Cumulus, FRR, ...) into a
single model. This bridge queries that model via the documented
``nodeProperties`` and ``interfaceProperties`` questions (REST template keys
``nodeproperties`` / ``interfaceproperties``) and converts the answers into
canonical facts and resources.

Two ways it is used:

* **Enrichment** — the engine calls :meth:`BatfishBridgeAdapter.extract` after a
  tier-1/2 adapter parsed a file, filling fact gaps the deterministic parser
  could not see. Deterministic evidence keeps primacy (ADR-001); the bridge
  only overrides an *inferred* ABSENT with a positively observed PRESENT.
* **Primary** — :class:`~inv4r.adapters.external_engine.ExternalEngineAdapter`
  runs the bridge as the normalization source for vendors INV4R has no
  dedicated parser for.

If Batfish is unreachable or cannot parse the input, ingestion degrades
gracefully: the primary adapter's result is returned untouched and no fact is
guessed.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from inv4r.adapters.base import NormalizationOutput, ParsedRepresentation
from inv4r.adapters.batfish_map import (
    BATFISH_SOURCE,
    Mapped,
    map_interface_properties,
    map_node_properties,
)
from inv4r.behaviour.batfish_client import BatfishClient, BatfishError, BatfishUnavailable
from inv4r.core.facts import FactStatus, SecurityFact
from inv4r.detection import DetectionResult

logger = logging.getLogger(__name__)

#: Question templates this bridge relies on. Both are documented configuration
#: property questions with stable column names. The REST template *keys* are
#: lower-cased (``nodeProperties`` is the pybatfish/Python name for the same
#: question), and a wrong key makes ``question_from_template`` raise — which
#: would silently disable every Batfish contribution.
NODE_PROPERTIES = "nodeproperties"
INTERFACE_PROPERTIES = "interfaceproperties"


class BatfishBridgeAdapter:
    """Queries a Batfish service and emits canonical facts/resources."""

    adapter_id = BATFISH_SOURCE
    adapter_version = "1.1.0"
    tier = 3
    vendor = "generic"
    platform = "generic"

    def __init__(self, client: BatfishClient | None = None) -> None:
        self.client = client or BatfishClient()
        self._cache: dict[str, Mapped] = {}

    # -- availability -----------------------------------------------------

    def available(self) -> bool:
        try:
            # Fast probe: a down service must not stall ingestion for the full
            # question timeout.
            return self.client.available(timeout=2.0)
        except Exception:
            return False

    # -- extraction -------------------------------------------------------

    def extract(self, parsed: ParsedRepresentation, detection: DetectionResult,
                out: NormalizationOutput) -> bool:
        """Query Batfish and append canonical facts/resources to ``out``.

        Returns True when Batfish contributed at least one fact. Never raises.
        """
        text = parsed.notes.get("evidence_text", "")
        if not text:
            return False

        filename = parsed.notes.get("filename") or "device.cfg"
        digest = hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()

        cached = self._cache.get(digest)
        if cached is None:
            cached = self._query(text, filename)
            self._cache[digest] = cached

        if not cached.facts and not cached.resources:
            return False

        known_ids = {r.resource_id for r in out.resources}
        out.facts.extend(cached.facts)
        out.resources.extend(r for r in cached.resources if r.resource_id not in known_ids)
        return bool(cached.facts)

    def _query(self, text: str, filename: str) -> Mapped:
        result = Mapped()
        snap_id: str | None = None
        try:
            if not self.available():
                logger.info("Batfish bridge: service unavailable; skipping.")
                return result

            snap_id = self.client.upload_snapshot({filename: text})
            result = self._collect(snap_id)
            if result.facts or result.resources:
                logger.info(
                    "Batfish bridge: %d fact(s), %d resource(s) from model.",
                    len(result.facts), len(result.resources))
        except (BatfishUnavailable, BatfishError) as exc:
            logger.warning("Batfish bridge: processing failed gracefully: %s", exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Batfish bridge: unexpected error: %s", exc)
        finally:
            if snap_id:
                try:
                    self.client.delete_snapshot(snap_id)
                except Exception:
                    pass
        return result

    def _collect(self, snap_id: str) -> Mapped:
        result = Mapped()

        node_rows = self._rows(snap_id, NODE_PROPERTIES)
        if node_rows:
            mapped = map_node_properties(node_rows[0])
            result.facts.extend(mapped.facts)
            result.resources.extend(mapped.resources)

        iface_rows = self._rows(snap_id, INTERFACE_PROPERTIES)
        if iface_rows:
            mapped = map_interface_properties(iface_rows)
            result.facts.extend(mapped.facts)
            result.resources.extend(mapped.resources)

        result.facts = _dedupe_facts(result.facts)
        result.resources = _dedupe_resources(result.resources)
        return result

    def _rows(self, snap_id: str, template: str) -> list[dict[str, Any]]:
        """Run one question template, returning its table rows (or [])."""
        try:
            question = self.client.question_from_template(template, {})
            answer = self.client.answer(snap_id, f"inv4r-{template}", question)
            return self._extract_rows(answer)
        except (BatfishUnavailable, BatfishError) as exc:
            logger.warning("Batfish bridge: %s query failed: %s", template, exc)
            return []
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Batfish bridge: %s query error: %s", template, exc)
            return []

    @staticmethod
    def _extract_rows(answer: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract table rows from a Batfish question answer payload."""
        try:
            elements = answer.get("answerElements") or []
            if not elements:
                return []
            rows = elements[0].get("rows")
            return rows if isinstance(rows, list) else []
        except (IndexError, KeyError, TypeError):
            return []


def _dedupe_facts(facts: list[SecurityFact]) -> list[SecurityFact]:
    """Collapse repeats of the same fact *instance*.

    Entity and value are part of the key on purpose: per-entity facts (one
    syslog/NTP server, one principal) are distinct instances and must all
    survive, while the same server reported twice is collapsed.
    """
    seen: dict[tuple[str, str, str, str], SecurityFact] = {}
    for f in facts:
        key = (f.name, f.status, str(f.entity or ""), str(f.value))
        if key not in seen:
            seen[key] = f
    return list(seen.values())


def _dedupe_resources(resources: list[Any]) -> list[Any]:
    seen: dict[str, Any] = {}
    for r in resources:
        seen.setdefault(r.resource_id, r)
    return list(seen.values())


def _instance_key(fact: SecurityFact) -> tuple[str, str, str]:
    """Identity of one fact *instance* — name plus the entity it is scoped to."""
    return (fact.name, str(fact.entity or ""), str(fact.value))


def merge_secondary_batfish_facts(primary_facts: list[SecurityFact],
                                  batfish_facts: list[SecurityFact]) -> list[SecurityFact]:
    """Merge Batfish facts into primary facts (deterministic-first, gap-filling).

    Reconciliation happens per fact *instance* (name + entity), so multi-valued
    inventories — one syslog/NTP server per fact — all survive.

    Rules, in order:

    * a fact the deterministic parser never reported is added;
    * a fact the deterministic parser marked ``UNKNOWN`` is replaced by Batfish's
      concrete value;
    * an *inferred/aggregated* ABSENT is replaced by a positively observed
      Batfish PRESENT (a text parser inferring absence can be wrong; Batfish
      actually parsed the model);
    * any other disagreement keeps the deterministic value, but is logged.
    """
    primary_by_name: dict[str, SecurityFact] = {}
    for f in primary_facts:
        primary_by_name.setdefault(f.name, f)
    merged = list(primary_facts)
    seen = {_instance_key(f) for f in primary_facts}

    for bfact in batfish_facts:
        if bfact is None or bfact.status == FactStatus.UNKNOWN:
            continue
        key = _instance_key(bfact)
        if key in seen:
            continue
        pfact = primary_by_name.get(bfact.name)
        same_instance = pfact is not None and (pfact.entity or "") == (bfact.entity or "")

        if pfact is None or not same_instance:
            merged.append(bfact)
            seen.add(key)
            continue

        if pfact.status == FactStatus.UNKNOWN:
            pfact.status = bfact.status
            pfact.value = bfact.value
            pfact.notes = f"{pfact.notes} | batfish: {bfact.notes}".strip(" |")
            pfact.source_adapter = f"{pfact.source_adapter}+batfish"
            continue

        if (pfact.status == FactStatus.ABSENT and bfact.status == FactStatus.PRESENT
                and getattr(pfact, "derivation", "direct") != "direct"):
            logger.info(
                "Batfish corroboration for '%s': replacing inferred ABSENT with "
                "observed PRESENT (%r).", bfact.name, bfact.value)
            pfact.status = bfact.status
            pfact.value = bfact.value
            pfact.confidence = max(float(pfact.confidence), 0.9)
            pfact.notes = f"{pfact.notes} | batfish: {bfact.notes}".strip(" |")
            pfact.source_adapter = f"{pfact.source_adapter}+batfish"
            continue

        if pfact.status == bfact.status and pfact.value != bfact.value:
            logger.warning(
                "Batfish fact conflict for '%s': primary=%r vs batfish=%r. "
                "Retaining primary value per ADR-001.", bfact.name, pfact.value, bfact.value)

    return merged
