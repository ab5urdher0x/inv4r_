"""Runtime mapping subsystem (tier 4): proposals -> human decision -> pack."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from inv4r.core.facts import CANONICAL_FACTS, FactStatus, SecurityFact
from inv4r.core.model import SourceSpan
from inv4r.core.unknown import UnknownFragment


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class PackStatus:
    DRAFT = "DRAFT"
    PENDING_REVIEW = "PENDING_REVIEW"
    ACTIVE = "ACTIVE"
    REJECTED = "REJECTED"
    DEPRECATED = "DEPRECATED"
    SUPERSEDED = "SUPERSEDED"
    REVOKED = "REVOKED"


ALL_STATUSES = frozenset({
    PackStatus.DRAFT, PackStatus.PENDING_REVIEW, PackStatus.ACTIVE,
    PackStatus.REJECTED, PackStatus.DEPRECATED, PackStatus.SUPERSEDED,
    PackStatus.REVOKED,
})

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    PackStatus.DRAFT: frozenset({PackStatus.PENDING_REVIEW, PackStatus.REJECTED}),
    PackStatus.PENDING_REVIEW: frozenset({PackStatus.ACTIVE, PackStatus.REJECTED}),
    PackStatus.ACTIVE: frozenset({PackStatus.DEPRECATED, PackStatus.SUPERSEDED, PackStatus.REVOKED}),
    PackStatus.REJECTED: frozenset({PackStatus.PENDING_REVIEW}),
    PackStatus.DEPRECATED: frozenset(),
    PackStatus.SUPERSEDED: frozenset(),
    PackStatus.REVOKED: frozenset(),
}


class MappingLifecycleError(ValueError):
    """Raised on illegal lifecycle transitions or uncontrolled writes."""


@dataclass
class PackValidationError(ValueError):
    """Structured rejection of an invalid pack. `errors` carries one record"""

    map_id: str
    source: str
    errors: list[dict[str, Any]]

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        head = f"pack '{self.map_id}' rejected from '{self.source}'"
        return head + "; " + "; ".join(
            f"{e.get('field')}={e.get('value')!r} (expected {e.get('expected')})"
            for e in self.errors)


def _err(field: str, value: Any, expected: str, rule_index: int | None = None,
         reason: str = "") -> dict[str, Any]:
    e: dict[str, Any] = {"field": field, "value": value, "expected": expected}
    if rule_index is not None:
        e["rule_index"] = rule_index
    if reason:
        e["reason"] = reason
    return e


def validate_pack_data(data: Any) -> list[dict[str, Any]]:
    """Validate a pack dict against the closed vocabulary BEFORE it can load."""
    errors: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return [_err("<document>", type(data).__name__, "mapping")]
    mid = data.get("map_id")
    if not mid or not isinstance(mid, str):
        errors.append(_err("map_id", mid, "non-empty string"))
    status = data.get("status", PackStatus.DRAFT)
    if status not in ALL_STATUSES:
        errors.append(_err("status", status, "one of " + "|".join(sorted(ALL_STATUSES))))

    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append(_err("rules", rules, "non-empty list"))
        return errors

    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            errors.append(_err(f"rules[{i}]", r, "mapping", i))
            continue
        fact = r.get("fact")
        if fact not in CANONICAL_FACTS:
            errors.append(_err(f"rules[{i}].fact", fact,
                               "CANONICAL_FACTS closed vocabulary", i,
                               "unknown fact names can never enter the registry"))
            continue
        ftype = CANONICAL_FACTS[fact][0]
        fv = r.get("fact_value")
        if fv is not None:
            if ftype == "bool" and not isinstance(fv, bool):
                errors.append(_err(f"rules[{i}].fact_value", fv, "bool", i,
                                   f"{fact} is declared {ftype}"))
            elif ftype == "number" and not isinstance(fv, (int, float)):
                errors.append(_err(f"rules[{i}].fact_value", fv, "number", i,
                                   f"{fact} is declared {ftype}"))

        prx = r.get("path_regex")
        if not prx or not isinstance(prx, str):
            errors.append(_err(f"rules[{i}].path_regex", prx, "non-empty regex", i))
        else:
            try:
                re.compile(prx)
            except re.error as exc:
                errors.append(_err(f"rules[{i}].path_regex", prx, "compilable regex", i, str(exc)))

        vrx = r.get("value_regex")
        if vrx is not None:
            if not isinstance(vrx, str):
                errors.append(_err(f"rules[{i}].value_regex", vrx, "regex or null", i))
            else:
                try:
                    re.compile(vrx)
                except re.error as exc:
                    errors.append(_err(f"rules[{i}].value_regex", vrx, "compilable regex", i, str(exc)))

        vt = r.get("value_type", "auto")
        if vt not in ("auto", "bool", "number", "string"):
            errors.append(_err(f"rules[{i}].value_type", vt, "auto|bool|number|string", i))
        vg = r.get("value_group", 1)
        if not isinstance(vg, int) or vg < 1:
            errors.append(_err(f"rules[{i}].value_group", vg, "int >= 1", i))
    return errors


@dataclass
class MappingProposal:
    proposal_id: str
    fragment: UnknownFragment
    suggested_fact: str | None
    suggested_value_rule: str = "literal_from_enable_state"
    suggested_value: Any = None
    confidence: float = 0.0
    status: str = "PENDING"

    def to_json(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "raw_path": self.fragment.raw_path,
            "raw_text": self.fragment.raw_text,
            "category": self.fragment.category,
            "source_span": self.fragment.source_span.to_json() if self.fragment.source_span else None,
            "suggested_fact": self.suggested_fact,
            "suggested_value": self.suggested_value,
            "confidence": round(float(self.confidence), 3),
            "status": self.status,
        }


@dataclass
class MappingDecision:
    proposal_id: str
    raw_path_regex: str
    value_regex: str | None
    fact: str
    fact_value: Any
    decision: str
    approver: str
    decided_at: str = field(default_factory=_now)

    def to_json(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "raw_path_regex": self.raw_path_regex,
            "value_regex": self.value_regex,
            "fact": self.fact,
            "fact_value": self.fact_value,
            "decision": self.decision,
            "approver": self.approver,
            "decided_at": self.decided_at,
        }


@dataclass
class MappingRule:
    path_regex: str
    fact: str
    fact_value: Any = None
    value_regex: str | None = None
    value_group: int = 1
    value_type: str = "auto"
    notes: str = ""

    def matches(self, path: str, value: str | None) -> bool:
        if not re.search(self.path_regex, path, re.IGNORECASE):
            return False
        if self.value_regex is not None:
            if value is None or not re.search(self.value_regex, str(value), re.IGNORECASE):
                return False
        return True

    def to_json(self) -> dict[str, Any]:
        return {
            "path_regex": self.path_regex,
            "fact": self.fact,
            "fact_value": self.fact_value,
            "value_regex": self.value_regex,
            "value_group": self.value_group,
            "value_type": self.value_type,
            "notes": self.notes,
        }


@dataclass
class MappingPack:
    map_id: str
    vendor: str
    platform: str
    match_evidence_regex: str | None = None
    rules: list[MappingRule] = field(default_factory=list)
    created_by: str = ""
    created_at: str = ""
    version: str = "1"
    source: str = "runtime_approved"
    status: str = PackStatus.DRAFT
    approved_by: str = ""
    approved_at: str = ""
    decision_at: str = ""
    decision_reason: str = ""
    supersedes: str = ""
    superseded_by: str = ""
    decisions: list[dict[str, Any]] = field(default_factory=list)

    def matches_evidence(self, vendor: str, platform: str, text: str) -> bool:
        if self.vendor and self.vendor == vendor:
            return True
        if self.platform and self.platform == platform:
            return True
        if self.match_evidence_regex:
            return bool(re.search(self.match_evidence_regex, text, re.IGNORECASE | re.MULTILINE))
        return False

    def to_json(self) -> dict[str, Any]:
        return {
            "map_id": self.map_id,
            "vendor": self.vendor,
            "platform": self.platform,
            "match_evidence_regex": self.match_evidence_regex,
            "rules": [r.to_json() for r in self.rules],
            "created_by": self.created_by,
            "created_at": self.created_at,
            "version": self.version,
            "source": self.source,
            "status": self.status,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "decision_at": self.decision_at,
            "decision_reason": self.decision_reason,
            "supersedes": self.supersedes,
            "superseded_by": self.superseded_by,
            "decisions": self.decisions,
        }


class MappingRegistry:
    """Loads, validates, and lifecycle-governs mapping packs from a directory."""

    QUARANTINE_DIR = "quarantine"
    REGISTRY_AUDIT = "registry-audit.jsonl"

    def __init__(self, directory: str | Path, include_pending: bool = False) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.packs: list[MappingPack] = []
        self.rejected: list[dict[str, Any]] = []
        self.integrity_notes: list[str] = []
        # Preview mode: human decisions still land as PENDING_REVIEW packs, but
        # a *provisional* evaluation may consult them so the operator sees the
        # predicted result immediately. This never writes or approves anything.
        self.include_pending = include_pending
        self.reload()

    def reload(self) -> None:
        self.packs = []
        self.rejected = []
        self.integrity_notes = []
        seen_ids: dict[str, Path] = {}
        qdir = self.directory / self.QUARANTINE_DIR
        for p in sorted(self.directory.glob("*.yaml")):
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            except Exception as exc:
                self._quarantine(p, [_err("<yaml>", str(exc), "parseable YAML")])
                continue

            violations = validate_pack_data(data)
            mid = data.get("map_id", p.stem) if isinstance(data, dict) else p.stem
            if violations:
                self._quarantine(p, violations)
                continue
            if mid in seen_ids:
                self._quarantine(p, [_err("map_id", mid, "unique across registry")],
                                 extra={"reason": f"duplicate map_id, first seen in {seen_ids[mid].name}"})
                continue
            seen_ids[mid] = p

            pack = MappingPack(
                map_id=mid,
                vendor=data.get("vendor", ""),
                platform=data.get("platform", ""),
                match_evidence_regex=data.get("match_evidence_regex"),
                created_by=data.get("created_by", ""),
                created_at=data.get("created_at", ""),
                version=str(data.get("version", "1")),
                source=data.get("source", "runtime_approved"),
                status=data.get("status", PackStatus.DRAFT),
                approved_by=data.get("approved_by", ""),
                approved_at=data.get("approved_at", ""),
                decision_at=data.get("decision_at", ""),
                decision_reason=data.get("decision_reason", ""),
                supersedes=data.get("supersedes", ""),
                superseded_by=data.get("superseded_by", ""),
                decisions=list(data.get("decisions") or []),
                rules=[
                    MappingRule(
                        path_regex=r["path_regex"],
                        fact=r["fact"],
                        fact_value=r.get("fact_value"),
                        value_regex=r.get("value_regex"),
                        value_group=int(r.get("value_group", 1)),
                        value_type=r.get("value_type", "auto"),
                        notes=r.get("notes", ""),
                    )
                    for r in data.get("rules", []) if isinstance(r, dict)
                ],
            )
            self.packs.append(pack)
            self._check_journal_integrity(mid)

    def _quarantine(self, path: Path, violations: list[dict[str, Any]],
                    extra: dict[str, Any] | None = None) -> None:
        """Physically isolate an invalid pack; it can never be loaded or replayed."""
        qdir = self.directory / self.QUARANTINE_DIR
        qdir.mkdir(exist_ok=True)
        dest = qdir / path.name
        record: dict[str, Any] = {
            "rejected_at": _now(),
            "source_file": path.name,
            "map_id": (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("map_id")
            if path.suffix == ".yaml" else None,
            "violations": violations,
        }
        if extra:
            record.update(extra)
        try:
            shutil.move(str(path), str(dest))
        except (shutil.Error, OSError):
            dest = path
        errors_path = (qdir / (dest.stem + ".errors.json")) if dest.suffix == ".yaml" \
            else (qdir / (path.name + ".errors.json"))
        errors_path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
        record["quarantined_to"] = str(dest)
        self.rejected.append(record)
        self._append_registry_audit({"event": "pack_rejected", **record})

    def _append_registry_audit(self, event: dict[str, Any]) -> None:
        log = self.directory / self.REGISTRY_AUDIT
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")

    def _check_journal_integrity(self, map_id: str) -> None:
        jp = self.directory / f"{map_id}.history.jsonl"
        if not jp.exists():
            return
        seqs: list[int] = []
        for line in jp.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                seqs.append(int(json.loads(line).get("seq", -1)))
            except json.JSONDecodeError:
                seqs.append(-1)
        if seqs != list(range(1, len(seqs) + 1)):
            self.integrity_notes.append(
                f"{map_id}: journal sequence broken {seqs} — possible tampering")

    def packs_for(self, vendor: str, platform: str, text: str,
                  include_pending: bool | None = None) -> list[MappingPack]:
        """Packs eligible for deterministic replay.

        ACTIVE packs only, unless ``include_pending`` is requested (the
        provisional preview path, where PENDING_REVIEW packs may be consulted
        to predict the outcome before a human promotes them).
        """
        pending = self.include_pending if include_pending is None else include_pending
        allowed = {PackStatus.ACTIVE}
        if pending:
            allowed.add(PackStatus.PENDING_REVIEW)
        return [p for p in self.packs
                if p.status in allowed and p.matches_evidence(vendor, platform, text)]

    def get(self, map_id: str) -> MappingPack:
        for p in self.packs:
            if p.map_id == map_id:
                return p
        raise KeyError(f"unknown mapping '{map_id}'")

    def active_packs(self) -> list[MappingPack]:
        return [p for p in self.packs if p.status == PackStatus.ACTIVE]

    def save_pack(self, pack: MappingPack, filename: str | None = None,
                  overwrite: bool = False) -> Path:
        """Persist a pack. Enforces validation + lifecycle invariants:"""
        violations = validate_pack_data(pack.to_json())
        if violations:
            raise PackValidationError(map_id=getattr(pack, "map_id", "?"),
                                      source=str(self.directory), errors=violations)
        if pack.status == PackStatus.ACTIVE and not (pack.approved_by and pack.approved_at):
            raise MappingLifecycleError(
                f"refusing to write ACTIVE pack '{pack.map_id}' without approval metadata; "
                f"create as PENDING_REVIEW and call approve()")
        if pack.status == PackStatus.DRAFT and pack.approved_by:
            raise MappingLifecycleError(
                f"pack '{pack.map_id}' carries approval metadata but is DRAFT; "
                f"lifecycle state and metadata disagree")

        fname = filename or f"{pack.map_id}.yaml"
        path = self.directory / fname
        if path.exists():
            try:
                existing = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except Exception:
                existing = {}
            same = existing == pack.to_json()
            if not same and not overwrite:
                raise MappingLifecycleError(
                    f"pack file '{fname}' already exists with different content; "
                    f"pass overwrite=True (never for ACTIVE packs) or use supersede()")
            if existing.get("status") == PackStatus.ACTIVE and not same and overwrite \
                    and pack.status == PackStatus.ACTIVE:
                raise MappingLifecycleError(
                    f"pack '{existing.get('map_id')}' is ACTIVE; silent mutation is forbidden — "
                    f"use supersede() to replace it")

        self._write_pack_file(pack, path)
        self._append_registry_audit({
            "event": "pack_written", "map_id": pack.map_id, "version": pack.version,
            "status": pack.status, "file": fname, "at": _now(),
        })
        self.reload()
        return path

    def _write_pack_file(self, pack: MappingPack, path: Path) -> None:
        path.write_text(yaml.safe_dump(pack.to_json(), sort_keys=False), encoding="utf-8")

    def transition(self, map_id: str, to_status: str, actor: str,
                   reason: str = "") -> MappingPack:
        pack = self.get(map_id)
        allowed = ALLOWED_TRANSITIONS.get(pack.status, frozenset())
        if to_status not in allowed:
            raise MappingLifecycleError(
                f"illegal transition {pack.status} -> {to_status} for '{map_id}' "
                f"(allowed: {sorted(allowed) or 'none — terminal'})")
        if to_status in (PackStatus.REVOKED, PackStatus.REJECTED, PackStatus.DEPRECATED,
                         PackStatus.SUPERSEDED) and not reason:
            raise MappingLifecycleError(f"a reason is required to {to_status.lower()} '{map_id}'")

        pack.decisions = list(pack.decisions) + [{
            "from": pack.status, "to": to_status, "actor": actor,
            "reason": reason, "at": _now(), "version": pack.version,
        }]
        previous_status = pack.decisions[-1]["from"]
        pack.status = to_status
        pack.decision_at = _now()
        pack.decision_reason = reason
        if to_status == PackStatus.ACTIVE:
            pack.approved_by = actor
            pack.approved_at = pack.decision_at
        if to_status == PackStatus.SUPERSEDED and not pack.superseded_by:
            raise MappingLifecycleError(
                f"SUPERSEDED requires superseded_by; use supersede(old, new) instead")

        violations = validate_pack_data(pack.to_json())
        if violations:
            raise PackValidationError(map_id=map_id, source=str(self.directory), errors=violations)
        self._write_pack_file(pack, self.directory / f"{map_id}.yaml")
        self._append_journal(pack, {
            "event": "transition", "map_id": map_id, "from": previous_status,
            "to": to_status, "actor": actor, "reason": reason, "version": pack.version,
        })
        self._append_registry_audit({
            "event": "lifecycle_transition", "map_id": map_id, "from": previous_status,
            "to": to_status, "actor": actor, "reason": reason, "at": pack.decision_at,
        })
        self.reload()
        return self.get(map_id)

    def _append_journal(self, pack: MappingPack, event: dict[str, Any]) -> None:
        jp = self.directory / f"{pack.map_id}.history.jsonl"
        seq = sum(1 for ln in jp.read_text(encoding="utf-8").splitlines() if ln.strip()) \
            if jp.exists() else 0
        event = {"seq": seq + 1, "at": _now(), **event}
        with open(jp, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")

    def submit(self, map_id: str, actor: str) -> MappingPack:
        return self.transition(map_id, PackStatus.PENDING_REVIEW, actor)

    def approve(self, map_id: str, approver: str, reason: str = "") -> MappingPack:
        return self.transition(map_id, PackStatus.ACTIVE, approver, reason)

    def reject(self, map_id: str, actor: str, reason: str) -> MappingPack:
        return self.transition(map_id, PackStatus.REJECTED, actor, reason)

    def revoke(self, map_id: str, actor: str, reason: str) -> MappingPack:
        return self.transition(map_id, PackStatus.REVOKED, actor, reason)

    def deprecate(self, map_id: str, actor: str, reason: str) -> MappingPack:
        return self.transition(map_id, PackStatus.DEPRECATED, actor, reason)

    def supersede(self, old_id: str, new_id: str, actor: str, reason: str = "") -> MappingPack:
        """Retire the old ACTIVE pack in favor of a replacement."""
        old = self.get(old_id)
        new = self.get(new_id)
        if new.supersedes != old_id:
            raise MappingLifecycleError(
                f"replacement pack '{new_id}' must declare supersedes: '{old_id}'")
        old.superseded_by = new_id
        self.transition(old_id, PackStatus.SUPERSEDED, actor,
                        reason or f"superseded by {new_id}")
        retired = self.get(old_id)
        retired.superseded_by = new_id
        self._write_pack_file(retired, self.directory / f"{old_id}.yaml")
        self.reload()
        return self.get(old_id)

    @staticmethod
    def validate_rule_fact(fact: str) -> None:
        if fact not in CANONICAL_FACTS:
            raise ValueError(f"mapping targets non-canonical fact '{fact}' — rejected")


def _coerce(raw: str, value_type: str) -> Any:
    if value_type == "bool":
        return raw.strip().lower() in ("on", "true", "yes", "enable", "enabled", "1")
    if value_type == "number":
        try:
            return float(raw) if "." in raw else int(raw)
        except ValueError:
            return raw
    return raw


def fact_from_rule(rule: MappingRule, path: str, value: str | None,
                   span: SourceSpan | None, adapter_id: str) -> SecurityFact | None:
    """Deterministically synthesize a SecurityFact from an approved rule."""
    if rule.fact not in CANONICAL_FACTS:
        return None
    ftype = CANONICAL_FACTS[rule.fact][0]
    val = rule.fact_value

    if val is None and value is not None and rule.value_regex:
        m = re.search(rule.value_regex, str(value), re.IGNORECASE)
        if m:
            val = _coerce(m.group(rule.value_group), rule.value_type if rule.value_type != "auto" else "string")

    if val is None:
        raw = str(value).strip().lower() if value is not None else ""
        if ftype == "bool":
            val = raw not in ("off", "disable", "disabled", "no", "false")
        elif ftype == "number" and value is not None:
            try:
                val = float(value) if "." in str(value) else int(value)
            except (TypeError, ValueError):
                val = True
        elif value is not None and str(value).strip():
            val = str(value).strip()
        else:
            val = True

    status = FactStatus.PRESENT
    if ftype == "bool" and val is False:
        status = FactStatus.ABSENT

    try:
        fact = SecurityFact(
            fact_id=f"sf-{abs(hash((rule.fact, path, str(val)))) % 10_000_000:07d}",
            name=rule.fact,
            status=status,
            value=val,
            confidence=1.0,
            evidence_spans=[{"line_start": span.line_start, "line_end": span.line_end}] if span else [],
            source_adapter=adapter_id,
            notes=f"runtime mapping rule: {rule.path_regex}",
        )
    except ValueError:
        return None
    errs = fact.validate()
    return fact if not errs else None


def build_proposals(fragments: list[UnknownFragment]) -> list[MappingProposal]:
    """Turn AI suggestions on fragments into reviewable proposals."""
    proposals: list[MappingProposal] = []
    for i, frag in enumerate(fragments):
        if frag.suggested_fact:
            proposals.append(MappingProposal(
                proposal_id=f"prop-{i:04d}",
                fragment=frag,
                suggested_fact=frag.suggested_fact,
                suggested_value=frag.raw_text,
                confidence=frag.suggestion_confidence,
            ))
    return proposals
