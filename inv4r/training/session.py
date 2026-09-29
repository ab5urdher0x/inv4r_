"""Training loop (the 'Dynamic Adaptation' requirement)."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from inv4r.core.facts import CANONICAL_FACTS, normalize_fact_name
from inv4r.training.queue import fragment_key
from inv4r.mapping.registry import (
    MappingPack,
    MappingRegistry,
    MappingRule,
    PackStatus,
)


logger = logging.getLogger(__name__)


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class TrainingSession:
    session_id: str
    vendor: str
    platform: str
    proposals: list[dict[str, Any]] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def pending(self) -> list[dict[str, Any]]:
        return [p for p in self.proposals if p["status"] == "PENDING"]

    def to_json(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "vendor": self.vendor,
            "platform": self.platform,
            "meta": self.meta,
            "proposals": self.proposals,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "TrainingSession":
        return cls(
            session_id=data.get("session_id", "session"),
            vendor=data.get("vendor", "unknown"),
            platform=data.get("platform", "unknown"),
            proposals=list(data.get("proposals") or []),
            meta=dict(data.get("meta") or {}),
        )

    @classmethod
    def load(cls, path: str | Path) -> "TrainingSession":
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_json(), indent=2), encoding="utf-8")
        return p


def build_session(evidence_id_to_unknown: dict[str, list[dict[str, Any]]],
                  vendor: str, platform: str, session_id: str = "training",
                  include_unsuggested: bool = False) -> TrainingSession:
    """Collect unknown fragments from normalize outputs into a session."""
    session = TrainingSession(session_id=session_id, vendor=vendor, platform=platform)
    n = 0
    for _eid, frags in evidence_id_to_unknown.items():
        for f in frags:
            n += 1
            if not f.get("suggested_fact") and not include_unsuggested:
                continue
            session.proposals.append({
                "proposal_id": f"prop-{n:04d}",
                "raw_path": f.get("raw_path", ""),
                "raw_text": f.get("raw_text", ""),
                "category": f.get("category", "other"),
                "source_span": f.get("source_span"),
                "suggested_fact": f.get("suggested_fact"),
                "suggestion_confidence": f.get("suggestion_confidence", 0.0),
                "suggested_by": f.get("suggested_by", ""),
                "status": "PENDING",
            })
    return session


def _path_regex_for(raw_path: str) -> str:
    """Deterministic matcher for future configs: escape, but generalize numbers"""
    parts = [re.escape(p) for p in raw_path.split(".")]
    rx = r"\.".join(parts)
    rx = re.sub(r"\\\d+", r"\\d+", rx)
    rx = re.sub(r"(?<![\\\w])\d+", r"\\d+", rx)
    return "^" + rx + "$"


_ON_WORDS = r"\b(on|enable|enabled|yes|true)\b"
_OFF_WORDS = r"\b(off|disable|disabled|no|false)\b"
_NUMBER_RE = r"\b(\d+)\b"


def _value_semantics(raw_text: str, fact_type: str = "auto") -> tuple[Any, str | None]:
    """Derive (fact_value, value_regex) from the observed raw text AND the"""
    v = raw_text.split()[-1] if raw_text.split() else ""
    vl = v.lower()
    if vl in ("on", "enable", "enabled", "yes", "true"):
        return (True, _ON_WORDS) if fact_type in ("auto", "bool") else (None, None)
    if vl in ("off", "disable", "disabled", "no", "false"):
        return (False, _OFF_WORDS) if fact_type in ("auto", "bool") else (None, None)
    if re.fullmatch(r"\d+", v):
        if fact_type in ("auto", "number"):
            return int(v), _NUMBER_RE
        if fact_type == "string":
            return None, _NUMBER_RE
    return None, None


def decide(session: TrainingSession, proposal_id: str, decision: str,
           fact: str | None = None, approver: str = "human") -> dict[str, Any] | None:
    """Record a decision on a proposal. Returns the updated proposal."""
    for p in session.proposals:
        if p["proposal_id"] == proposal_id:
            if decision == "APPROVED":
                chosen = fact or p.get("suggested_fact")
                if not chosen:
                    p["status"] = "DEFERRED"
                    return p
                try:
                    normalize_fact_name(chosen)
                except ValueError as exc:
                    p["status"] = "PENDING"
                    p["error"] = str(exc)
                    return p
                p["status"] = "APPROVED"
                p["approved_fact"] = chosen
                p["approver"] = approver
            elif decision == "REJECTED":
                p["status"] = "REJECTED"
                p["approver"] = approver
            elif decision == "DEFERRED":
                p["status"] = "DEFERRED"
            return p
    return None


def write_pack(session: TrainingSession, registry: MappingRegistry,
               pack_version: str = "1", activate_by: str = "",
               activate_reason: str = "") -> Path | None:
    """Persist APPROVED proposals as a mapping pack.

    Without ``activate_by`` the pack lands in PENDING_REVIEW (the governance
    queue, used by the CLI and node-level training). When ``activate_by`` names
    the human who approved the lines, that explicit decision IS the approval, so
    the pack is promoted to ACTIVE immediately — the authoritative result then
    moves without a second promotion step.
    """
    approved = [p for p in session.proposals if p.get("status") == "APPROVED"]
    if not approved:
        return None

    rules: list[MappingRule] = []
    for p in approved:
        ftype = CANONICAL_FACTS.get(p["approved_fact"], ("auto", ""))[0]
        fact_value, value_regex = _value_semantics(p.get("raw_text", ""), ftype)
        rules.append(MappingRule(
            path_regex=_path_regex_for(p["raw_path"]),
            fact=p["approved_fact"],
            fact_value=fact_value,
            value_regex=value_regex,
            value_type="auto",
            # The original raw line travels with the rule: the learned lane can
            # then recognize that the pack rule and its ledger record are the
            # SAME training example instead of counting it twice.
            notes=f"evidence: {p.get('raw_text', '')} | from training session "
                  f"{session.session_id} (approver={p.get('approver', 'human')})",
        ))

    base_id = f"runtime-{session.vendor}-{session.session_id}"
    map_id, supersedes, overwrite = base_id, "", False
    created_at = _now()

    try:
        existing = registry.get(base_id)
    except KeyError:
        existing = None

    if existing is not None and existing.status == PackStatus.ACTIVE:
        n = 2
        while any(p.map_id == f"{base_id}-v{n}" for p in registry.packs):
            n += 1
        map_id = f"{base_id}-v{n}"
        supersedes = existing.map_id
        pack_version = str(n)
    elif existing is not None:
        created_at = existing.created_at or created_at
        overwrite = True

    pack = MappingPack(
        map_id=map_id,
        vendor=session.vendor,
        platform=session.platform,
        rules=rules,
        created_by=", ".join(sorted({p.get("approver", "human") for p in approved})),
        created_at=created_at,
        version=pack_version,
        source="runtime_approved",
        status=PackStatus.PENDING_REVIEW,
        supersedes=supersedes,
        decisions=[{
            "event": "submitted_from_training_session",
            "session": session.session_id,
            "approved_proposals": len(approved),
            "rejected_proposals": sum(1 for p in session.proposals
                                      if p.get("status") == "REJECTED"),
            "approvers": sorted({p.get("approver", "human") for p in approved}),
            "at": created_at,
        }],
    )
    path = registry.save_pack(pack, filename=f"{map_id}.yaml", overwrite=overwrite)
    if activate_by:
        reason = (activate_reason or
                  "Reviewer approved the lines in the review queue")
        try:
            if supersedes:
                # Only the newest reviewed pack stays live, so a superseded
                # pack can never keep contributing stale rules.
                registry.supersede(supersedes, map_id, activate_by, reason=reason)
            registry.approve(map_id, approver=activate_by, reason=reason)
        except Exception as exc:  # pragma: no cover - defensive only
            logger.warning(f"pack '{map_id}' could not be activated: {exc}")
    return path


def apply_decision_file(session: TrainingSession, decisions_path: str | Path,
                        approver: str = "human") -> int:
    """GUI integration point: apply a JSON file of decisions."""
    data = json.loads(Path(decisions_path).read_text(encoding="utf-8"))
    count = 0
    for d in data:
        if decide(session, d["proposal_id"], d.get("decision", "REJECTED"),
                  d.get("fact"), approver):
            count += 1
    return count


def decision_ledger_path(mappings_dir: str | Path) -> Path:
    return Path(mappings_dir) / "decisions.json"


def load_decisions(mappings_dir: str | Path) -> dict[str, dict[str, dict[str, Any]]]:
    p = decision_ledger_path(mappings_dir)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (json.JSONDecodeError, OSError):
        return {}


def record_decisions(mappings_dir: str | Path, node_id: str,
                     decisions: list[dict[str, Any]]) -> None:
    """Append decisions for a node. Never rewrites earlier entries."""
    ledger = load_decisions(mappings_dir)
    node = ledger.setdefault(node_id, {})
    for d in decisions:
        pid = d.get("proposal_id")
        if not pid:
            continue
        node[pid] = {
            "decision": d.get("decision", ""),
            "fact": d.get("fact"),
            "approver": d.get("approver", ""),
            "at": d.get("at") or _now(),
        }
    p = decision_ledger_path(mappings_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(ledger, indent=2, default=str), encoding="utf-8")


def _content_decision(session: TrainingSession, proposal: dict[str, Any],
                      fragment_ledger: dict[str, dict[str, Any]] | None) -> dict[str, Any] | None:
    """Cross-node decision for a proposal's raw line, if any."""
    if not fragment_ledger:
        return None
    key = fragment_key(session.vendor, session.platform, proposal.get("raw_text", ""))
    return fragment_ledger.get(key)


def undecided(session: TrainingSession, node_id: str,
              ledger: dict[str, dict[str, dict[str, Any]]],
              fragment_ledger: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Proposals for a node that a human has not decided yet.

    A decision is node-scoped when recorded per proposal_id, and content-scoped
    when recorded in the deduplicated fragment ledger — the latter resolves the
    matching raw line on every node that contains it.
    """
    decided = ledger.get(node_id) or {}
    out: list[dict[str, Any]] = []
    for p in session.proposals:
        if p.get("proposal_id") in decided:
            continue
        if _content_decision(session, p, fragment_ledger) is not None:
            continue
        out.append(p)
    return out


def replay_decisions(session: TrainingSession, node_id: str,
                     ledger: dict[str, dict[str, dict[str, Any]]],
                     approver_default: str = "ledger") -> int:
    """Re-apply recorded human decisions onto a freshly rebuilt session."""
    decided = ledger.get(node_id) or {}
    applied = 0
    for p in session.proposals:
        rec = decided.get(p.get("proposal_id"))
        if not rec:
            continue
        status = (rec.get("decision") or "").upper()
        if status == "APPROVED":
            fact = rec.get("fact") or p.get("suggested_fact")
            p["status"] = "APPROVED" if fact else "PENDING"
            p["approved_fact"] = fact
        elif status in ("REJECTED", "DEFERRED"):
            p["status"] = status
        else:
            continue
        p["approver"] = rec.get("approver") or approver_default
        applied += 1
    return applied


def decided_for(session: TrainingSession, node_id: str,
                ledger: dict[str, dict[str, dict[str, Any]]],
                fragment_ledger: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Proposals already decided, annotated with the recorded decision."""
    decided = ledger.get(node_id) or {}
    out: list[dict[str, Any]] = []
    for p in session.proposals:
        rec = decided.get(p.get("proposal_id"))
        if not rec:
            cross = _content_decision(session, p, fragment_ledger)
            if cross:
                rec = {"decision": cross.get("decision"), "fact": cross.get("fact"),
                       "approver": cross.get("approver", "ledger"), "at": cross.get("at", "")}
        if rec:
            out.append({**p, "status": rec.get("decision", "DECIDED"),
                        "decided_fact": rec.get("fact"),
                        "approver": rec.get("approver", ""), "decided_at": rec.get("at", "")})
    return out


def vocabulary_for_ui() -> list[dict[str, str]]:
    """The low-code mapping UI offers exactly this list — nothing else."""
    return [{"fact": k, "type": t, "description": d} for k, (t, d) in sorted(CANONICAL_FACTS.items())]
