"""INV4R FastAPI routers — every endpoint backed by real engine code."""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse

from inv4r.ai import get_learned_model, get_settings, set_settings
from inv4r.ai.eval import run_eval
from inv4r.api.auth import (
    SESSION_COOKIE,
    AuthError,
    authenticate,
    issue_token,
)
from inv4r.api.config import artifacts_dir, configs_dir, controls_dir, mappings_dir
from inv4r.api.deps import (
    admin_only,
    analyst_only,
    authenticated,
    get_engine,
    get_preview_engine,
    get_registry,
    reset_engine,
    reset_preview_engine,
    reviewer_or_above,
)
from inv4r.api.models import (
    AIImplOut,
    AssessOut,
    AuthMeOut,
    CategoryStats,
    CloudKeyIn,
    CloudKeyStatusOut,
    CreateUserIn,
    DeleteUserIn,
    DeviceAssessmentOut,
    ControlDefinitionIn,
    DeviceMetadataOut,
    EVOut,
    FrameworkControlOut,
    FrameworkDetailOut,
    FrameworkSummary,
    FrameworksOut,
    LoginOut,
    LoginRequest,
    LogoutOut,
    MappingDecisionOut,
    MappingHistoryEntry,
    MappingHistoryOut,
    MappingPackDetails,
    MappingsOut,
    NodeDetailControl,
    NodeDetailFact,
    NodeDetailFragment,
    NodeDetailOut,
    NodeOut,
    NodesOut,
    OkOut,
    ResetPasswordIn,
    ReviewNodeOut,
    ReviewStatusOut,
    SetSettingsOut,
    SettingsUpdate,
    StatusOut,
    TrainDecideBatchIn,
    TrainDecideOut,
    UploadOut,
    UploadResultOut,
    UserListOut,
    UserOut,    VocabularyOut,
    SessionOut,
    SessionsOut,
    SessionEndOut,
    ReviewItemOut,
    ReviewQueueOut,
    ReviewDecideIn,
    ReviewDecideOut,
    ReviewCategoryIn,
    ReviewDismissIn,
    ReviewDismissOut,
    InvariantEndpointIn,
    InvariantOut,
    InvariantsOut,
    InvariantVerifyIn,
    InvariantVerifyOut,
)

from inv4r.api import sessions as session_store
from inv4r.controls.engine import (
    ControlEngine,
    ProfileError,
    control_category,
    risk_score,
    validate_control_definition,
)
from inv4r.engine import DeviceResult, Engine
from inv4r.reporting.assessment import render_pdf, run_assessment
from inv4r.training.session import (
    TrainingSession,
    build_session,
    decide,
    decided_for,
    load_decisions,
    record_decisions,
    replay_decisions,
    undecided,
    vocabulary_for_ui,
    write_pack,
)
from inv4r.training.queue import (
    CATEGORY_LABELS,
    build_review_queue,
    fragment_key,
    load_fragment_decisions,
    record_fragment_decisions,
    unresolved_items,
)

api = APIRouter(prefix="/api", tags=["inv4r"])


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _user_email(user: dict[str, Any]) -> str:
    return user.get("email", "unknown")


def _adapter_of(r: DeviceResult) -> tuple[str, int]:
    if r.resolution and r.resolution.chosen:
        return r.resolution.chosen.adapter_id, int(r.resolution.chosen.tier)
    return "none", 5


_DEVICE_META_KEYS = ("hostname", "device_model", "serial", "ip_address", "site", "notes")

_IP_ADDRESS_RE = re.compile(
    r"^\s*(?:set\s+)?(?:ip\s+address|ip-address|address|ipaddr)\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})",
    re.IGNORECASE | re.MULTILINE,
)


def _detect_ip_address(raw_text: str) -> str:
    """Best-effort management IP from the config text itself (real data only)."""
    if not raw_text:
        return ""
    m = _IP_ADDRESS_RE.search(raw_text)
    return m.group(1) if m else ""


def _device_metadata(r: DeviceResult, raw_text: str = "") -> DeviceMetadataOut:
    """Merge auto-detected identity (Mode B) with user-supplied identity (Mode A)."""
    det = r.detection
    meta = getattr(r.envelope, "metadata", None) or {}
    user_supplied = {k: meta[k] for k in _DEVICE_META_KEYS if meta.get(k)}

    hostname = user_supplied.get("hostname") or getattr(det, "hostname", "") or ""
    model = (user_supplied.get("device_model")
             or getattr(det, "model_hint", "") or "")
    serial = user_supplied.get("serial") or getattr(det, "serial", "") or ""
    ip_address = user_supplied.get("ip_address") or _detect_ip_address(raw_text or "")
    return DeviceMetadataOut(
        hostname=hostname,
        os_version=det.os_version or "",
        model_hint=model,
        serial=serial,
        ip_address=ip_address,
        site=str(user_supplied.get("site", "") or ""),
        notes=str(user_supplied.get("notes", "") or ""),
        user_supplied=user_supplied,
        source="merged" if user_supplied else "auto",
    )


def _controls_engine() -> ControlEngine:
    return ControlEngine(controls_dir())


def _engine() -> Engine:
    return get_engine()


def _parse_profile_ids(framework: str | None, frameworks: str | None) -> list[str]:
    """Resolve the requested framework selection (multi-framework aware)."""
    raw = frameworks if frameworks else (framework or "cis-network-baseline")
    ids = [x.strip() for x in str(raw).split(",") if x.strip()]
    return ids or ["cis-network-baseline"]


def _parse_control_ids(controls: str | None) -> tuple[list[str], dict[str, list[str]]]:
    """Split a control filter into global ids and framework-scoped ids.

    A bare id (``controls=CIS-1.1.1``) applies to every selected framework.
    A qualified id (``controls=cis-network-baseline:CIS-1.1.1``) narrows only
    that framework, and a framework with no applicable entry is left
    unfiltered — so subsetting one framework never hides another's controls.
    """
    if not controls:
        return [], {}
    shared: list[str] = []
    scoped: dict[str, list[str]] = {}
    for entry in str(controls).split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" in entry:
            profile, _, control_id = entry.partition(":")
            profile, control_id = profile.strip(), control_id.strip()
            # A malformed qualifier names nothing, so it filters nothing.
            if profile and control_id:
                scoped.setdefault(profile, []).append(control_id)
            continue
        shared.append(entry)
    return shared, scoped


def _canonical_scope(scoped: dict[str, list[str]]) -> dict[str, list[str]]:
    """Map framework-scoped ids onto canonical profile ids (400 on unknown)."""
    if not scoped:
        return {}
    ce = _controls_engine()
    out: dict[str, list[str]] = {}
    for profile_id, ids in scoped.items():
        try:
            canonical = ce.get_profile(profile_id).get("profile_id", profile_id)
        except ProfileError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        out.setdefault(canonical, []).extend(ids)
    return out


def _requested_control_ids(shared: list[str], scoped: dict[str, list[str]]) -> list[str]:
    """The explicitly requested control ids, for echoing back in a response."""
    ids = list(shared)
    for scoped_ids in scoped.values():
        ids.extend(scoped_ids)
    return list(dict.fromkeys(ids))


def _merged_weights(ce: ControlEngine, profile_ids: list[str]) -> dict[str, float]:
    merged: dict[str, float] = {}
    for pid in profile_ids:
        try:
            merged.update(ce.get_profile(pid).get("severity_weights") or {})
        except ProfileError:
            continue
    return merged


def _evaluate_and_score(r: DeviceResult, profile_ids: list[str],
                        control_ids: list[str] | None = None,
                        controls_by_profile: dict[str, list[str]] | None = None
                        ) -> tuple[float, str, list[Any]]:
    """Evaluate one processed DeviceResult; returns (score, band, raw results)."""
    ce = _controls_engine()
    # Controls are always evaluated, even on a device with no extractable facts:
    # every control then reports UNKNOWN, which is exactly what the training
    # loop consumes. No score is invented for such a device, however.
    results = ce.evaluate_profiles(r.facts, r.vendor, profile_ids, control_ids,
                                   controls_by_profile)
    score, band = 0.0, "insufficient evidence"
    if r.facts and results:
        s, b = risk_score(results, {"severity_weights": _merged_weights(ce, profile_ids)})
        score, band = (0.0 if s == "N/A" else float(s)), b
    return score, band, results


def _to_detail_controls(controls: list[Any]) -> list[NodeDetailControl]:
    return [
        NodeDetailControl(
            control_id=c.control_id,
            title=c.title,
            result=c.result,
            severity=c.severity,
            detail=c.detail,
            evidence_lines=c.evidence_lines,
            remediation="\n".join(c.remediation) if isinstance(c.remediation, list) else str(c.remediation or ""),
            remediation_cli_sequence=list(c.remediation_cli_sequence),
            framework=getattr(c, "framework", "") or "",
            expected=getattr(c, "expected", "") or "",
            observed=getattr(c, "observed", "") or "",
            reason=getattr(c, "reason", "") or "",
            # Deterministic policy data only — never a generated command.
            has_remediation=bool(c.remediation),
        )
        for c in controls
    ]


def _assess_device(r: DeviceResult, profile_ids: list[str],
                   control_ids: list[str] | None = None,
                   controls_by_profile: dict[str, list[str]] | None = None
                   ) -> tuple[float, str, list[NodeDetailControl]]:
    """Evaluate one processed DeviceResult against the selected profiles/controls."""
    score, band, results = _evaluate_and_score(r, profile_ids, control_ids,
                                               controls_by_profile)
    return score, band, _to_detail_controls(results)


def _assess_one(r: DeviceResult, framework: str = "cis-network-baseline"
                ) -> tuple[float, str, list[NodeDetailControl]]:
    """Single-framework assessment (compatibility wrapper)."""
    return _assess_device(r, [framework])


def _resolve_profiles(profile_ids: list[str]) -> list[str]:
    """Resolve aliases to canonical profile ids (400 on an unknown profile)."""
    ce = _controls_engine()
    resolved: list[str] = []
    try:
        for pid in profile_ids:
            canonical = ce.get_profile(pid).get("profile_id", pid)
            if canonical not in resolved:
                resolved.append(canonical)
    except ProfileError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return resolved


def _node_out(r: DeviceResult, path: Path) -> NodeOut:
    adapter, tier = _adapter_of(r)
    score, band, ctrls = _assess_one(r)
    cov = r.coverage
    # "Controls Evaluated" = applicable controls that resolved to PASS/FAIL
    # (a real numerator/denominator) rather than the pipeline coverage level.
    evaluated = sum(1 for c in ctrls if c.result in ("PASS", "FAIL"))
    raw = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    meta = _device_metadata(r, raw)
    return NodeOut(
        id=path.name,
        name=path.name,
        path=str(path),
        vendor=r.vendor,
        platform=r.platform,
        adapter=adapter,
        tier=tier,
        facts_count=len(r.facts),
        unknown_count=len(r.normalization.unknown_fragments) if r.normalization else 0,
        coverage_level=cov.achieved_level,
        coverage_name=cov.level_name(),
        compliance_score=score,
        compliance_band=band,
        controls_evaluated=evaluated,
        controls_total=len(ctrls),
        ip_address=meta.ip_address,
        serial=meta.serial,
        hardware_model=meta.model_hint,
        session_id=session_store.session_id_for(path.name) or "",
        file_size=path.stat().st_size if path.exists() else 0,
        evidence_id=r.envelope.evidence_id,
        sha256=r.envelope.raw_bytes_sha256,
        duplicate=bool(r.envelope.metadata.get("duplicate")),
        error="; ".join(r.errors),
    )


def _node_detail(r: DeviceResult, node_id: str, path: Path,
                 profile_ids: list[str] | None = None,
                 control_ids: list[str] | None = None,
                 controls_by_profile: dict[str, list[str]] | None = None) -> NodeDetailOut:
    adapter, tier = _adapter_of(r)
    profile_ids = profile_ids or ["cis-network-baseline"]
    score, band, controls = _assess_device(r, profile_ids, control_ids,
                                           controls_by_profile)
    raw = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""

    facts: list[NodeDetailFact] = []
    fact_counts: dict[str, int] = {}
    for f in r.facts:
        lines = sorted({int(s.get("line_start", 0)) for s in (f.evidence_spans or []) if s.get("line_start")})
        facts.append(NodeDetailFact(
            name=f.name,
            value=f.value,
            status=f.status,
            confidence=float(f.confidence),
            source_adapter=f.source_adapter,
            evidence_lines=lines,
            scope=getattr(f, "scope", "device"),
            entity=getattr(f, "entity", None),
            derivation=getattr(f, "derivation", "direct"),
            evidence_texts=getattr(f, "evidence_texts", [])[:4],
        ))
        fact_counts[f.name.split(".")[0]] = fact_counts.get(f.name.split(".")[0], 0) + 1

    frags: list[NodeDetailFragment] = []
    if r.normalization and r.normalization.unknown_fragments:
        raw_frags = [f.to_json() for f in r.normalization.unknown_fragments]
        session = build_session({r.envelope.evidence_id: raw_frags}, r.vendor, r.platform,
                                "web-inspect", include_unsuggested=True)
        for p in session.proposals:
            frags.append(NodeDetailFragment(
                proposal_id=p.get("proposal_id", ""),
                raw_path=p.get("raw_path", ""),
                raw_text=p.get("raw_text", ""),
                category=p.get("category", "other"),
                source_span=p.get("source_span") or {},
                suggested_fact=p.get("suggested_fact"),
                suggestion_confidence=float(p.get("suggestion_confidence", 0.0) or 0.0),
                suggested_by=p.get("suggested_by", ""),
                status=p.get("status", "PENDING"),
            ))

    meta = _device_metadata(r, raw)
    return NodeDetailOut(
        id=node_id,
        name=node_id,
        vendor=r.vendor,
        platform=r.platform,
        os_version=r.detection.os_version,
        model_hint=r.detection.model_hint,
        device_metadata=meta,
        adapter=adapter,
        tier=tier,
        coverage_level=r.coverage.achieved_level,
        coverage_name=r.coverage.level_name(),
        coverage_reasons=r.coverage.reasons,
        raw_config=raw,
        raw_lines_count=len(raw.splitlines()),
        hashes={"sha256": r.envelope.raw_bytes_sha256, "md5": r.envelope.raw_bytes_md5},
        evidence_id=r.envelope.evidence_id,
        provenance=r.provenance.to_json().get("events", []),
        errors=r.errors,
        fact_counts=fact_counts,
        facts=facts,
        compliance={
            "framework": ",".join(profile_ids),
            "frameworks": profile_ids,
            "score": score,
            "band": band,
            "controls": [c.model_dump() for c in controls],
        },
        controls_summary={
            "pass": sum(1 for c in controls if c.result == "PASS"),
            "fail": sum(1 for c in controls if c.result == "FAIL"),
            "unknown": sum(1 for c in controls if c.result == "UNKNOWN"),
        },
        unknown_fragments=frags,
        detection_reasons=r.detection.reasons,
        candidate_vendors=r.detection.candidate_vendors,
        detection_confidence=float(r.detection.confidence),
    )


def _process(path: Path) -> DeviceResult:
    return _engine().process_file(str(path))


def _process_preview(path: Path) -> DeviceResult:
    """Process with the preview engine (PENDING_REVIEW packs consulted).

    Used only for the provisional preview surface; the authoritative engine is
    untouched and nothing is written as ACTIVE.
    """
    return get_preview_engine().process_file(str(path))


def _manifest_path() -> Path:
    return artifacts_dir() / "nodes.json"


def _purge_nodes(node_ids: list[str]) -> list[str]:
    """Remove ingested nodes and every artifact derived from them.

    Called when a session closes: sessions are the unit of work, so the configs
    of a finished session are not left behind as clutter in the next one.
    Deleting the uploaded config makes the node invisible to every assessment
    path (they are all driven by ``_iter_config_files``), and the per-evidence
    artifacts plus manifest/session entries are dropped so nothing dangles.
    Review decisions are NOT touched: the ledger is content-keyed, so a line
    already resolved stays resolved, and an unresolved line re-appears only if
    the same raw content is uploaded again.
    """
    removed: list[str] = []
    for node_id in node_ids:
        name = Path(node_id).name
        p = configs_dir() / name
        if p.is_file():
            try:
                p.unlink()
                removed.append(name)
            except OSError:
                continue
        # Best-effort artifact cleanup (envelope/facts/unknown/audit/...): the
        # envelope artifact records which evidence id belongs to this node.
        eid = ""
        try:
            for candidate in artifacts_dir().glob("envelope-*.json"):
                try:
                    payload = json.loads(candidate.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
                if Path(payload.get("source_path", "")).name == name:
                    eid = payload.get("evidence_id", "")
                    break
        except Exception:
            eid = ""
        if eid:
            for artifact in artifacts_dir().glob(f"*-{eid}.json"):
                try:
                    artifact.unlink()
                except OSError:
                    pass
            evidence_root = artifacts_dir() / "evidence"
            if evidence_root.is_dir():
                shutil.rmtree(evidence_root / eid[:16], ignore_errors=True)
        manifest = _load_manifest()
        if name in (manifest.get("nodes") or {}):
            manifest["nodes"].pop(name, None)
            _mpath = _manifest_path()
            _mpath.parent.mkdir(parents=True, exist_ok=True)
            _mpath.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        session_store.forget_node(name)
    if removed:
        # Cached DeviceResults and engine state must not outlive their files.
        reset_engine()
        reset_preview_engine()
    return removed


def _load_manifest() -> dict[str, Any]:
    p = _manifest_path()
    if not p.exists():
        return {"nodes": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"nodes": {}}
    if not isinstance(data, dict):
        return {"nodes": {}}
    data.setdefault("nodes", {})
    return data


def _register_uploaded(names: list[str]) -> None:
    """Record uploaded node ids. Unregistered bundled files are never nodes."""
    if not names:
        return
    data = _load_manifest()
    for name in names:
        data["nodes"][name] = {"uploaded_at": _now_iso()}
    p = _manifest_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _iter_config_files() -> list[Path]:
    """Only files a user actually uploaded — bundled samples are not nodes."""
    d = configs_dir()
    if not d.exists():
        return []
    known = set((_load_manifest().get("nodes") or {}).keys())
    return sorted(p for p in d.glob("*")
                  if p.is_file() and not p.name.startswith(".") and p.name in known)


def _assign_session(results: list[UploadResultOut], framework: str | None) -> None:
    ok = [r.filename for r in results if r.status == "ok" and r.filename]
    if ok:
        _register_uploaded(ok)
        session_store.register_upload(ok, framework or "")


def _pack_details(p) -> MappingPackDetails:
    return MappingPackDetails(
        map_id=p.map_id,
        vendor=p.vendor or "",
        platform=p.platform or "",
        version=p.version or "",
        status=p.status,
        created_by=p.created_by or "",
        created_at=p.created_at or "",
        approved_by=p.approved_by or "",
        approved_at=p.approved_at or "",
        version_comment=getattr(p, "version_comment", "") or "",
        rules_count=len(p.rules),
        active_rules=sum(1 for r in p.rules if getattr(r, "status", "ACTIVE") == "ACTIVE"),
        supersedes=p.supersedes or "",
        superseded_by=p.superseded_by or "",
        decision_reason=p.decision_reason or "",
    )


def _save_upload(name: str, content: bytes) -> Path:
    d = configs_dir()
    d.mkdir(parents=True, exist_ok=True)
    safe = Path(name).name
    target = d / safe
    target.write_bytes(content)
    return target


def _process_upload(name: str, content: bytes, user_meta: dict[str, Any] | None = None) -> UploadResultOut:
    """Store + process one upload. user_meta (Mode A) is merged into the envelope."""
    try:
        target = _save_upload(name, content)
        duplicate, duplicate_of = False, ""
        if user_meta:
            from inv4r.core.evidence_store import EvidenceStore
            store = EvidenceStore(artifacts_dir() / "evidence")
            ref = store.ingest_bytes(content, str(target), metadata=user_meta)
            duplicate, duplicate_of = ref.duplicate, ref.duplicate_of
            r = _engine().process_envelope(ref.envelope, duplicate=duplicate,
                                           duplicate_of=duplicate_of)
        else:
            r = _process(target)
        adapter, tier = _adapter_of(r)
        return UploadResultOut(
            status="ok",
            job_id=f"job-{r.envelope.evidence_id}",
            filename=name,
            vendor=r.vendor,
            platform=r.platform,
            os_version=r.detection.os_version,
            adapter=adapter,
            tier=tier,
            facts_count=len(r.facts),
            unknown_count=len(r.normalization.unknown_fragments) if r.normalization else 0,
            coverage_level=r.coverage.achieved_level,
            coverage_name=r.coverage.level_name(),
            evidence_id=r.envelope.evidence_id,
            duplicate=duplicate,
            duplicate_of=duplicate_of,
            coverage_reasons=r.coverage.reasons,
        )
    except Exception as exc:
        return UploadResultOut(status="error", filename=name, error=str(exc))


def _behaviour():
    from inv4r.api.deps import get_behaviour
    return get_behaviour()


@api.get("/behaviour/status")
def behaviour_status(user: dict = Depends(analyst_only)):
    """Batfish availability + supported query types + suggested NL queries."""
    be = _behaviour()
    from inv4r.behaviour.models import QUERY_TYPES, SUGGESTED_QUERIES
    return {
        "batfish_available": be.available(),
        "query_types": list(QUERY_TYPES),
        "suggested_queries": SUGGESTED_QUERIES,
    }


@api.post("/behaviour/analyze")
def behaviour_analyze(body: dict, user: dict = Depends(analyst_only)):
    """Natural language OR structured query -> BehaviourQuery -> Batfish -> result."""
    from inv4r.behaviour.models import BehaviourQuery, interpret
    be = _behaviour()
    try:
        if body.get("query") and not body.get("type"):
            bq = interpret(str(body["query"]))
        else:
            bq = BehaviourQuery.from_json(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = be.analyze(bq)
    return result.to_json()


@api.post("/behaviour/situation")
def behaviour_situation(body: dict | None = None,
                        user: dict = Depends(analyst_only)):
    """Deterministic check suite over the SELECTED scope's snapshot.

    ``session_id`` limits the Batfish snapshot to that session's devices, so
    results are never derived from another session's uploads.
    """
    session_id = (body or {}).get("session_id")
    scoped = _scoped_node_names(session_id) if session_id else None
    report = _behaviour().network_situation(scoped)
    return report.to_json()


@api.get("/health")
def health():
    return {"status": "ok", "service": "inv4r-api", "version": "0.2.0", "time": _now_iso()}


@api.get("/sample-configs/{filename}")
def get_sample_config(filename: str, user: dict = Depends(analyst_only)):
    """Serve a bundled sample configuration from configs/ for 1-click ingestion."""
    p = configs_dir() / Path(filename).name
    if not p.is_file():
        raise HTTPException(status_code=404, detail=f"sample config {filename!r} not found")
    return FileResponse(str(p), filename=p.name, media_type="text/plain")


@api.get("/status", response_model=StatusOut)
def get_status(user: dict = Depends(analyst_only)):
    s = get_settings()
    registry = get_registry()
    active = [p for p in registry.packs if p.status == "ACTIVE"]
    pending = [p for p in registry.packs if p.status == "PENDING_REVIEW"]
    model = get_learned_model()
    trained = model.trained_on() if callable(getattr(model, "trained_on", None)) else 0
    return StatusOut(
        version="0.2.0",
        posture="air_gapped" if s.air_gapped else "connected",
        ai_mode=s.mode,
        air_gapped=s.air_gapped,
        total_nodes=len(_iter_config_files()),
        active_mapping_packs=len(active),
        pending_mapping_packs=len(pending),
        learned_examples=int(trained or 0),
        server_time=_now_iso(),
    )


@api.get("/frameworks", response_model=FrameworksOut)
def list_frameworks(user: dict = Depends(analyst_only)):
    ce = _controls_engine()
    out = [
        FrameworkSummary(
            profile_id=p.get("profile_id", ""),
            title=p.get("title", p.get("name", "")),
            framework=p.get("framework", ""),
            version=str(p.get("version", "1.0")),
            description=p.get("description", ""),
            control_count=len(p.get("controls") or []),
        )
        for p in ce.profiles()
    ]
    return FrameworksOut(frameworks=out, total=len(out))


_USER_OVERLAY_SUFFIX = "__user.yaml"


def _framework_detail(profile_id: str) -> FrameworkDetailOut:
    """The framework's actual policy data — never a hardcoded control count."""
    ce = _controls_engine()
    try:
        prof = ce.get_profile(profile_id)
    except ProfileError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    controls = [
        FrameworkControlOut(
            control_id=str(c.get("id", "")),
            title=str(c.get("title", "")),
            severity=str(c.get("severity", "medium")).upper(),
            category=control_category(str(c.get("id", ""))),
            description=str(c.get("description", "")),
            rationale=str(c.get("rationale", "")),
        )
        for c in (prof.get("controls") or [])
    ]
    return FrameworkDetailOut(
        profile_id=str(prof.get("profile_id", profile_id)),
        title=str(prof.get("title", "")),
        framework=str(prof.get("framework", "")),
        version=str(prof.get("version", "1.0")),
        description=str(prof.get("description", "")),
        control_count=len(controls),
        controls=controls,
    )


@api.get("/frameworks/{profile_id}", response_model=FrameworkDetailOut)
def get_framework(profile_id: str, user: dict = Depends(analyst_only)):
    """Every currently implemented rule for a framework (checklist source)."""
    return _framework_detail(profile_id)


@api.post("/frameworks/{profile_id}/controls", response_model=FrameworkDetailOut)
def add_framework_control(profile_id: str, body: ControlDefinitionIn,
                          user: dict = Depends(admin_only)):
    """Add a control to a framework's *user overlay*.

    Admin-only and enforced server-side (hiding the button is not enough). The
    complete definition is validated before anything is written; an invalid or
    duplicate control is rejected and never persisted.
    """
    ce = _controls_engine()
    try:
        prof = ce.get_profile(profile_id)
    except ProfileError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    canonical = str(prof.get("profile_id", profile_id))

    raw = body.model_dump(exclude_none=True)
    ctrl: dict[str, Any] = {k: v for k, v in raw.items() if v not in ({}, [], "")}
    errors = validate_control_definition(ctrl)
    if errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))

    existing_ids = {str(c.get("id")) for c in (prof.get("controls") or []) if isinstance(c, dict)}
    if str(ctrl.get("id")) in existing_ids:
        raise HTTPException(status_code=400,
                            detail=f"control {ctrl['id']!r} already exists in {canonical}")

    path = controls_dir() / f"{canonical}{_USER_OVERLAY_SUFFIX}"
    data: dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, yaml.YAMLError):
            data = {}
    data["profile_id"] = canonical
    controls = data.get("controls")
    if not isinstance(controls, list):
        controls = []
    controls.append(ctrl)
    data["controls"] = controls
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"could not persist control: {exc}") from exc
    # _controls_engine() constructs a fresh engine per call, so the new control
    # is visible (and evaluable) on the very next request.
    return _framework_detail(canonical)


@api.get("/vocabulary", response_model=VocabularyOut)
def get_vocabulary(user: dict = Depends(analyst_only)):
    """The closed security-fact vocabulary — the exact list the Training UI offers."""
    from inv4r.core.facts import FACT_VERSION
    entries = vocabulary_for_ui()
    return VocabularyOut(
        fact_version=FACT_VERSION,
        facts=[{"fact": e["fact"], "type": e["type"], "description": e["description"]} for e in entries],
        total=len(entries),
    )


@api.get("/nodes", response_model=NodesOut)
def list_nodes(session_id: str | None = None, user: dict = Depends(analyst_only)):
    files = _iter_config_files()
    if session_id:
        wanted = set(session_store.node_ids_for_session(session_id))
        files = [p for p in files if p.name in wanted]
    items: list[NodeOut] = []
    for p in files:
        try:
            r = _process(p)
            items.append(_node_out(r, p))
        except Exception as exc:
            items.append(NodeOut(
                id=p.name, name=p.name, path=str(p), vendor="unknown", platform="unknown",
                adapter="error", tier=5, facts_count=0, unknown_count=0, coverage_level=1,
                compliance_score=0.0, compliance_band="error",
                file_size=p.stat().st_size if p.exists() else 0, error=str(exc),
            ))
    return NodesOut(nodes=items, total=len(items))


@api.get("/nodes/{node_id}", response_model=NodeDetailOut)
def get_node(node_id: str, framework: str = "cis-network-baseline",
             frameworks: str | None = None,
             controls: str | None = None,
             preview: bool = False,
             user: dict = Depends(analyst_only)):
    """Node detail, evaluated against the selected framework(s)/controls only.

    ``preview=true`` additionally replays PENDING_REVIEW mapping packs so a
    freshly-trained control shows a provisional result immediately.
    """
    p = configs_dir() / Path(node_id).name
    if not p.is_file():
        raise HTTPException(status_code=404, detail=f"node {node_id!r} not found")
    profile_ids = _resolve_profiles(_parse_profile_ids(framework, frameworks))
    control_ids, scoped_ids = _parse_control_ids(controls)
    scoped_ids = _canonical_scope(scoped_ids)
    try:
        r = _process_preview(p) if preview else _process(p)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"processing failed: {exc}") from exc
    return _node_detail(r, node_id, p, profile_ids, control_ids, scoped_ids)


@api.get("/assess", response_model=AssessOut)
def assess_all(framework: str = "cis-network-baseline",
               frameworks: str | None = None,
               controls: str | None = None,
               node_id: str | None = None,
               session_id: str | None = None,
               preview: bool = False,
               user: dict = Depends(analyst_only)):
    """Assess ingested configs against the selected policy and control subset.

    Only the requested framework(s) are scored, and only the requested controls
    are evaluated — an unselected framework is never computed for results,
    statistics, the training queue, evidence or remediation. ``preview=true``
    replays PENDING_REVIEW mapping packs for a provisional result.
    """
    files = _iter_config_files()
    if session_id:
        wanted = set(session_store.node_ids_for_session(session_id))
        files = [p for p in files if p.name in wanted]
    if node_id:
        wanted = Path(node_id).name
        files = [p for p in files if p.name == wanted]
        if not files:
            raise HTTPException(status_code=404, detail=f"node {wanted!r} not found")

    profile_ids = _resolve_profiles(_parse_profile_ids(framework, frameworks))
    control_ids, scoped_ids = _parse_control_ids(controls)
    scoped_ids = _canonical_scope(scoped_ids)
    if not files:
        return AssessOut(framework=",".join(profile_ids), frameworks=profile_ids,
                         controls=_requested_control_ids(control_ids, scoped_ids),
                         preview=preview,
                         summary={"devices": 0}, devices=[], category_breakdown={},
                         server_time=_now_iso())

    engine = get_preview_engine() if preview else _engine()
    cats: dict[str, dict[str, int]] = {}
    devices: list[DeviceAssessmentOut] = []
    all_results: list[Any] = []
    agg = {"PASS": 0, "FAIL": 0, "UNKNOWN": 0, "NOT_APPLICABLE": 0}
    for p in files:
        try:
            r = engine.process_file(str(p))
        except Exception:
            continue
        score, band, results = _evaluate_and_score(r, profile_ids, control_ids,
                                                   scoped_ids)
        all_results.extend(results)
        for c in results:
            cat = control_category(c.control_id)
            cats.setdefault(cat, {"PASS": 0, "FAIL": 0, "UNKNOWN": 0, "NOT_APPLICABLE": 0})
            if c.result in cats[cat]:
                cats[cat][c.result] += 1
            if c.result in agg:
                agg[c.result] += 1
        adapter, tier = _adapter_of(r)
        devices.append(DeviceAssessmentOut(
            device_id=r.envelope.evidence_id,
            filename=Path(r.envelope.source_path).name,
            vendor=r.vendor,
            platform=r.platform,
            adapter=adapter,
            tier=tier,
            facts_count=len(r.facts),
            unknown_count=len(r.normalization.unknown_fragments) if r.normalization else 0,
            coverage_level=r.coverage.achieved_level,
            compliance_score=score,
            compliance_band=band,
            controls_summary={
                "pass": sum(1 for c in results if c.result == "PASS"),
                "fail": sum(1 for c in results if c.result == "FAIL"),
                "unknown": sum(1 for c in results if c.result == "UNKNOWN"),
                "not_applicable": sum(1 for c in results if c.result == "NOT_APPLICABLE"),
            },
            control_results=[c.model_dump() for c in _to_detail_controls(results)],
        ))

    summary = {
        "devices": len(devices),
        "controls_passed": agg["PASS"],
        "controls_failed": agg["FAIL"],
        "controls_unknown": agg["UNKNOWN"],
        "controls_not_applicable": agg["NOT_APPLICABLE"],
        "avg_score": (round(sum(d.compliance_score for d in devices) / len(devices), 1)
                      if devices else 0),
    }
    try:
        from inv4r.reporting.assessment import remediation_coverage
        summary["remediation"] = remediation_coverage(all_results).to_json()
    except Exception:
        pass

    scoped = (_scoped_node_names(session_id) if session_id
              else ({Path(node_id).name} if node_id else None))
    total, _nodes = _review_outstanding(scoped)
    return AssessOut(
        framework=",".join(profile_ids), frameworks=profile_ids,
        controls=_requested_control_ids(control_ids, scoped_ids), preview=preview,
        summary=summary,
        category_breakdown={k: CategoryStats(**v) for k, v in cats.items()},
        devices=devices,
        review_status="needs_review" if total else "ready_for_report",
        server_time=_now_iso(),
    )


def _parse_user_metadata(raw: str | None) -> dict[str, Any] | None:
    """Parse optional Mode A metadata (JSON object) from a form field."""
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="metadata must be a JSON object") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="metadata must be a JSON object")
    clean = {k: str(parsed[k]) for k in _DEVICE_META_KEYS if parsed.get(k)}
    return clean or None


@api.post("/upload", response_model=UploadOut)
async def upload_files(files: list[UploadFile] = File(...),
                       metadata: str | None = Form(None),
                       framework: str | None = Form(None),
                       user: dict = Depends(reviewer_or_above)):
    """Bulk upload. Per-file isolation: a bad file never fails the batch."""
    user_meta = _parse_user_metadata(metadata)
    if user_meta and len(files) != 1:
        raise HTTPException(
            status_code=400,
            detail="metadata applies to a single-file upload; send one file or omit metadata",
        )
    results = [_process_upload(f.filename or "upload.cfg", await f.read(), user_meta)
               for f in files]
    _assign_session(results, framework)
    return _upload_out(results)


@api.post("/upload/json", response_model=UploadOut)
async def upload_json(body: dict,
                      user: dict = Depends(reviewer_or_above)):
    """Programmatic ingestion: raw config text + optional device metadata."""
    content = body.get("content")
    if not isinstance(content, str) or not content.strip():
        raise HTTPException(status_code=400, detail="content (config text) is required")
    filename = Path(str(body.get("filename") or "upload.cfg")).name
    user_meta = _parse_user_metadata(json.dumps(body.get("metadata"))) if body.get("metadata") else None
    results = [_process_upload(filename, content.encode("utf-8"), user_meta)]
    _assign_session(results, body.get("framework"))
    return _upload_out(results)


@api.post("/upload/zip", response_model=UploadOut)
async def upload_zip(archive: UploadFile = File(...),
                     framework: str | None = Form(None),
                     user: dict = Depends(reviewer_or_above)):
    """Bulk ingestion of a zip of configs (mass-upload requirement)."""
    data = await archive.read()
    results: list[UploadResultOut] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.filename.startswith("__MACOSX") or Path(info.filename).name.startswith("."):
                    continue
                results.append(_process_upload(Path(info.filename).name, zf.read(info)))
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="not a valid zip archive") from exc
    _assign_session(results, framework)
    return _upload_out(results)


def _upload_out(results: list[UploadResultOut]) -> UploadOut:
    return UploadOut(
        results=results,
        total=len(results),
        failed=sum(1 for r in results if r.status == "error"),
        duplicates=sum(1 for r in results if r.duplicate),
        server_time=_now_iso(),
    )


@api.get("/mappings", response_model=MappingsOut)
def list_packs(user: dict = Depends(analyst_only)):
    packs = get_registry().packs
    return MappingsOut(packs=[_pack_details(p) for p in packs],
                       total=len(packs), server_time=_now_iso())


@api.get("/mappings/history", response_model=MappingHistoryOut)
def mapping_history(user: dict = Depends(analyst_only)):
    items = []
    for p in get_registry().packs:
        items.append(MappingHistoryEntry(
            map_id=p.map_id, vendor=p.vendor or "", platform=p.platform or "",
            status=p.status, created_by=p.created_by or "", created_at=p.created_at or "",
            approved_by=p.approved_by or "", approved_at=p.approved_at or "",
            rules_count=len(p.rules),
            active_rules=sum(1 for r in p.rules if getattr(r, "status", "ACTIVE") == "ACTIVE"),
            decision_reason=p.decision_reason or "",
        ))
    return MappingHistoryOut(history=items, total=len(items), server_time=_now_iso())


@api.post("/mappings/approve", response_model=MappingDecisionOut)
def approve_pack(body: dict, user: dict = Depends(reviewer_or_above)):
    mid = body.get("map_id")
    if not mid:
        raise HTTPException(status_code=400, detail="map_id required")
    try:
        pack = get_registry().approve(mid, approver=_user_email(user),
                                      reason=body.get("reason", "Approved via API"))
        from inv4r.ai import proposer
        proposer.reset_model_cache()
        # A newly ACTIVE pack must take effect for the authoritative engine too.
        reset_engine()
        reset_preview_engine()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return MappingDecisionOut(status="ok", decision="APPROVED", map_id=mid,
                              pack=_pack_details(pack))


@api.post("/mappings/reject", response_model=MappingDecisionOut)
def reject_pack(body: dict, user: dict = Depends(reviewer_or_above)):
    mid = body.get("map_id")
    if not mid:
        raise HTTPException(status_code=400, detail="map_id required")
    try:
        pack = get_registry().reject(mid, actor=_user_email(user),
                                     reason=body.get("reason", "Rejected via API"))
        from inv4r.ai import proposer
        proposer.reset_model_cache()
        reset_engine()
        reset_preview_engine()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return MappingDecisionOut(status="ok", decision="REJECTED", map_id=mid,
                              pack=_pack_details(pack))


def _session_for_node(node_id: str):
    p = configs_dir() / Path(node_id).name
    if not p.is_file():
        raise HTTPException(status_code=404, detail=f"node {node_id!r} not found")
    r = _process(p)
    raw_frags = [f.to_json() for f in r.normalization.unknown_fragments] if r.normalization else []
    session = build_session({r.envelope.evidence_id: raw_frags}, r.vendor, r.platform,
                            f"web-{r.envelope.evidence_id}", include_unsuggested=True)
    replay_decisions(session, node_id, load_decisions(mappings_dir()))
    return r, session


def _scoped_node_names(session_id: str | None) -> set[str] | None:
    """Node ids belonging to a session scope; None means "every session"."""
    if not session_id or session_id == "all":
        return None
    return set(session_store.node_ids_for_session(session_id))


def _unique_review_items(node_names: set[str] | None = None) -> list[dict[str, Any]]:
    """Every ingested unknown fragment, deduplicated by content within vendor.

    ``node_names`` limits the scan to one session's nodes so the current
    session's count never includes earlier uploads.
    """
    node_frags: dict[str, dict[str, Any]] = {}
    for p in _iter_config_files():
        if node_names is not None and p.name not in node_names:
            continue
        try:
            r = _process(p)
        except Exception:
            continue
        raw_frags = ([f.to_json() for f in r.normalization.unknown_fragments]
                     if r.normalization else [])
        node_frags[p.name] = {"vendor": r.vendor, "platform": r.platform,
                              "fragments": raw_frags}
    return build_review_queue(node_frags)


def _review_outstanding(node_names: set[str] | None = None) -> tuple[int, list[ReviewNodeOut]]:
    """Count UNIQUE unresolved review items and how many nodes each touches."""
    ledger = load_fragment_decisions(mappings_dir())
    unresolved = unresolved_items(_unique_review_items(node_names), ledger)
    per_node: dict[str, dict[str, Any]] = {}
    for it in unresolved:
        for node_id in it["nodes"]:
            entry = per_node.setdefault(node_id, {"vendor": it["vendor"], "pending": 0})
            entry["pending"] += 1
    nodes = [ReviewNodeOut(node_id=n, vendor=v["vendor"], pending=v["pending"])
             for n, v in sorted(per_node.items())]
    return len(unresolved), nodes


def _backlog_count(node_names: set[str] | None) -> int:
    """Unresolved items that fall outside the requested scope.

    ``node_names=None`` (the "all" scope) means every ingested node, so the
    backlog is 0 by definition. A cleared node no longer contributes: its file
    is gone, so its lines are not items at all.
    """
    if node_names is None:
        return 0
    ledger = load_fragment_decisions(mappings_dir())
    everything = unresolved_items(_unique_review_items(None), ledger)
    return sum(1 for it in everything if not (set(it["nodes"]) & node_names))


def _require_review_clear(node_ids: list[str] | None = None,
                          session_id: str | None = None) -> None:
    """Backend gate: a report cannot be generated while review items remain.

    The gate is scoped: only unresolved items whose raw line occurs on a node
    in this report may block it. Unresolved items that exist only in another
    session are backlog and must never block a different report.
    """
    ledger = load_fragment_decisions(mappings_dir())
    if node_ids is not None:
        wanted = {Path(n).name for n in node_ids}
    elif session_id is not None:
        wanted = _scoped_node_names(session_id) or set()
    else:
        wanted = None
    unresolved = unresolved_items(_unique_review_items(wanted), ledger)
    if wanted is not None:
        unresolved = [it for it in unresolved if wanted & set(it["nodes"])]
    if unresolved:
        raise HTTPException(
            status_code=409,
            detail=(f"{len(unresolved)} unresolved review item(s) must be resolved "
                    "through the mapping review queue before a report can be generated"),
        )


def _suggestion_map(node_names: set[str] | None = None,
                    ) -> dict[str, dict[int, dict[str, Any]]]:
    """Proposed canonical fact per unmapped line, keyed by node then line.

    The preliminary report prints this so an operator sees what the pipeline
    *would* map each unresolved line to before anything is applied.
    """
    ledger = load_fragment_decisions(mappings_dir())
    out: dict[str, dict[int, dict[str, Any]]] = {}
    for it in _unique_review_items(node_names):
        entry = {
            "fact": it.get("suggested_fact") or "",
            "confidence": float(it.get("suggestion_confidence", 0.0) or 0.0),
            "source": it.get("suggested_by", ""),
            "resolved": it["key"] in ledger,
        }
        for occ in it.get("occurrences") or []:
            line = (occ.get("source_span") or {}).get("line_start")
            try:
                line_no = int(line)
            except (TypeError, ValueError):
                continue
            out.setdefault(occ.get("node_id", ""), {})[line_no] = entry
    return out


def _fragment_out(proposals: list[dict[str, Any]]) -> list[NodeDetailFragment]:
    out = []
    for p in proposals:
        out.append(NodeDetailFragment(**{k: p.get(k) for k in
                                         ("proposal_id", "raw_path", "raw_text", "category",
                                          "source_span", "suggested_fact",
                                          "suggestion_confidence", "suggested_by", "status",
                                          "decided_fact", "approver", "decided_at")
                                         if k in p}))
    return out


def _record_fragment_decisions_for_session(session, recorded: list[dict[str, Any]],
                                           approver: str) -> None:
    """Mirror node-level decisions into the content-keyed ledger so the same
    raw line on other nodes is resolved too."""
    by_id = {p["proposal_id"]: p for p in session.proposals}
    out: list[dict[str, Any]] = []
    for rec in recorded:
        p = by_id.get(rec.get("proposal_id"))
        if not p:
            continue
        out.append({
            "key": fragment_key(session.vendor, session.platform, p.get("raw_text", "")),
            "decision": rec.get("decision"),
            "fact": rec.get("fact"),
            "vendor": session.vendor,
            "platform": session.platform,
            "raw_text": p.get("raw_text", ""),
            "approver": approver,
        })
    if out:
        record_fragment_decisions(mappings_dir(), out)


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-") or "x"


def _write_pending_packs(node_ids: list[str], activate_by: str = "",
                         activate_reason: str = "") -> list[str]:
    """Persist the mapping packs derived from recorded human decisions.

    Both review-queue and node-training decisions land in the same per-node
    ledger, so a session rebuilt and replayed against it yields the approved
    proposals, merged per vendor/platform into one pack.

    ``activate_by`` carries the email of the human whose approve decision this
    is: their explicit decision IS the approval, so the pack goes straight to
    ACTIVE and the authoritative result moves with it (no second promotion
    step for a reviewer to forget). Without it the pack stays PENDING_REVIEW for
    the governance queue and only feeds the provisional preview.
    """
    groups: dict[tuple[str, str], TrainingSession] = {}
    seen: dict[tuple[str, str], set[tuple[str, str]]] = {}
    # Review-queue decisions are content-keyed in the fragment ledger; a rebuilt
    # session carries the raw paths needed to turn them into mapping rules.
    fragment_ledger = load_fragment_decisions(mappings_dir())
    for node_id in node_ids:
        try:
            _r, session = _session_for_node(node_id)
        except Exception:
            continue
        key = (session.vendor, session.platform)
        if key not in groups:
            groups[key] = TrainingSession(
                session_id=f"review-{_slug(session.vendor)}-{_slug(session.platform)}",
                vendor=session.vendor, platform=session.platform)
            seen[key] = set()
        for p in session.proposals:
            proposal = p
            if proposal.get("status") != "APPROVED":
                rec = fragment_ledger.get(
                    fragment_key(session.vendor, session.platform, p.get("raw_text", "")))
                if not (rec and str(rec.get("decision", "")).upper() == "APPROVED" and rec.get("fact")):
                    continue
                proposal = {**p, "status": "APPROVED", "approved_fact": rec["fact"],
                            "approver": rec.get("approver", "human")}
            sig = (str(proposal.get("raw_path", "")), str(proposal.get("approved_fact", "")))
            if sig in seen[key]:
                continue
            seen[key].add(sig)
            groups[key].proposals.append(proposal)
    written: list[str] = []
    for group in groups.values():
        if not group.proposals:
            continue
        try:
            path = write_pack(group, get_registry(), activate_by=activate_by,
                              activate_reason=activate_reason)
        except Exception:
            path = None
        if path:
            written.append(str(path))
    if written:
        # Decisions change the preview surface; an activated pack changes the
        # authoritative one, so that engine is reset too.
        reset_preview_engine()
        if activate_by:
            reset_engine()
    return written


def _apply_fragment_decisions(item_index: dict[str, dict[str, Any]],
                              decisions: list[Any], approver: str) -> tuple[int, set[str]]:
    """Apply content-keyed decisions to EVERY node containing the matching line."""
    from inv4r.core.facts import normalize_fact_name

    applied = 0
    nodes_updated: set[str] = set()
    global_records: list[dict[str, Any]] = []
    for d in decisions:
        item = item_index.get(getattr(d, "key", None))
        if item is None:
            continue
        decision = getattr(d, "decision", "REJECTED")
        fact = getattr(d, "fact", None)
        if decision == "APPROVED":
            fact = fact or item.get("suggested_fact")
            if not fact:
                decision = "REJECTED"
            else:
                try:
                    normalize_fact_name(fact)
                except ValueError as exc:
                    raise HTTPException(status_code=400, detail=str(exc)) from exc
        for occ in item["occurrences"]:
            record_decisions(mappings_dir(), occ["node_id"], [{
                "proposal_id": occ.get("proposal_id", ""),
                "decision": decision,
                "fact": fact if decision == "APPROVED" else None,
                "approver": approver,
            }])
            nodes_updated.add(occ["node_id"])
        global_records.append({
            "key": item["key"], "decision": decision,
            "fact": fact if decision == "APPROVED" else None,
            "vendor": item["vendor"], "platform": item["platform"],
            "raw_text": item.get("raw_text", ""),
            "approver": approver,
        })
        applied += 1
    if global_records:
        record_fragment_decisions(mappings_dir(), global_records)
    return applied, nodes_updated


@api.get("/train/session/{node_id}")
def train_session(node_id: str, user: dict = Depends(analyst_only)):
    """Unknown fragments for a node plus AI candidates not yet decided by a human."""
    _, session = _session_for_node(node_id)
    ledger = load_decisions(mappings_dir())
    fragment_ledger = load_fragment_decisions(mappings_dir())
    pending = undecided(session, node_id, ledger, fragment_ledger)
    done = decided_for(session, node_id, ledger, fragment_ledger)
    return {
        "session_id": session.session_id,
        "vendor": session.vendor,
        "platform": session.platform,
        "proposals": session.proposals,
        "pending": _fragment_out(pending),
        "pending_count": len(pending),
        "decided": _fragment_out(done),
        "decided_count": len(done),
    }


@api.post("/train/decide", response_model=TrainDecideOut)
def train_decide(body: TrainDecideBatchIn, user: dict = Depends(reviewer_or_above)):
    """Record human decisions on proposals, then persist a PENDING_REVIEW pack."""
    decisions = body.effective_decisions
    if not decisions:
        raise HTTPException(status_code=400, detail="proposal_id or decisions[] is required")

    _, session = _session_for_node(body.node_id)
    approver = _user_email(user)
    applied = 0
    recorded: list[dict[str, Any]] = []
    for d in decisions:
        updated = decide(session, d.proposal_id, d.decision, fact=d.fact, approver=approver)
        if updated is None:
            continue
        if updated.get("status") == "PENDING":
            raise HTTPException(
                status_code=400,
                detail=updated.get("error") or
                       f"proposal {d.proposal_id} could not be applied",
            )
        applied += 1
        recorded.append({"proposal_id": d.proposal_id, "decision": updated.get("status", d.decision),
                         "fact": updated.get("approved_fact", d.fact), "approver": approver})
    if recorded:
        record_decisions(mappings_dir(), body.node_id, recorded)
        _record_fragment_decisions_for_session(session, recorded, approver)

    try:
        pack_path = write_pack(session, get_registry())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"mapping pack rejected: {exc}") from exc
    from inv4r.ai import proposer
    proposer.reset_model_cache()
    reset_preview_engine()
    ledger = load_decisions(mappings_dir())
    fragment_ledger = load_fragment_decisions(mappings_dir())
    pending = undecided(session, body.node_id, ledger, fragment_ledger)
    return TrainDecideOut(status="ok", pack_written=str(pack_path) if pack_path else "",
                          decisions=applied, session_id=session.session_id,
                          pending_count=len(pending),
                          decided_count=len(decided_for(session, body.node_id, ledger,
                                                       fragment_ledger)))


@api.get("/ai")
def get_ai(user: dict = Depends(analyst_only)):
    s = get_settings()
    model = get_learned_model()
    return {
        "settings": s.to_json(),
        "learned_model": {"trained_examples": model.trained_on()},
        "cloud_key": {
            "configured": bool(s.cloud_api_key),
            "provider": s.cloud_llm_provider if s.cloud_api_key else "",
            "masked": s.to_json()["cloud_llm"]["api_key_masked"],
        },
    }


@api.post("/settings", response_model=SetSettingsOut)
def put_settings(body: SettingsUpdate, user: dict = Depends(admin_only)):
    s = get_settings()
    target_air = body.air_gapped if body.air_gapped is not None else s.air_gapped
    target_mode = body.mode or s.mode
    # The air-gap invariant is enforced here, independent of the frontend: a
    # cloud lane can never be persisted while air_gapped is true.
    if target_mode == "cloud_llm" and target_air:
        raise HTTPException(
            status_code=400,
            detail="cloud_llm cannot be selected while air_gapped is true",
        )
    if target_mode == "cloud_llm" and not s.cloud_api_key:
        raise HTTPException(
            status_code=400,
            detail="cloud_llm requires a configured cloud API key",
        )
    import dataclasses
    set_settings(dataclasses.replace(s, mode=target_mode, air_gapped=target_air))
    from inv4r.ai import proposer
    proposer.reset_model_cache()
    return SetSettingsOut(status="ok", settings=get_settings().to_json())


@api.post("/ai/cloud-key", response_model=CloudKeyStatusOut)
def set_cloud_key(body: CloudKeyIn, user: dict = Depends(admin_only)):
    """Encrypt a cloud LLM API key at rest. The key is never logged, echoed,
    or persisted in plaintext; only a masked indicator is returned."""
    from inv4r.ai.secrets import mask_key, save_cloud_key

    key = (body.key or "").strip()
    if len(key) < 8:
        raise HTTPException(status_code=400, detail="a valid API key is required")
    provider = (body.provider or "openai").strip() or "openai"
    try:
        save_cloud_key(key, provider)
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    import dataclasses
    s = get_settings()
    set_settings(dataclasses.replace(s, cloud_api_key=key, cloud_llm_provider=provider))
    from inv4r.ai import proposer
    proposer.reset_model_cache()
    return CloudKeyStatusOut(configured=True, masked=mask_key(key), provider=provider)


@api.post("/ai/cloud-key/remove", response_model=CloudKeyStatusOut)
def delete_cloud_key(user: dict = Depends(admin_only)):
    from inv4r.ai.secrets import remove_cloud_key

    remove_cloud_key()
    import dataclasses
    s = get_settings()
    set_settings(dataclasses.replace(s, cloud_api_key=""))
    from inv4r.ai import proposer
    proposer.reset_model_cache()
    return CloudKeyStatusOut(configured=False, masked="", provider="")


@api.post("/ai/eval", response_model=EVOut)
def ai_eval(body: dict, user: dict = Depends(admin_only)):
    mode = body.get("mode", get_settings().mode)
    air_gapped = bool(body.get("air_gapped", get_settings().air_gapped))
    try:
        res = run_eval(mode=mode, air_gapped=air_gapped)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"eval failed: {exc}") from exc
    metrics = res.get("metrics", res)
    return EVOut(
        mode=str(res.get("mode", mode)),
        dataset_size=int(res.get("total_examples", 0) or 0),
        true_positives=int(metrics.get("true_positives", 0) or 0),
        false_positives=int(metrics.get("false_positives", 0) or 0),
        false_negatives=int(metrics.get("false_negatives", 0) or 0),
        precision=float(metrics.get("precision", 0.0) or 0.0),
        recall=float(metrics.get("recall", 0.0) or 0.0),
        f1=float(metrics.get("f1", 0.0) or 0.0),
        vocab_violations=int(metrics.get("vocab_violations", 0) or 0),
        per_example=[AIImplOut(
            suggested=str(ex.get("proposed", "") or ""),
            suggested_confidence=float(ex.get("confidence", 0.0) or 0.0),
            suggested_by=str(ex.get("lane_used", "") or ""),
            could_not_suggest=ex.get("proposed") is None,
        ) for ex in (res.get("details") or [])],
        server_time=_now_iso(),
    )


@api.get("/assessment/review-status", response_model=ReviewStatusOut)
def assessment_review_status(framework: str = "cis-network-baseline",
                             session_id: str | None = None,
                             user: dict = Depends(analyst_only)):
    """Outstanding review items that block report generation for this scope."""
    scoped = _scoped_node_names(session_id)
    total, nodes = _review_outstanding(scoped)
    return ReviewStatusOut(framework=framework, needs_review=total > 0,
                           outstanding=total, nodes=nodes,
                           backlog=_backlog_count(scoped), session_id=session_id or "all")


def _session_counts(session: dict[str, Any]) -> tuple[int, int, int, int]:
    existing = {p.name for p in _iter_config_files()}
    node_ids = [n for n in session_store.node_ids_for_session(session["id"]) if n in existing]
    fw = session.get("framework") or "cis-network-baseline"
    pass_c = fail_c = unk_c = 0
    for node_id in node_ids:
        p = configs_dir() / Path(node_id).name
        if not p.is_file():
            continue
        try:
            r = _process(p)
            _, _band, ctrls = _assess_one(r, fw)
        except Exception:
            continue
        for c in ctrls:
            if c.result == "PASS":
                pass_c += 1
            elif c.result == "FAIL":
                fail_c += 1
            elif c.result == "UNKNOWN":
                unk_c += 1
    return len(node_ids), pass_c, fail_c, unk_c


def _session_out(s: dict[str, Any]) -> SessionOut:
    node_count, pass_c, fail_c, unk_c = _session_counts(s)
    return SessionOut(
        id=s["id"], created_at=s.get("created_at", ""), closed_at=s.get("closed_at"),
        framework=s.get("framework", ""), status=s.get("status", "open"),
        node_count=node_count, pass_count=pass_c, fail_count=fail_c, unknown_count=unk_c,
    )


@api.get("/sessions", response_model=SessionsOut)
def list_sessions_endpoint(user: dict = Depends(analyst_only)):
    """Every assessment session with its scoped node count and posture summary."""
    out = [_session_out(s) for s in session_store.list_sessions()]
    current = session_store.current_session()
    return SessionsOut(sessions=out, total=len(out),
                       current_session_id=(current or {}).get("id", ""))


@api.get("/sessions/{session_id}", response_model=SessionOut)
def get_session_endpoint(session_id: str, user: dict = Depends(analyst_only)):
    s = session_store.get_session(session_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"session {session_id!r} not found")
    return _session_out(s)


@api.post("/sessions/end", response_model=SessionEndOut)
def end_session_endpoint(user: dict = Depends(reviewer_or_above)):
    """Close the currently open session and clear its devices.

    A session is the unit of work: closing it removes the configs uploaded
    during it (and their per-evidence artifacts) so the next session starts
    from a clean slate. Learned knowledge is content-keyed and is NOT deleted:
    resolved lines stay resolved, and an unresolved line only re-appears if the
    same raw content is uploaded again.
    """
    s = session_store.end_session()
    if s is None:
        return SessionEndOut(status="ok", session=None)
    removed = _purge_nodes(session_store.nodes_of(s["id"]))
    return SessionEndOut(status="ok", session=SessionOut(
        id=s["id"], created_at=s.get("created_at", ""), closed_at=s.get("closed_at"),
        framework=s.get("framework", ""), status=s.get("status", "closed")),
        nodes_cleared=len(removed))


@api.post("/sessions/new", response_model=SessionEndOut)
def new_session_endpoint(framework: str = "",
                         user: dict = Depends(reviewer_or_above)):
    """Close the open session, clear its devices, and open a fresh one.

    Devices uploaded during the closing session are purged (files, artifacts,
    manifest and session-registry entries) — the previous session's work must
    not clutter the new one. What survives the rollover is knowledge, not
    clutter: content-keyed review decisions, learned examples and mapping packs.
    """
    previous = session_store.end_session()
    removed = _purge_nodes(session_store.nodes_of(previous["id"])) if previous else []
    # Pre-existing clutter: nodes registered to sessions that closed before the
    # purge-on-close rule existed. They belong to no open session, so they are
    # cleared too — a fresh session must start with a clean fleet.
    data = session_store.list_sessions()
    open_ids = {s["id"] for s in data if s.get("status") == "open"}
    strays: list[str] = []
    for s in data:
        if s.get("status") != "open":
            strays.extend(n for n in session_store.nodes_of(s["id"])
                          if n not in removed)
    removed += _purge_nodes(sorted(set(strays)))
    opened = session_store.ensure_open_session(framework)
    return SessionEndOut(
        status="ok", session=_session_out(opened),
        previous=_session_out(previous) if previous else None,
        backlog=_backlog_count(None),
        nodes_cleared=len(removed),
    )


@api.get("/review/queue", response_model=ReviewQueueOut)
def review_queue(session_id: str | None = None,
                 node_id: str | None = None,
                 user: dict = Depends(analyst_only)):
    """Deduplicated review queue: one item per unique raw line per vendor.

    ``session_id`` scopes the queue to that session's nodes and ``node_id`` to
    a single uploaded configuration — the audit workflow uses the latter so the
    unknowns of the config just audited are listed (and resolvable) without
    pulling in another config's queue. Decisions stay global (keyed by
    vendor/platform/raw line); only the counts and the report gate are scoped.
    """
    if node_id:
        scoped: set[str] | None = {Path(node_id).name}
        scope = "node"
    else:
        scoped = _scoped_node_names(session_id)
        scope = "session" if scoped is not None else "all"
    ledger = load_fragment_decisions(mappings_dir())
    items = _unique_review_items(scoped)
    out_items: list[ReviewItemOut] = []
    categories: dict[str, int] = {}
    unresolved_n = 0
    for it in items:
        record = ledger.get(it["key"]) or {}
        is_resolved = it["key"] in ledger
        if not is_resolved:
            unresolved_n += 1
            categories[it["category"]] = categories.get(it["category"], 0) + 1
        out_items.append(ReviewItemOut(
            key=it["key"], raw_text=it["raw_text"], raw_path=it["raw_path"],
            category=it["category"],
            category_label=CATEGORY_LABELS.get(it["category"], it["category"]),
            vendor=it["vendor"], platform=it["platform"],
            suggested_fact=it.get("suggested_fact"),
            suggestion_confidence=it.get("suggestion_confidence", 0.0),
            suggested_by=it.get("suggested_by", ""),
            nodes=it["nodes"], affected_count=it["affected_count"],
            resolved=is_resolved,
            resolution=str(record.get("decision", "")),
            applied_fact=str(record.get("fact") or ""),
        ))
    return ReviewQueueOut(items=out_items, total=len(items),
                          unresolved=unresolved_n, categories=categories,
                          resolved=len(items) - unresolved_n,
                          session_id=session_id or "all",
                          scope=scope,
                          backlog=_backlog_count(scoped))


@api.post("/review/decide", response_model=ReviewDecideOut)
def review_decide(body: ReviewDecideIn, user: dict = Depends(reviewer_or_above)):
    """Apply content-keyed decisions to every node containing the line."""
    ledger = load_fragment_decisions(mappings_dir())
    pending = unresolved_items(_unique_review_items(), ledger)
    item_index = {it["key"]: it for it in pending}
    approver = _user_email(user)
    applied, updated = _apply_fragment_decisions(item_index, body.decisions, approver)
    # The reviewer just approved these lines, so the packs are activated now:
    # "resolved" in the queue means the authoritative result actually changed.
    _write_pending_packs(sorted(updated), activate_by=approver,
                         activate_reason="Approved in the review queue")
    from inv4r.ai import proposer
    proposer.reset_model_cache()
    remaining, _ = _review_outstanding(None)
    return ReviewDecideOut(status="ok", applied=applied,
                           nodes_updated=len(updated), unresolved=remaining,
                           backlog=0)


@api.post("/review/approve-category", response_model=ReviewDecideOut)
def review_approve_category(body: ReviewCategoryIn,
                            user: dict = Depends(reviewer_or_above)):
    """Approve every unresolved item in a category (rejecting those with no
    canonical suggestion, which is still a valid human decision)."""
    from inv4r.api.models import ReviewDecisionIn

    ledger = load_fragment_decisions(mappings_dir())
    items = [it for it in unresolved_items(_unique_review_items(), ledger)
             if it["category"] == body.category]
    decisions = []
    for it in items:
        fact = body.fact or it.get("suggested_fact")
        decisions.append(ReviewDecisionIn(
            key=it["key"], decision="APPROVED" if fact else "REJECTED", fact=fact))
    approver = _user_email(user)
    applied, updated = _apply_fragment_decisions(
        {it["key"]: it for it in items}, decisions, approver)
    _write_pending_packs(sorted(updated), activate_by=approver,
                         activate_reason="Approved by category in the review queue")
    from inv4r.ai import proposer
    proposer.reset_model_cache()
    remaining, _ = _review_outstanding(None)
    return ReviewDecideOut(status="ok", applied=applied,
                           nodes_updated=len(updated), unresolved=remaining,
                           backlog=0)


@api.post("/review/dismiss", response_model=ReviewDismissOut)
def review_dismiss(body: ReviewDismissIn, user: dict = Depends(reviewer_or_above)):
    """Clear stale backlog items deliberately, without recording a mapping.

    A dismissal is not a rejection, so it creates no negative training example;
    it only marks the content key resolved for counting purposes.
    """
    ledger = load_fragment_decisions(mappings_dir())
    pending = {it["key"]: it for it in unresolved_items(_unique_review_items(None), ledger)}
    records: list[dict[str, Any]] = []
    for key in body.keys:
        it = pending.get(key)
        if it is None:
            continue
        records.append({"key": key, "decision": "DISMISSED", "fact": None,
                        "vendor": it["vendor"], "platform": it["platform"],
                        "approver": _user_email(user)})
    if records:
        record_fragment_decisions(mappings_dir(), records)
    remaining, _ = _review_outstanding(None)
    return ReviewDismissOut(status="ok", dismissed=len(records), unresolved=remaining,
                            backlog=_backlog_count(None))


@api.get("/behaviour/invariants", response_model=InvariantsOut)
def behaviour_invariants(user: dict = Depends(analyst_only)):
    """Configurable security invariants (source, destination, expected action).

    ``needs`` lists endpoints the operator must supply because they are not
    concrete IPs Batfish can evaluate. Destinations are never hardcoded.
    """
    from inv4r.behaviour.models import INVARIANTS, invariant_needs_endpoints
    out = []
    for inv in INVARIANTS:
        needs = [InvariantEndpointIn(**n) for n in invariant_needs_endpoints(inv)]
        out.append(InvariantOut(**inv, needs=needs))
    return InvariantsOut(invariants=out)


@api.post("/behaviour/verify", response_model=InvariantVerifyOut)
def behaviour_verify(body: InvariantVerifyIn, user: dict = Depends(analyst_only)):
    """Run one invariant against Batfish. Honest UNKNOWN when Batfish is down."""
    from inv4r.behaviour.models import (
        invariant_by_id,
        invariant_to_query,
        invariant_verdict,
    )
    inv = invariant_by_id(body.invariant_id)
    if inv is None:
        raise HTTPException(status_code=400,
                            detail=f"unknown invariant {body.invariant_id!r}")
    be = _behaviour()
    # Device-level filter verification pins the question to one device and
    # uses Batfish's filter question (testfilters); otherwise run reachability.
    qtype = body.qtype or ("acl_check" if body.node_id else "reachability")
    query = invariant_to_query(
        inv, source=body.source, destination=body.destination,
        protocol=body.protocol, port=body.port, node=body.node_id, qtype=qtype)
    scoped = _scoped_node_names(body.session_id) if body.session_id else None
    result = be.analyze(query, scoped)
    verdict = invariant_verdict(inv.get("expected", "DENIED"), result.status)
    return InvariantVerifyOut(
        invariant=InvariantOut(**inv), result=verdict,
        behaviour_status=result.status, summary=result.summary,
        explanation=result.explanation, path=[h.to_json() for h in result.path],
        batfish_available=be.available(),
        evidence=[e.to_json() for e in result.evidence], server_time=_now_iso())


@api.get("/report/pdf")
def report_pdf(node_id: str, framework: str = "cis-network-baseline",
               preliminary: bool = False,
               user: dict = Depends(analyst_only)):
    """Final report (gated on unresolved lines) or a preliminary one.

    ``preliminary=true`` produces a clearly-marked draft that may be downloaded
    at any time: it lists the unresolved lines together with the mapping each
    one is *suggested* to become. The final report still requires the queue to
    be clear, so a draft can never be mistaken for a verified result.
    """
    p = configs_dir() / Path(node_id).name
    if not p.is_file():
        raise HTTPException(status_code=404, detail=f"node {node_id!r} not found")
    if not preliminary:
        _require_review_clear([p.name])
    ass = run_assessment(_engine(), [str(p)], framework, _controls_engine())
    suffix = "_preliminary" if preliminary else ""
    out_pdf = artifacts_dir() / f"report_{Path(node_id).stem}_{framework}{suffix}.pdf"
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    render_pdf(ass, str(out_pdf), preliminary=preliminary,
               suggestions=_suggestion_map({p.name}) if preliminary else None)
    return FileResponse(str(out_pdf), media_type="application/pdf", filename=out_pdf.name)


@api.get("/report/pdf/fleet")
def report_pdf_fleet(framework: str = "cis-network-baseline",
                     session_id: str | None = None,
                     preliminary: bool = False,
                     user: dict = Depends(analyst_only)):
    files = _iter_config_files()
    if session_id:
        wanted = set(session_store.node_ids_for_session(session_id))
        files = [p for p in files if p.name in wanted]
    if not files:
        raise HTTPException(status_code=400, detail="no configs ingested")
    if not preliminary:
        _require_review_clear([p.name for p in files])
    ass = run_assessment(_engine(), [str(p) for p in files], framework, _controls_engine())
    suffix = "_preliminary" if preliminary else ""
    out_pdf = artifacts_dir() / f"report_fleet_{framework}{suffix}.pdf"
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    render_pdf(ass, str(out_pdf), kind="fleet", preliminary=preliminary,
               suggestions=_suggestion_map({p.name for p in files}) if preliminary else None)
    return FileResponse(str(out_pdf), media_type="application/pdf", filename=out_pdf.name)


@api.post("/auth/login", response_model=LoginOut)
def login(body: LoginRequest, response: Response):
    try:
        user = authenticate(body.email, body.password)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
    token = issue_token(user)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=os.environ.get("INV4R_ENV", "development").lower() == "production",
        max_age=12 * 3600,
        samesite="lax",
        path="/",
    )
    return LoginOut(status="ok", user=UserOut(**user), token=token)


@api.get("/auth/me", response_model=AuthMeOut)
def auth_me(user: dict = Depends(authenticated)):
    return AuthMeOut(user=UserOut(**user))


@api.post("/auth/logout", response_model=LogoutOut)
def logout(response: Response, user: dict = Depends(authenticated)):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return LogoutOut(status="ok")


@api.get("/auth/users", response_model=UserListOut)
def list_users(user: dict = Depends(admin_only)):
    from inv4r.api.auth import load_users
    users = load_users()
    return UserListOut(
        users=[UserOut(email=u["email"], name=u.get("name", ""), role=u["role"])
               for u in users],
        total=len(users),
    )


@api.post("/auth/users", response_model=OkOut)
def create_user(body: CreateUserIn, user: dict = Depends(admin_only)):
    from inv4r.api.auth import add_user
    try:
        created = add_user(body.email, body.name, body.role, body.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return OkOut(message=f"account created for {created['email']} ({created['role']})")


@api.post("/auth/reset-password", response_model=OkOut)
def reset_password(body: ResetPasswordIn, user: dict = Depends(admin_only)):
    from inv4r.api.auth import admin_reset_password
    try:
        admin_reset_password(body.email, body.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return OkOut(message=f"password reset for {body.email}")


@api.post("/auth/delete-user", response_model=OkOut)
def delete_user_endpoint(body: DeleteUserIn, user: dict = Depends(admin_only)):
    from inv4r.api.auth import delete_user
    try:
        delete_user(body.email)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return OkOut(message=f"account deleted for {body.email}")
