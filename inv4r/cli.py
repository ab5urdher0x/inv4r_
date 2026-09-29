"""INV4R command line interface."""

from __future__ import annotations

import logging
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
import argparse
import json
import sys
from pathlib import Path

from inv4r import __version__
from inv4r.adapters.builtin import default_adapters
from inv4r.adapters.external_engine import ExternalEngineAdapter
from inv4r.adapters.generic_structural import GenericStructuralAdapter
from inv4r.adapters.runtime_mapping import RuntimeMappingAdapter
from inv4r.controls import ControlEngine
from inv4r.core.facts import vocabulary_json
from inv4r.engine import Engine
from inv4r.mapping.registry import MappingRegistry
from inv4r.reporting import render_pdf, run_assessment
from inv4r.training import TrainingSession, decide, write_pack


def _new_engine(args) -> Engine:
    from inv4r.ai import reset_model_cache
    from inv4r.ai.settings import set_overrides

    air = getattr(args, "air_gapped", None)
    set_overrides(mode=getattr(args, "ai_mode", None),
                  mappings_dir=args.mappings,
                  air_gapped=(None if air is None else bool(air)))
    reset_model_cache()
    return Engine(mapping_dir=args.mappings, artifact_dir=args.out)


def cmd_ingest(args) -> int:
    engine = _new_engine(args)
    results = engine.process_path(args.path)
    if not results:
        print("no evidence files found")
        return 1
    print(f"{'file':30s} {'vendor':18s} {'adapter':24s} {'facts':>5s} {'unk':>4s} {'lvl':>3s}")
    for r in results:
        n = r.normalization
        print(f"{Path(r.envelope.source_path).name:30s} {r.vendor:18s} "
              f"{(r.resolution.chosen.adapter_id if r.resolution.chosen else 'none'):24s} "
              f"{len(r.facts):5d} {(len(n.unknown_fragments) if n else 0):4d} "
              f"{r.coverage.achieved_level:3d}")
    print(f"\nartifacts written to {engine.registry.root}")
    return 0


def cmd_assess(args) -> int:
    engine = _new_engine(args)
    ce = ControlEngine(args.controls)
    try:
        ce.get_profile(args.framework)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    ass = run_assessment(engine, [args.path], args.framework, ce)
    out = Path(args.out) / "assessment.json"
    ass.save_json(out)
    s = ass.summary()
    print(f"assessment saved: {out}")
    print(f"devices={s['devices']} passed={s['controls_passed']} "
          f"failed={s['controls_failed']} unknown={s['controls_unknown']} "
          f"avg_score={s['avg_score']}")
    for d in ass.devices:
        name = Path(d.device_result.envelope.source_path).name
        print(f"  {name:30s} score={d.score:3d} ({d.band:8s}) "
              f"pass={sum(1 for c in d.controls if c.result == 'PASS')} "
              f"fail={sum(1 for c in d.controls if c.result == 'FAIL')} "
              f"unk={sum(1 for c in d.controls if c.result == 'UNKNOWN')}")
    return 0


def cmd_report(args) -> int:
    from inv4r.reporting.assessment import Assessment

    src = Path(args.source)
    if src.is_dir():
        src = src / "assessment.json"
    if not src.exists():
        print(f"error: assessment file '{src}' not found", file=sys.stderr)
        return 2
    payload = json.loads(src.read_text(encoding="utf-8"))
    if not hasattr(Assessment, "from_json"):
        print("error: cannot load assessment", file=sys.stderr)
        return 2
    ass = Assessment.from_json(payload)
    out_pdf = getattr(args, "out_pdf", None) or "out/report.pdf"
    Path(out_pdf).parent.mkdir(parents=True, exist_ok=True)
    render_pdf(ass, out_pdf)
    print(f"pdf written: {out_pdf}")
    return 0


def cmd_train(args) -> int:
    """Interactive training loop over an assessment's unknown fragments."""
    engine = _new_engine(args)
    ass = run_assessment(engine, [args.path], args.framework,
                         ControlEngine(args.controls))

    from inv4r.training import build_session

    frag_maps: dict[str, list[dict]] = {}
    vendor = platform = "unknown"
    for d in ass.devices:
        r = d.device_result
        if r.normalization and r.normalization.unknown_fragments:
            vendor, platform = r.vendor, r.platform
            frag_maps[r.envelope.evidence_id] = [
                f.to_json() for f in r.normalization.unknown_fragments]

    if not frag_maps:
        print("no unknown fragments found — nothing to train")
        return 0

    session = build_session(frag_maps, vendor, platform,
                            session_id=args.session_name)
    total = len(session.proposals)
    print(f"Training session '{session.session_id}': {total} proposal(s) "
          f"for vendor '{vendor}'. Vocabulary is closed — pick from the list.\n")
    vocab = [(k, d) for k, (t, d) in sorted(vocabulary_json()["facts"].items())]

    for p in session.proposals:
        print("-" * 70)
        print(f"{p['proposal_id']}  line {p['source_span']['line_start'] if p['source_span'] else '?'}"
              f"  [{p['category']}]  confidence={p['suggestion_confidence']}")
        print(f"  raw: {p['raw_text'][:90]}")
        if p.get("suggested_fact"):
            print(f"  AI suggests: {p['suggested_fact']}")
        else:
            print("  AI suggests: (none — choose manually)")
        choice = input("map to fact (blank=AI suggestion, 's'=skip, 'r'=reject, "
                       "'l'=list vocabulary): ").strip()
        if choice == "s":
            continue
        if choice == "r":
            decide(session, p["proposal_id"], "REJECTED", approver=args.user)
            continue
        if choice == "l":
            for k, d in vocab:
                print(f"  {k:36s} {d}")
            choice = input("map to fact: ").strip()
        if not choice and p.get("suggested_fact"):
            choice = p["suggested_fact"]
        if choice:
            decide(session, p["proposal_id"], "APPROVED", fact=choice, approver=args.user)

    out = Path(args.out) / "session.json"
    session.save(out)
    pack_path = write_pack(session, MappingRegistry(args.mappings))
    approved = sum(1 for p in session.proposals if p.get("status") == "APPROVED")
    print("-" * 70)
    print(f"session saved: {out}")
    print(f"approved {approved}/{total}; "
          + (f"mapping pack written: {pack_path}" if pack_path
             else "no pack written (nothing approved)"))
    if pack_path:
        pack_id = Path(pack_path).stem
        print(f"pack '{pack_id}' is PENDING_REVIEW — a second reviewer must approve it "
              f"before it can affect compliance results:")
        print(f"  inv4r mappings approve --map-id {pack_id} --actor <reviewer> --reason '<why>'")
    return 0


def cmd_ai(args) -> int:
    """Show the active AI lane, air-gap posture, and learned-model stats."""
    from inv4r.ai.eval import format_eval_report, run_eval
    from inv4r.ai.proposer import get_learned_model
    from inv4r.ai.settings import get_settings

    _new_engine(args)
    s = get_settings()
    if getattr(args, "eval", False):
        res = run_eval(mode=s.mode, air_gapped=s.air_gapped)
        print(format_eval_report(res))
        return 0
    print(json.dumps(s.to_json(), indent=2))
    model = get_learned_model()
    print(f"\nlearned model: trained on {model.trained_on()} approved example(s) "
          f"from {s.mappings_dir}/")
    if s.mode == "rules":
        print("proposer: rules only (no learning, no LLM)")
    elif s.mode == "learned":
        print("proposer: tfidf-knn learned model, rules as floor (air-gap safe)")
    elif s.mode == "local_llm":
        print(f"proposer: learned model + local LLM ({s.local_llm_model} at "
              f"{s.local_llm_base}) — air-gap safe only if endpoint is loopback")
    elif s.mode == "cloud_llm":
        print(f"proposer: learned model + cloud LLM ({s.cloud_llm_model}) — "
              f"config data LEAVES this machine")
    print("proposals are always human-approved before use (tier-4 workflow)")
    return 0


def cmd_mappings(args) -> int:
    """Lifecycle operations over runtime mapping packs (tier 4)."""
    from inv4r.mapping.registry import MappingRegistry

    reg = MappingRegistry(args.mappings)
    if args.action == "list":
        print(f"{'map_id':40s} {'ver':4s} {'status':16s} {'vendor':18s} {'approved_by':12s} rules")
        for p in sorted(reg.packs, key=lambda x: (x.status, x.map_id)):
            print(f"{p.map_id:40s} {p.version:4s} {p.status:16s} {p.vendor:18s} "
                  f"{(p.approved_by or '-'):12s} {len(p.rules)}")
        if reg.rejected:
            print(f"\nquarantined (rejected at load): {len(reg.rejected)}")
            for rec in reg.rejected:
                print(f"  {rec['source_file']}: " +
                      "; ".join(f"{v.get('field')}={v.get('value')!r}" for v in rec["violations"]))
        for note in reg.integrity_notes:
            print(f"  INTEGRITY WARNING: {note}")
        return 0

    if not args.map_id:
        print("error: --map-id required for this action", file=sys.stderr)
        return 2
    try:
        if args.action == "submit":
            p = reg.submit(args.map_id, actor=args.actor)
        elif args.action == "approve":
            p = reg.approve(args.map_id, approver=args.actor, reason=args.reason)
        elif args.action == "reject":
            p = reg.reject(args.map_id, actor=args.actor, reason=args.reason)
        elif args.action == "revoke":
            p = reg.revoke(args.map_id, actor=args.actor, reason=args.reason)
        elif args.action == "deprecate":
            p = reg.deprecate(args.map_id, actor=args.actor, reason=args.reason)
        elif args.action == "show":
            p = reg.get(args.map_id)
            print(json.dumps(p.to_json(), indent=2))
            return 0
        else:
            print(f"error: unknown action {args.action}", file=sys.stderr)
            return 2
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"{p.map_id}: {p.status} (by {args.actor}, reason: {args.reason or '-'})")
    return 0


def cmd_vocabulary(_args) -> int:
    print(json.dumps(vocabulary_json(), indent=2))
    return 0


def cmd_adapters(_args) -> int:
    rows = [("tier", "adapter_id", "vendor/format", "produces facts")]
    adapters = list(default_adapters())
    adapters.append(RuntimeMappingAdapter(MappingRegistry("mappings")))
    adapters.append(ExternalEngineAdapter())
    adapters.append(GenericStructuralAdapter())
    for ad in sorted(adapters, key=lambda a: a.tier):
        rows.append((str(ad.tier), ad.adapter_id,
                     getattr(ad, "formats", ("any",))[0] if getattr(ad, "formats", None) else "any",
                     str(ad.capabilities().produces_security_facts)))
    for row in rows:
        print(f"{row[0]:6s} {row[1]:26s} {row[2]:18s} {row[3]}")
    return 0


def cmd_serve_api(args) -> int:
    """Launch the FastAPI REST API server."""
    from inv4r.ai.settings import get_settings
    from inv4r.api import create_app

    _new_engine(args)
    settings = get_settings()
    host = getattr(args, "host", "127.0.0.1")
    port = getattr(args, "port", 8000)
    cors = getattr(args, "cors_origins", None)
    allow_origins = list(cors) if cors else None

    print("  INV4R FastAPI API Server Running")
    print(f"  URL        : http://{host}:{port}")
    print(f"  OpenAPI docs: http://{host}:{port}/docs (development or INV4R_EXPOSE_DOCS=true)")
    print(f"  Posture    : {'AIR-GAPPED (SAFE)' if settings.air_gapped else 'CONNECTED'}")
    print(f"  AI Mode    : {settings.mode}")
    print(f"  CORS       : {', '.join(allow_origins or ['same-origin / environment configuration'])}")
    print("  Press Ctrl+C to stop.\n")

    app = create_app(allow_origins=allow_origins)
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="inv4r",
                                 description="Universal network compliance auditor")
    ap.add_argument("--version", action="version", version=f"inv4r {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out", default="out", help="artifact output directory")
    common.add_argument("--mappings", default="mappings", help="mapping pack directory")
    common.add_argument("--controls", default="controls", help="control profile directory")
    common.add_argument("--ai-mode", default=None,
                        choices=["rules", "learned", "local-llm", "cloud-llm", "auto"],
                        help="AI proposer lane (default from inv4r.yaml; learned if unset)")
    common.add_argument("--air-gapped", default=None, type=lambda v: str(v).lower()
                        not in ("0", "false", "no"),
                        help="force air-gap posture on/off (default from inv4r.yaml)")
    ap.add_argument("--out", default="out", help=argparse.SUPPRESS)
    ap.add_argument("--mappings", default="mappings", help=argparse.SUPPRESS)
    ap.add_argument("--controls", default="controls", help=argparse.SUPPRESS)
    ap.add_argument("--ai-mode", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--air-gapped", default=None, type=lambda v: str(v).lower()
                    not in ("0", "false", "no"), help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest", parents=[common], help="detect + parse + normalize")
    p.add_argument("path")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("assess", parents=[common], help="evaluate controls")
    p.add_argument("path")
    p.add_argument("--framework", default="cis-network-baseline")
    p.set_defaults(func=cmd_assess)

    p = sub.add_parser("report", parents=[common], help="render PDF from assessment JSON")
    p.add_argument("source", nargs="?", default="out/assessment.json")
    p.add_argument("--format", default="pdf", choices=["pdf"])
    p.add_argument("--out-pdf", dest="out_pdf", default="out/report.pdf")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("train", parents=[common], help="interactive mapping of unknown fragments")
    p.add_argument("path", nargs="?", default="configs/unknown_vendor.cfg")
    p.add_argument("--framework", default="cis-network-baseline")
    p.add_argument("--session-name", "--session", dest="session_name", default="session1")
    p.add_argument("--user", default="admin")
    p.set_defaults(func=cmd_train)

    p = sub.add_parser("ai", parents=[common], help="show AI lane status and model stats")
    p.add_argument("--eval", action="store_true", help="run quantitative evaluation benchmark over labeled dataset")
    p.set_defaults(func=cmd_ai)

    p = sub.add_parser("mappings", parents=[common],
                       help="lifecycle operations over runtime mapping packs")
    p.add_argument("action", choices=["list", "show", "submit", "approve", "reject",
                                      "revoke", "deprecate"])
    p.add_argument("--map-id", default=None)
    p.add_argument("--actor", default="admin", help="reviewer/approver identity")
    p.add_argument("--reason", default="", help="required for reject/revoke/deprecate")
    p.set_defaults(func=cmd_mappings)

    p = sub.add_parser("serve-api", parents=[common], help="launch the FastAPI API and bundled dashboard")
    p.add_argument("--host", default="127.0.0.1", help="server bind host (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8000, help="server bind port (default: 8000)")
    p.add_argument("--cors-origins", nargs="*", default=None,
                  help="explicit allowed CORS origins (otherwise INV4R_CORS_ORIGINS; localhost only in development)")
    p.set_defaults(func=cmd_serve_api)

    sub.add_parser("vocabulary", help="print closed fact vocabulary").set_defaults(func=cmd_vocabulary)
    sub.add_parser("adapters", help="list adapter stack").set_defaults(func=cmd_adapters)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
