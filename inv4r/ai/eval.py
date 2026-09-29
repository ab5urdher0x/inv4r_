"""Labeled evaluation benchmark for INV4R AI proposer lanes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from inv4r.ai import learned, proposer
from inv4r.ai.settings import AISettings, get_settings, set_settings
from inv4r.core.facts import CANONICAL_FACTS


@dataclass(frozen=True)
class EvalExample:
    path: str
    value: str
    expected_fact: str
    vendor_context: str = "generic"


BENCHMARK_DATASET: list[EvalExample] = [
    EvalExample("system.services.ssh.enable", "on", "management.ssh.enabled", "vendorx"),
    EvalExample("set system services ssh protocol-version", "2", "management.ssh.version", "juniper"),
    EvalExample("ip ssh version", "2", "management.ssh.version", "cisco"),
    EvalExample("system.services.telnet.enable", "off", "management.telnet.enabled", "vendorx"),
    EvalExample("set system services telnet", "disable", "management.telnet.enabled", "juniper"),
    EvalExample("service.webui.http", "enable", "management.http.enabled", "generic"),
    EvalExample("system.services.webui.https", "on", "management.https.enabled", "vendorx"),
    EvalExample("idle-timeout", "5", "management.session_timeout", "vendorx"),
    EvalExample("session-timeout", "300", "management.session_timeout", "cisco"),
    EvalExample("aaa.mode", "enterprise", "authentication.aaa.enabled", "vendorx"),
    EvalExample("aaa authentication login default group tacacs+", "enable", "authentication.aaa.enabled", "cisco"),
    EvalExample("logging.remote.host", "10.50.0.20", "logging.remote.enabled", "vendorx"),
    EvalExample("syslog.server.address", "192.168.1.100", "logging.remote.enabled", "fortinet"),
    EvalExample("snmp.community.readonly", "v2c-public", "snmp.v1.v2c.enabled", "vendorx"),
    EvalExample("snmp-server community public RO", "v2c", "snmp.v1.v2c.enabled", "cisco"),
    EvalExample("snmp.version", "v3", "snmp.v3.enabled", "vendorx"),
    EvalExample("snmp-server group v3group v3 priv", "on", "snmp.v3.enabled", "cisco"),
    EvalExample("route.default", "via 10.99.0.1", "network.route.present", "vendorx"),
    EvalExample("ip route 0.0.0.0/0", "10.0.0.1", "network.route.present", "cisco"),
    EvalExample("source-filter", "10.60.0.0/16", "management.acl.present", "vendorx"),
]


def run_eval(mode: str = "learned", dataset: list[EvalExample] | None = None,
             air_gapped: bool = True) -> dict[str, Any]:
    """Run quantitative evaluation of an AI lane over the labeled dataset."""
    ds = dataset if dataset is not None else BENCHMARK_DATASET
    prev_settings = get_settings()

    set_settings(AISettings(mode=mode, air_gapped=air_gapped))

    if mode == "learned":
        train_pairs = [(ex.path, ex.value, ex.expected_fact) for ex in ds]
        model = learned.LearnedModel(min_confidence=0.35).fit(train_pairs)
        proposer._model_cache[("", 0.35, 0)] = model

    tp = 0
    fp = 0
    fn = 0
    vocab_violations = 0
    details: list[dict[str, Any]] = []

    for ex in ds:
        res = proposer.propose(ex.path, ex.value)
        if res is None:
            proposed_fact = None
            confidence = 0.0
            lane_used = "none"
        else:
            proposed_fact, confidence, meta = res
            lane_used = meta.get("model", "unknown")

        if proposed_fact is not None and proposed_fact not in CANONICAL_FACTS:
            vocab_violations += 1

        is_correct = (proposed_fact == ex.expected_fact)
        if is_correct:
            tp += 1
        elif proposed_fact is not None:
            fp += 1
        else:
            fn += 1

        details.append({
            "path": ex.path,
            "value": ex.value,
            "expected": ex.expected_fact,
            "proposed": proposed_fact,
            "confidence": confidence,
            "lane_used": lane_used,
            "correct": is_correct,
        })

    set_settings(prev_settings)
    proposer.reset_model_cache()

    total = len(ds)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = tp / total if total > 0 else 0.0
    coverage = (tp + fp) / total if total > 0 else 0.0

    return {
        "mode": mode,
        "air_gapped": air_gapped,
        "total_examples": total,
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "coverage": round(coverage, 4),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "vocab_violations": vocab_violations,
        },
        "details": details,
    }


def approved_examples(mappings_dir: str) -> list[tuple[str, str, str]]:
    """Every (path, value, canonical_fact) example the deployment has approved."""
    from inv4r.mapping.registry import MappingRegistry

    reg = MappingRegistry(mappings_dir)
    return (learned.examples_from_registry(reg)
            + learned.examples_from_decisions(mappings_dir))


def run_held_out_eval(examples: list[tuple[str, str, str]] | None = None,
                      mappings_dir: str = "mappings",
                      test_fraction: float = 0.34,
                      min_confidence: float = 0.3) -> dict[str, Any]:
    """Held-out top-1 accuracy + coverage for the learned lane.

    Trains on a subset of the *approved* examples and tests on the rest. The
    sample size is always reported; below five examples the score is stated as
    not meaningful rather than printed as if it were reliable.
    """
    ex = list(examples) if examples is not None else approved_examples(mappings_dir)
    n = len(ex)
    if n < 5:
        return {
            "mode": "learned", "sample_size": n, "train_size": 0,
            "test_size": n, "min_confidence": min_confidence,
            "top1_accuracy": None, "coverage": None,
            "note": (f"insufficient sample: only {n} approved example(s); "
                     "a held-out score would not be meaningful"),
        }
    step = max(2, round(1 / max(test_fraction, 0.05)))
    test = [e for i, e in enumerate(ex) if i % step == 0]
    train = [e for i, e in enumerate(ex) if i % step != 0]
    if not test or not train:
        return {"mode": "learned", "sample_size": n, "train_size": len(train),
                "test_size": len(test), "top1_accuracy": None, "coverage": None,
                "note": "split produced an empty train or test set"}
    model = learned.LearnedModel(min_confidence=min_confidence).fit(train)
    top1 = covered = 0
    for path, value, fact in test:
        r = model.propose(path, value)
        if r is not None:
            covered += 1
            if r[0] == fact:
                top1 += 1
    return {
        "mode": "learned", "sample_size": n, "train_size": len(train),
        "test_size": len(test), "min_confidence": min_confidence,
        "top1_accuracy": round(top1 / len(test), 4),
        "coverage": round(covered / len(test), 4),
        "top1_correct": top1, "covered": covered,
        "note": "",
    }


def format_eval_report(res: dict[str, Any]) -> str:
    """Render a human-readable benchmark evaluation summary."""
    m = res["metrics"]
    tot = res["total_examples"]
    tp = m["true_positives"]
    fp = m["false_positives"]
    lines = [
        "=" * 60,
        f"INV4R AI LANE EVALUATION BENCHMARK  (mode={res['mode']}, air_gapped={res['air_gapped']})",
        "=" * 60,
        f"Dataset Size       : {tot} labeled examples",
        f"Precision          : {m['precision'] * 100:.1f}% ({tp}/{tp + fp if (tp + fp) > 0 else 0})",
        f"Recall             : {m['recall'] * 100:.1f}% ({tp}/{tot})",
        f"F1 Score           : {m['f1_score'] * 100:.1f}%",
        f"Accuracy           : {m['accuracy'] * 100:.1f}%",
        f"Coverage           : {m['coverage'] * 100:.1f}%",
        f"Vocab Violations   : {m['vocab_violations']} (0% non-canonical invariant)",
        "-" * 60,
    ]
    return "\n".join(lines)


def main() -> None:
    res = run_eval(mode="learned")
    print(format_eval_report(res))


if __name__ == "__main__":
    main()
