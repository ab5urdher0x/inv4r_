"""Deduplicated training review queue.

Each unknown configuration line is one review item, keyed by its raw content
within a vendor + platform. The same line seen on five nodes produces one item
that lists all five affected nodes, so a human decision applies everywhere at
once instead of node-by-node.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

CATEGORY_LABELS = {
    "management_access": "Management Access",
    "authentication": "Authentication",
    "logging": "Logging",
    "snmp": "SNMP",
    "network_services": "Network Services",
    "firewall_policy": "Firewall Policy",
    "crypto": "Crypto",
    "routing": "Routing",
    "interfaces": "Interfaces",
    "other": "Other",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fragment_key(vendor: str, platform: str, raw_text: str) -> str:
    """Stable content identity for a raw line within one vendor + platform."""
    material = f"{(vendor or 'unknown').strip()}\x1f{(platform or 'unknown').strip()}\x1f{(raw_text or '').strip()}"
    return hashlib.sha1(material.encode("utf-8")).hexdigest()[:16]


def load_fragment_decisions(mappings_dir: str | Path) -> dict[str, dict[str, Any]]:
    p = Path(mappings_dir) / "fragment_decisions.json"
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8")) or {}
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def record_fragment_decisions(mappings_dir: str | Path,
                              decisions: Iterable[dict[str, Any]]) -> None:
    """Persist decisions keyed by fragment content, applying to all nodes."""
    ledger = load_fragment_decisions(mappings_dir)
    for d in decisions:
        key = d.get("key")
        if not key:
            continue
        ledger[key] = {
            "decision": d.get("decision", ""),
            "fact": d.get("fact"),
            "vendor": d.get("vendor", ""),
            "platform": d.get("platform", ""),
            # The raw line is kept so approved decisions can train the learned
            # lane (the key alone is a hash and cannot be tokenized).
            "raw_text": d.get("raw_text", ""),
            "approver": d.get("approver", ""),
            "at": d.get("at") or _now(),
        }
    p = Path(mappings_dir) / "fragment_decisions.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(ledger, indent=2, default=str), encoding="utf-8")


def build_review_queue(node_fragments: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse per-node unknown fragments into deduplicated review items.

    ``node_fragments`` maps node_id -> {"vendor", "platform", "fragments": [...]},
    where each fragment is the ``UnknownFragment.to_json()`` shape.
    """
    items: dict[str, dict[str, Any]] = {}
    for node_id, info in node_fragments.items():
        vendor = info.get("vendor", "")
        platform = info.get("platform", "")
        for frag in info.get("fragments") or []:
            raw_text = frag.get("raw_text", "") or ""
            if not (raw_text or frag.get("raw_path")):
                continue
            key = fragment_key(vendor, platform, raw_text)
            item = items.get(key)
            if item is None:
                item = {
                    "key": key,
                    "raw_text": raw_text,
                    "raw_path": frag.get("raw_path", ""),
                    "category": frag.get("category", "other"),
                    "vendor": vendor,
                    "platform": platform,
                    "suggested_fact": frag.get("suggested_fact"),
                    "suggestion_confidence": float(frag.get("suggestion_confidence", 0.0) or 0.0),
                    "suggested_by": frag.get("suggested_by", ""),
                    "occurrences": [],
                    "nodes": [],
                }
                items[key] = item
            item["occurrences"].append({
                "node_id": node_id,
                "proposal_id": frag.get("proposal_id", ""),
                "source_span": frag.get("source_span") or {},
            })
            if node_id not in item["nodes"]:
                item["nodes"].append(node_id)
            if not item.get("suggested_fact") and frag.get("suggested_fact"):
                item["suggested_fact"] = frag["suggested_fact"]
                item["suggestion_confidence"] = float(frag.get("suggestion_confidence", 0.0) or 0.0)
                item["suggested_by"] = frag.get("suggested_by", "")

    for item in items.values():
        item["affected_count"] = len(item["nodes"])
    return sorted(items.values(), key=lambda i: (-i["affected_count"], i["raw_text"]))


def unresolved_items(items: list[dict[str, Any]],
                     ledger: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [it for it in items if it["key"] not in ledger]
