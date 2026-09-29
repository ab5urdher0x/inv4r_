"""Assessment sessions — the organizing unit for uploaded nodes.

An assessment session groups every node uploaded while it is open. Uploading
with no open session opens one automatically; ending a session closes it so the
next upload starts a fresh one. Sessions and their node membership are persisted
next to the other runtime artifacts so a restart preserves the grouping.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from inv4r.api.config import artifacts_dir


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _store_path() -> Path:
    return artifacts_dir() / "sessions.json"


def _load() -> dict[str, Any]:
    p = _store_path()
    if not p.exists():
        return {"sessions": [], "nodes": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"sessions": [], "nodes": {}}
    if not isinstance(data, dict):
        return {"sessions": [], "nodes": {}}
    data.setdefault("sessions", [])
    data.setdefault("nodes", {})
    return data


def _save(data: dict[str, Any]) -> None:
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _new_id(data: dict[str, Any]) -> str:
    n = len(data.get("sessions") or []) + 1
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"sess-{stamp}-{n:03d}"


def current_session(data: dict[str, Any] | None = None) -> dict[str, Any] | None:
    data = data if data is not None else _load()
    for s in reversed(data.get("sessions") or []):
        if s.get("status") == "open":
            return s
    return None


def ensure_open_session(framework: str = "") -> dict[str, Any]:
    """Return the open session, creating one if none is open."""
    data = _load()
    s = current_session(data)
    if s is None:
        s = {
            "id": _new_id(data),
            "created_at": _now(),
            "closed_at": None,
            "framework": framework or "cis-network-baseline",
            "status": "open",
        }
        data["sessions"].append(s)
    if framework:
        s["framework"] = framework
    _save(data)
    return s


def register_upload(node_ids: list[str], framework: str = "") -> dict[str, Any]:
    """Assign freshly-uploaded nodes to the open session (opening one if needed)."""
    data = _load()
    s = current_session(data)
    if s is None:
        s = {
            "id": _new_id(data),
            "created_at": _now(),
            "closed_at": None,
            "framework": framework or "cis-network-baseline",
            "status": "open",
        }
        data["sessions"].append(s)
    if framework:
        s["framework"] = framework
    for node_id in node_ids:
        data["nodes"][node_id] = {"session_id": s["id"], "assigned_at": _now()}
    _save(data)
    return s


def end_session() -> dict[str, Any] | None:
    """Close the currently open session. Returns the closed record, or None."""
    data = _load()
    s = current_session(data)
    if s is None:
        return None
    s["status"] = "closed"
    s["closed_at"] = _now()
    _save(data)
    return s


def nodes_of(session_id: str) -> list[str]:
    """Node ids registered to a session (registry entries, not the files)."""
    data = _load()
    return sorted(n for n, entry in (data.get("nodes") or {}).items()
                  if (entry or {}).get("session_id") == session_id)


def assign_node(node_id: str, session_id: str) -> None:
    data = _load()
    if any(s.get("id") == session_id for s in data.get("sessions") or []):
        data["nodes"][node_id] = {"session_id": session_id, "assigned_at": _now()}
        _save(data)


def forget_node(node_id: str) -> None:
    data = _load()
    if node_id in data.get("nodes", {}):
        data["nodes"].pop(node_id, None)
        _save(data)


def list_sessions() -> list[dict[str, Any]]:
    data = _load()
    return list(data.get("sessions") or [])


def get_session(session_id: str) -> dict[str, Any] | None:
    for s in list_sessions():
        if s.get("id") == session_id:
            return s
    return None


def session_id_for(node_id: str) -> str | None:
    data = _load()
    entry = (data.get("nodes") or {}).get(node_id)
    return (entry or {}).get("session_id") if entry else None


def node_ids_for_session(session_id: str) -> list[str]:
    data = _load()
    return sorted(n for n, entry in (data.get("nodes") or {}).items()
                  if (entry or {}).get("session_id") == session_id)
