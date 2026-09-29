"""Deterministic Batfish client (stdlib only — no pybatfish dependency)."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from typing import Any


class BatfishUnavailable(RuntimeError):
    """Raised when the Batfish service cannot be reached."""


class BatfishError(RuntimeError):
    """Raised when Batfish answered but the result could not be used."""


_SNAPSHOT_SUBDIR = "configs"

_TERMINAL_WORK_STATES = {
    "ASSIGNMENTERROR", "REQUEUEFAILURE", "TERMINATEDABNORMALLY",
    "TERMINATEDBYUSER", "TERMINATEDNORMALLY",
}
_OK_WORK_STATE = "TERMINATEDNORMALLY"


class BatfishClient:
    """Thin REST client for a Batfish allinone container."""

    def __init__(self, host: str | None = None, port: int | None = None,
                 network: str = "inv4r") -> None:
        host = host or os.environ.get("INV4R_BATFISH_HOST", "") or "localhost"
        port = port or int(os.environ.get("INV4R_BATFISH_PORT", "9996") or 9996)
        self.base = f"http://{host}:{port}"
        self.network = network
        self.timeout = float(os.environ.get("INV4R_BATFISH_TIMEOUT", "30") or 30)


    def _http(self, method: str, path: str, data: bytes | None = None,
              headers: dict[str, str] | None = None,
              params: dict[str, Any] | None = None,
              timeout: float | None = None) -> tuple[bytes, dict[str, str]]:
        url = f"{self.base}{path}"
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url = f"{url}?{urllib.parse.urlencode(clean)}"
        req = urllib.request.Request(url, data=data, method=method,
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:
                return resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            body = exc.read()
            raise BatfishError(
                f"batfish HTTP {exc.code} on {method} {path}: {body[:300]!r}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise BatfishUnavailable(f"batfish unreachable at {self.base}: {exc}") from exc

    def _json(self, method: str, path: str, payload: Any = None,
              params: dict[str, Any] | None = None) -> Any:
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"} if data else {}
        body, _ = self._http(method, path, data, headers, params)
        if not body:
            return {}
        try:
            return json.loads(body.decode("utf-8"))
        except Exception as exc:
            raise BatfishError(f"invalid JSON from batfish {path}") from exc


    def available(self, timeout: float | None = None) -> bool:
        """Cheap liveness probe. Pass ``timeout`` to fail fast during ingestion."""
        try:
            body, _ = self._http("GET", "/v2/networks", timeout=timeout)
            return bool(body) or True
        except Exception:
            return False

    def list_networks(self) -> list[str]:
        data = self._json("GET", "/v2/networks")
        if not isinstance(data, list):
            return []
        return [str(n.get("name")) for n in data if isinstance(n, dict) and n.get("name")]

    def ensure_network(self) -> str:
        """Return a usable network name, creating ours if it does not exist."""
        names = self.list_networks()
        if self.network in names:
            return self.network
        try:
            self._json("POST", "/v2/networks", None, {"name": self.network})
        except BatfishError:
            if self.network not in self.list_networks():
                raise
        return self.network


    @staticmethod
    def _package_snapshot(config_files: dict[str, str]) -> bytes:
        """Zip configs the way Batfish requires: one top-level folder that"""
        top = f"snapshot-{uuid.uuid4().hex[:8]}"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{top}/README", "packaged by INV4R\n")
            for name, content in config_files.items():
                safe = name.replace("\\", "/").split("/")[-1].strip() or "unnamed"
                z.writestr(f"{top}/{_SNAPSHOT_SUBDIR}/{safe}", content)
        return buf.getvalue()

    def upload_snapshot(self, config_files: dict[str, str],
                        snapshot: str | None = None,
                        initialize: bool = True) -> str:
        """Zip configs in-memory, push as a snapshot, and parse it."""
        network = self.ensure_network()
        snap = snapshot or f"snap-{uuid.uuid4().hex[:10]}"
        payload = self._package_snapshot(config_files)
        self._http(
            "POST",
            f"/v2/networks/{network}/snapshots/{snap}",
            data=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        if initialize:
            self.initialize_snapshot(snap)
        return snap

    def initialize_snapshot(self, snapshot: str) -> None:
        """Parse + convert a snapshot so dataplane questions can run on it."""
        network = self.ensure_network()
        self._queue_work(
            network,
            {"testrig": snapshot, "si": "", "sv": "", "initinfo": ""},
            snapshot,
            what=f"initialize snapshot {snapshot}",
        )

    def delete_snapshot(self, snapshot: str) -> None:
        try:
            self._http("DELETE",
                       f"/v2/networks/{self.network}/snapshots/{snapshot}")
        except (BatfishError, BatfishUnavailable):
            pass


    def question_from_template(self, template_key: str,
                               variables: dict[str, Any]) -> dict[str, Any]:
        """Build a question from Batfish's own template catalog."""
        templates = self._json("GET", "/v2/question_templates")
        raw = templates.get(template_key)
        if raw is None:
            raise BatfishError(
                f"batfish has no question template {template_key!r} "
                f"(available: {', '.join(sorted(templates))[:200]})")
        template = json.loads(raw) if isinstance(raw, str) else dict(raw)
        template.pop("instance", None)
        placeholder = re.compile(r"^\$\{(\w+)\}$")

        def fill(value: Any) -> Any:
            if isinstance(value, str):
                m = placeholder.match(value)
                if not m:
                    return value
                return variables.get(m.group(1))
            if isinstance(value, dict):
                out: dict[str, Any] = {}
                for k, v in value.items():
                    filled = fill(v)
                    if filled is not None:
                        out[k] = filled
                return out
            if isinstance(value, list):
                filled_list = [fill(v) for v in value]
                return [v for v in filled_list if v is not None] or value
            return value

        return fill(template)

    def answer(self, snapshot: str, question_name: str,
               question: dict[str, Any]) -> dict[str, Any]:
        """Store the question, run it on the work queue, and fetch its answer."""
        network = self.ensure_network()
        digest = hashlib.sha256(
            (json.dumps(question, sort_keys=True) + snapshot).encode("utf-8")
        ).hexdigest()[:10]
        qname = f"{question_name}-{digest}"

        self._http(
            "PUT",
            f"/v2/networks/{network}/questions/{qname}",
            data=json.dumps(question).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        self._queue_work(
            network,
            {"answer": "", "questionname": qname, "testrig": snapshot},
            snapshot,
            what=f"answer {qname}",
        )
        return self._json(
            "GET",
            f"/v2/networks/{network}/questions/{qname}/answer",
            params={"snapshot": snapshot},
        )

    def _queue_work(self, network: str, request_params: dict[str, Any],
                    snapshot: str, what: str) -> None:
        """Queue a work item and poll until Batfish terminates it."""
        work_id = str(uuid.uuid4())
        self._json("POST", f"/v2/networks/{network}/work", {
            "containerName": network,
            "id": work_id,
            "requestParams": request_params,
            "testrigName": snapshot,
        })
        timeout = float(os.environ.get("INV4R_BATFISH_QUESTION_TIMEOUT", "180") or 180)
        deadline = time.time() + timeout
        interval = 0.5
        while True:
            status = self._json("GET", f"/v2/networks/{network}/work/{work_id}")
            code = str(status.get("workstatuscode", ""))
            if code in _TERMINAL_WORK_STATES:
                if code != _OK_WORK_STATE:
                    detail = status.get("task") or status
                    raise BatfishError(f"batfish could not {what} ({code}): {str(detail)[:300]}")
                return
            if time.time() > deadline:
                raise BatfishError(
                    f"batfish did not {what} within {timeout:g}s "
                    f"(last status {code or 'unknown'})")
            time.sleep(interval)
            interval = min(2.0, interval * 1.5)
