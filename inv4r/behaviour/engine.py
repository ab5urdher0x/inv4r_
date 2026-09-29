"""Behaviour engine: BehaviourQuery -> Batfish question -> BehaviourResult."""

from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any, Iterable

from inv4r.behaviour.batfish_client import (
    BatfishClient,
    BatfishError,
    BatfishUnavailable,
)
from inv4r.behaviour.models import (
    BehaviourQuery,
    BehaviourResult,
    Evidence,
    NetworkHop,
    NetworkSituationReport,
    FAIL_REASONS,
)

SUPPORTED_SUFFIXES = {".cfg", ".conf", ".txt", ".log", ".set", ".boot", ".rsc", ""}

# An ipSpaceSpec Batfish can consume directly. Anything else (a symbolic name
# such as "management") must NOT be silently widened to 0.0.0.0/0.
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?$")
_ANY_VALUES = {"", "any", "*", "all", "0.0.0.0/0"}


def endpoint_spec(value: str | None) -> tuple[str | None, str | None]:
    """Classify an endpoint: (usable ipSpace, reason it cannot be used).

    ``None``/empty/any means "no constraint". A concrete IPv4 address or CIDR
    is passed through. Any other value is reported as unresolved instead of
    being treated as the whole internet.
    """
    v = (value or "").strip()
    if not v or v.lower() in _ANY_VALUES:
        return None, None
    if _IPV4_RE.match(v):
        parts = v.split("/")[0].split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return v, None
    if ":" in v:
        return v, None
    return None, (f"endpoint {value!r} is not a concrete IP address or prefix, "
                  "so Batfish cannot evaluate it; specify the actual subnet")

_FORWARDED = ("ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK", "NEIGHBOR_UNREACHABLE",
              "INSUFFICIENT_INFO")
_BLOCKED = {
    "DENIED_IN": "acl_denial",
    "DENIED_OUT": "acl_denial",
    "DENIED": "acl_denial",
    "NO_ROUTE": "no_route",
    "NULL_ROUTED": "no_route",
    "NO_INTERFACE": "missing_path",
    "INSUFFICIENT_INFO": "incorrect_forwarding",
}


def _table(answer: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Normalize a Batfish answer into (rows, summary)."""
    for element in answer.get("answerElements") or []:
        rows = element.get("rows")
        if rows is not None:
            return list(rows), dict(element.get("summary") or {})
    result = (answer.get("answer") or {}).get("result")
    if isinstance(result, dict) and "rows" in result:
        return list(result.get("rows") or []), dict(answer.get("summary") or {})
    if isinstance(result, list):
        return result, dict(answer.get("summary") or {})
    return [], dict(answer.get("summary") or {})


def _traces_of(row: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("Traces", "Forward_Traces", "Reverse_Traces"):
        value = row.get(key)
        if isinstance(value, list):
            return value
    return []


def _dispositions(rows: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for row in rows:
        for trace in _traces_of(row):
            d = str(trace.get("disposition") or "").upper()
            if d:
                out.append(d)
    return out


def _status_from_dispositions(dispositions: list[str]) -> tuple[str, str | None]:
    """Map Batfish traceroute dispositions to PASS/FAIL + fail reason."""
    if not dispositions:
        return "UNKNOWN", None
    for d in dispositions:
        if d in _BLOCKED:
            return "FAIL", _BLOCKED[d]
    if any(any(f in d for f in _FORWARDED) for d in dispositions):
        return "PASS", None
    return "FAIL", "incorrect_forwarding"


def _extract_hops(rows: list[dict[str, Any]], limit: int = 20) -> list[NetworkHop]:
    hops: list[NetworkHop] = []
    seen: set[str] = set()
    for row in rows:
        for trace in _traces_of(row):
            for hop in trace.get("hops") or []:
                node = hop.get("node")
                name = node.get("name") if isinstance(node, dict) else (node or "")
                if not name or name in seen:
                    continue
                seen.add(name)
                hops.append(NetworkHop(node=str(name)))
                if len(hops) >= limit:
                    return hops
    return hops


class BehaviourEngine:
    """Turns structured BehaviourQueries into Batfish questions and results."""

    def __init__(self, client: BatfishClient | None = None,
                 configs_dir: str | Path | None = None) -> None:
        self.client = client or BatfishClient()
        from inv4r.api.config import configs_dir as _cfg_dir
        self.configs_dir = Path(configs_dir) if configs_dir else _cfg_dir()
        self._snapshot: str | None = None
        self._snapshot_key: tuple | None = None
        self._last_files: dict[str, str] = {}


    def available(self) -> bool:
        # Short probe so a down Batfish never blocks the status/health view.
        try:
            return self.client.available(timeout=3.0)
        except Exception:
            return False

    def _config_fingerprint(self, node_names: set[str] | None = None) -> tuple:
        entries = []
        if self.configs_dir.exists():
            for p in sorted(self.configs_dir.rglob("*")):
                if not p.is_file() or p.name.startswith("."):
                    continue
                if not (p.suffix.lower() in SUPPORTED_SUFFIXES or not p.suffix):
                    continue
                if node_names is not None and p.name not in node_names:
                    continue
                try:
                    st = p.stat()
                except OSError:
                    continue
                entries.append((p.name, st.st_size, int(st.st_mtime)))
        return (node_names is not None and frozenset(node_names) or None, *entries)

    def _snapshot_from_configs(self, node_names: set[str] | None = None
                               ) -> tuple[str, list[str], dict[str, str]]:
        """Upload + parse the scope's configs once, then reuse the snapshot.

        ``node_names`` limits the snapshot to the nodes in the selected scope;
        without it every ingested config is included (the "all nodes" scope).
        """
        files: dict[str, str] = {}
        if self.configs_dir.exists():
            for p in sorted(self.configs_dir.rglob("*")):
                if not p.is_file() or p.name.startswith("."):
                    continue
                if not (p.suffix.lower() in SUPPORTED_SUFFIXES or not p.suffix):
                    continue
                if node_names is not None and p.name not in node_names:
                    continue
                try:
                    files[p.name] = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
        if not files:
            raise BatfishError("no ingested configs available to analyze "
                              "in the selected scope")

        # Keep the raw scope text so returned policy lines can be mapped back to
        # the config line that produced them.
        self._last_files = files
        key = self._config_fingerprint(node_names)
        if self._snapshot and key == self._snapshot_key:
            return self._snapshot, sorted(files), files

        snap = self.client.upload_snapshot(files, initialize=True)
        # Drop the previous snapshot so Batfish does not accumulate one testrig
        # per upload (which eventually breaks its snapshot store).
        if self._snapshot and self._snapshot != snap:
            try:
                self.client.delete_snapshot(self._snapshot)
            except Exception:
                pass
        self._snapshot, self._snapshot_key = snap, key
        return snap, sorted(files), files

    def _unknown_result(self, q: BehaviourQuery, why: str) -> BehaviourResult:
        return BehaviourResult(
            type=q.type, status="UNKNOWN",
            summary=f"Behaviour check could not be performed: {why}",
            source=q.source, destination=q.destination, protocol=q.protocol,
            destination_port=q.destination_port, prefix=q.prefix,
            explanation=("Batfish could not establish this. Per policy, INV4R "
                         "does not guess — the result is UNKNOWN."),
            evidence=[Evidence(kind="note", summary=why)],
            query=q.to_json(),
        )

    @staticmethod
    def _ip_or_none(value: str | None) -> str | None:
        """Headers take an ipSpaceSpec string; node names are not IPs."""
        v = (value or "").strip()
        if not v:
            return None
        parts = v.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            return v
        if "/" in v:
            return v
        return None

    def _headers(self, q: BehaviourQuery) -> tuple[dict[str, str] | None, str | None]:
        """Header constraints, or (None, reason) when an endpoint is unusable."""
        src, src_err = endpoint_spec(q.source)
        if src_err:
            return None, f"source: {src_err}"
        dst, dst_err = endpoint_spec(q.destination)
        if dst_err:
            return None, f"destination: {dst_err}"
        headers: dict[str, str] = {
            "srcIps": src or "0.0.0.0/0",
            "dstIps": dst or "0.0.0.0/0",
        }
        if q.protocol:
            headers["ipProtocols"] = q.protocol.lower()
        if q.destination_port:
            headers["dstPorts"] = str(q.destination_port)
        return headers, None


    def _cited_rules(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Which policy line decided the flow, mapped back to the config line."""
        out: list[dict[str, Any]] = []
        for row in rows:
            node = row.get("Node")
            node_name = node.get("name") if isinstance(node, dict) else node
            content = (row.get("Line_Content") or row.get("lineContent")
                       or row.get("line_content") or "")
            filt = row.get("Filter_Name") or row.get("filterName") or ""
            action = row.get("Action") or row.get("action") or ""
            item: dict[str, Any] = {
                "node": str(node_name or ""),
                "filter": str(filt),
                "action": str(action),
                "line_content": str(content),
                "config_file": "",
                "config_line": None,
            }
            loc = _locate_config_line(self._last_files, str(node_name or ""),
                                      str(content))
            if loc:
                item["config_file"], item["config_line"] = loc
            if item["line_content"] or item["filter"]:
                out.append(item)
            if len(out) >= 20:
                break
        return out

    def _acl_scope(self, q: BehaviourQuery, node_names: set[str] | None) -> str:
        """Device-level verification pins the question to one node."""
        if q.node:
            return Path(q.node).stem or q.node
        if node_names:
            return ".*"
        return ".*"

    def analyze(self, q: BehaviourQuery, node_names: set[str] | None = None) -> BehaviourResult:
        if not self.available():
            return self._unknown_result(
                q, "Batfish service is not reachable (start it with "
                   "`docker compose up -d batfish`)")

        try:
            snap, _files_used, _content = self._snapshot_from_configs(node_names)
        except (BatfishError, BatfishUnavailable) as exc:
            return self._unknown_result(q, str(exc))

        try:
            if q.type == "reachability":
                return self._reachability(q, snap)
            if q.type == "path_trace":
                return self._path_trace(q, snap)
            if q.type == "route_check":
                return self._route_check(q, snap)
            if q.type == "acl_check":
                return self._acl_check(q, snap, node_names)
            if q.type == "segmentation":
                return self._segmentation(q, snap)
            if q.type == "network_health":
                return self._network_health(q, snap)
            return self._unknown_result(q, f"unsupported query type {q.type!r}")
        except BatfishUnavailable as exc:
            return self._unknown_result(q, str(exc))
        except BatfishError as exc:
            return self._unknown_result(q, str(exc))


    def _reachability(self, q: BehaviourQuery, snap: str) -> BehaviourResult:
        headers, err = self._headers(q)
        if headers is None:
            return self._unknown_result(q, err or "unresolvable endpoint")
        question = self.client.question_from_template(
            "bidirectionalreachability",
            {"headers": headers, "returnFlowType": "SUCCESS"})
        raw = self.client.answer(snap, "inv4r-reachability", question)
        rows, summary = _table(raw)
        hops = _extract_hops(rows)
        devices = sorted({h.node for h in hops})

        if rows:
            status, reason = "PASS", None
            summary_text = (f"{q.source or 'any source'} can reach "
                            f"{q.destination or 'all destinations'}"
                            + (f" via {q.protocol}/{q.destination_port}"
                               if q.protocol or q.destination_port else ""))
            explanation = ("Batfish found at least one successfully delivered "
                           "bidirectional flow; the traces are in the evidence.")
        else:
            trace_q = self.client.question_from_template(
                "traceroute", {"headers": {**headers, "srcIps": headers["srcIps"]},
                               "maxTraces": 10})
            trace_raw = self.client.answer(snap, "inv4r-reachability-probe", trace_q)
            trace_rows, _ = _table(trace_raw)
            status, reason = _status_from_dispositions(_dispositions(trace_rows))
            hops = _extract_hops(trace_rows)
            devices = sorted({h.node for h in hops})
            if status in ("FAIL", "UNKNOWN"):
                label = FAIL_REASONS.get(reason or "", "no successful path")
                summary_text = (f"{q.source or 'any source'} cannot reach "
                                f"{q.destination or 'destination'}: {label}")
                explanation = ("Batfish dispositions show the flow does not "
                               "complete in both directions; inspect traces.")
                raw = trace_raw
            else:
                summary_text = (f"{q.source or 'any source'} reaches "
                                f"{q.destination or 'destination'} in one "
                                "direction only (no return flow)")
                explanation = ("Forward traces succeed but no bidirectional flow "
                               "was delivered — the return path is missing.")
                reason = "missing_path"
        return BehaviourResult(
            type="reachability", status=status, summary=summary_text,
            source=q.source, destination=q.destination, protocol=q.protocol,
            destination_port=q.destination_port, fail_reason=reason,
            path=hops, relevant_devices=devices, explanation=explanation,
            evidence=[
                Evidence(kind="question", summary="batfish bidirectionalReachability",
                         detail={"question": question, "headers": headers}),
                Evidence(kind="flows", summary=f"{len(rows)} delivered flow(s)",
                         detail={"rows": rows[:20], "summary": summary}),
            ],
            batfish_result=raw, query=q.to_json(),
        )

    def _path_trace(self, q: BehaviourQuery, snap: str) -> BehaviourResult:
        headers, err = self._headers(q)
        if headers is None:
            return self._unknown_result(q, err or "unresolvable endpoint")
        question = self.client.question_from_template(
            "traceroute", {"headers": headers, "maxTraces": 10})
        raw = self.client.answer(snap, "inv4r-pathtrace", question)
        rows, summary = _table(raw)
        dispositions = _dispositions(rows)
        status, reason = _status_from_dispositions(dispositions)
        hops = _extract_hops(rows)
        devices = sorted({h.node for h in hops})
        if rows:
            summary_text = (f"Traced {len(rows)} flow(s) toward "
                            f"{q.destination or 'destination'}: "
                            + ", ".join(sorted(set(dispositions))[:4]))
            expl = "Batfish traced the forwarding path; hops are listed in order."
        else:
            summary_text = "No trace evidence returned for the requested flow"
            expl = "Batfish returned no traces for this query."
        return BehaviourResult(
            type="path_trace", status=status, summary=summary_text,
            source=q.source, destination=q.destination, protocol=q.protocol,
            destination_port=q.destination_port, fail_reason=reason,
            path=hops, relevant_devices=devices, explanation=expl,
            evidence=[
                Evidence(kind="question", summary="batfish traceroute",
                         detail={"question": question, "headers": headers}),
                Evidence(kind="flows", summary=f"{len(rows)} flow(s) traced",
                         detail={"rows": rows[:10], "summary": summary,
                                 "dispositions": dispositions[:20]}),
            ],
            batfish_result=raw, query=q.to_json(),
        )

    def _route_check(self, q: BehaviourQuery, snap: str) -> BehaviourResult:
        prefix = q.prefix or (self._ip_or_none(q.destination) if "/" in (q.destination or "")
                              else None)
        question = self.client.question_from_template(
            "routes", {"nodes": ".*", "network": prefix,
                       "prefixMatchType": "LONGEST_PREFIX_MATCH",
                       "vrfs": ".*", "rib": "main", "status": None})
        raw = self.client.answer(snap, "inv4r-routes", question)
        rows, summary = _table(raw)
        nodes = sorted({str((r.get("Node") or {}).get("name") if isinstance(r.get("Node"), dict)
                            else r.get("Node")) for r in rows if r.get("Node")})
        if prefix:
            status = "PASS" if rows else "FAIL"
            reason = None if rows else "no_route"
            summary_text = (f"{len(rows)} route(s) matching {prefix}"
                            if rows else f"no route to {prefix} on any node")
        else:
            status = "PASS" if rows else "UNKNOWN"
            reason = None
            summary_text = f"{len(rows)} route(s) across {len(nodes)} node(s)"
        return BehaviourResult(
            type="route_check", status=status, summary=summary_text,
            prefix=prefix, fail_reason=reason, relevant_devices=nodes,
            explanation=("Routes reported by Batfish's RoutesQuestion; the full "
                         "table (protocol, next hop, metric) is in the evidence."
                         if rows else "Batfish returned no routes."),
            evidence=[
                Evidence(kind="question", summary="batfish Routes",
                         detail={"question": question, "prefix": prefix}),
                Evidence(kind="routes", summary=f"{len(rows)} route(s)",
                         detail={"rows": rows[:50], "summary": summary}),
            ],
            batfish_result=raw, query=q.to_json(),
        )

    def _acl_check(self, q: BehaviourQuery, snap: str,
                   node_names: set[str] | None = None) -> BehaviourResult:
        headers, err = self._headers(q)
        if headers is None:
            return self._unknown_result(q, err or "unresolvable endpoint")
        scope = self._acl_scope(q, node_names)
        question = self.client.question_from_template(
            "testfilters", {"nodes": scope, "filters": ".*", "headers": headers})
        raw = self.client.answer(snap, "inv4r-acl", question)
        rows, summary = _table(raw)
        actions = [str(r.get("Action", "")).lower() for r in rows]
        permits = [a for a in actions if "permit" in a or "accept" in a]
        denies = [a for a in actions if "deny" in a or "drop" in a or "reject" in a]
        nodes = sorted({str((r.get("Node") or {}).get("name") if isinstance(r.get("Node"), dict)
                            else r.get("Node")) for r in rows if r.get("Node")})
        cited = self._cited_rules(rows)
        if not rows:
            status, reason = "UNKNOWN", None
            summary_text = "No matching ACL/filter processed this flow"
            expl = ("Batfish found no filter that applies to this flow on any "
                    "node, so nothing can be asserted.")
        elif denies and not permits:
            status, reason = "FAIL", "acl_denial"
            summary_text = f"{len(denies)} filter line(s) deny this flow"
            expl = "Batfish shows the flow denied by the matching ACL line(s)."
        else:
            status, reason = "PASS", None
            summary_text = (f"{len(permits)} filter line(s) permit this flow"
                            + (f", {len(denies)} deny" if denies else ""))
            expl = ("Batfish evaluated the matching filters; the deciding line "
                    "is in the evidence.")
        if cited:
            first = cited[0]
            where = (f" (config line {first['config_line']} of {first['config_file']})"
                     if first.get("config_line") else "")
            expl += (f" Deciding line: {first['action']} {first['line_content']}"
                     f" in filter {first['filter']}{where}.")
        return BehaviourResult(
            type="acl_check", status=status, summary=summary_text,
            source=q.source, destination=q.destination, protocol=q.protocol,
            destination_port=q.destination_port, fail_reason=reason,
            relevant_devices=nodes, explanation=expl,
            evidence=[
                Evidence(kind="question", summary="batfish TestFilters",
                         detail={"question": question, "headers": headers,
                                 "scope": scope}),
                Evidence(kind="cited_rule", summary=(cited[0]["line_content"][:120]
                                                     if cited else "no deciding line"),
                         detail={"cited_rules": cited}),
                Evidence(kind="acls", summary=f"{len(rows)} filter evaluation(s)",
                         detail={"rows": rows[:30], "summary": summary}),
            ],
            batfish_result=raw, query=q.to_json(),
        )

    def _segmentation(self, q: BehaviourQuery, snap: str) -> BehaviourResult:
        if not (q.source and q.destination):
            return self._unknown_result(q, "segmentation needs source and destination")
        r = self._reachability(q, snap)
        r.type = "segmentation"
        if r.status == "PASS":
            r.summary = (f"{q.source} is NOT segmented from {q.destination} "
                         "(traffic can flow)")
            r.explanation = ("Reachability succeeded, so segmentation between the "
                             "two endpoints does not hold.")
        elif r.status == "FAIL":
            r.summary = f"{q.source} IS segmented from {q.destination}"
            r.explanation = ("Traffic cannot flow, which is the intended "
                             "segmentation outcome.")
        return r

    def _network_health(self, q: BehaviourQuery, snap: str) -> BehaviourResult:
        r = self._reachability(q, snap)
        r.type = "network_health"
        return r


    def network_situation(self, node_names: set[str] | None = None
                          ) -> NetworkSituationReport:
        """Deterministic suite of real Batfish questions over the selected scope.

        No destinations are hardcoded: the ACL check runs unfiltered across the
        scope, and a symbolic endpoint ("management") would be reported as
        UNKNOWN rather than silently widened to the whole internet.
        """
        report = NetworkSituationReport(snapshot="")
        report.batfish_available = self.available()
        if not report.batfish_available:
            note = BehaviourResult(
                type="network_health", status="UNKNOWN",
                summary="Batfish service is not reachable",
                explanation=("Start Batfish (docker compose up -d batfish) and "
                             "upload configs to enable behaviour verification."),
                evidence=[Evidence(kind="note",
                                   summary="batfish unavailable — no behaviour claims made")],
            )
            report.checks.append(note)
            return report

        try:
            snap, files_used, _ = self._snapshot_from_configs(node_names)
        except (BatfishError, BatfishUnavailable) as exc:
            report.checks.append(BehaviourResult(
                type="network_health", status="UNKNOWN",
                summary=f"snapshot build failed: {exc}",
                evidence=[Evidence(kind="note", summary=str(exc))]))
            return report
        report.snapshot = snap

        scope_note = ("all ingested devices" if node_names is None
                      else f"{len(files_used)} device(s) in scope")
        checks: list[tuple[str, BehaviourQuery]] = [
            (f"routing: route table populated ({len(files_used)} devices)",
             BehaviourQuery(type="route_check")),
            (f"reachability: bidirectional flows across {scope_note}",
             BehaviourQuery(type="reachability", source=None, destination=None,
                            protocol="tcp")),
            ("ACL: applicable filter evaluation across the scope "
             "(no destination filter)",
             BehaviourQuery(type="acl_check", protocol="tcp")),
        ]
        for _label, q in checks:
            report.checks.append(self.analyze(q, node_names))
        return report


def _locate_config_line(files: dict[str, str], node: str,
                        line_content: str) -> tuple[str, int] | None:
    """Map a Batfish policy line back to its source config line, if possible."""
    text = ""
    if node:
        for name, content in files.items():
            if Path(name).stem == node or name == node:
                text = content
                break
    if not text:
        return None
    if not line_content:
        return None
    needle = " ".join(line_content.split()).lower().rstrip(";")
    if not needle:
        return None
    for i, raw in enumerate(text.splitlines(), start=1):
        if " ".join(raw.split()).lower().rstrip(";") == needle:
            return node, i
    # Fall back to a token match: Batfish normalises ACL text, so the exact
    # line usually differs. Report the first line containing the same tokens.
    tokens = [t for t in needle.split() if len(t) > 2][:4]
    if tokens:
        for i, raw in enumerate(text.splitlines(), start=1):
            low = raw.lower()
            if all(t in low for t in tokens):
                return node, i
    return None
