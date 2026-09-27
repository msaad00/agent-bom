"""Bounded, summary-first responses for the MCP ``scan`` tool.

A full AI-BOM for a small project is megabytes of JSON, far over the MCP
response budget. The scan tool therefore answers with a summary (counts, top
findings, affected paths) and a ``result_id``; the full, redacted report stays
in a small per-process store so callers can page any section with follow-up
calls instead of receiving a sliced document.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
from collections import Counter, OrderedDict
from typing import Any, Callable

from agent_bom.graph.severity import normalize_severity
from agent_bom.mcp_server_runtime import ToolErrorPayload

SCAN_DETAIL_LEVELS = ("summary", "full")
DEFAULT_TOP_N = 10
DEFAULT_PAGE_LIMIT = 25
MAX_PAGE_LIMIT = 200

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_TRUTHY = {"1", "true", "yes", "on"}

_PASSTHROUGH_KEYS = (
    "schema_version",
    "document_type",
    "ai_bom_version",
    "scan_id",
    "generated_at",
    "scan_sources",
    "posture_grade",
    "gate_status",
    "gate_severity",
    "warn_gate_status",
    "warn_gate_severity",
    "warn_gate_count",
    "policy_results",
    "warnings",
    "coverage_warnings",
)

_FINDING_FIELDS = (
    "id",
    "title",
    "severity",
    "finding_category",
    "finding_type",
    "cve_id",
    "risk_score",
    "cvss_score",
    "epss_score",
    "is_kev",
    "fixed_version",
    "remediation_guidance",
    "reachability",
)

_PATH_FIELDS = ("id", "rank", "label", "summary", "severity", "riskScore", "fix")

_LIST_SAMPLE = 5


class IncompleteScanPayload(ToolErrorPayload):
    """A JSON scan payload that reports a scan which could not complete.

    It is still a plain JSON string for direct callers; the MCP tool layer maps
    it to a ``CallToolResult`` with ``isError=True``.
    """


def resolve_offline(offline: bool | None) -> bool:
    """Resolve the scan tool's ``offline`` argument.

    An explicit value wins. Omitted, the operator's offline configuration
    decides — ``AGENT_BOM_OFFLINE`` (the CLI ``--offline`` env var),
    ``AGENT_BOM_VULN_DB_OFFLINE`` (airgap toggle), or process-wide offline mode.
    Otherwise vulnerability sources are queried online.
    """
    if offline is not None:
        return bool(offline)
    if os.environ.get("AGENT_BOM_OFFLINE", "").strip().lower() in _TRUTHY:
        return True
    from agent_bom import http_client
    from agent_bom.vuln_freshness import offline_env

    return offline_env() or bool(http_client._OFFLINE)


class ScanResultStore:
    """Bounded, TTL-limited, caller-bound store of full scan results.

    Result ids are unguessable, and a lookup also requires the same caller
    identity that produced the result. Results are held as compact JSON text
    (a fraction of the live object graph's memory). The store is per process:
    a follow-up that lands on a different worker gets a clean "not found" and
    must re-scan.
    """

    def __init__(self, *, max_entries: int, ttl_seconds: float, clock: Callable[[], float] = time.monotonic) -> None:
        self._max_entries = max(1, int(max_entries))
        self._ttl = float(ttl_seconds)
        self._clock = clock
        self._entries: OrderedDict[str, tuple[str, float, str]] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def ttl_seconds(self) -> float:
        return self._ttl

    def _evict_expired(self, now: float) -> None:
        expired = [rid for rid, (_owner, created, _result) in self._entries.items() if now - created > self._ttl]
        for rid in expired:
            del self._entries[rid]

    def put(self, owner: str, result: dict[str, Any]) -> str:
        result_id = secrets.token_urlsafe(18)
        serialized = json.dumps(result, separators=(",", ":"), default=str)
        now = self._clock()
        with self._lock:
            self._evict_expired(now)
            self._entries[result_id] = (owner, now, serialized)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)
        return result_id

    def get(self, owner: str, result_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._evict_expired(self._clock())
            entry = self._entries.get(result_id)
            if entry is None or not secrets.compare_digest(entry[0].encode(), owner.encode()):
                return None
            serialized = entry[2]
        loaded = json.loads(serialized)
        return loaded if isinstance(loaded, dict) else None


def _default_store() -> ScanResultStore:
    from agent_bom.config import MCP_SCAN_RESULT_CACHE_SIZE, MCP_SCAN_RESULT_TTL_SECONDS

    return ScanResultStore(max_entries=MCP_SCAN_RESULT_CACHE_SIZE, ttl_seconds=MCP_SCAN_RESULT_TTL_SECONDS)


SCAN_RESULTS = _default_store()


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _exposure_paths(result: dict[str, Any]) -> list[Any]:
    value = result.get("exposure_paths")
    if isinstance(value, dict):
        return _as_list(value.get("paths"))
    return _as_list(value)


def _sample(value: Any) -> Any:
    if isinstance(value, list) and len(value) > _LIST_SAMPLE:
        return value[:_LIST_SAMPLE]
    return value


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _compact_finding(finding: dict[str, Any]) -> dict[str, Any]:
    row = {key: finding.get(key) for key in _FINDING_FIELDS if key in finding}
    asset = finding.get("asset")
    if isinstance(asset, dict) and (asset.get("identifier") or asset.get("name")):
        version = asset.get("version")
        name = asset.get("name")
        row["asset"] = asset.get("identifier") or (f"{name}@{version}" if version else str(name))
    for key in ("affected_agents", "affected_servers"):
        if key in finding:
            row[key] = _sample(finding.get(key))
    return row


def _compact_path(path: dict[str, Any]) -> dict[str, Any]:
    row = {key: path.get(key) for key in _PATH_FIELDS if key in path}
    for key in ("affectedAgents", "affectedServers", "exposedCredentials", "reachableTools"):
        if path.get(key):
            row[key] = _sample(path.get(key))
    return row


def _top_findings(findings: list[Any], top_n: int) -> list[dict[str, Any]]:
    active = [f for f in findings if isinstance(f, dict) and not f.get("suppressed")]
    ranked = sorted(
        active,
        key=lambda f: (-_number(f.get("risk_score")), _SEVERITY_RANK.get(normalize_severity(str(f.get("severity") or "")), 9)),
    )
    return [_compact_finding(f) for f in ranked[:top_n]]


def _top_paths(paths: list[Any], top_n: int) -> list[dict[str, Any]]:
    rows = [p for p in paths if isinstance(p, dict)]
    ranked = sorted(rows, key=lambda p: (_number(p.get("rank")) or float("inf"), -_number(p.get("riskScore"))))
    return [_compact_path(p) for p in ranked[:top_n]]


def _counts(result: dict[str, Any], findings: list[Any], paths: list[Any]) -> dict[str, Any]:
    raw_summary = result.get("summary")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    raw_finding_summary = result.get("finding_summary")
    finding_summary: dict[str, Any] = raw_finding_summary if isinstance(raw_finding_summary, dict) else {}
    agents = _as_list(result.get("agents"))
    finding_rows = [f for f in findings if isinstance(f, dict)]

    by_severity = finding_summary.get("by_severity")
    if not isinstance(by_severity, dict):
        tally = Counter(normalize_severity(str(f.get("severity") or "")) or "unknown" for f in finding_rows)
        by_severity = {sev: tally.get(sev, 0) for sev in (*_SEVERITY_RANK, "unknown")}
    by_category = Counter(str(f.get("finding_category") or "uncategorized") for f in finding_rows)

    return {
        "agents": summary.get("total_agents", len(agents)),
        "mcp_servers": summary.get("total_mcp_servers"),
        "packages": summary.get("total_packages", len(_as_list(result.get("packages")))),
        "unique_packages": summary.get("unique_packages"),
        "vulnerabilities": summary.get("total_vulnerabilities"),
        "findings": finding_summary.get("total", len(finding_rows)),
        "findings_by_severity": by_severity,
        "findings_by_type": finding_summary.get("by_type"),
        "findings_by_category": dict(by_category),
        "kev": sum(1 for f in finding_rows if f.get("is_kev")),
        "suppressed": sum(1 for f in finding_rows if f.get("suppressed")),
        "exposure_paths": len(paths),
    }


def _sections(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sections: dict[str, dict[str, Any]] = {}
    for key, value in result.items():
        if key == "exposure_paths" and isinstance(value, dict):
            sections[key] = {"kind": "list", "total": len(_as_list(value.get("paths")))}
        elif isinstance(value, list) and value:
            sections[key] = {"kind": "list", "total": len(value)}
        elif isinstance(value, dict) and value:
            sections[key] = {"kind": "object", "keys": len(value)}
    return sections


def _compact_agents(result: dict[str, Any], top_n: int) -> list[dict[str, Any]]:
    rows = []
    for agent in _as_list(result.get("agents"))[:top_n]:
        if not isinstance(agent, dict):
            continue
        servers = _as_list(agent.get("mcp_servers"))
        rows.append(
            {
                "name": agent.get("name"),
                "agent_type": agent.get("agent_type") or agent.get("type"),
                "mcp_servers": len(servers),
                "packages": sum(len(_as_list(s.get("packages"))) for s in servers if isinstance(s, dict)),
            }
        )
    return rows


def build_scan_summary(
    result: dict[str, Any],
    *,
    result_id: str,
    ttl_seconds: float,
    offline: bool,
    top_n: int = DEFAULT_TOP_N,
) -> dict[str, Any]:
    """Return a bounded summary view of a full ``to_json`` scan result."""
    findings = _as_list(result.get("findings"))
    paths = _exposure_paths(result)
    out: dict[str, Any] = {"detail": "summary", "result_id": result_id}
    for key in _PASSTHROUGH_KEYS:
        if key in result:
            out[key] = result[key]
    out["vulnerability_lookup"] = "offline" if offline else "online"
    if isinstance(result.get("summary"), dict):
        out["summary"] = result["summary"]
    out["counts"] = _counts(result, findings, paths)
    posture = result.get("posture_scorecard")
    if isinstance(posture, dict):
        out["posture"] = {key: posture.get(key) for key in ("grade", "score", "summary") if key in posture}
    out["top_findings"] = _top_findings(findings, top_n)
    out["affected_paths"] = _top_paths(paths, top_n)
    out["agents"] = _compact_agents(result, top_n)
    out["sections"] = _sections(result)
    out["next"] = {
        "result_id": result_id,
        "how": (
            "Call scan again with result_id and a section name from 'sections' (for example "
            "section='findings', offset=0, limit=25) to page full-fidelity records, or pass "
            "detail='full' on a new scan for the whole document (bounded to the response budget)."
        ),
        "expires_in_seconds": int(ttl_seconds),
    }
    return out


def section_page(
    result: dict[str, Any],
    *,
    result_id: str,
    section: str,
    offset: int,
    limit: int,
    max_chars: int,
) -> dict[str, Any]:
    """Return one page of a stored result section, sized to fit ``max_chars``.

    Raises ``KeyError`` for an unknown section.
    """
    if section not in result:
        raise KeyError(section)
    value = result[section]
    if section == "exposure_paths" and isinstance(value, dict):
        value = _as_list(value.get("paths"))
    base: dict[str, Any] = {"result_id": result_id, "section": section}
    if not isinstance(value, list):
        return {**base, "value": value}

    total = len(value)
    start = max(0, offset)
    limit = max(1, min(int(limit), MAX_PAGE_LIMIT))
    envelope = {**base, "total": total, "offset": start, "limit": limit, "items": [], "next_offset": total}
    budget = max_chars - len(json.dumps(envelope, separators=(",", ":"))) - 64
    items: list[Any] = []
    used = 0
    for item in value[start : start + limit]:
        size = len(json.dumps(item, separators=(",", ":"), default=str)) + 1
        if items and used + size > budget:
            break
        items.append(item)
        used += size
    end = start + len(items)
    envelope["items"] = items
    envelope["next_offset"] = end if end < total else None
    return envelope
