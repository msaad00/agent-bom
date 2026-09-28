"""Per-agent projection of estate-shaped blast-radius rows.

A blast-radius row describes one (advisory, package) exposure across the whole
scan: every agent that reaches the package and the union of their credentials
and tools. The same pair also recurs once per inventoried occurrence of the
package and across rescans. An agent's detail view therefore folds rows to one
per (advisory, package) and keeps only reach evidence that belongs to that
agent — another agent's credentials are never attributed to it.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from agent_bom.api.findings_current import current_scan_jobs
from agent_bom.core.severity import normalize_severity, severity_rank

_OWN_CREDENTIAL_FIELDS = ("exposed_credentials", "all_server_credentials", "transitive_credentials")
_MAX_SCORE_FIELDS = ("risk_score", "unsuppressed_risk_score", "transitive_risk_score", "cvss_score", "epss_score")


def _names(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _fold_key(row: dict[str, Any]) -> tuple[str, str]:
    vuln = str(row.get("vulnerability_id") or row.get("canonical_id") or "").upper()
    package = str(row.get("package") or "")
    if not package:
        name = row.get("package_name") or ""
        version = row.get("package_version") or ""
        package = f"{name}@{version}" if version else str(name)
    return vuln, package


def _base_priority(row: dict[str, Any]) -> tuple[int, float, str]:
    """Worst severity, then highest risk, then content — independent of input order."""
    return (
        severity_rank(normalize_severity(row.get("severity"))),
        _number(row.get("risk_score")) or 0.0,
        json.dumps(row, sort_keys=True, default=str),
    )


def row_reaches_agent(row: dict[str, Any], agent_id: str) -> bool:
    return bool(agent_id) and agent_id in _names(row.get("affected_agent_ids"))


def agent_scoped_blast_rows(
    rows: Iterable[dict[str, Any]],
    *,
    agent_id: str,
    credential_names: set[str],
    tool_names: set[str],
    server_names: set[str],
) -> list[dict[str, Any]]:
    """Fold ``rows`` reaching ``agent_id`` into one row per (advisory, package)."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        if isinstance(row, dict) and row_reaches_agent(row, agent_id):
            groups.setdefault(_fold_key(row), []).append(row)

    folded: list[dict[str, Any]] = []
    for key in sorted(groups):
        members = groups[key]
        base: dict[str, Any] = max(members, key=_base_priority)
        merged = dict(base)
        for field in _OWN_CREDENTIAL_FIELDS:
            if field in merged or any(field in member for member in members):
                merged[field] = sorted({name for member in members for name in _names(member.get(field)) if name in credential_names})
        merged["exposed_tools"] = sorted({name for member in members for name in _names(member.get("exposed_tools")) if name in tool_names})
        if server_names:
            merged["affected_servers"] = sorted(
                {name for member in members for name in _names(member.get("affected_servers")) if name in server_names}
            )
        for field in _MAX_SCORE_FIELDS:
            values = [number for member in members if (number := _number(member.get(field))) is not None]
            if values:
                merged[field] = max(values)
        merged["graph_reachable"] = any(member.get("graph_reachable") is True for member in members)
        hops = [number for member in members if (number := _number(member.get("graph_min_hop_distance"))) is not None]
        if hops:
            merged["graph_min_hop_distance"] = int(min(hops))
        if any("graph_reachable_from_agents" in member for member in members):
            merged["graph_reachable_from_agents"] = sorted(
                {name for member in members for name in _names(member.get("graph_reachable_from_agents"))}
            )
        merged["is_kev"] = any(member.get("is_kev") is True for member in members)
        merged["occurrence_count"] = len(members)
        folded.append(merged)
    return folded


def estate_reach_names(servers: list[dict[str, Any]], credentials: list[str]) -> dict[str, set[str]]:
    """Credential, tool and server names a serialized estate agent owns."""
    return {
        "credential_names": set(credentials),
        "tool_names": {
            str(tool.get("name") if isinstance(tool, dict) else tool) for server in servers for tool in server.get("tools") or [] if tool
        },
        "server_names": {str(server.get("name")) for server in servers if server.get("name")},
    }


def current_agent_blast_rows(
    jobs: Iterable[Any],
    *,
    agent_id: str,
    credential_names: set[str],
    tool_names: set[str],
    server_names: set[str],
) -> list[dict[str, Any]]:
    """Fold the agent's rows from the current (newest-per-scope) scan snapshots.

    Superseded rescans of the same scope are excluded by the same selection the
    findings list and executive counts use, so history never inflates the view.
    """
    rows: list[dict[str, Any]] = []
    for job in current_scan_jobs(jobs, since=None, scan_id=None):
        result = getattr(job, "result", None) or {}
        rows.extend(row for row in result.get("blast_radius", []) or [] if isinstance(row, dict))
    return agent_scoped_blast_rows(
        rows,
        agent_id=agent_id,
        credential_names=credential_names,
        tool_names=tool_names,
        server_names=server_names,
    )


__all__ = ["agent_scoped_blast_rows", "current_agent_blast_rows", "estate_reach_names", "row_reaches_agent"]
