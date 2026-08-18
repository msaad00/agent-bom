"""Analysis tools — blast_radius, context_graph, analytics_query implementations."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from agent_bom.graph.completeness import graph_completeness
from agent_bom.mcp_errors import (
    CODE_INTERNAL_UNEXPECTED,
    CODE_NOT_FOUND_AGENTS,
    CODE_NOT_FOUND_RESOURCE,
    CODE_UNSUPPORTED_QUERY_TYPE,
    CODE_VALIDATION_INVALID_ARGUMENT,
    CODE_VALIDATION_INVALID_VULN_ID,
    mcp_error_json,
)

logger = logging.getLogger(__name__)


async def blast_radius_impl(
    *,
    cve_id: str,
    tenant_id: str = "default",
    scan_id: str | None = None,
    _validate_cve_id,
    _run_scan_pipeline,
    _truncate_response,
    _get_persisted_evidence: Callable[..., dict[str, Any]] | None = None,
) -> str:
    """Implementation of the blast_radius tool."""
    try:
        validated_cve = _validate_cve_id(cve_id)
    except ValueError as exc:
        logger.exception("MCP tool error")
        return mcp_error_json(CODE_VALIDATION_INVALID_VULN_ID, exc, details={"argument": "cve_id"})

    try:
        from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id

        tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
        if _get_persisted_evidence is not None:
            persisted = _get_persisted_evidence(tenant_id=tenant_id, cve_id=validated_cve, scan_id=scan_id)
            if persisted.get("available"):
                findings = persisted.get("findings")
                rows = findings if isinstance(findings, list) else []
                persisted_matches = [row for row in rows if isinstance(row, dict)]
                if not persisted_matches:
                    return mcp_error_json(
                        CODE_NOT_FOUND_RESOURCE,
                        "CVE not found in persisted tenant findings",
                        details={
                            "cve_id": validated_cve,
                            "source": persisted.get("source"),
                            "scope": persisted.get("scope"),
                        },
                    )
                results = [_finding_blast_radius(row, validated_cve) for row in persisted_matches]
                return _truncate_response(
                    json.dumps(
                        {
                            "cve_id": validated_cve,
                            "found": True,
                            "source": persisted.get("source", "persisted_scan_findings"),
                            "scope": persisted.get("scope", {"tenant_id": tenant_id, "scan_id": scan_id}),
                            "count": len(results),
                            "completeness": persisted.get("completeness", {"status": "complete", "reason": ""}),
                            "blast_radii": results,
                        },
                        indent=2,
                        default=str,
                    )
                )

        _agents, blast_radii, _warnings, _srcs = await _run_scan_pipeline()

        local_matches = [br for br in blast_radii if br.vulnerability.id.upper() == validated_cve.upper()]
        if not local_matches:
            return mcp_error_json(
                CODE_NOT_FOUND_RESOURCE,
                "CVE not found in current scan results",
                details={"cve_id": cve_id, "suggestion": "Run a fresh scan via the scan tool first."},
            )

        results = []
        for br in local_matches:
            results.append(
                {
                    "cve_id": br.vulnerability.id,
                    "severity": br.vulnerability.severity.value,
                    "cvss_score": br.vulnerability.cvss_score,
                    "risk_score": br.risk_score,
                    "package": f"{br.package.name}@{br.package.version}",
                    "ecosystem": br.package.ecosystem,
                    "affected_servers": [s.name for s in br.affected_servers],
                    "affected_agents": [a.name for a in br.affected_agents],
                    "exposed_credentials": br.exposed_credentials,
                    "exposed_tools": [t.name for t in br.exposed_tools],
                    "fixed_version": br.vulnerability.fixed_version,
                    "ai_risk_context": br.ai_risk_context,
                }
            )
        return _truncate_response(
            json.dumps(
                {
                    "cve_id": validated_cve,
                    "found": True,
                    "source": "local_scan",
                    "scope": {"tenant_id": None, "scan_id": None},
                    "count": len(results),
                    "completeness": {"status": "complete", "reason": "standalone MCP local scan"},
                    "blast_radii": results,
                },
                indent=2,
                default=str,
            )
        )
    except Exception as exc:
        logger.exception("MCP tool error")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, exc)


def _finding_blast_radius(row: dict[str, Any], fallback_cve: str) -> dict[str, Any]:
    """Project a canonical persisted finding into the legacy blast-radius row."""

    def string_list(value: object) -> list[str]:
        return [str(item) for item in value] if isinstance(value, list | tuple | set) else []

    raw_asset = row.get("asset")
    asset: dict[str, Any] = raw_asset if isinstance(raw_asset, dict) else {}
    package = row.get("package") or row.get("package_name") or asset.get("name") or ""
    exposed_tools = row.get("exposed_tools")
    if not isinstance(exposed_tools, list):
        exposed_tools = row.get("reachable_tools")
    return {
        "finding_id": row.get("id"),
        "cve_id": row.get("cve_id") or row.get("vulnerability_id") or fallback_cve,
        "severity": row.get("effective_severity") or row.get("severity") or "unknown",
        "cvss_score": row.get("cvss_score"),
        "risk_score": row.get("risk_score") or row.get("effective_reach_score") or 0,
        "package": package,
        "ecosystem": row.get("ecosystem"),
        "affected_servers": string_list(row.get("affected_servers")),
        "affected_agents": string_list(row.get("affected_agents")),
        "exposed_credentials": string_list(row.get("exposed_credentials")),
        "exposed_tools": string_list(exposed_tools),
        "fixed_version": row.get("fixed_version"),
        "graph_reachable": row.get("graph_reachable"),
        "graph_min_hop_distance": row.get("graph_min_hop_distance"),
        "owner": row.get("owner"),
        "sla_due_at": row.get("sla_due_at"),
    }


async def context_graph_impl(
    *,
    config_path: str | None = None,
    source_agent: str | None = None,
    max_depth: int = 4,
    _run_scan_pipeline,
    _truncate_response,
) -> str:
    """Implementation of the context_graph tool."""
    try:
        from agent_bom.context_graph import (
            NodeKind,
            build_context_graph,
            collect_lateral_paths,
            compute_interaction_risks,
            to_serializable,
        )
        from agent_bom.models import AIBOMReport
        from agent_bom.output import to_json

        agents, blast_radii, _warnings, scan_sources = await _run_scan_pipeline(config_path)
        if not agents:
            return mcp_error_json(CODE_NOT_FOUND_AGENTS, "No agents discovered in the current scan scope.")

        report = AIBOMReport(agents=agents, blast_radii=blast_radii, scan_sources=scan_sources)
        report_json = to_json(report)
        graph = build_context_graph(
            report_json["agents"],
            report_json.get("blast_radius", []),
        )

        paths: list = []
        paths_truncated = False
        depth = max(1, min(max_depth, 6))
        if source_agent:
            node_id = f"agent:{source_agent}"
            if node_id in graph.nodes:
                paths, paths_truncated = collect_lateral_paths(graph, [node_id], max_depth=depth)
        else:
            source_ids = (nid for nid in sorted(graph.nodes.keys()) if graph.nodes[nid].kind == NodeKind.AGENT)
            paths, paths_truncated = collect_lateral_paths(graph, source_ids, max_depth=depth)

        risks = compute_interaction_risks(graph)
        result = to_serializable(graph, paths, risks)
        result["stats"]["lateral_paths_truncated"] = paths_truncated
        result["completeness"] = graph_completeness(
            returned=len(paths),
            sampled=paths_truncated,
            reason=("multi-source path budget reached; request a source_agent for exhaustive local traversal" if paths_truncated else ""),
        )
        return _truncate_response(json.dumps(result, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, exc)


async def analytics_query_impl(
    *,
    query_type: str,
    days: int = 30,
    hours: int = 24,
    agent: str | None = None,
    limit: int = 20,
    _truncate_response,
) -> str:
    """Implementation of the analytics_query tool."""
    try:
        from agent_bom.api.stores import _get_analytics_store

        store = _get_analytics_store()
        valid_types = {
            "vuln_trends",
            "top_cves",
            "posture_history",
            "event_summary",
            "fleet_riskiest",
            "compliance_heatmap",
        }
        if query_type not in valid_types:
            return mcp_error_json(
                CODE_UNSUPPORTED_QUERY_TYPE,
                f"Invalid query_type. Use one of: {', '.join(sorted(valid_types))}",
                details={"argument": "query_type", "value": query_type, "allowed": sorted(valid_types)},
            )

        # Validate agent name to prevent SQL injection via ClickHouse
        import re as _re

        if agent and not _re.fullmatch(r"[a-zA-Z0-9._\-/ ]{1,200}", agent):
            return mcp_error_json(
                CODE_VALIDATION_INVALID_ARGUMENT,
                "Invalid agent name. Use only alphanumeric, dot, dash, underscore, slash, space (max 200 chars).",
                details={"argument": "agent"},
            )

        if query_type == "vuln_trends":
            data = store.query_vuln_trends(days=days, agent=agent)
        elif query_type == "top_cves":
            data = store.query_top_cves(limit=limit)
        elif query_type == "posture_history":
            data = store.query_posture_history(agent=agent, days=days)
        elif query_type == "fleet_riskiest":
            data = store.query_top_riskiest_agents(limit=limit)
        elif query_type == "compliance_heatmap":
            data = store.query_compliance_heatmap(days=days)
        else:
            data = store.query_event_summary(hours=hours)

        return _truncate_response(json.dumps({"query_type": query_type, "results": data, "count": len(data)}, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, exc)
