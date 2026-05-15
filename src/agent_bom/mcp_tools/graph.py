"""Graph-native MCP tools for headless agent consumers."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from agent_bom.mcp_errors import CODE_INTERNAL_UNEXPECTED, CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json

logger = logging.getLogger(__name__)


def _node_role(node: Any) -> str:
    entity_type = getattr(node, "entity_type", "")
    value = entity_type.value if hasattr(entity_type, "value") else str(entity_type)
    return value or "unknown"


def _node_ref(node_id: str, nodes_by_id: dict[str, Any]) -> dict[str, Any]:
    node = nodes_by_id.get(node_id)
    if node is None:
        return {"id": node_id, "label": node_id, "role": "unknown"}
    return {
        "id": node.id,
        "label": node.label,
        "role": _node_role(node),
        "severity": getattr(node, "severity", ""),
        "riskScore": float(getattr(node, "risk_score", 0.0) or 0.0),
    }


def _relationship_refs(path: Any, edges: list[Any]) -> list[dict[str, Any]]:
    edge_ids = set(getattr(path, "edges", []) or [])
    hop_pairs = set(zip(getattr(path, "hops", [])[:-1], getattr(path, "hops", [])[1:]))
    refs: list[dict[str, Any]] = []
    for edge in edges:
        edge_id = str(getattr(edge, "id", ""))
        source = str(getattr(edge, "source", ""))
        target = str(getattr(edge, "target", ""))
        if edge_id not in edge_ids and (source, target) not in hop_pairs:
            continue
        relationship = getattr(edge, "relationship", "")
        relationship_value = relationship.value if hasattr(relationship, "value") else str(relationship)
        refs.append(
            {
                "id": edge_id,
                "source": source,
                "target": target,
                "relationship": relationship_value,
                "confidence": float(getattr(edge, "confidence", 1.0) or 0.0),
            }
        )
    return refs


def _severity_for_path(path: Any, nodes_by_id: dict[str, Any]) -> str:
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0, "": 0}
    severity = ""
    for hop in getattr(path, "hops", []) or []:
        node = nodes_by_id.get(hop)
        candidate = str(getattr(node, "severity", "") or "").lower() if node is not None else ""
        if severity_order.get(candidate, 0) > severity_order.get(severity, 0):
            severity = candidate
    if severity:
        return severity
    risk = float(getattr(path, "composite_risk", 0.0) or 0.0)
    if risk >= 90 or risk >= 9:
        return "critical"
    if risk >= 70 or risk >= 7:
        return "high"
    if risk >= 40 or risk >= 4:
        return "medium"
    return "none"


def _exposure_path_payload(path: Any, *, nodes_by_id: dict[str, Any], edges: list[Any], rank: int, scan_id: str) -> dict[str, Any]:
    hops = [_node_ref(hop, nodes_by_id) for hop in getattr(path, "hops", []) or []]
    source = _node_ref(str(getattr(path, "source", "") or ""), nodes_by_id) if getattr(path, "source", "") else (hops[0] if hops else {})
    target = _node_ref(str(getattr(path, "target", "") or ""), nodes_by_id) if getattr(path, "target", "") else (hops[-1] if hops else {})
    relationships = _relationship_refs(path, edges)
    return {
        "id": f"{source.get('id', '')}::{target.get('id', '')}::{'->'.join(getattr(path, 'hops', []) or [])}",
        "rank": rank,
        "label": getattr(path, "summary", "") or "Exposure path",
        "summary": getattr(path, "summary", ""),
        "riskScore": float(getattr(path, "composite_risk", 0.0) or 0.0),
        "severity": _severity_for_path(path, nodes_by_id),
        "source": source,
        "target": target,
        "hops": hops,
        "relationships": relationships,
        "nodeIds": list(getattr(path, "hops", []) or []),
        "edgeIds": [relationship["id"] for relationship in relationships if relationship.get("id")],
        "findings": list(getattr(path, "vuln_ids", []) or []),
        "reachableTools": list(getattr(path, "tool_exposure", []) or []),
        "exposedCredentials": list(getattr(path, "credential_exposure", []) or []),
        "provenance": {"source": "mcp_exposure_paths", "scanId": scan_id},
    }


def _candidate_matches_path(candidate: str, path: dict[str, Any]) -> bool:
    needle = candidate.strip().lower()
    if not needle:
        return True
    haystack: list[str] = [
        str(path.get("id", "")),
        str(path.get("label", "")),
        str(path.get("summary", "")),
        *[str(value) for value in path.get("nodeIds", [])],
        *[str(value) for value in path.get("edgeIds", [])],
        *[str(value) for value in path.get("findings", [])],
        *[str(value) for value in path.get("reachableTools", [])],
    ]
    for endpoint in ("source", "target"):
        value = path.get(endpoint)
        if isinstance(value, dict):
            haystack.extend(str(value.get(key, "")) for key in ("id", "label", "role"))
    for hop in path.get("hops", []):
        if isinstance(hop, dict):
            haystack.extend(str(hop.get(key, "")) for key in ("id", "label", "role"))
    return any(needle in value.lower() for value in haystack)


def _decision_for_risk(risk: float, *, warn_risk: float, block_risk: float) -> str:
    if risk >= block_risk:
        return "block"
    if risk >= warn_risk:
        return "warn"
    return "allow"


async def exposure_paths_impl(
    *,
    tenant_id: str = "default",
    scan_id: str | None = None,
    limit: int = 5,
    min_risk: float = 0.0,
    _get_graph_store=None,
    _truncate_response=None,
) -> str:
    """Return ranked ExposurePath JSON for headless agent consumers."""
    if limit < 1 or limit > 100:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "limit must be between 1 and 100",
            details={"argument": "limit", "value": limit},
        )
    if min_risk < 0 or min_risk > 100:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "min_risk must be between 0 and 100",
            details={"argument": "min_risk", "value": min_risk},
        )

    try:
        if _get_graph_store is None:
            from agent_bom.api.stores import _get_graph_store as _default_get_graph_store

            _get_graph_store = _default_get_graph_store

        store = _get_graph_store()
        effective_scan_id, created_at, paths, total = await asyncio.to_thread(
            store.attack_paths,
            tenant_id=tenant_id,
            scan_id=scan_id or "",
            offset=0,
            limit=min(max(limit * 3, limit), 1000),
        )
        ranked_paths = [path for path in paths if float(getattr(path, "composite_risk", 0.0) or 0.0) >= min_risk][:limit]
        hop_ids = {hop for path in ranked_paths for hop in (getattr(path, "hops", []) or [])}
        nodes = await asyncio.to_thread(store.nodes_by_ids, tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=hop_ids)
        edges = await asyncio.to_thread(store.edges_for_node_ids, tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=hop_ids)
        stats = await asyncio.to_thread(store.snapshot_stats, tenant_id=tenant_id, scan_id=effective_scan_id)
        nodes_by_id = {node.id: node for node in nodes}
        payload = {
            "schema_version": "v1",
            "tool": "exposure_paths",
            "tenant_id": tenant_id,
            "scan_id": effective_scan_id,
            "created_at": created_at,
            "count": len(ranked_paths),
            "total": total,
            "filters": {"limit": limit, "min_risk": min_risk},
            "paths": [
                _exposure_path_payload(path, nodes_by_id=nodes_by_id, edges=edges, rank=index + 1, scan_id=effective_scan_id)
                for index, path in enumerate(ranked_paths)
            ],
            "nodes": [node.to_dict() for node in nodes],
            "edges": [edge.to_dict() for edge in edges],
            "stats": stats,
        }
        encoded = json.dumps(payload, indent=2, default=str)
        return _truncate_response(encoded) if _truncate_response is not None else encoded
    except Exception as exc:
        logger.exception("MCP graph tool error")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, exc)


async def deploy_decision_impl(
    *,
    candidate: str,
    tenant_id: str = "default",
    scan_id: str | None = None,
    limit: int = 5,
    warn_risk: float = 40.0,
    block_risk: float = 80.0,
    _get_graph_store=None,
    _truncate_response=None,
) -> str:
    """Return an allow/warn/block deployment decision from ExposurePath risk."""
    candidate_value = candidate.strip()
    if not candidate_value:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "candidate must not be empty",
            details={"argument": "candidate"},
        )
    if limit < 1 or limit > 25:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "limit must be between 1 and 25",
            details={"argument": "limit", "value": limit},
        )
    if warn_risk < 0 or warn_risk > 100 or block_risk < 0 or block_risk > 100 or warn_risk > block_risk:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "warn_risk and block_risk must be ordered thresholds between 0 and 100",
            details={"warn_risk": warn_risk, "block_risk": block_risk},
        )

    response = await exposure_paths_impl(
        tenant_id=tenant_id,
        scan_id=scan_id,
        limit=100,
        min_risk=0.0,
        _get_graph_store=_get_graph_store,
        _truncate_response=lambda value: value,
    )
    payload = json.loads(response)
    if "error" in payload:
        return json.dumps(payload, indent=2)

    matched_paths = [path for path in payload.get("paths", []) if _candidate_matches_path(candidate_value, path)]
    matched_paths = matched_paths[:limit]
    max_risk = max((float(path.get("riskScore", 0.0) or 0.0) for path in matched_paths), default=0.0)
    decision = _decision_for_risk(max_risk, warn_risk=warn_risk, block_risk=block_risk)
    reasons: list[str] = []
    if matched_paths:
        top = matched_paths[0]
        reasons.append(f"Top matched exposure path risk is {top.get('riskScore', 0)} for {top.get('label') or top.get('id')}.")
        findings = sorted({str(finding) for path in matched_paths for finding in path.get("findings", []) if finding})
        if findings:
            reasons.append(f"Matched findings: {', '.join(findings[:5])}.")
    else:
        reasons.append("No matching exposure paths were found for the candidate in the selected graph snapshot.")

    encoded = json.dumps(
        {
            "schema_version": "v1",
            "tool": "should_i_deploy",
            "tenant_id": tenant_id,
            "scan_id": payload.get("scan_id", scan_id or ""),
            "candidate": {"value": candidate_value},
            "decision": decision,
            "maxRisk": max_risk,
            "thresholds": {"warnRisk": warn_risk, "blockRisk": block_risk},
            "reasons": reasons,
            "matchedPathCount": len(matched_paths),
            "matchedPaths": matched_paths,
            "provenance": {"source": "mcp_should_i_deploy", "basis": "exposure_paths"},
        },
        indent=2,
        default=str,
    )
    return _truncate_response(encoded) if _truncate_response is not None else encoded
