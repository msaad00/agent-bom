"""Canonical exposure references for API and MCP graph consumers.

Transport envelopes retain their own provenance. Finding occurrences, unknown
risk, hop-selected relationships and evidence dimensions share one projection.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.container import AttackPath
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_lookup import _build_edge_lookup, _EdgeLookup, _rel_value
from agent_bom.graph.integration_contract import EVIDENCE_VERSION, node_evidence_provenance
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_derivation import _node_type_value
from agent_bom.graph.types import EntityType


def _finding_ids_for_nodes(nodes: dict[str, Any], path_hops: list[str], vuln_ids: list[str]) -> list[str]:
    """Resolve stable finding identifiers for a path.

    Preference order per hop: ``attributes.finding_id`` (canonical Finding.id) →
    vulnerability label / CVE string → raw ``vuln_ids`` entries. CVE labels remain
    for backward compatibility when a node was not stamped with a finding id.
    """
    from agent_bom.graph.asset_entity import finding_ids_for_asset_path

    ids: list[str] = []
    seen: set[str] = set()

    def _add(value: str | None) -> None:
        cleaned = (value or "").strip()
        if cleaned and cleaned not in seen:
            ids.append(cleaned)
            seen.add(cleaned)

    for hop in path_hops:
        node = nodes.get(hop)
        if not node or node.entity_type not in {EntityType.VULNERABILITY, EntityType.MISCONFIGURATION}:
            continue
        attrs = getattr(node, "attributes", None) or {}
        stamped = finding_ids_for_asset_path(attrs if isinstance(attrs, dict) else None, path_hops)
        if stamped:
            for value in stamped:
                _add(value)
        else:
            _add(node.label or node.id)
    for value in vuln_ids:
        _add(value if isinstance(value, str) else str(value))
    return ids


def _exposure_role_for_node(node: UnifiedNode) -> str:
    entity_type = _node_type_value(node)
    if entity_type in {EntityType.VULNERABILITY.value, EntityType.MISCONFIGURATION.value}:
        return "finding"
    if entity_type == EntityType.PACKAGE.value:
        return "package"
    if entity_type in {EntityType.SERVER.value, EntityType.CONTAINER.value, EntityType.CLOUD_RESOURCE.value}:
        return "server"
    if entity_type in {EntityType.AGENT.value, EntityType.USER.value, EntityType.GROUP.value, EntityType.SERVICE_ACCOUNT.value}:
        return "agent"
    if entity_type == EntityType.CREDENTIAL.value:
        return "credential"
    if entity_type == EntityType.TOOL.value:
        return "tool"
    if entity_type == EntityType.ENVIRONMENT.value:
        return "environment"
    if entity_type == EntityType.CLUSTER.value:
        return "cluster"
    return "unknown"


def _exposure_ref_for_node(node_id: str, nodes_by_id: dict[str, Any]) -> dict[str, Any]:
    node = nodes_by_id.get(node_id)
    if node is None:
        return {"id": node_id, "label": node_id, "role": "unknown", "entityType": "unknown"}
    ref: dict[str, Any] = {
        "id": node.id,
        "label": node.label,
        "rawLabel": node.label,
        "entityType": _node_type_value(node),
        "role": _exposure_role_for_node(node),
        "evidenceProvenance": node_evidence_provenance(node),
    }
    if getattr(node, "severity", ""):
        ref["severity"] = node.severity
    ref["risk_assessment"] = node.risk_assessment
    if float(getattr(node, "risk_score", 0.0) or 0.0) > 0 or node.risk_assessment["status"] == "assessed":
        ref["riskScore"] = node.risk_score
    return ref


def _exposure_relationships_for_path(
    path: AttackPath,
    edges: list[UnifiedEdge] | None,
    *,
    edge_lookup: _EdgeLookup | None = None,
) -> list[dict[str, Any]]:
    by_pair = edge_lookup if edge_lookup is not None else _build_edge_lookup(edges)

    relationships: list[dict[str, Any]] = []
    for index, (source, target) in enumerate(zip(path.hops, path.hops[1:], strict=False)):
        relationship_key = path.edges[index] if index < len(path.edges) else None
        edge: UnifiedEdge | None = by_pair.get((source, target, relationship_key)) if relationship_key else by_pair.get((source, target))
        if edge is None:
            continue
        relationship = _rel_value(edge)
        edge_id = edge.id
        direction = edge.direction
        traversable = edge.traversable
        confidence = edge.confidence
        relationships.append(
            {
                "id": edge_id,
                "source": edge.source,
                "target": edge.target,
                "relationship": relationship,
                "direction": direction,
                "traversable": traversable,
                "confidence": confidence,
            }
        )
    return relationships


def _severity_for_exposure_path(path: AttackPath, nodes_by_id: dict[str, Any]) -> str:
    from agent_bom.graph.path_evidence import finding_severity_for_path

    return finding_severity_for_path(path, nodes_by_id)


def _exposure_path_for_attack_path(
    path: AttackPath,
    *,
    nodes_by_id: dict[str, Any],
    edges: list[UnifiedEdge] | None = None,
    rank: int | None = None,
    scan_id: str = "",
    edge_lookup: _EdgeLookup | None = None,
) -> dict[str, Any]:
    hops = [_exposure_ref_for_node(hop, nodes_by_id) for hop in path.hops]
    empty_ref = {"id": "", "label": "", "role": "unknown"}
    source = _exposure_ref_for_node(path.source, nodes_by_id) if path.source else (hops[0] if hops else empty_ref)
    target = _exposure_ref_for_node(path.target, nodes_by_id) if path.target else (hops[-1] if hops else empty_ref)
    relationships = _exposure_relationships_for_path(path, edges, edge_lookup=edge_lookup)
    packages = [hop for hop in hops if hop["role"] == "package"]
    servers = [hop for hop in hops if hop["role"] == "server"]
    agents = [hop for hop in hops if hop["role"] == "agent"]
    findings = _finding_ids_for_nodes(nodes_by_id, path.hops, path.vuln_ids)
    label_parts = [findings[0] if findings else target["label"], agents[0]["label"] if agents else source["label"]]
    from agent_bom.graph.hop_evidence import exposure_hop_evidence
    from agent_bom.graph.path_evidence import exposure_advisory_evidence, exposure_evidence_dimensions, qualify_exposure_reachability

    finding_node = nodes_by_id.get(path.target)
    exposure: dict[str, Any] = {
        "schemaVersion": EVIDENCE_VERSION,
        "id": f"{path.source}::{path.target}::{'->'.join(path.hops)}",
        "label": " via ".join(part for part in label_parts if part) or path.summary or "Exposure path",
        "summary": path.summary,
        "riskScore": path.composite_risk,
        "severity": _severity_for_exposure_path(path, nodes_by_id),
        "source": source,
        "target": target,
        "hops": hops,
        "relationships": relationships,
        "nodeIds": list(path.hops),
        "edgeIds": [relationship["id"] for relationship in relationships],
        "findings": findings,
        "affectedAgents": [hop["label"] for hop in agents],
        "affectedServers": [hop["label"] for hop in servers],
        "reachableTools": list(path.tool_exposure),
        "exposedCredentials": list(path.credential_exposure),
        "reachability": path.reachability,
        "reachabilityBasis": list(path.reachability_basis),
        "hopEvidence": exposure_hop_evidence(path),
        "evidenceDimensions": exposure_evidence_dimensions(path, finding_node, relationships=relationships),
        "provenance": {"source": "graph_attack_path", "scanId": scan_id} if scan_id else {"source": "graph_attack_path"},
    }
    if rank is not None:
        exposure["rank"] = rank
    if packages or servers:
        package_node = nodes_by_id.get(packages[0]["id"]) if packages else None
        exposure["dependencyContext"] = {
            "packageName": packages[0]["label"] if packages else "",
            "packageVersion": getattr(package_node, "attributes", {}).get("version", "") if package_node is not None else "",
            "ecosystem": getattr(package_node, "attributes", {}).get("ecosystem", "") if package_node is not None else "",
            "serverName": servers[0]["label"] if servers else "",
        }
    advisory = exposure_advisory_evidence(finding_node)
    if advisory is not None:
        exposure["evidence"] = advisory
    return qualify_exposure_reachability(exposure)
