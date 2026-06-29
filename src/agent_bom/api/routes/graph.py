"""Graph query API — unified graph data with filters, pagination, RBAC, presets.

Endpoints:
  GET  /v1/graph                — load unified graph (filtered, paginated)
  GET  /v1/graph/diff           — diff between two scan snapshots
  GET  /v1/graph/edges/active   — edge versions active at a timestamp
  GET  /v1/graph/edges/changes  — edge lifecycle changes between scans
  GET  /v1/graph/attack-paths   — global risk-sorted attack path queue
  GET  /v1/graph/exposure-paths — agent-native ExposurePath queue
  POST /v1/graph/should-i-deploy — agent-native deploy decision
  GET  /v1/graph/paths          — attack paths from a source node
  GET  /v1/graph/impact         — blast radius of a node (reverse BFS)
  GET  /v1/graph/rollup         — estate-scale CONTAINS roll-up + drill-down
  GET  /v1/graph/search         — full-text graph search
  GET  /v1/graph/agents         — paginated agent node selector
  GET  /v1/graph/clusters       — semantic cluster rollups
  POST /v1/graph/query          — programmable traversal query
  GET  /v1/graph/node/{id}      — single node detail with edges + impact
  GET  /v1/graph/snapshots      — list persisted scan snapshots
  GET  /v1/graph/history        — retained snapshot history with adjacent diffs
  GET  /v1/graph/evidence-manifest — reviewer manifest for one graph snapshot
  GET  /v1/graph/legend         — entity + relationship legends
  GET  /v1/graph/schema         — canonical entity/edge taxonomy (codegen source)
  POST /v1/graph/presets        — save a filter preset
  GET  /v1/graph/presets        — list saved presets
  DEL  /v1/graph/presets/{name} — delete a preset
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Literal, Optional
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from agent_bom.api.stores import _get_graph_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.graph import SEVERITY_RANK, AttackPath, EntityType, GraphFilterOptions, GraphSemanticLayer, RelationshipType, UnifiedGraph
from agent_bom.graph.semantic_clusters import SEMANTIC_CLUSTER_KINDS, build_semantic_clusters, semantic_cluster_stats
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)
router = APIRouter()
_ALLOWED_ENTITY_TYPES = {entity_type.value for entity_type in EntityType}
_GRAPH_QUERY_ABSOLUTE_LIMITS = {
    "max_depth": 10,
    "max_nodes": 5000,
    "max_edges": 25_000,
    "timeout_ms": 5000,
}
_GRAPH_QUERY_DEFAULT_BUDGET = {
    "max_depth": 5,
    "max_nodes": 1000,
    "max_edges": 10_000,
    "timeout_ms": 2500,
}

_SEMANTIC_LAYER_LABELS = {
    GraphSemanticLayer.USER.value: "User",
    GraphSemanticLayer.IDENTITY.value: "Identity",
    GraphSemanticLayer.APP.value: "Application",
    GraphSemanticLayer.API_GATEWAY.value: "API / Gateway",
    GraphSemanticLayer.ORCHESTRATION.value: "Orchestration",
    GraphSemanticLayer.MCP_SERVER.value: "MCP Server",
    GraphSemanticLayer.TOOL.value: "Tool",
    GraphSemanticLayer.PACKAGE.value: "Package",
    GraphSemanticLayer.RUNTIME_EVIDENCE.value: "Runtime Evidence",
    GraphSemanticLayer.ASSET.value: "Asset",
    GraphSemanticLayer.INFRA.value: "Infrastructure",
    GraphSemanticLayer.FINDING.value: "Finding",
    GraphSemanticLayer.CODE.value: "Code",
    GraphSemanticLayer.CI.value: "CI/CD",
}

_EXPOSURE_PATH_OPENAPI_SCHEMA: dict[str, Any] = {
    "type": "object",
    "description": "Investigation-first exposure path shared by graph views and report exports.",
    "required": ["id", "label", "summary", "riskScore", "severity", "source", "target", "hops", "relationships"],
    "properties": {
        "id": {"type": "string"},
        "rank": {"type": "integer", "minimum": 1},
        "label": {"type": "string"},
        "summary": {"type": "string"},
        "riskScore": {"type": "number"},
        "severity": {"type": "string"},
        "source": {"type": "object", "additionalProperties": True},
        "target": {"type": "object", "additionalProperties": True},
        "hops": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "relationships": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "nodeIds": {"type": "array", "items": {"type": "string"}},
        "edgeIds": {"type": "array", "items": {"type": "string"}},
        "findings": {"type": "array", "items": {"type": "string"}},
        "affectedAgents": {"type": "array", "items": {"type": "string"}},
        "affectedServers": {"type": "array", "items": {"type": "string"}},
        "reachableTools": {"type": "array", "items": {"type": "string"}},
        "exposedCredentials": {"type": "array", "items": {"type": "string"}},
        "dependencyContext": {"type": "object", "additionalProperties": True},
        "evidence": {"type": "object", "additionalProperties": True},
        "provenance": {"type": "object", "additionalProperties": True},
    },
}

_FIX_FIRST_VIEW_OPENAPI_RESPONSE: dict[str, Any] = {
    "description": "Fix-first graph view with ranked cards and embedded ExposurePath payloads.",
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "tenant_id": {"type": "string"},
                    "created_at": {"type": "string"},
                    "cards": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "exposure_path": _EXPOSURE_PATH_OPENAPI_SCHEMA,
                            },
                            "additionalProperties": True,
                        },
                    },
                    "summary": {"type": "object", "additionalProperties": True},
                    "focus": {"type": "object", "additionalProperties": True},
                },
            }
        }
    },
}

_ATTACK_PATHS_OPENAPI_RESPONSE: dict[str, Any] = {
    "description": "Ranked attack-path queue with embedded ExposurePath payloads.",
    "content": {
        "application/json": {
            "schema": {
                "type": "object",
                "properties": {
                    "scan_id": {"type": "string"},
                    "tenant_id": {"type": "string"},
                    "created_at": {"type": "string"},
                    "nodes": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                    "edges": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
                    "attack_paths": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "exposure_path": _EXPOSURE_PATH_OPENAPI_SCHEMA,
                            },
                            "additionalProperties": True,
                        },
                    },
                    "stats": {"type": "object", "additionalProperties": True},
                    "pagination": {"type": "object", "additionalProperties": True},
                },
            }
        }
    },
}


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _get_graph_store_or_503():
    """Resolve the active graph store backend."""
    return _get_graph_store()


def _tenant(request: Request) -> str:
    """Extract tenant_id from request (set by auth middleware)."""
    return require_request_tenant_id(request)


def _paginate(items: list, offset: int, limit: int) -> tuple[list, dict]:
    """Apply offset/limit pagination and return (page, pagination_meta)."""
    total = len(items)
    page = items[offset : offset + limit]
    return page, {
        "total": total,
        "offset": offset,
        "limit": limit,
        "has_more": offset + limit < total,
    }


def _page_meta(total: int, offset: int, limit: int, *, cursor: str | None = None, next_cursor: str | None = None) -> dict:
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "cursor": cursor or "",
        "next_cursor": next_cursor or "",
        "has_more": bool(next_cursor) if cursor else offset + limit < total,
    }


def _parse_entity_type_filter(raw: str | None) -> set[str] | None:
    if not raw:
        return None
    values = {value.strip() for value in raw.split(",") if value.strip()}
    invalid = sorted(values - _ALLOWED_ENTITY_TYPES)
    if invalid:
        raise HTTPException(status_code=422, detail=f"Unsupported graph entity type: {invalid[0]}")
    return values or None


def _parse_relationship_filter(raw: str | None) -> set[RelationshipType]:
    if not raw:
        return set()
    parsed: set[RelationshipType] = set()
    for value in raw.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            parsed.add(RelationshipType(value))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Unsupported graph relationship type: {value}") from exc
    return parsed


def _coalesce_alias(primary: str | None, alias: str | None, *, primary_name: str, alias_name: str) -> str:
    if primary and alias and primary != alias:
        raise HTTPException(status_code=422, detail=f"Conflicting query parameters: {primary_name} and {alias_name}")
    return primary or alias or ""


def _validate_relationship_list(values: list[str]) -> set[RelationshipType] | None:
    if not values:
        return None
    parsed: set[RelationshipType] = set()
    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        try:
            parsed.add(RelationshipType(cleaned))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Unsupported graph relationship type: {cleaned}") from exc
    return parsed or None


def _validate_entity_type_list(values: list[str]) -> list[str]:
    cleaned = [value.strip() for value in values if value.strip()]
    invalid = sorted(set(cleaned) - _ALLOWED_ENTITY_TYPES)
    if invalid:
        raise HTTPException(status_code=422, detail=f"Unsupported graph entity type: {invalid[0]}")
    return cleaned


def _node_labels_for_types(graph: UnifiedGraph, path_hops: list[str], entity_types: set[EntityType]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for hop in path_hops:
        node = graph.nodes.get(hop)
        if not node or node.entity_type not in entity_types:
            continue
        label = node.label or node.id
        key = label.lower()
        if key in seen:
            continue
        labels.append(label)
        seen.add(key)
    return labels


def _finding_ids_for_path(graph: UnifiedGraph, path_hops: list[str], vuln_ids: list[str]) -> list[str]:
    return _finding_ids_for_nodes(graph.nodes, path_hops, vuln_ids)


def _finding_ids_for_nodes(nodes: dict[str, Any], path_hops: list[str], vuln_ids: list[str]) -> list[str]:
    ids: list[str] = []
    seen: set[str] = set()
    for value in vuln_ids:
        cleaned = value.strip()
        if cleaned and cleaned not in seen:
            ids.append(cleaned)
            seen.add(cleaned)
    for hop in path_hops:
        node = nodes.get(hop)
        if not node or node.entity_type not in {EntityType.VULNERABILITY, EntityType.MISCONFIGURATION}:
            continue
        label = node.label or node.id
        if label not in seen:
            ids.append(label)
            seen.add(label)
    return ids


def _first_href_for_agent(agent: str) -> str:
    return f"/agents?name={quote(agent)}"


_RUNTIME_OBSERVED_RELS = frozenset(
    {
        RelationshipType.INVOKED.value,
        RelationshipType.CALLED.value,
        RelationshipType.ACCESSED.value,
        RelationshipType.ACTED_AS.value,
        RelationshipType.USED_CREDENTIAL.value,
        RelationshipType.DELEGATED_TO.value,
    }
)


def _exposed_port_detail(attrs: dict) -> str:
    """Render the internet-open ports on a node as ' on port(s) 22, 3389'."""
    ports = attrs.get("exposed_ports") or []
    if not isinstance(ports, list):
        return ""
    nums = sorted({str(p["from_port"]) for p in ports if isinstance(p, dict) and p.get("from_port") is not None})
    return f" on port(s) {', '.join(nums[:5])}" if nums else ""


def _fusion_signals_for_path(graph: UnifiedGraph, hops: list[str]) -> list[tuple[str, str, str, float]]:
    """Governance / CNAPP / runtime signals that should weight a path's rank.

    Returns ``(kind, label, detail, risk_boost)`` tuples. Inspects each hop node
    and its one-hop governance/exposure neighbours so the managed-identity,
    drift, and internet-exposure edges (added by the governance + CNAPP
    overlays) actually sharpen attack-path ranking rather than sitting inert.
    """
    signals: list[tuple[str, str, str, float]] = []
    seen_kinds: set[str] = set()

    def add(kind: str, label: str, detail: str, boost: float) -> None:
        if kind not in seen_kinds:
            seen_kinds.add(kind)
            signals.append((kind, label, detail, boost))

    for hop_id in hops:
        node = graph.nodes.get(hop_id)
        if node is None:
            continue
        attrs = node.attributes
        port_detail = _exposed_port_detail(attrs)
        if attrs.get("toxic_exposed_vulnerable"):
            add("toxic_exposed_vulnerable", "Toxic: exposed + vulnerable", f"{node.label}: exposed{port_detail} + vulnerable.", 20.0)
        elif attrs.get("internet_exposed"):
            add("internet_exposed", "Internet exposed", f"{node.label} is reachable from the public internet{port_detail}.", 15.0)
        if attrs.get("escalates_to_admin"):
            add("privilege_escalation_admin", "Admin escalation", f"{node.label} can assume an admin-privileged role.", 20.0)
        elif attrs.get("can_escalate_privilege"):
            add("privilege_escalation", "Privilege escalation", f"{node.label} can assume a role with broader effective access.", 16.0)
        if attrs.get("toxic_exposed_sensitive"):
            add("exposed_sensitive_data", "Exposed sensitive data", f"{node.label} holds sensitive data and is internet-exposed.", 22.0)
        elif attrs.get("data_sensitivity"):
            add("sensitive_data", "Sensitive data", f"{node.label} holds sensitive (PII/PHI/secret) data.", 8.0)
        # Runtime-observed reachability: a hop with actual observed runtime
        # activity is confirmed reachable, not just statically connected — so it
        # ranks above an identical static-only chain.
        hop_edges = graph.adjacency.get(hop_id, []) + graph.reverse_adjacency.get(hop_id, [])
        if any(_rel_value(e) in _RUNTIME_OBSERVED_RELS for e in hop_edges):
            add("runtime_observed", "Runtime-observed", f"{node.label} has observed runtime activity (confirmed reachable).", 10.0)
        # One-hop governance/exposure neighbours of this node.
        for edge in graph.adjacency.get(hop_id, []):
            target = graph.nodes.get(edge.target)
            if target is None:
                continue
            rel = _rel_value(edge)
            if rel == RelationshipType.EXHIBITS_DRIFT.value:
                add("behavioral_drift", "Behavioral drift", f"{node.label} has an open drift incident.", 12.0)
            elif rel == RelationshipType.AUTHENTICATES_AS.value and not target.attributes.get("scope_bound", True):
                add("broad_identity_scope", "Unscoped identity", f"{node.label} runs as an identity with no per-tool scope.", 8.0)
            elif rel == RelationshipType.STORES.value and target.attributes.get("internet_exposed"):
                add("exposed_data_store", "Exposed data store", f"{node.label} backs an internet-exposed data store.", 14.0)
    return signals


def _risk_reasons_for_path(graph: UnifiedGraph, path) -> list[dict[str, str]]:
    reasons: list[dict[str, str]] = []
    for kind, label, detail, _boost in _fusion_signals_for_path(graph, path.hops):
        reasons.append({"kind": kind, "label": label, "detail": detail})
    if path.composite_risk >= 90:
        reasons.append(
            {
                "kind": "critical_reach",
                "label": "Critical reach",
                "detail": "Composite risk is at or above the release-blocking threshold.",
            }
        )
    elif path.composite_risk >= 70:
        reasons.append(
            {
                "kind": "high_reach",
                "label": "High reach",
                "detail": "Composite risk is high enough to prioritize before broad topology review.",
            }
        )
    if path.credential_exposure:
        reasons.append(
            {
                "kind": "credential_exposure",
                "label": "Credential exposure",
                "detail": f"{len(path.credential_exposure)} credential signal(s) sit on this path.",
            }
        )
    if path.tool_exposure:
        dangerous_tools = [
            tool
            for tool in path.tool_exposure
            if any(keyword in tool.lower() for keyword in ("shell", "exec", "run", "command", "subprocess", "filesystem"))
        ]
        reasons.append(
            {
                "kind": "tool_reach",
                "label": "Tool reach",
                "detail": (
                    f"{len(dangerous_tools)} execution/file-capable tool(s) are reachable."
                    if dangerous_tools
                    else f"{len(path.tool_exposure)} tool(s) are reachable from the affected agent/server."
                ),
            }
        )
    finding_ids = _finding_ids_for_path(graph, path.hops, path.vuln_ids)
    if finding_ids:
        reasons.append(
            {
                "kind": "finding",
                "label": "Finding in chain",
                "detail": f"{len(finding_ids)} vulnerability or misconfiguration finding(s) anchor this path.",
            }
        )
    if not reasons:
        reasons.append(
            {
                "kind": "topology",
                "label": "Connected exposure",
                "detail": "The graph found a connected exposure path that should be reviewed before full expansion.",
            }
        )
    return reasons[:4]


def _next_actions_for_path(graph: UnifiedGraph, path) -> list[dict[str, str]]:
    findings = _finding_ids_for_path(graph, path.hops, path.vuln_ids)
    agents = _node_labels_for_types(
        graph,
        path.hops,
        {EntityType.AGENT, EntityType.USER, EntityType.GROUP, EntityType.SERVICE_ACCOUNT},
    )
    actions: list[dict[str, str]] = []
    if findings:
        actions.append(
            {
                "title": "Validate lead finding",
                "detail": "Open the first finding and confirm the root cause before expanding the graph.",
                "href": f"/findings?cve={quote(findings[0])}",
            }
        )
    if agents:
        actions.append(
            {
                "title": "Inspect exposed identity",
                "detail": "Review the agent, user, or service account that can trigger this path.",
                "href": _first_href_for_agent(agents[0]),
            }
        )
    if path.credential_exposure:
        actions.append(
            {
                "title": "Contain credentials",
                "detail": "Rotate, scope, or remove exposed credentials before widening blast-radius analysis.",
                "href": "/mesh",
            }
        )
    elif path.tool_exposure:
        actions.append(
            {
                "title": "Review reachable tools",
                "detail": "Check whether the tool permissions turn this finding into a real incident path.",
                "href": "/mesh",
            }
        )
    actions.append(
        {
            "title": "Expand topology",
            "detail": "Open the full lineage graph only when neighboring context is needed.",
            "href": "/graph",
        }
    )
    return actions[:4]


def _fix_first_card_for_path(graph: UnifiedGraph, path, rank: int) -> dict:
    findings = _finding_ids_for_path(graph, path.hops, path.vuln_ids)
    agents = _node_labels_for_types(
        graph,
        path.hops,
        {EntityType.AGENT, EntityType.USER, EntityType.GROUP, EntityType.SERVICE_ACCOUNT},
    )
    servers = _node_labels_for_types(graph, path.hops, {EntityType.SERVER, EntityType.CONTAINER, EntityType.CLOUD_RESOURCE})
    packages = _node_labels_for_types(graph, path.hops, {EntityType.PACKAGE})
    sequence = [graph.nodes[hop].label for hop in path.hops if hop in graph.nodes]
    title_parts = [findings[0] if findings else "Exposure path"]
    if agents:
        title_parts.append(f"via {agents[0]}")
    if path.tool_exposure:
        title_parts.append(f"with {path.tool_exposure[0]}")
    return {
        "id": f"{path.source}::{path.target}::{'->'.join(path.hops)}",
        "rank": rank,
        "title": " ".join(title_parts),
        "summary": path.summary or "Review this path before opening the full topology graph.",
        "attack_path": path.to_dict(),
        "exposure_path": _exposure_path_for_attack_path(path, nodes_by_id=graph.nodes, edges=graph.edges, rank=rank, scan_id=graph.scan_id),
        "nodes": [graph.nodes[hop].to_dict() for hop in path.hops if hop in graph.nodes],
        "sequence_labels": sequence,
        "risk_reasons": _risk_reasons_for_path(graph, path),
        "next_actions": _next_actions_for_path(graph, path),
        "affected": {
            "agents": agents,
            "servers": servers,
            "packages": packages,
            "findings": findings,
            "credentials": list(path.credential_exposure),
            "tools": list(path.tool_exposure),
        },
    }


def _path_matches_focus(graph: UnifiedGraph, path, *, cve: str, package: str, agent: str) -> bool:
    def norm(value: str) -> str:
        return value.strip().lower()

    cve_n = norm(cve)
    package_n = norm(package)
    agent_n = norm(agent)
    if not cve_n and not package_n and not agent_n:
        return True
    labels = {norm(graph.nodes[hop].label) for hop in path.hops if hop in graph.nodes}
    finding_ids = {norm(value) for value in _finding_ids_for_path(graph, path.hops, path.vuln_ids)}
    if cve_n and cve_n not in labels and cve_n not in finding_ids:
        return False
    if package_n:
        package_labels = {norm(label) for label in _node_labels_for_types(graph, path.hops, {EntityType.PACKAGE})}
        if package_n not in package_labels:
            return False
    if agent_n:
        agent_labels = {
            norm(label)
            for label in _node_labels_for_types(
                graph,
                path.hops,
                {EntityType.AGENT, EntityType.USER, EntityType.GROUP, EntityType.SERVICE_ACCOUNT},
            )
        }
        if agent_n not in agent_labels:
            return False
    return True


def _is_finding_like_node(node) -> bool:
    entity_type = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
    return entity_type in {EntityType.VULNERABILITY.value, EntityType.MISCONFIGURATION.value}


def _rel_value(edge) -> str:
    return edge.relationship.value if hasattr(edge.relationship, "value") else str(edge.relationship)


def _edge_relationships_for_hops(hops: list[str], edges) -> list[str]:
    """Return relationship names for consecutive hop pairs when topology is available."""
    if len(hops) < 2:
        return []
    by_pair: dict[tuple[str, str], str] = {}
    for edge in edges:
        rel = _rel_value(edge)
        by_pair.setdefault((edge.source, edge.target), rel)
        if edge.is_bidirectional:
            by_pair.setdefault((edge.target, edge.source), rel)
    relationships: list[str] = []
    for source, target in zip(hops, hops[1:], strict=False):
        relationship = by_pair.get((source, target))
        if relationship:
            relationships.append(relationship)
    return relationships


def _exposure_role_for_node(node) -> str:
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
        return {"id": node_id, "label": node_id, "role": "unknown"}
    ref: dict[str, Any] = {
        "id": node.id,
        "label": node.label,
        "role": _exposure_role_for_node(node),
    }
    if getattr(node, "severity", ""):
        ref["severity"] = node.severity
    if float(getattr(node, "risk_score", 0.0) or 0.0) > 0:
        ref["riskScore"] = node.risk_score
    return ref


def _exposure_relationships_for_path(path: AttackPath, edges) -> list[dict[str, Any]]:
    by_pair: dict[tuple[str, str], Any] = {}
    for edge in edges or []:
        by_pair.setdefault((edge.source, edge.target), edge)
        if edge.is_bidirectional:
            by_pair.setdefault((edge.target, edge.source), edge)

    relationships: list[dict[str, Any]] = []
    for index, (source, target) in enumerate(zip(path.hops, path.hops[1:], strict=False)):
        edge = by_pair.get((source, target))
        relationship = ""
        if edge is not None:
            relationship = _rel_value(edge)
            edge_id = edge.id
            direction = edge.direction
            traversable = edge.traversable
            confidence = edge.confidence
        else:
            relationship = path.edges[index] if index < len(path.edges) else "related"
            edge_id = f"{relationship}:{source}:{target}"
            direction = "directed"
            traversable = True
            confidence = 1.0
        relationships.append(
            {
                "id": edge_id,
                "source": source,
                "target": target,
                "relationship": relationship,
                "direction": direction,
                "traversable": traversable,
                "confidence": confidence,
            }
        )
    return relationships


def _severity_for_exposure_path(path: AttackPath, nodes_by_id: dict[str, Any]) -> str:
    severity = ""
    for hop in path.hops:
        node = nodes_by_id.get(hop)
        if node is not None and SEVERITY_RANK.get(str(getattr(node, "severity", "") or "").lower(), 0) > SEVERITY_RANK.get(severity, 0):
            severity = str(node.severity).lower()
    if severity:
        return severity
    if path.composite_risk >= 90 or path.composite_risk >= 9:
        return "critical"
    if path.composite_risk >= 70 or path.composite_risk >= 7:
        return "high"
    if path.composite_risk >= 40 or path.composite_risk >= 4:
        return "medium"
    return "none"


def _exposure_path_for_attack_path(
    path: AttackPath,
    *,
    nodes_by_id: dict[str, Any],
    edges=None,
    rank: int | None = None,
    scan_id: str = "",
) -> dict[str, Any]:
    hops = [_exposure_ref_for_node(hop, nodes_by_id) for hop in path.hops]
    empty_ref = {"id": "", "label": "", "role": "unknown"}
    source = _exposure_ref_for_node(path.source, nodes_by_id) if path.source else (hops[0] if hops else empty_ref)
    target = _exposure_ref_for_node(path.target, nodes_by_id) if path.target else (hops[-1] if hops else empty_ref)
    relationships = _exposure_relationships_for_path(path, edges)
    packages = [hop for hop in hops if hop["role"] == "package"]
    servers = [hop for hop in hops if hop["role"] == "server"]
    agents = [hop for hop in hops if hop["role"] == "agent"]
    findings = _finding_ids_for_nodes(nodes_by_id, path.hops, path.vuln_ids)
    label_parts = [findings[0] if findings else target["label"], agents[0]["label"] if agents else source["label"]]
    exposure: dict[str, Any] = {
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
    finding_node = nodes_by_id.get(path.target)
    if finding_node is not None:
        attributes = getattr(finding_node, "attributes", {}) or {}
        exposure["evidence"] = {
            "cvssScore": attributes.get("cvss_score"),
            "cvssVector": attributes.get("cvss_vector"),
            "epssScore": attributes.get("epss_score"),
            "isKev": bool(attributes.get("is_kev")),
            "attackVector": attributes.get("attack_vector"),
            "attackComplexity": attributes.get("attack_complexity"),
            "privilegesRequired": attributes.get("privileges_required"),
            "userInteraction": attributes.get("user_interaction"),
            "networkExploitable": bool(attributes.get("network_exploitable")),
            "impactCategory": attributes.get("impact_category"),
            "source": "graph_attack_path",
        }
    return exposure


def _serialize_attack_path(
    path: AttackPath,
    edges=None,
    *,
    nodes_by_id: dict[str, Any] | None = None,
    rank: int | None = None,
    scan_id: str = "",
) -> dict:
    data = path.to_dict()
    if not data.get("edges") and edges is not None:
        data["edges"] = _edge_relationships_for_hops(path.hops, edges)
    if nodes_by_id is not None:
        data["exposure_path"] = _exposure_path_for_attack_path(path, nodes_by_id=nodes_by_id, edges=edges, rank=rank, scan_id=scan_id)
    return data


def _node_type_value(node) -> str:
    return node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)


def _node_risk_100(node) -> float:
    risk = float(getattr(node, "risk_score", 0.0) or 0.0)
    if risk <= 10.0:
        risk *= 10.0
    if risk <= 0:
        risk = float(SEVERITY_RANK.get(str(getattr(node, "severity", "") or "").lower(), 0) * 20)
    return max(0.0, min(100.0, risk))


_DANGEROUS_TOOL_KEYWORDS = ("shell", "exec", "run", "command", "subprocess", "filesystem", "admin", "delete", "write", "sudo", "deploy")
_MAX_GOVERNANCE_PATHS = 200


def _is_dangerous_tool(label: str) -> bool:
    low = label.lower()
    return any(keyword in low for keyword in _DANGEROUS_TOOL_KEYWORDS)


def _derived_governance_attack_paths(graph: UnifiedGraph) -> list[AttackPath]:
    """Derive attack paths that the governance / CNAPP / effective-permission
    overlays make possible but that are not anchored on a CVE/misconfig finding.

    Surfaces five chains as first-class paths so humans and agents can
    investigate them via /v1/graph/attack-paths and the governance endpoint:

    - privilege escalation: principal --HAS_PERMISSION(assume_chain)--> resource
    - over-scoped tool access: agent --AUTHENTICATES_AS--> identity --SCOPED_TO-->
      dangerous tool (standing scope or JIT grant)
    - behavioral drift: agent --EXHIBITS_DRIFT--> drift_incident --SCOPED_TO--> tool
    - data exposure: resource --EXPOSED_TO--> internet-exposed data_store
    - broad-scope identity: agent --AUTHENTICATES_AS--> identity with no per-tool
      scope (standing access to everything it can reach), no finding anchor needed
    """
    paths: list[AttackPath] = []
    seen: set[tuple[str, str, str]] = set()

    def emit(kind: str, source: str, target: str, hops: list[str], edges: list[str], base: float, summary: str) -> None:
        key = (kind, source, target)
        if key in seen or len(paths) >= _MAX_GOVERNANCE_PATHS:
            return
        seen.add(key)
        risk = base + sum(boost for _k, _l, _d, boost in _fusion_signals_for_path(graph, hops))
        paths.append(
            AttackPath(
                source=source,
                target=target,
                hops=hops,
                edges=edges,
                composite_risk=round(min(100.0, risk), 2),
                summary=summary,
                vuln_ids=[],
            )
        )

    for edge in graph.edges:
        rel = _rel_value(edge)
        src = graph.nodes.get(edge.source)
        tgt = graph.nodes.get(edge.target)
        if src is None or tgt is None:
            continue

        # Privilege escalation: effective access gained only by assuming a role.
        if rel == RelationshipType.HAS_PERMISSION.value and (edge.evidence or {}).get("access") == "assume_chain":
            exposed = bool(tgt.attributes.get("internet_exposed"))
            emit(
                "privilege_escalation",
                src.id,
                tgt.id,
                [src.id, tgt.id],
                ["has_permission"],
                65.0 if exposed else 55.0,
                f"{src.label} reaches {tgt.label} by assuming another role" + (" (internet-exposed)." if exposed else "."),
            )
        # Data exposure: internet-exposed resource backing a data store.
        elif rel == RelationshipType.EXPOSED_TO.value and _node_type_value(tgt) == EntityType.DATA_STORE.value:
            sensitive = bool(tgt.attributes.get("data_sensitivity"))
            frameworks = tgt.attributes.get("data_regulatory_frameworks") or []
            # Name the regulation at risk when classified (PCI-DSS / HIPAA / GDPR / SOC2).
            data_descr = f"{'/'.join(frameworks)} data store" if frameworks else f"{'sensitive ' if sensitive else ''}data store"
            emit(
                "data_exposure",
                src.id,
                tgt.id,
                [src.id, tgt.id],
                ["exposed_to"],
                70.0 if sensitive else 55.0,
                f"{src.label} is internet-exposed and backs {data_descr} {tgt.label}.",
            )

    # Agent → identity → dangerous tool, and agent → drift incident → tool.
    for node in graph.nodes.values():
        ntype = _node_type_value(node)
        if ntype == EntityType.AGENT.value:
            for id_edge in graph.adjacency.get(node.id, []):
                if _rel_value(id_edge) == RelationshipType.AUTHENTICATES_AS.value:
                    identity = graph.nodes.get(id_edge.target)
                    if identity is None:
                        continue
                    for tool_edge in graph.adjacency.get(identity.id, []):
                        tool = graph.nodes.get(tool_edge.target)
                        if tool is None or _node_type_value(tool) != EntityType.TOOL.value or not _is_dangerous_tool(tool.label):
                            continue
                        emit(
                            "over_scoped_tool",
                            node.id,
                            tool.id,
                            [node.id, identity.id, tool.id],
                            ["authenticates_as", _rel_value(tool_edge)],
                            48.0,
                            f"{node.label} can reach high-capability tool {tool.label} through identity {identity.label}.",
                        )
                    # Broad-scope identity: standing access with no per-tool scope.
                    # This is a posture risk on its own — no vulnerability or
                    # dangerous-tool anchor required — so surface it as a path even
                    # when the identity's reachable tools are benign or not yet wired.
                    if identity.attributes.get("scope_bound") is False:
                        emit(
                            "broad_scope_identity",
                            node.id,
                            identity.id,
                            [node.id, identity.id],
                            ["authenticates_as"],
                            40.0,
                            f"{node.label} authenticates as {identity.label}, an identity with no per-tool scope — "
                            "it holds standing access to every tool it can reach.",
                        )
                elif _rel_value(id_edge) == RelationshipType.EXHIBITS_DRIFT.value:
                    incident = graph.nodes.get(id_edge.target)
                    if incident is None:
                        continue
                    for tool_edge in graph.adjacency.get(incident.id, []):
                        tool = graph.nodes.get(tool_edge.target)
                        if tool is None or _node_type_value(tool) != EntityType.TOOL.value:
                            continue
                        emit(
                            "drift_to_tool",
                            node.id,
                            tool.id,
                            [node.id, incident.id, tool.id],
                            ["exhibits_drift", _rel_value(tool_edge)],
                            45.0,
                            f"{node.label} drifted to using tool {tool.label} outside its declared blueprint.",
                        )
    return paths


_TOXIC_RESOURCE_TYPES = frozenset(
    {
        EntityType.CLOUD_RESOURCE.value,
        EntityType.RESOURCE.value,
        EntityType.SERVER.value,
        EntityType.DATA_STORE.value,
    }
)
_MAX_TOXIC_PATHS = 100


# Factor-count → base composite-risk band. Two stacked factors is already a
# toxic combination; three-plus is a crown jewel — the single most dangerous
# thing in the estate — banded above the constituent single-factor governance
# paths it fuses, so it tops the queue rather than competing with its parts.
def _toxic_band(factor_count: int) -> float:
    if factor_count >= 4:
        return 100.0
    if factor_count == 3:
        return 99.0
    return 82.0


def _derived_toxic_combination_paths(graph: UnifiedGraph) -> list[AttackPath]:
    """Cloud-security crown-jewel paths: assets where multiple toxic factors stack.

    A single resource that is *internet-exposed* AND carries an *exploitable
    vulnerability* AND can *reach sensitive data* AND/or is *reachable by an
    admin-escalating identity* is the chain an attacker actually walks — and the
    one thing a security team must fix first. Each independent factor present
    raises the band; three or more is surfaced as a crown jewel at the top of
    the attack-path queue. Fuses attributes the overlays already computed (no new
    scanner input), so it surfaces wherever attack paths do — the headless
    ``/v1/graph/attack-paths`` queue for agents and the graph cockpit for humans.
    """
    vulnerable: set[str] = set()
    admin_reachable: set[str] = set()
    sensitive_neighbors: dict[str, list[str]] = {}
    for edge in graph.edges:
        rel = _rel_value(edge)
        if rel == RelationshipType.VULNERABLE_TO.value:
            vulnerable.add(edge.source)
        elif rel == RelationshipType.HAS_PERMISSION.value:
            principal = graph.nodes.get(edge.source)
            if principal is not None and principal.attributes.get("escalates_to_admin"):
                admin_reachable.add(edge.target)
        elif rel in (RelationshipType.STORES.value, RelationshipType.EXPOSED_TO.value):
            store = graph.nodes.get(edge.target)
            if store is not None and store.attributes.get("data_sensitivity"):
                sensitive_neighbors.setdefault(edge.source, []).append(edge.target)

    paths: list[AttackPath] = []
    for node in graph.nodes.values():
        if _node_type_value(node) not in _TOXIC_RESOURCE_TYPES or len(paths) >= _MAX_TOXIC_PATHS:
            continue
        attrs = node.attributes
        factors: list[str] = []
        if attrs.get("internet_exposed"):
            factors.append("internet-exposed")
        if node.id in vulnerable or attrs.get("toxic_exposed_vulnerable"):
            factors.append("exploitable vulnerability")
        sens_ids = sensitive_neighbors.get(node.id, [])
        if attrs.get("data_sensitivity") or sens_ids:
            regs = list(attrs.get("data_regulatory_frameworks") or [])
            for sid in sens_ids:
                store = graph.nodes.get(sid)
                for code in (store.attributes.get("data_regulatory_frameworks") or []) if store else []:
                    if code not in regs:
                        regs.append(code)
            factors.append("sensitive data" + (f" ({'/'.join(regs)})" if regs else ""))
        if node.id in admin_reachable:
            factors.append("admin-privilege reachable")
        if len(factors) < 2:
            continue
        target = sens_ids[0] if sens_ids else node.id
        hops = [node.id, target] if target != node.id else [node.id]
        edges = ["exposed_to"] if target != node.id else []
        base = _toxic_band(len(factors))
        prefix = "Crown jewel" if len(factors) >= 3 else "Toxic combination"
        paths.append(
            AttackPath(
                source=node.id,
                target=target,
                hops=hops,
                edges=edges,
                composite_risk=round(min(100.0, base), 2),
                summary=f"{prefix}: {node.label} stacks {len(factors)} toxic factors — " + ", ".join(factors) + ".",
                vuln_ids=[],
            )
        )
    return paths


def _derived_attack_paths(graph: UnifiedGraph) -> list[AttackPath]:
    """Derive fix-first paths when a snapshot lacks materialised path rows.

    Older snapshots and some stores have rich topology but no `attack_paths`
    records. Security operators still need the obvious chain:
    agent -> MCP server -> package/server -> vulnerability, enriched with the
    server's credential and tool exposure. Keep this deterministic and bounded;
    stores with first-class path rows remain the source of truth.

    Governance / CNAPP / effective-permission chains (privilege escalation,
    over-scoped tool access, drift, data exposure) are derived and merged in
    both branches so they surface even when materialised vuln paths exist.
    """
    governance_paths = _derived_governance_attack_paths(graph) + _derived_toxic_combination_paths(graph)
    if graph.attack_paths:
        return sorted(
            list(graph.attack_paths) + governance_paths,
            key=lambda path: (path.composite_risk, len(path.hops), len(path.credential_exposure), len(path.tool_exposure)),
            reverse=True,
        )

    incoming: dict[str, list] = {}
    outgoing: dict[str, list] = {}
    for edge in graph.edges:
        incoming.setdefault(edge.target, []).append(edge)
        outgoing.setdefault(edge.source, []).append(edge)

    paths: list[AttackPath] = []
    seen: set[tuple[str, str, str, str]] = set()
    finding_types = {EntityType.VULNERABILITY.value, EntityType.MISCONFIGURATION.value}

    for finding in graph.nodes.values():
        if _node_type_value(finding) not in finding_types:
            continue
        for finding_edge in incoming.get(finding.id, []):
            if _rel_value(finding_edge) != RelationshipType.VULNERABLE_TO.value:
                continue
            vulnerable_source = graph.nodes.get(finding_edge.source)
            if vulnerable_source is None:
                continue

            server_ids: list[str] = []
            if _node_type_value(vulnerable_source) == EntityType.SERVER.value:
                server_ids.append(vulnerable_source.id)
            else:
                for source_edge in incoming.get(vulnerable_source.id, []):
                    if _rel_value(source_edge) == RelationshipType.DEPENDS_ON.value:
                        source_parent = graph.nodes.get(source_edge.source)
                        if source_parent is not None and _node_type_value(source_parent) == EntityType.SERVER.value:
                            server_ids.append(source_parent.id)

            for server_id in server_ids:
                agent_ids = [
                    edge.source
                    for edge in incoming.get(server_id, [])
                    if _rel_value(edge) == RelationshipType.USES.value
                    and graph.nodes.get(edge.source) is not None
                    and _node_type_value(graph.nodes[edge.source])
                    in {EntityType.AGENT.value, EntityType.USER.value, EntityType.SERVICE_ACCOUNT.value}
                ]
                if not agent_ids:
                    agent_ids = [server_id]

                credentials = [
                    graph.nodes[edge.target].label
                    for edge in outgoing.get(server_id, [])
                    if _rel_value(edge) == RelationshipType.EXPOSES_CRED.value and edge.target in graph.nodes
                ]
                tools = [
                    graph.nodes[edge.target].label
                    for edge in outgoing.get(server_id, [])
                    if _rel_value(edge) == RelationshipType.PROVIDES_TOOL.value and edge.target in graph.nodes
                ]

                for agent_id in sorted(set(agent_ids)):
                    hop_ids = [agent_id, server_id]
                    if vulnerable_source.id != server_id:
                        hop_ids.append(vulnerable_source.id)
                    hop_ids.append(finding.id)
                    path_edges = _edge_relationships_for_hops(hop_ids, graph.edges)
                    key = (agent_id, server_id, vulnerable_source.id, finding.id)
                    if key in seen:
                        continue
                    seen.add(key)

                    risk = _node_risk_100(finding)
                    risk += min(10.0, len(credentials) * 3.0)
                    risk += min(10.0, len(tools) * 0.75)
                    # Fuse governance / CNAPP / runtime evidence into the score so
                    # exposed, drifting, or unscoped-identity paths rank higher.
                    risk += sum(boost for _k, _l, _d, boost in _fusion_signals_for_path(graph, hop_ids))
                    paths.append(
                        AttackPath(
                            source=agent_id,
                            target=finding.id,
                            hops=hop_ids,
                            edges=path_edges,
                            composite_risk=round(min(100.0, risk), 2),
                            summary=(
                                "Derived from graph topology: vulnerable package/server is reachable from an agent "
                                "and inherits the server's credential/tool exposure."
                            ),
                            credential_exposure=sorted(set(credentials)),
                            tool_exposure=sorted(set(tools)),
                            vuln_ids=[finding.label or finding.id],
                        )
                    )

    paths.extend(governance_paths)
    return sorted(
        paths,
        key=lambda path: (path.composite_risk, len(path.hops), len(path.credential_exposure), len(path.tool_exposure)),
        reverse=True,
    )


def _bounded_env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return min(max(value, minimum), maximum)


def _graph_query_budget() -> dict[str, int]:
    """Return the deployer-configured graph traversal budget.

    Pydantic keeps absolute request ceilings. This budget is the lower,
    operator-tunable resource control used by the traversal endpoint.
    """
    return {
        key: _bounded_env_int(
            f"AGENT_BOM_GRAPH_QUERY_{key.upper()}",
            default,
            minimum=1 if key != "timeout_ms" else 100,
            maximum=_GRAPH_QUERY_ABSOLUTE_LIMITS[key],
        )
        for key, default in _GRAPH_QUERY_DEFAULT_BUDGET.items()
    }


def _enforce_graph_query_budget(body: GraphQueryRequest) -> dict[str, int]:
    budget = _graph_query_budget()
    requested = {
        "max_depth": body.max_depth,
        "max_nodes": body.max_nodes,
        "max_edges": body.max_edges,
        "timeout_ms": body.timeout_ms,
    }
    violations = {key: {"requested": value, "allowed": budget[key]} for key, value in requested.items() if value > budget[key]}
    if violations:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Graph query exceeds tenant query budget",
                "violations": violations,
                "budget": budget,
            },
        )
    return budget


async def _graph_store_call(fn, /, *args, **kwargs):
    """Run sync graph store methods off the event loop."""
    try:
        async with adaptive_backpressure("graph"):
            return await asyncio.to_thread(fn, *args, **kwargs)
    except BackpressureRejectedError as exc:
        raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc


async def _graph_compute_call(fn, /, *args, **kwargs):
    """Run CPU-heavy graph derivation and serialization off the event loop."""
    try:
        async with adaptive_backpressure("graph"):
            return await asyncio.to_thread(fn, *args, **kwargs)
    except BackpressureRejectedError as exc:
        raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc


def _filtered_graph_response(graph: UnifiedGraph, *, offset: int, limit: int) -> dict[str, Any]:
    stats = graph.stats()
    all_nodes = list(graph.nodes.values())
    paged_nodes, pagination = _paginate(all_nodes, offset, limit)
    paged_ids = {n.id for n in paged_nodes}
    paged_edges = [e for e in graph.edges if e.source in paged_ids and e.target in paged_ids]
    attack_paths = [
        _serialize_attack_path(p, graph.edges, nodes_by_id=graph.nodes, scan_id=graph.scan_id)
        for p in _derived_attack_paths(graph)
        if p.hops and all(hop in paged_ids for hop in p.hops)
    ]
    interaction_risks = [
        r.to_dict() for r in graph.interaction_risks if r.agents and all(f"agent:{agent_name}" in paged_ids for agent_name in r.agents)
    ]

    return {
        "scan_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "created_at": graph.created_at,
        "nodes": [n.to_dict() for n in paged_nodes],
        "edges": [e.to_dict() for e in paged_edges],
        "attack_paths": attack_paths,
        "interaction_risks": interaction_risks,
        "stats": stats,
        "pagination": pagination,
    }


def _fix_first_graph_view_payload(graph: UnifiedGraph, *, cve: str, package: str, agent: str, limit: int) -> dict[str, Any]:
    available_paths = _derived_attack_paths(graph)
    ranked_paths = sorted(
        (path for path in available_paths if _path_matches_focus(graph, path, cve=cve, package=package, agent=agent)),
        key=lambda path: (path.composite_risk, len(path.hops), len(path.credential_exposure), len(path.tool_exposure)),
        reverse=True,
    )
    cards = [_fix_first_card_for_path(graph, path, index + 1) for index, path in enumerate(ranked_paths[:limit])]
    covered_findings = {finding for card in cards for finding in card["affected"]["findings"]}
    return {
        "scan_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "created_at": graph.created_at,
        "cards": cards,
        "summary": {
            "total_paths": len(available_paths),
            "matched_paths": len(ranked_paths),
            "returned_paths": len(cards),
            "highest_risk": cards[0]["attack_path"]["composite_risk"] if cards else 0.0,
            "covered_findings": len(covered_findings),
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
        },
        "focus": {
            "cve": cve,
            "package": package,
            "agent": agent,
        },
    }


def _derived_attack_path_page(graph: UnifiedGraph, *, offset: int, limit: int) -> tuple[str, str, list[AttackPath], int]:
    derived_paths = _derived_attack_paths(graph)
    return graph.scan_id, graph.created_at, derived_paths[offset : offset + limit], len(derived_paths)


def _serialize_attack_path_queue(
    *,
    scan_id: str,
    tenant: str,
    created_at: str,
    nodes: list[Any],
    path_edges: list[Any],
    paths: list[AttackPath],
    total: int,
    offset: int,
    limit: int,
    stats: dict[str, Any],
) -> dict[str, Any]:
    nodes_by_id = {node.id: node for node in nodes}
    if total and int(stats.get("attack_path_count") or 0) == 0:
        stats = {
            **stats,
            "attack_path_count": total,
            "max_attack_path_risk": max((path.composite_risk for path in paths), default=0.0),
        }
    return {
        "scan_id": scan_id,
        "tenant_id": tenant,
        "created_at": created_at,
        "nodes": [node.to_dict() for node in nodes],
        "edges": [edge.to_dict() for edge in path_edges],
        "attack_paths": [
            _serialize_attack_path(path, path_edges, nodes_by_id=nodes_by_id, rank=offset + index + 1, scan_id=scan_id)
            for index, path in enumerate(paths)
        ],
        "interaction_risks": [],
        "stats": stats,
        "pagination": _page_meta(total, offset, limit),
    }


def _semantic_cluster_payload(
    graph: UnifiedGraph,
    *,
    selected_kinds: set[str],
    min_members: int,
    limit: int,
) -> dict[str, Any]:
    clusters = [
        cluster
        for cluster in build_semantic_clusters(graph.nodes.values(), graph.edges, min_members=min_members)
        if cluster.kind in selected_kinds
    ][:limit]
    return {
        "scan_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "created_at": graph.created_at,
        "clusters": [cluster.to_dict() for cluster in clusters],
        "stats": semantic_cluster_stats(clusters),
        "available_kinds": list(SEMANTIC_CLUSTER_KINDS),
    }


def _graph_rollup_payload(
    graph: UnifiedGraph,
    *,
    node: str | None,
    min_severity: str,
    exposed: bool,
    toxic: bool,
    mode: Literal["rollup", "attack_path"],
) -> dict[str, Any]:
    from agent_bom.graph.rollup import RollupFilters, attack_path_view, drill_down, rollup_view

    filters = RollupFilters(
        min_severity=min_severity,
        exposed_only=exposed,
        toxic_only=toxic,
    )
    if node:
        return drill_down(graph, node, filters=filters)
    if mode == "attack_path":
        return attack_path_view(graph, _derived_attack_paths(graph), filters=filters)
    return rollup_view(graph, filters=filters)


# ═══════════════════════════════════════════════════════════════════════════
# Preset model
# ═══════════════════════════════════════════════════════════════════════════


class PresetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str = ""
    filters: dict


class GraphQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    roots: list[str] = Field(..., min_length=1, description="One or more starting node IDs")
    scan_id: str = ""
    direction: Literal["forward", "reverse", "both"] = "forward"
    max_depth: int = Field(4, ge=1, le=10)
    max_nodes: int = Field(500, ge=1, le=5000)
    max_edges: int = Field(10_000, ge=1, le=25_000)
    timeout_ms: int = Field(2500, ge=100, le=5000)
    traversable_only: bool = False
    static_only: bool = False
    dynamic_only: bool = False
    include_roots: bool = True
    include_attack_paths: bool = False
    min_severity: str = ""
    entity_types: list[str] = Field(default_factory=list)
    relationship_types: list[str] = Field(default_factory=list)
    compliance_prefixes: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)


class GraphDeployDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    candidate: str | dict[str, Any] = Field(..., description="Package, image, service, or structured candidate descriptor")
    tenant_id: str | None = Field(default=None, description="Accepted for SDK compatibility; request tenant scope is authoritative")
    scan_id: str | None = Field(default=None, description="Scan snapshot ID; latest if omitted")
    limit: int = Field(5, ge=1, le=25, description="Maximum matched exposure paths")
    warn_risk: float = Field(40.0, ge=0, le=100, alias="warnRisk", description="Risk threshold for warning")
    block_risk: float = Field(80.0, ge=0, le=100, alias="blockRisk", description="Risk threshold for blocking")
    context: dict[str, Any] = Field(default_factory=dict, description="Optional caller context for future policy extensions")


def _candidate_to_string(candidate: str | dict[str, Any]) -> str:
    if isinstance(candidate, str):
        return candidate.strip()
    return json.dumps(candidate, sort_keys=True, separators=(",", ":"), default=str)


def _raise_mcp_error_as_http(payload: dict[str, Any]) -> None:
    error = payload.get("error")
    if not isinstance(error, dict):
        return
    category = str(error.get("category") or "internal")
    status_by_category = {
        "validation": 422,
        "auth": 403,
        "rate_limited": 429,
        "not_found": 404,
        "unsupported": 400,
        "timeout": 504,
        "upstream": 502,
        "internal": 500,
    }
    raise HTTPException(status_code=status_by_category.get(category, 500), detail=error)


def _node_matches_query(
    node,
    *,
    entity_types: set[str],
    min_severity_rank: int,
    compliance_prefixes: set[str],
    data_sources: set[str],
) -> bool:
    from agent_bom.graph import SEVERITY_RANK

    if entity_types:
        entity_type = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
        if entity_type not in entity_types:
            return False
    if min_severity_rank and _is_finding_like_node(node) and SEVERITY_RANK.get(node.severity.lower(), 0) < min_severity_rank:
        return False
    if compliance_prefixes:
        prefixes = {tag.split("-")[0].upper() if "-" in tag else tag.upper() for tag in node.compliance_tags}
        if not prefixes.intersection(compliance_prefixes):
            return False
    if data_sources and not set(node.data_sources).intersection(data_sources):
        return False
    return True


def _filtered_query_graph(
    graph,
    *,
    roots: list[str],
    entity_types: set[str],
    min_severity_rank: int,
    compliance_prefixes: set[str],
    data_sources: set[str],
):
    filtered = UnifiedGraph(scan_id=graph.scan_id, tenant_id=graph.tenant_id, created_at=graph.created_at)
    keep_ids = {
        node.id
        for node in graph.nodes.values()
        if _node_matches_query(
            node,
            entity_types=entity_types,
            min_severity_rank=min_severity_rank,
            compliance_prefixes=compliance_prefixes,
            data_sources=data_sources,
        )
    }
    keep_ids.update(root for root in roots if root in graph.nodes)

    for node_id in keep_ids:
        node = graph.nodes.get(node_id)
        if node:
            filtered.add_node(node)
    for edge in graph.edges:
        if edge.source in keep_ids and edge.target in keep_ids:
            filtered.add_edge(edge)
    return filtered


# ═══════════════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/v1/graph", tags=["graph"])
async def get_graph(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    scan: Optional[str] = Query(None, description="Alias for scan_id"),
    entity_types: Optional[str] = Query(None, description="Comma-separated entity types"),
    min_severity: Optional[str] = Query(None, description="Minimum severity (critical/high/medium/low)"),
    relationships: Optional[str] = Query(None, description="Comma-separated relationship types"),
    static_only: bool = Query(False, description="Exclude runtime edges"),
    dynamic_only: bool = Query(False, description="Only runtime edges"),
    max_depth: Optional[int] = Query(None, ge=1, le=20, description="Max traversal depth"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset node pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset for nodes"),
    limit: int = Query(500, ge=1, le=5000, description="Max nodes to return"),
) -> dict:
    """Load the unified graph with filters and pagination.

    Nodes are paginated (offset/limit). Edges are filtered to only include
    edges between returned nodes. Stats reflect the full (unpaginated) graph.
    """
    from agent_bom.graph import SEVERITY_RANK, GraphFilterOptions

    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    requested_scan_id = _coalesce_alias(scan_id, scan, primary_name="scan_id", alias_name="scan")

    if not requested_scan_id and not await _graph_store_call(graph_store.latest_snapshot_id, tenant_id=tenant):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    et_set = _parse_entity_type_filter(entity_types)

    min_rank = 0
    if min_severity:
        min_rank = SEVERITY_RANK.get(min_severity.lower(), 0)

    if relationships or static_only or dynamic_only:
        graph = await _graph_store_call(
            graph_store.load_graph,
            scan_id=requested_scan_id,
            tenant_id=tenant,
            entity_types=et_set,
            min_severity_rank=min_rank,
        )
        # Overlay the live agent-identity governance control plane (managed
        # identities, JIT grants, conditional-access policies, drift incidents)
        # so attack paths can traverse agent → identity → grant → tool and
        # agent ↔ drift. Applied BEFORE the scoped filter so governance edges
        # are subject to the relationship filter and governance nodes left
        # unconnected in a scoped view are pruned with everything else, rather
        # than reappearing as orphan nodes. Best-effort; never breaks the read.
        if not et_set:
            try:
                from agent_bom.graph.governance_overlay import apply_governance_overlay

                apply_governance_overlay(graph, tenant_id=tenant)
            except Exception:  # noqa: BLE001
                logger.warning("governance overlay failed", exc_info=True)

        rel_set = _parse_relationship_filter(relationships)
        filters = GraphFilterOptions(
            relationship_types=rel_set,
            static_only=static_only,
            dynamic_only=dynamic_only,
            max_depth=max_depth or 6,
        )
        graph = graph.filtered_view(filters)

        return await _graph_compute_call(_filtered_graph_response, graph, offset=offset, limit=limit)

    try:
        effective_scan_id, created_at, paged_nodes, total, next_cursor = await _graph_store_call(
            graph_store.page_nodes,
            scan_id=requested_scan_id,
            tenant_id=tenant,
            entity_types=et_set,
            min_severity_rank=min_rank,
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    paged_ids = {n.id for n in paged_nodes}
    paged_edges = await _graph_store_call(
        graph_store.edges_for_node_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=paged_ids,
    )
    source_attack_paths = await _graph_store_call(
        graph_store.attack_paths_for_sources,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        source_ids=paged_ids,
    )
    attack_path_hop_ids = {hop for path in source_attack_paths for hop in path.hops}
    attack_path_nodes = await _graph_store_call(
        graph_store.nodes_by_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=attack_path_hop_ids - paged_ids,
    )
    nodes_by_id = {node.id: node for node in [*paged_nodes, *attack_path_nodes]}
    return {
        "scan_id": effective_scan_id,
        "tenant_id": tenant,
        "created_at": created_at,
        "nodes": [n.to_dict() for n in paged_nodes],
        "edges": [e.to_dict() for e in paged_edges],
        "attack_paths": [
            _serialize_attack_path(path, paged_edges, nodes_by_id=nodes_by_id, scan_id=effective_scan_id) for path in source_attack_paths
        ],
        "interaction_risks": [],
        "stats": await _graph_store_call(
            graph_store.snapshot_stats,
            scan_id=effective_scan_id,
            tenant_id=tenant,
            entity_types=et_set,
            min_severity_rank=min_rank,
        ),
        "pagination": _page_meta(total, offset, limit, cursor=cursor, next_cursor=next_cursor),
    }


@router.get("/v1/graph/views/fix-first", tags=["graph"], responses={200: _FIX_FIRST_VIEW_OPENAPI_RESPONSE})
async def get_fix_first_graph_view(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
    cve: str = Query("", description="Optional finding focus"),
    package: str = Query("", description="Optional package focus"),
    agent: str = Query("", description="Optional agent or identity focus"),
    limit: int = Query(8, ge=1, le=25, description="Maximum ranked path cards to return"),
) -> dict:
    """Return a fix-first security graph view model.

    This endpoint is intentionally more product-shaped than `/v1/graph`: it
    ranks persisted attack paths and attaches the operator context needed for
    a fix-first remediation cockpit. The full topology remains available
    through `/v1/graph`; this view answers "what should I inspect first?"
    """

    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    requested_scan_id = scan_id or ""

    if not requested_scan_id and not await _graph_store_call(graph_store.latest_snapshot_id, tenant_id=tenant):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    graph = await _graph_store_call(
        graph_store.load_graph,
        scan_id=requested_scan_id,
        tenant_id=tenant,
    )
    return await _graph_compute_call(_fix_first_graph_view_payload, graph, cve=cve, package=package, agent=agent, limit=limit)


@router.get("/v1/graph/diff", tags=["graph"])
async def get_graph_diff(
    request: Request,
    old: str = Query(..., description="Old scan ID"),
    new: str = Query(..., description="New scan ID"),
) -> dict:
    """Diff two scan snapshots — nodes/edges added, removed, changed."""
    return await _graph_store_call(_get_graph_store_or_503().diff_snapshots, old, new, tenant_id=_tenant(request))


@router.get("/v1/graph/edges/active", tags=["graph"])
async def get_active_graph_edges(
    request: Request,
    at: str = Query(..., description="ISO timestamp for replay lookup"),
) -> list[dict]:
    """Return edge versions active at a timestamp for replay views."""
    return await _graph_store_call(_get_graph_store_or_503().active_edges_at, at, tenant_id=_tenant(request))


@router.get("/v1/graph/edges/changes", tags=["graph"])
async def get_graph_edge_changes(
    request: Request,
    old: str = Query(..., description="Old scan ID"),
    new: str = Query(..., description="New scan ID"),
) -> dict:
    """Return edge lifecycle changes between two scan snapshots."""
    return await _graph_store_call(_get_graph_store_or_503().changed_edges_between_scans, old, new, tenant_id=_tenant(request))


@router.get("/v1/graph/attack-paths", tags=["graph"], responses={200: _ATTACK_PATHS_OPENAPI_RESPONSE})
async def get_graph_attack_paths(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Max attack paths"),
) -> dict:
    """Return the global attack-path queue independent of node pagination.

    `/v1/graph` intentionally windows nodes and therefore cannot be the source
    of truth for fix-first triage. This endpoint ranks persisted paths across
    the whole snapshot and hydrates only the hop nodes needed to render the
    selected queue page.
    """
    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    effective_scan_id, created_at, paths, total = await _graph_store_call(
        graph_store.attack_paths,
        scan_id=scan_id or "",
        tenant_id=tenant,
        offset=offset,
        limit=limit,
    )
    if total == 0:
        graph = await _graph_store_call(
            graph_store.load_graph,
            scan_id=effective_scan_id,
            tenant_id=tenant,
        )
        effective_scan_id, created_at, paths, total = await _graph_compute_call(
            _derived_attack_path_page,
            graph,
            offset=offset,
            limit=limit,
        )
    hop_ids = {hop for path in paths for hop in path.hops}
    nodes = await _graph_store_call(
        graph_store.nodes_by_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=hop_ids,
    )
    path_edges = await _graph_store_call(
        graph_store.edges_for_node_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=hop_ids,
    )
    stats = await _graph_store_call(
        graph_store.snapshot_stats,
        scan_id=effective_scan_id,
        tenant_id=tenant,
    )
    return await _graph_compute_call(
        _serialize_attack_path_queue,
        scan_id=effective_scan_id,
        tenant=tenant,
        created_at=created_at,
        nodes=nodes,
        path_edges=path_edges,
        paths=paths,
        total=total,
        offset=offset,
        limit=limit,
        stats=stats,
    )


@router.get("/v1/graph/governance", tags=["graph"])
async def get_graph_governance(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    limit: int = Query(2000, ge=1, le=10000, description="Max nodes to return"),
) -> dict:
    """Return the agent-identity governance subgraph projected onto the inventory.

    Loads the latest unified graph, overlays the live governance control plane
    (managed identities, JIT grants, conditional-access policies, drift
    incidents) from the identity/drift stores, and returns the governance nodes
    plus the agent/tool nodes they connect to — making
    `agent → identity → grant → tool → vulnerable package` and `agent ↔ drift`
    traversable for headless agents, the API, and the UI cockpits.
    """
    from agent_bom.graph.governance_overlay import apply_governance_overlay

    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    graph = await _graph_store_call(graph_store.load_graph, scan_id=scan_id or "", tenant_id=tenant)
    overlay_stats = apply_governance_overlay(graph, tenant_id=tenant)

    governance_types = {
        EntityType.MANAGED_IDENTITY,
        EntityType.ACCESS_GRANT,
        EntityType.ACCESS_POLICY,
        EntityType.DRIFT_INCIDENT,
    }
    governance_ids = {node.id for node in graph.nodes.values() if node.entity_type in governance_types}
    # Keep governance nodes plus the inventory nodes they touch (one hop) so the
    # subgraph is self-contained and renderable.
    keep_edges = [e for e in graph.edges if e.source in governance_ids or e.target in governance_ids]
    keep_ids = set(governance_ids)
    for edge in keep_edges:
        keep_ids.add(edge.source)
        keep_ids.add(edge.target)
    nodes = [graph.nodes[nid].to_dict() for nid in keep_ids if nid in graph.nodes][:limit]
    node_id_window = {n["id"] for n in nodes}
    edges = [e.to_dict() for e in keep_edges if e.source in node_id_window and e.target in node_id_window]

    derived = [
        _serialize_attack_path(p, keep_edges, nodes_by_id=graph.nodes, scan_id=graph.scan_id)
        for p in _derived_attack_paths(graph)
        if p.hops and any(hop in governance_ids for hop in p.hops)
    ]
    counts: dict[str, int] = {}
    for node in graph.nodes.values():
        if node.entity_type in governance_types:
            counts[node.entity_type.value] = counts.get(node.entity_type.value, 0) + 1
    return {
        "scan_id": graph.scan_id,
        "tenant_id": tenant,
        "created_at": graph.created_at,
        "nodes": nodes,
        "edges": edges,
        "attack_paths": derived,
        "overlay": overlay_stats,
        "governance_counts": counts,
        "stats": {"node_count": len(nodes), "edge_count": len(edges)},
    }


@router.get("/v1/graph/nhi/governance", tags=["graph"])
async def get_nhi_governance(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
) -> dict:
    """Return the non-human-identity governance posture for the latest graph.

    Loads the latest unified graph, projects the live governance control plane
    and resolves effective permissions, then computes the three Natoma-parity
    analytics — usage-based right-sizing, dormant/orphaned detection, and the
    0-100 per-identity risk score — and returns a non-secret posture ranked
    worst risk first. Right-sizing here uses the durable `last_used_at` markers
    in the graph (no caller usage map is accepted over the API).
    """
    from agent_bom.graph.effective_permissions import apply_effective_permissions
    from agent_bom.graph.governance_overlay import apply_governance_overlay
    from agent_bom.graph.nhi_governance import describe_nhi_governance_posture

    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    graph = await _graph_store_call(graph_store.load_graph, scan_id=scan_id or "", tenant_id=tenant)
    apply_governance_overlay(graph, tenant_id=tenant)
    apply_effective_permissions(graph)
    posture = describe_nhi_governance_posture(graph)
    posture["scan_id"] = graph.scan_id
    posture["tenant_id"] = tenant
    return posture


@router.get("/v1/graph/exposure-paths", tags=["graph"])
async def get_graph_exposure_paths(
    request: Request,
    tenant_id: Optional[str] = Query(None, include_in_schema=False),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    limit: int = Query(5, ge=1, le=100, description="Maximum ExposurePaths"),
    min_risk: float = Query(0.0, ge=0, le=100, description="Minimum ExposurePath risk score"),
) -> dict:
    """Return the MCP-compatible ExposurePath queue over REST for SDK consumers."""
    del tenant_id  # SDK compatibility only; request tenant scope is authoritative.
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    graph_store = _get_graph_store_or_503()
    raw = await exposure_paths_impl(
        tenant_id=_tenant(request),
        scan_id=scan_id,
        limit=limit,
        min_risk=min_risk,
        _get_graph_store=lambda: graph_store,
        _truncate_response=lambda value: value,
    )
    payload = json.loads(raw)
    _raise_mcp_error_as_http(payload)
    return payload


@router.post("/v1/graph/should-i-deploy", tags=["graph"])
async def post_graph_should_i_deploy(request: Request, body: GraphDeployDecisionRequest) -> dict:
    """Return the MCP-compatible allow/warn/block deploy decision over REST."""
    _ = (body.tenant_id, body.context)  # SDK compatibility/future policy context; request tenant scope is authoritative today.
    from agent_bom.mcp_tools.graph import deploy_decision_impl

    candidate = _candidate_to_string(body.candidate)
    if not candidate:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT",
                "category": "validation",
                "message": "candidate must not be empty",
                "details": {"argument": "candidate"},
            },
        )
    if body.warn_risk > body.block_risk:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT",
                "category": "validation",
                "message": "warn_risk and block_risk must be ordered thresholds between 0 and 100",
                "details": {"warn_risk": body.warn_risk, "block_risk": body.block_risk},
            },
        )

    graph_store = _get_graph_store_or_503()
    raw = await deploy_decision_impl(
        candidate=candidate,
        tenant_id=_tenant(request),
        scan_id=body.scan_id,
        limit=body.limit,
        warn_risk=body.warn_risk,
        block_risk=body.block_risk,
        _get_graph_store=lambda: graph_store,
        _truncate_response=lambda value: value,
    )
    payload = json.loads(raw)
    _raise_mcp_error_as_http(payload)
    return payload


@router.get("/v1/graph/paths", tags=["graph"])
async def get_graph_paths(
    request: Request,
    source_id: Optional[str] = Query(None, description="Source node ID (e.g. agent:claude-desktop)"),
    source: Optional[str] = Query(None, include_in_schema=False),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    scan: Optional[str] = Query(None, include_in_schema=False),
    max_depth: int = Query(4, ge=1, le=10, description="Maximum BFS depth"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Max paths"),
) -> dict:
    """Find all attack paths from a source node via BFS."""
    graph_store = _get_graph_store_or_503()
    source_node_id = _coalesce_alias(source_id, source, primary_name="source_id", alias_name="source")
    if not source_node_id:
        raise HTTPException(status_code=422, detail="Missing required query parameter: source_id")
    requested_scan_id = _coalesce_alias(scan_id, scan, primary_name="scan_id", alias_name="scan")
    tenant = _tenant(request)
    source_nodes = await _graph_store_call(graph_store.nodes_by_ids, scan_id=requested_scan_id, tenant_id=tenant, node_ids={source_node_id})
    if not source_nodes:
        raise HTTPException(status_code=404, detail=f"Node '{source_node_id}' not found in graph")

    all_paths, reachable = await _graph_store_call(
        graph_store.bfs_paths,
        scan_id=requested_scan_id,
        tenant_id=tenant,
        source=source_node_id,
        max_depth=max_depth,
        traversable_only=True,
    )
    paged_paths, pagination = _paginate(all_paths, offset, limit)
    attack_paths = await _graph_store_call(
        graph_store.attack_paths_for_sources,
        scan_id=requested_scan_id,
        tenant_id=tenant,
        source_ids={source_node_id},
    )
    path_node_ids = {source_node_id, *reachable}
    path_edges = await _graph_store_call(
        graph_store.edges_for_node_ids,
        scan_id=requested_scan_id,
        tenant_id=tenant,
        node_ids=path_node_ids,
    )
    path_nodes = await _graph_store_call(
        graph_store.nodes_by_ids,
        scan_id=requested_scan_id,
        tenant_id=tenant,
        node_ids=path_node_ids,
    )
    nodes_by_id = {node.id: node for node in path_nodes}

    return {
        "source": source_node_id,
        "source_id": source_node_id,
        "max_depth": max_depth,
        "reachable_count": len(reachable),
        "reachable_nodes": sorted(reachable),
        "paths": [{"target": p[-1], "hops": p, "depth": len(p) - 1} for p in paged_paths],
        "attack_paths": [
            _serialize_attack_path(ap, path_edges, nodes_by_id=nodes_by_id, scan_id=requested_scan_id)
            for ap in attack_paths
            if ap.source == source_node_id
        ],
        "pagination": pagination,
    }


@router.get("/v1/graph/impact", tags=["graph"])
async def get_graph_impact(
    request: Request,
    node: str = Query(..., description="Node ID to compute impact for"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    max_depth: int = Query(4, ge=1, le=10, description="Maximum reverse BFS depth"),
) -> dict:
    """Compute blast radius of a node — what depends on it?"""
    impact = await _graph_store_call(
        _get_graph_store_or_503().impact_of,
        scan_id=scan_id or "",
        tenant_id=_tenant(request),
        node_id=node,
        max_depth=max_depth,
    )
    if impact is None:
        raise HTTPException(status_code=404, detail=f"Node '{node}' not found")
    return impact


@router.get("/v1/graph/search", tags=["graph"])
async def search_graph(
    request: Request,
    q: str = Query(..., min_length=1, description="Search query"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    entity_types: Optional[str] = Query(None, description="Comma-separated entity types"),
    min_severity: Optional[str] = Query(None, description="Minimum severity (critical/high/medium/low)"),
    compliance_prefixes: Optional[str] = Query(None, description="Comma-separated compliance prefixes"),
    data_sources: Optional[str] = Query(None, description="Comma-separated data sources"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset search pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> dict:
    """Search graph nodes by label, type, tags, and attributes."""
    entity_type_filters = _parse_entity_type_filter(entity_types)
    min_rank = SEVERITY_RANK.get(min_severity.lower(), 0) if min_severity else 0
    prefix_filters = {value.strip().upper() for value in compliance_prefixes.split(",") if value.strip()} if compliance_prefixes else None
    data_source_filters = {value.strip() for value in data_sources.split(",") if value.strip()} if data_sources else None
    try:
        results, total, next_cursor = await _graph_store_call(
            _get_graph_store_or_503().search_nodes,
            scan_id=scan_id or "",
            tenant_id=_tenant(request),
            query=q,
            entity_types=entity_type_filters,
            min_severity_rank=min_rank,
            compliance_prefixes=prefix_filters,
            data_sources=data_source_filters,
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    return {
        "query": q,
        "filters": {
            "scan_id": scan_id or "",
            "entity_types": sorted(entity_type_filters) if entity_type_filters else [],
            "min_severity": min_severity or "",
            "compliance_prefixes": sorted(prefix_filters) if prefix_filters else [],
            "data_sources": sorted(data_source_filters) if data_source_filters else [],
        },
        "results": [n.to_dict() for n in results],
        "pagination": {
            "total": total,
            "offset": offset,
            "limit": limit,
            "cursor": cursor or "",
            "next_cursor": next_cursor or "",
            "has_more": bool(next_cursor) if cursor else offset + limit < total,
        },
    }


@router.get("/v1/graph/clusters", tags=["graph"])
async def get_graph_clusters(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
    kinds: Optional[str] = Query(None, description="Comma-separated semantic cluster kinds"),
    min_members: int = Query(2, ge=1, le=100, description="Minimum members required to emit a cluster"),
    limit: int = Query(250, ge=1, le=1000, description="Maximum clusters to return"),
) -> dict:
    """Return API-backed semantic clusters for graph readability.

    The response is intentionally reversible: each cluster carries member IDs
    and expansion metadata so the dashboard can collapse and expand topology
    without deriving families client-side.
    """

    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    requested_scan_id = scan_id or ""
    if not requested_scan_id and not await _graph_store_call(graph_store.latest_snapshot_id, tenant_id=tenant):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    selected_kinds = {kind.strip() for kind in kinds.split(",") if kind.strip()} if kinds else set(SEMANTIC_CLUSTER_KINDS)
    unknown_kinds = selected_kinds - set(SEMANTIC_CLUSTER_KINDS)
    if unknown_kinds:
        raise HTTPException(status_code=400, detail=f"Unknown semantic cluster kind(s): {', '.join(sorted(unknown_kinds))}")

    graph = await _graph_store_call(
        graph_store.load_graph,
        scan_id=requested_scan_id,
        tenant_id=tenant,
    )
    return await _graph_compute_call(_semantic_cluster_payload, graph, selected_kinds=selected_kinds, min_members=min_members, limit=limit)


@router.get("/v1/graph/agents", tags=["graph"])
async def list_graph_agents(
    request: Request,
    q: str = Query("", description="Optional agent label/id search"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Max agents"),
) -> dict:
    """List agent nodes for large-graph selectors without loading the full graph."""
    graph_store = _get_graph_store_or_503()
    tenant_id = _tenant(request)
    query = q.strip()
    if query:
        agents, total, next_cursor = await _graph_store_call(
            graph_store.search_nodes,
            scan_id=scan_id or "",
            tenant_id=tenant_id,
            query=query,
            entity_types={"agent"},
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
        effective_scan_id = scan_id or await _graph_store_call(graph_store.latest_snapshot_id, tenant_id=tenant_id)
        created_at = ""
    else:
        effective_scan_id, created_at, agents, total, next_cursor = await _graph_store_call(
            graph_store.page_nodes,
            scan_id=scan_id or "",
            tenant_id=tenant_id,
            entity_types={"agent"},
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
    return {
        "scan_id": effective_scan_id,
        "tenant_id": tenant_id,
        "created_at": created_at,
        "agents": [
            {
                "id": node.id,
                "label": node.label,
                "risk_score": node.risk_score,
                "severity": node.severity,
                "status": node.status.value if hasattr(node.status, "value") else str(node.status),
                "data_sources": node.data_sources,
                "first_seen": node.first_seen,
                "last_seen": node.last_seen,
            }
            for node in agents
        ],
        "pagination": _page_meta(total, offset, limit, cursor=cursor, next_cursor=next_cursor),
    }


@router.post("/v1/graph/query", tags=["graph"])
async def query_graph(request: Request, body: GraphQueryRequest) -> dict:
    """Run a bounded programmable traversal over the canonical graph."""
    graph_store = _get_graph_store_or_503()
    budget = _enforce_graph_query_budget(body)
    root_nodes = await _graph_store_call(
        graph_store.nodes_by_ids,
        scan_id=body.scan_id or "",
        tenant_id=_tenant(request),
        node_ids=set(body.roots),
    )
    known_roots = {node.id for node in root_nodes}
    missing_roots = [root for root in body.roots if root not in known_roots]
    if missing_roots:
        raise HTTPException(status_code=404, detail={"message": "Root nodes not found", "missing_roots": missing_roots})

    rel_types = _validate_relationship_list(body.relationship_types)
    deadline = time.monotonic() + (body.timeout_ms / 1000)
    traversal_graph, depth_by_node, truncated = await _graph_store_call(
        graph_store.traverse_subgraph,
        scan_id=body.scan_id or "",
        tenant_id=_tenant(request),
        roots=body.roots,
        direction=body.direction,
        max_depth=body.max_depth,
        max_nodes=body.max_nodes,
        max_edges=body.max_edges,
        deadline_monotonic=deadline,
        traversable_only=body.traversable_only,
        relationship_types=rel_types,
        static_only=body.static_only,
        dynamic_only=body.dynamic_only,
        include_roots=body.include_roots,
    )

    filtered_graph = _filtered_query_graph(
        traversal_graph,
        roots=body.roots,
        entity_types=set(_validate_entity_type_list(body.entity_types)),
        min_severity_rank=SEVERITY_RANK.get(body.min_severity.lower(), 0) if body.min_severity else 0,
        compliance_prefixes={prefix.upper() for prefix in body.compliance_prefixes},
        data_sources=set(body.data_sources),
    )

    attack_paths = []
    if body.include_attack_paths:
        root_attack_paths = await _graph_store_call(
            graph_store.attack_paths_for_sources,
            scan_id=body.scan_id or "",
            tenant_id=_tenant(request),
            source_ids=set(body.roots),
        )
        attack_paths = [
            _serialize_attack_path(ap, filtered_graph.edges, nodes_by_id=filtered_graph.nodes, scan_id=filtered_graph.scan_id)
            for ap in root_attack_paths
            if ap.source in body.roots and all(hop in filtered_graph.nodes for hop in ap.hops)
        ]

    return {
        "scan_id": filtered_graph.scan_id,
        "tenant_id": filtered_graph.tenant_id,
        "roots": body.roots,
        "direction": body.direction,
        "max_depth": body.max_depth,
        "max_nodes": body.max_nodes,
        "max_edges": body.max_edges,
        "timeout_ms": body.timeout_ms,
        "budget": budget,
        "truncated": truncated,
        "missing_roots": [],
        "depth_by_node": {node_id: depth for node_id, depth in depth_by_node.items() if node_id in filtered_graph.nodes},
        "nodes": [node.to_dict() for node in filtered_graph.nodes.values()],
        "edges": [edge.to_dict() for edge in filtered_graph.edges],
        "attack_paths": attack_paths,
        "stats": filtered_graph.stats(),
        "filters": GraphFilterOptions(
            max_depth=body.max_depth,
            min_severity=body.min_severity,
            relationship_types=rel_types or set(),
            static_only=body.static_only,
            dynamic_only=body.dynamic_only,
            include_ids=set(body.roots),
        ).to_dict(),
    }


@router.get("/v1/graph/node/{node_id}", tags=["graph"])
async def get_graph_node(
    request: Request,
    node_id: str,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
) -> dict:
    """Get a single node with its edges, neighbors, and impact stats."""
    node_context = await _graph_store_call(
        _get_graph_store_or_503().node_context,
        scan_id=scan_id or "",
        tenant_id=_tenant(request),
        node_id=node_id,
    )
    if node_context is None:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    return {
        "node": node_context["node"].to_dict(),
        "edges_out": [edge.to_dict() for edge in node_context["edges_out"]],
        "edges_in": [edge.to_dict() for edge in node_context["edges_in"]],
        "neighbors": node_context["neighbors"],
        "sources": node_context["sources"],
        "impact": node_context["impact"],
    }


@router.get("/v1/graph/snapshots", tags=["graph"])
async def get_graph_snapshots(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Max snapshots"),
) -> list[dict]:
    """List persisted scan snapshots ordered by creation time."""
    return await _graph_store_call(_get_graph_store_or_503().list_snapshots, tenant_id=_tenant(request), limit=limit)


@router.get("/v1/graph/history", tags=["graph"])
async def get_graph_history(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Max snapshots"),
) -> dict:
    """Return retained graph history and adjacent diff summaries for the request tenant."""
    return await _graph_store_call(_get_graph_store_or_503().graph_history, tenant_id=_tenant(request), limit=limit)


@router.get("/v1/graph/evidence-manifest", tags=["graph"])
async def get_graph_evidence_manifest(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
    baseline_scan_id: Optional[str] = Query(None, description="Optional diff baseline scan ID"),
) -> dict:
    """Return a redaction-aware reviewer manifest for a retained graph snapshot."""
    manifest = await _graph_store_call(
        _get_graph_store_or_503().evidence_manifest,
        tenant_id=_tenant(request),
        scan_id=scan_id or "",
        baseline_scan_id=baseline_scan_id or "",
    )
    if not manifest.get("scan_id"):
        raise HTTPException(status_code=404, detail="Graph snapshot not found")
    return manifest


@router.get("/v1/graph/compliance", tags=["graph"])
async def get_graph_compliance(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    framework: Optional[str] = Query(None, description="Filter by framework prefix (e.g. OWASP, NIST, MITRE, CIS, SOC2)"),
) -> dict:
    """Compliance posture across all frameworks — aggregated from graph nodes.

    Returns per-framework finding counts, severity breakdown, affected entity
    counts, and the list of tagged findings. Filter by framework to drill down.
    """
    return await _graph_store_call(
        _get_graph_store_or_503().compliance_summary,
        scan_id=scan_id or "",
        tenant_id=_tenant(request),
        framework=framework or "",
    )


@router.get("/v1/graph/legend", tags=["graph"])
async def get_graph_legend() -> dict:
    """Return entity and relationship legends for UI rendering."""
    from agent_bom.graph import ENTITY_LEGEND, RELATIONSHIP_LEGEND

    return {
        "entities": [{"key": e.key, "label": e.label, "color": e.color, "shape": e.shape, "layer": e.layer} for e in ENTITY_LEGEND],
        "relationships": [{"key": r.key, "label": r.label, "color": r.color} for r in RELATIONSHIP_LEGEND],
    }


# Map canonical "shape" hint → icon hint that the TS lineage-nodes module
# understands.  Keeping the mapping server-side means the TypeScript codegen
# stays a thin renderer; adding a new icon in lucide just means changing the
# server map and re-running the codegen.
_SHAPE_TO_ICON: dict[str, str] = {
    "circle": "circle",
    "diamond": "diamond",
    "square": "square",
    "triangle": "triangle",
}


_RESERVED_GRAPH_NODE_KINDS: dict[str, tuple[list[str], str]] = {
    EntityType.CODE_MODULE.value: (
        ["code_graph"],
        "Reserved for source-code topology; static supply-chain scans do not emit module-level nodes yet.",
    ),
    EntityType.EXTERNAL_IMPORT.value: (
        ["code_graph"],
        "Reserved for source-code import topology; static supply-chain scans do not emit import nodes yet.",
    ),
    EntityType.CI_JOB.value: (
        ["ci_graph"],
        "Reserved for CI/CD topology; scan jobs are tracked operationally but are not emitted as graph nodes yet.",
    ),
}


_RESERVED_GRAPH_EDGE_KINDS: dict[str, tuple[list[str], str]] = {
    RelationshipType.IMPORTS.value: (
        ["code_graph"],
        "Reserved for source-code topology linking files, modules, packages, and imports.",
    ),
    RelationshipType.DEFINES.value: (
        ["code_graph"],
        "Reserved for source-code topology linking source files to modules, tools, and CI jobs.",
    ),
    RelationshipType.RUNS.value: (
        ["ci_graph"],
        "Reserved for CI/CD topology linking workflow jobs to tools, servers, and agents.",
    ),
    RelationshipType.CONFIGURES.value: (
        ["code_graph"],
        "Reserved for configuration topology linking config files to agents, servers, CI jobs, and tools.",
    ),
    RelationshipType.OWNS.value: (
        ["identity_graph"],
        "Reserved for ownership imports from enterprise identity and cloud inventory sources.",
    ),
    RelationshipType.REMEDIATES.value: (
        ["remediation_graph"],
        "Reserved for fixed-version and remediation-plan graph edges.",
    ),
    RelationshipType.ACTED_AS.value: (
        ["runtime_graph"],
        "Reserved for explicit user/service-principal runtime delegation once traces carry that identity link.",
    ),
}


_EMITTED_GRAPH_NODE_SURFACES: dict[str, list[str]] = {
    EntityType.TOOL_CALL.value: ["runtime_proxy", "gateway_event_projection"],
    EntityType.RESOURCE.value: ["runtime_proxy", "gateway_event_projection", "cnapp_overlay"],
    # Repository folder/file-structure nodes emitted by the repo-structure
    # overlay for a code / project scan (directory tree + manifest files).
    EntityType.DIRECTORY.value: ["repo_structure_overlay"],
    EntityType.SOURCE_FILE.value: ["repo_structure_overlay"],
    EntityType.CONFIG_FILE.value: ["repo_structure_overlay"],
}


_EMITTED_GRAPH_EDGE_SURFACES: dict[str, list[str]] = {
    RelationshipType.CALLED.value: ["runtime_proxy", "gateway_event_projection"],
    RelationshipType.USED_CREDENTIAL.value: ["runtime_proxy", "gateway_event_projection"],
}


def _graph_schema_emission_meta(
    key: str,
    *,
    reserved: dict[str, tuple[list[str], str]],
    emitted_surfaces: dict[str, list[str]],
    default_surfaces: list[str],
) -> dict[str, object]:
    """Document whether a graph kind is emitted today or reserved vocabulary."""
    if key in reserved:
        surfaces, notes = reserved[key]
        return {
            "emission_status": "reserved",
            "emission_surfaces": surfaces,
            "emission_notes": notes,
        }
    return {
        "emission_status": "emitted",
        "emission_surfaces": emitted_surfaces.get(key, default_surfaces),
        "emission_notes": "Emitted by at least one graph builder or runtime projection.",
    }


_RELATIONSHIP_SCHEMA_META: dict[str, dict[str, object]] = {
    RelationshipType.HOSTS.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [
            EntityType.PROVIDER.value,
            EntityType.ENVIRONMENT.value,
            EntityType.FLEET.value,
            EntityType.ACCOUNT.value,
            EntityType.CLOUD_RESOURCE.value,
        ],
        "target_types": [
            EntityType.ACCOUNT.value,
            EntityType.ORG.value,
            EntityType.AGENT.value,
            EntityType.SERVER.value,
            EntityType.CLOUD_RESOURCE.value,
        ],
        "traversable": True,
    },
    RelationshipType.USES.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [EntityType.AGENT.value],
        "target_types": [EntityType.SERVER.value],
        "traversable": True,
    },
    RelationshipType.DEPENDS_ON.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [
            EntityType.SERVER.value,
            EntityType.CONTAINER.value,
            EntityType.CONFIG_FILE.value,
            EntityType.SOURCE_FILE.value,
        ],
        "target_types": [EntityType.PACKAGE.value],
        "traversable": True,
    },
    RelationshipType.PROVIDES_TOOL.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [EntityType.SERVER.value],
        "target_types": [EntityType.TOOL.value],
        "traversable": True,
    },
    RelationshipType.EXPOSES_CRED.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [EntityType.SERVER.value, EntityType.AGENT.value],
        "target_types": [EntityType.CREDENTIAL.value],
        "traversable": True,
    },
    RelationshipType.REACHES_TOOL.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [EntityType.CREDENTIAL.value, EntityType.AGENT.value],
        "target_types": [EntityType.TOOL.value],
        "traversable": True,
    },
    RelationshipType.SERVES_MODEL.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [EntityType.SERVER.value],
        "target_types": [EntityType.MODEL.value],
        "traversable": True,
    },
    RelationshipType.CONTAINS.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [
            EntityType.CONTAINER.value,
            EntityType.CLUSTER.value,
            EntityType.FLEET.value,
            EntityType.DIRECTORY.value,
        ],
        "target_types": [
            EntityType.PACKAGE.value,
            EntityType.SERVER.value,
            EntityType.CONTAINER.value,
            EntityType.DIRECTORY.value,
            EntityType.SOURCE_FILE.value,
            EntityType.CONFIG_FILE.value,
        ],
        "traversable": True,
    },
    RelationshipType.IMPORTS.value: {
        "category": "code_topology",
        "direction": "directed",
        "source_types": [EntityType.SOURCE_FILE.value, EntityType.CODE_MODULE.value],
        "target_types": [EntityType.EXTERNAL_IMPORT.value, EntityType.CODE_MODULE.value, EntityType.PACKAGE.value],
        "traversable": True,
    },
    RelationshipType.DEFINES.value: {
        "category": "code_topology",
        "direction": "directed",
        "source_types": [EntityType.SOURCE_FILE.value],
        "target_types": [EntityType.CODE_MODULE.value, EntityType.TOOL.value, EntityType.CI_JOB.value],
        "traversable": True,
    },
    RelationshipType.RUNS.value: {
        "category": "code_topology",
        "direction": "directed",
        "source_types": [EntityType.CI_JOB.value],
        "target_types": [EntityType.TOOL.value, EntityType.SERVER.value, EntityType.AGENT.value],
        "traversable": True,
    },
    RelationshipType.CONFIGURES.value: {
        "category": "code_topology",
        "direction": "directed",
        "source_types": [EntityType.CONFIG_FILE.value],
        "target_types": [EntityType.AGENT.value, EntityType.SERVER.value, EntityType.CI_JOB.value, EntityType.TOOL.value],
        "traversable": True,
    },
    RelationshipType.AFFECTS.value: {
        "category": "vulnerability",
        "direction": "directed",
        "source_types": [EntityType.VULNERABILITY.value, EntityType.MISCONFIGURATION.value],
        "target_types": [
            EntityType.PACKAGE.value,
            EntityType.SERVER.value,
            EntityType.CONTAINER.value,
            EntityType.SOURCE_FILE.value,
            EntityType.CONFIG_FILE.value,
        ],
        "traversable": True,
    },
    RelationshipType.VULNERABLE_TO.value: {
        "category": "vulnerability",
        "direction": "directed",
        "source_types": [EntityType.PACKAGE.value, EntityType.SERVER.value, EntityType.CONTAINER.value],
        "target_types": [EntityType.VULNERABILITY.value],
        "traversable": True,
    },
    RelationshipType.EXPLOITABLE_VIA.value: {
        "category": "vulnerability",
        "direction": "directed",
        "source_types": [EntityType.VULNERABILITY.value, EntityType.MISCONFIGURATION.value],
        "target_types": [EntityType.TOOL.value, EntityType.CREDENTIAL.value],
        "traversable": True,
    },
    RelationshipType.REMEDIATES.value: {
        "category": "vulnerability",
        "direction": "directed",
        "source_types": [EntityType.PACKAGE.value],
        "target_types": [EntityType.VULNERABILITY.value, EntityType.MISCONFIGURATION.value],
        "traversable": False,
    },
    RelationshipType.TRIGGERS.value: {
        "category": "vulnerability",
        "direction": "directed",
        "source_types": [EntityType.VULNERABILITY.value],
        "target_types": [EntityType.MISCONFIGURATION.value],
        "traversable": True,
    },
    RelationshipType.SHARES_SERVER.value: {
        "category": "lateral_movement",
        "direction": "bidirectional",
        "source_types": [EntityType.AGENT.value],
        "target_types": [EntityType.AGENT.value],
        "traversable": True,
    },
    RelationshipType.SHARES_CRED.value: {
        "category": "lateral_movement",
        "direction": "bidirectional",
        "source_types": [EntityType.AGENT.value],
        "target_types": [EntityType.AGENT.value],
        "traversable": True,
    },
    RelationshipType.LATERAL_PATH.value: {
        "category": "lateral_movement",
        "direction": "directed",
        "source_types": [EntityType.AGENT.value],
        "target_types": [EntityType.AGENT.value],
        "traversable": True,
    },
    RelationshipType.MANAGES.value: {
        "category": "governance",
        "direction": "directed",
        "source_types": [
            EntityType.USER.value,
            EntityType.GROUP.value,
            EntityType.ROLE.value,
            EntityType.SERVICE_ACCOUNT.value,
            EntityType.SERVICE_PRINCIPAL.value,
            EntityType.FEDERATED_IDENTITY.value,
        ],
        "target_types": [EntityType.AGENT.value, EntityType.FLEET.value, EntityType.ENVIRONMENT.value, EntityType.CLOUD_RESOURCE.value],
        "traversable": True,
    },
    RelationshipType.OWNS.value: {
        "category": "governance",
        "direction": "directed",
        "source_types": [
            EntityType.ORG.value,
            EntityType.ACCOUNT.value,
            EntityType.USER.value,
            EntityType.GROUP.value,
            EntityType.ROLE.value,
            EntityType.SERVICE_ACCOUNT.value,
            EntityType.SERVICE_PRINCIPAL.value,
        ],
        "target_types": [EntityType.ENVIRONMENT.value, EntityType.CLOUD_RESOURCE.value, EntityType.AGENT.value],
        "traversable": True,
    },
    RelationshipType.PART_OF.value: {
        "category": "governance",
        "direction": "directed",
        "source_types": [EntityType.ACCOUNT.value, EntityType.AGENT.value, EntityType.SERVER.value, EntityType.CONTAINER.value],
        "target_types": [EntityType.ORG.value, EntityType.FLEET.value, EntityType.CLUSTER.value, EntityType.ENVIRONMENT.value],
        "traversable": True,
    },
    RelationshipType.MEMBER_OF.value: {
        "category": "governance",
        "direction": "directed",
        "source_types": [
            EntityType.USER.value,
            EntityType.GROUP.value,
            EntityType.ROLE.value,
            EntityType.SERVICE_ACCOUNT.value,
            EntityType.SERVICE_PRINCIPAL.value,
            EntityType.FEDERATED_IDENTITY.value,
            EntityType.AGENT.value,
        ],
        "target_types": [EntityType.ACCOUNT.value, EntityType.GROUP.value, EntityType.AGENT.value, EntityType.FLEET.value],
        "traversable": True,
    },
    RelationshipType.ASSUMES.value: {
        "category": "identity",
        "direction": "directed",
        "source_types": [
            EntityType.USER.value,
            EntityType.SERVICE_ACCOUNT.value,
            EntityType.SERVICE_PRINCIPAL.value,
            EntityType.FEDERATED_IDENTITY.value,
        ],
        "target_types": [EntityType.ROLE.value],
        "traversable": True,
    },
    RelationshipType.TRUSTS.value: {
        "category": "identity",
        "direction": "directed",
        "source_types": [EntityType.ROLE.value, EntityType.ACCOUNT.value],
        "target_types": [
            EntityType.ACCOUNT.value,
            EntityType.USER.value,
            EntityType.GROUP.value,
            EntityType.ROLE.value,
            EntityType.SERVICE_ACCOUNT.value,
            EntityType.SERVICE_PRINCIPAL.value,
            EntityType.FEDERATED_IDENTITY.value,
        ],
        "traversable": True,
    },
    RelationshipType.ATTACHED.value: {
        "category": "identity",
        "direction": "directed",
        "source_types": [
            EntityType.USER.value,
            EntityType.GROUP.value,
            EntityType.ROLE.value,
            EntityType.SERVICE_ACCOUNT.value,
            EntityType.SERVICE_PRINCIPAL.value,
            EntityType.MANAGED_IDENTITY.value,
        ],
        "target_types": [EntityType.POLICY.value, EntityType.ACCESS_GRANT.value],
        "traversable": True,
    },
    RelationshipType.INHERITS.value: {
        "category": "identity",
        "direction": "directed",
        "source_types": [
            EntityType.USER.value,
            EntityType.GROUP.value,
            EntityType.ROLE.value,
            EntityType.SERVICE_ACCOUNT.value,
            EntityType.SERVICE_PRINCIPAL.value,
        ],
        "target_types": [EntityType.POLICY.value, EntityType.ROLE.value],
        "traversable": True,
    },
    RelationshipType.CAN_ACCESS.value: {
        "category": "identity",
        "direction": "directed",
        "source_types": [
            EntityType.ACCOUNT.value,
            EntityType.USER.value,
            EntityType.GROUP.value,
            EntityType.ROLE.value,
            EntityType.SERVICE_ACCOUNT.value,
            EntityType.SERVICE_PRINCIPAL.value,
            EntityType.FEDERATED_IDENTITY.value,
        ],
        "target_types": [EntityType.CLOUD_RESOURCE.value, EntityType.DATASET.value, EntityType.CREDENTIAL.value, EntityType.RESOURCE.value],
        "traversable": True,
    },
    RelationshipType.CROSS_ACCOUNT_TRUST.value: {
        "category": "identity",
        "direction": "directed",
        "source_types": [
            EntityType.ACCOUNT.value,
            EntityType.ROLE.value,
            EntityType.SERVICE_PRINCIPAL.value,
            EntityType.FEDERATED_IDENTITY.value,
        ],
        "target_types": [
            EntityType.ACCOUNT.value,
            EntityType.ROLE.value,
            EntityType.SERVICE_PRINCIPAL.value,
            EntityType.FEDERATED_IDENTITY.value,
        ],
        "traversable": True,
    },
    RelationshipType.ACTED_AS.value: {
        "category": "runtime",
        "direction": "directed",
        "source_types": [
            EntityType.USER.value,
            EntityType.SERVICE_ACCOUNT.value,
            EntityType.SERVICE_PRINCIPAL.value,
            EntityType.FEDERATED_IDENTITY.value,
        ],
        "target_types": [EntityType.AGENT.value],
        "traversable": True,
    },
    RelationshipType.INVOKED.value: {
        "category": "runtime",
        "direction": "directed",
        "source_types": [EntityType.AGENT.value, EntityType.USER.value],
        "target_types": [EntityType.TOOL.value, EntityType.TOOL_CALL.value],
        "traversable": True,
    },
    RelationshipType.CALLED.value: {
        "category": "runtime",
        "direction": "directed",
        "source_types": [EntityType.TOOL_CALL.value, EntityType.AGENT.value],
        "target_types": [EntityType.TOOL.value, EntityType.SERVER.value],
        "traversable": True,
    },
    RelationshipType.USED_CREDENTIAL.value: {
        "category": "runtime",
        "direction": "directed",
        "source_types": [EntityType.TOOL_CALL.value, EntityType.AGENT.value, EntityType.TOOL.value],
        "target_types": [EntityType.CREDENTIAL_REF.value, EntityType.CREDENTIAL.value],
        "traversable": True,
    },
    RelationshipType.ACCESSED.value: {
        "category": "runtime",
        "direction": "directed",
        "source_types": [EntityType.TOOL.value, EntityType.TOOL_CALL.value],
        "target_types": [
            EntityType.CLOUD_RESOURCE.value,
            EntityType.DATASET.value,
            EntityType.CREDENTIAL.value,
            EntityType.CREDENTIAL_REF.value,
            EntityType.RESOURCE.value,
        ],
        "traversable": True,
    },
    RelationshipType.DELEGATED_TO.value: {
        "category": "runtime",
        "direction": "directed",
        "source_types": [EntityType.AGENT.value],
        "target_types": [EntityType.AGENT.value],
        "traversable": True,
    },
    RelationshipType.CORRELATES_WITH.value: {
        "category": "correlation",
        "direction": "bidirectional",
        "source_types": [EntityType.AGENT.value, EntityType.SERVER.value],
        "target_types": [EntityType.AGENT.value, EntityType.SERVER.value],
        "traversable": True,
    },
    RelationshipType.POSSIBLY_CORRELATES_WITH.value: {
        "category": "correlation",
        "direction": "bidirectional",
        "source_types": [EntityType.AGENT.value, EntityType.SERVER.value],
        "target_types": [EntityType.AGENT.value, EntityType.SERVER.value],
        "traversable": False,
    },
    RelationshipType.AUTHENTICATES_AS.value: {
        "category": "governance",
        "direction": "directed",
        "source_types": [EntityType.AGENT.value],
        "target_types": [EntityType.MANAGED_IDENTITY.value],
        "traversable": True,
    },
    RelationshipType.SCOPED_TO.value: {
        "category": "governance",
        "direction": "directed",
        "source_types": [
            EntityType.MANAGED_IDENTITY.value,
            EntityType.ACCESS_GRANT.value,
            EntityType.DRIFT_INCIDENT.value,
        ],
        "target_types": [EntityType.TOOL.value],
        "traversable": True,
    },
    RelationshipType.GOVERNS.value: {
        "category": "governance",
        "direction": "directed",
        "source_types": [EntityType.ACCESS_POLICY.value],
        "target_types": [EntityType.AGENT.value, EntityType.MANAGED_IDENTITY.value, EntityType.TOOL.value],
        "traversable": False,
    },
    RelationshipType.EXHIBITS_DRIFT.value: {
        "category": "governance",
        "direction": "bidirectional",
        "source_types": [EntityType.AGENT.value],
        "target_types": [EntityType.DRIFT_INCIDENT.value],
        "traversable": True,
    },
    RelationshipType.EXPOSED_TO.value: {
        "category": "exposure",
        "direction": "directed",
        "source_types": [
            EntityType.CLOUD_RESOURCE.value,
            EntityType.SERVER.value,
            EntityType.AGENT.value,
            EntityType.DATA_STORE.value,
        ],
        "target_types": [EntityType.CLOUD_RESOURCE.value, EntityType.RESOURCE.value, EntityType.DATA_STORE.value],
        "traversable": True,
    },
    RelationshipType.STORES.value: {
        "category": "exposure",
        "direction": "directed",
        "source_types": [EntityType.CLOUD_RESOURCE.value, EntityType.DATA_STORE.value, EntityType.SERVER.value],
        "target_types": [EntityType.DATASET.value, EntityType.DATA_STORE.value],
        "traversable": True,
    },
    RelationshipType.HAS_PERMISSION.value: {
        "category": "identity",
        "direction": "directed",
        "source_types": [
            EntityType.USER.value,
            EntityType.ROLE.value,
            EntityType.SERVICE_ACCOUNT.value,
            EntityType.SERVICE_PRINCIPAL.value,
            EntityType.MANAGED_IDENTITY.value,
        ],
        "target_types": [EntityType.CLOUD_RESOURCE.value, EntityType.DATA_STORE.value, EntityType.RESOURCE.value, EntityType.TOOL.value],
        "traversable": True,
    },
    RelationshipType.PROTECTS.value: {
        "category": "exposure",
        "direction": "directed",
        "source_types": [EntityType.API_GATEWAY.value, EntityType.CLOUD_RESOURCE.value],
        "target_types": [EntityType.CLOUD_RESOURCE.value, EntityType.DATA_STORE.value, EntityType.RESOURCE.value],
        "traversable": True,
    },
    RelationshipType.BELONGS_TO.value: {
        "category": "aspm",
        "direction": "directed",
        "source_types": [
            EntityType.VULNERABILITY.value,
            EntityType.MISCONFIGURATION.value,
            EntityType.PACKAGE.value,
            EntityType.CONTAINER.value,
            EntityType.CLOUD_RESOURCE.value,
            EntityType.SERVER.value,
            EntityType.CREDENTIAL.value,
        ],
        "target_types": [EntityType.APPLICATION.value],
        "traversable": True,
    },
}


@router.get("/v1/graph/schema", tags=["graph"])
async def get_graph_schema() -> dict:
    """Canonical graph entity/edge taxonomy — single source of truth.

    Drives the TypeScript codegen at ``ui/scripts/codegen-graph-schema.mjs``,
    which materialises ``ui/lib/graph-schema.generated.ts``.  CI fails the
    build when the checked-in generated file drifts from what this endpoint
    would emit, so adding a new ``EntityType`` or ``RelationshipType`` in
    Python automatically forces a regen + commit on the UI side.
    """
    from agent_bom.graph import ENTITY_LEGEND, ENTITY_OCSF_MAP, RELATIONSHIP_LEGEND
    from agent_bom.graph.types import EntityType, RelationshipType

    legend_entities = {entry.key: entry for entry in ENTITY_LEGEND}
    legend_relationships = {entry.key: entry for entry in RELATIONSHIP_LEGEND}

    node_kinds = []
    for entity in EntityType:
        legend = legend_entities.get(entity.value)
        label = legend.label if legend else entity.value.replace("_", " ").title()
        color = legend.color if legend else "#6b7280"
        shape = legend.shape if legend else "circle"
        layer = legend.layer if legend and legend.layer else GraphSemanticLayer.ASSET.value
        node_kinds.append(
            {
                "key": entity.value,
                "label": label,
                "color": color,
                "shape": shape,
                "layer": layer,
                "icon": _SHAPE_TO_ICON.get(shape, "circle"),
                "category_uid": ENTITY_OCSF_MAP.get(entity.value, {}).get("category_uid", 0),
                "class_uid": ENTITY_OCSF_MAP.get(entity.value, {}).get("class_uid", 0),
                **_graph_schema_emission_meta(
                    entity.value,
                    reserved=_RESERVED_GRAPH_NODE_KINDS,
                    emitted_surfaces=_EMITTED_GRAPH_NODE_SURFACES,
                    default_surfaces=["static_scan", "graph_overlay"],
                ),
            }
        )

    edge_kinds = []
    for rel in RelationshipType:
        legend = legend_relationships.get(rel.value)
        label = legend.label if legend else rel.value.replace("_", " ").title()
        color = legend.color if legend else "#6b7280"
        edge_kinds.append(
            {
                "key": rel.value,
                "label": label,
                "color": color,
                **_graph_schema_emission_meta(
                    rel.value,
                    reserved=_RESERVED_GRAPH_EDGE_KINDS,
                    emitted_surfaces=_EMITTED_GRAPH_EDGE_SURFACES,
                    default_surfaces=["static_scan", "graph_overlay", "computed_path"],
                ),
                **_RELATIONSHIP_SCHEMA_META.get(
                    rel.value,
                    {
                        "category": "custom",
                        "direction": "directed",
                        "source_types": [],
                        "target_types": [],
                        "traversable": True,
                    },
                ),
            }
        )

    return {
        "version": 1,
        "semantic_layers": [{"key": layer.value, "label": _SEMANTIC_LAYER_LABELS[layer.value]} for layer in GraphSemanticLayer],
        "node_kinds": sorted(node_kinds, key=lambda d: d["key"]),
        "edge_kinds": sorted(edge_kinds, key=lambda d: d["key"]),
        "node_types": sorted(entity.value for entity in EntityType),
        "edge_types": sorted(rel.value for rel in RelationshipType),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Saved filter presets
# ═══════════════════════════════════════════════════════════════════════════


@router.post("/v1/graph/presets", tags=["graph"])
async def create_preset(request: Request, body: PresetCreate) -> dict:
    """Save a named graph filter preset for the current tenant."""
    from agent_bom.graph.util import _now_iso

    tenant = _tenant(request)
    await _graph_store_call(
        _get_graph_store_or_503().save_preset,
        tenant_id=tenant,
        name=body.name,
        description=body.description,
        filters=body.filters,
        created_at=_now_iso(),
    )
    return {"name": body.name, "status": "saved"}


@router.get("/v1/graph/presets", tags=["graph"])
async def list_presets(request: Request) -> list[dict]:
    """List saved filter presets for the current tenant."""
    return await _graph_store_call(_get_graph_store_or_503().list_presets, tenant_id=_tenant(request))


@router.delete("/v1/graph/presets/{name}", tags=["graph"])
async def delete_preset(request: Request, name: str) -> dict:
    """Delete a saved filter preset."""
    deleted = await _graph_store_call(_get_graph_store_or_503().delete_preset, tenant_id=_tenant(request), name=name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Preset '{name}' not found")
    return {"name": name, "status": "deleted"}


# ═══════════════════════════════════════════════════════════════════════════
# Estate-scale roll-up (CONTAINS) — backend for the UI graph-nav drill-down
# ═══════════════════════════════════════════════════════════════════════════


@router.get("/v1/graph/rollup", tags=["graph"])
async def get_graph_rollup(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
    node: Optional[str] = Query(None, description="Drill down into a container node's direct children"),
    min_severity: Optional[str] = Query(None, description="Only roll up descendants at/above this severity"),
    exposed: bool = Query(False, description="Only roll up internet-exposed descendants"),
    toxic: bool = Query(False, description="Only roll up toxic-combination descendants"),
    mode: Literal["rollup", "attack_path"] = Query("rollup", description="rollup (default) or attack_path-first view"),
) -> dict:
    """Collapse the estate along ``CONTAINS`` into a small, readable view.

    Past a few hundred nodes the raw topology is an unreadable hairball. This
    endpoint rolls the graph up along the containment hierarchy
    (org -> account/project -> app -> resource) so a 1000+ node estate renders
    as a handful of top-level containers, each carrying aggregate descendant
    counts, worst-severity, a per-severity histogram, and exposure / toxic
    flags. ``?node=<id>`` returns one level of direct children for on-demand
    drill-down; ``?mode=attack_path`` returns the nodes/edges on materialised
    attack paths first with the rest collapsed.

    Backend for the UI graph-navigation surface. Read-only: never mutates the
    source graph.
    """
    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    requested_scan_id = scan_id or ""

    if not requested_scan_id and not await _graph_store_call(graph_store.latest_snapshot_id, tenant_id=tenant):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    if min_severity and min_severity.lower() not in SEVERITY_RANK:
        raise HTTPException(status_code=422, detail=f"Unsupported severity: {min_severity}")

    try:
        graph = await _graph_store_call(
            graph_store.load_graph,
            scan_id=requested_scan_id,
            tenant_id=tenant,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    try:
        return await _graph_compute_call(
            _graph_rollup_payload,
            graph,
            node=node,
            min_severity=(min_severity or "").lower(),
            exposed=exposed,
            toxic=toxic,
            mode=mode,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Never leak internal exception detail in the response (CodeQL lesson).
        logger.warning("graph rollup failed", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to compute graph roll-up") from exc
