"""Graph query API — unified graph data with filters, pagination, RBAC, presets.

Endpoints:
  GET  /v1/graph                — load unified graph (filtered, paginated)
  GET  /v1/graph/diff           — diff between two scan snapshots
  GET  /v1/graph/attack-paths   — global risk-sorted attack path queue
  GET  /v1/graph/paths          — attack paths from a source node
  GET  /v1/graph/impact         — blast radius of a node (reverse BFS)
  GET  /v1/graph/search         — full-text graph search
  GET  /v1/graph/agents         — paginated agent node selector
  POST /v1/graph/query          — programmable traversal query
  GET  /v1/graph/node/{id}      — single node detail with edges + impact
  GET  /v1/graph/snapshots      — list persisted scan snapshots
  GET  /v1/graph/legend         — entity + relationship legends
  GET  /v1/graph/schema         — canonical entity/edge taxonomy (codegen source)
  POST /v1/graph/presets        — save a filter preset
  GET  /v1/graph/presets        — list saved presets
  DEL  /v1/graph/presets/{name} — delete a preset
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Literal, Optional
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from agent_bom.api.stores import _get_graph_store
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.graph import SEVERITY_RANK, AttackPath, EntityType, GraphFilterOptions, GraphSemanticLayer, RelationshipType, UnifiedGraph
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
}


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _get_graph_store_or_503():
    """Resolve the active graph store backend."""
    return _get_graph_store()


def _tenant(request: Request) -> str:
    """Extract tenant_id from request (set by auth middleware)."""
    return getattr(request.state, "tenant_id", "default")


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
    ids: list[str] = []
    seen: set[str] = set()
    for value in vuln_ids:
        cleaned = value.strip()
        if cleaned and cleaned not in seen:
            ids.append(cleaned)
            seen.add(cleaned)
    for hop in path_hops:
        node = graph.nodes.get(hop)
        if not node or node.entity_type not in {EntityType.VULNERABILITY, EntityType.MISCONFIGURATION}:
            continue
        label = node.label or node.id
        if label not in seen:
            ids.append(label)
            seen.add(label)
    return ids


def _first_href_for_agent(agent: str) -> str:
    return f"/agents?name={quote(agent)}"


def _risk_reasons_for_path(graph: UnifiedGraph, path) -> list[dict[str, str]]:
    reasons: list[dict[str, str]] = []
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


def _node_type_value(node) -> str:
    return node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)


def _node_risk_100(node) -> float:
    risk = float(getattr(node, "risk_score", 0.0) or 0.0)
    if risk <= 10.0:
        risk *= 10.0
    if risk <= 0:
        risk = float(SEVERITY_RANK.get(str(getattr(node, "severity", "") or "").lower(), 0) * 20)
    return max(0.0, min(100.0, risk))


def _derived_attack_paths(graph: UnifiedGraph) -> list[AttackPath]:
    """Derive fix-first paths when a snapshot lacks materialised path rows.

    Older snapshots and some stores have rich topology but no `attack_paths`
    records. Security operators still need the obvious chain:
    agent -> MCP server -> package/server -> vulnerability, enriched with the
    server's credential and tool exposure. Keep this deterministic and bounded;
    stores with first-class path rows remain the source of truth.
    """
    if graph.attack_paths:
        return list(graph.attack_paths)

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
                    key = (agent_id, server_id, vulnerable_source.id, finding.id)
                    if key in seen:
                        continue
                    seen.add(key)

                    risk = _node_risk_100(finding)
                    risk += min(10.0, len(credentials) * 3.0)
                    risk += min(10.0, len(tools) * 0.75)
                    paths.append(
                        AttackPath(
                            source=agent_id,
                            target=finding.id,
                            hops=hop_ids,
                            edges=[],
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


# ═══════════════════════════════════════════════════════════════════════════
# Preset model
# ═══════════════════════════════════════════════════════════════════════════


class PresetCreate(BaseModel):
    name: str
    description: str = ""
    filters: dict


class GraphQueryRequest(BaseModel):
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
    requested_scan_id = scan_id or ""

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
        rel_set = _parse_relationship_filter(relationships)
        filters = GraphFilterOptions(
            relationship_types=rel_set,
            static_only=static_only,
            dynamic_only=dynamic_only,
            max_depth=max_depth or 6,
        )
        graph = graph.filtered_view(filters)

        stats = graph.stats()
        all_nodes = list(graph.nodes.values())
        paged_nodes, pagination = _paginate(all_nodes, offset, limit)
        paged_ids = {n.id for n in paged_nodes}
        paged_edges = [e for e in graph.edges if e.source in paged_ids and e.target in paged_ids]
        attack_paths = [p.to_dict() for p in _derived_attack_paths(graph) if p.hops and all(hop in paged_ids for hop in p.hops)]
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
    return {
        "scan_id": effective_scan_id,
        "tenant_id": tenant,
        "created_at": created_at,
        "nodes": [n.to_dict() for n in paged_nodes],
        "edges": [e.to_dict() for e in paged_edges],
        "attack_paths": [path.to_dict() for path in source_attack_paths],
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


@router.get("/v1/graph/views/fix-first", tags=["graph"])
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
    a Wiz/Orca-style remediation cockpit. The full topology remains available
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


@router.get("/v1/graph/diff", tags=["graph"])
async def get_graph_diff(
    request: Request,
    old: str = Query(..., description="Old scan ID"),
    new: str = Query(..., description="New scan ID"),
) -> dict:
    """Diff two scan snapshots — nodes/edges added, removed, changed."""
    return await _graph_store_call(_get_graph_store_or_503().diff_snapshots, old, new, tenant_id=_tenant(request))


@router.get("/v1/graph/attack-paths", tags=["graph"])
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
        derived_paths = _derived_attack_paths(graph)
        total = len(derived_paths)
        paths = derived_paths[offset : offset + limit]
        created_at = graph.created_at
    hop_ids = {hop for path in paths for hop in path.hops}
    nodes = await _graph_store_call(
        graph_store.nodes_by_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=hop_ids,
    )
    stats = await _graph_store_call(
        graph_store.snapshot_stats,
        scan_id=effective_scan_id,
        tenant_id=tenant,
    )
    if total and int(stats.get("attack_path_count") or 0) == 0:
        stats = {
            **stats,
            "attack_path_count": total,
            "max_attack_path_risk": max((path.composite_risk for path in paths), default=0.0),
        }
    return {
        "scan_id": effective_scan_id,
        "tenant_id": tenant,
        "created_at": created_at,
        "nodes": [node.to_dict() for node in nodes],
        "edges": [],
        "attack_paths": [path.to_dict() for path in paths],
        "interaction_risks": [],
        "stats": stats,
        "pagination": _page_meta(total, offset, limit),
    }


@router.get("/v1/graph/paths", tags=["graph"])
async def get_graph_paths(
    request: Request,
    source: str = Query(..., description="Source node ID (e.g. agent:claude-desktop)"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    max_depth: int = Query(4, ge=1, le=10, description="Maximum BFS depth"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Max paths"),
) -> dict:
    """Find all attack paths from a source node via BFS."""
    graph_store = _get_graph_store_or_503()
    source_nodes = await _graph_store_call(graph_store.nodes_by_ids, scan_id=scan_id or "", tenant_id=_tenant(request), node_ids={source})
    if not source_nodes:
        raise HTTPException(status_code=404, detail=f"Node '{source}' not found in graph")

    all_paths, reachable = await _graph_store_call(
        graph_store.bfs_paths,
        scan_id=scan_id or "",
        tenant_id=_tenant(request),
        source=source,
        max_depth=max_depth,
        traversable_only=True,
    )
    paged_paths, pagination = _paginate(all_paths, offset, limit)
    attack_paths = await _graph_store_call(
        graph_store.attack_paths_for_sources,
        scan_id=scan_id or "",
        tenant_id=_tenant(request),
        source_ids={source},
    )

    return {
        "source": source,
        "max_depth": max_depth,
        "reachable_count": len(reachable),
        "reachable_nodes": sorted(reachable),
        "paths": [{"target": p[-1], "hops": p, "depth": len(p) - 1} for p in paged_paths],
        "attack_paths": [ap.to_dict() for ap in attack_paths if ap.source == source],
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
            ap.to_dict() for ap in root_attack_paths if ap.source in body.roots and all(hop in filtered_graph.nodes for hop in ap.hops)
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


_RELATIONSHIP_SCHEMA_META: dict[str, dict[str, object]] = {
    RelationshipType.HOSTS.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [EntityType.PROVIDER.value, EntityType.ENVIRONMENT.value, EntityType.FLEET.value],
        "target_types": [EntityType.AGENT.value, EntityType.SERVER.value],
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
        "source_types": [EntityType.SERVER.value, EntityType.CONTAINER.value],
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
        "source_types": [EntityType.CONTAINER.value, EntityType.CLUSTER.value, EntityType.FLEET.value],
        "target_types": [EntityType.PACKAGE.value, EntityType.SERVER.value, EntityType.CONTAINER.value],
        "traversable": True,
    },
    RelationshipType.AFFECTS.value: {
        "category": "vulnerability",
        "direction": "directed",
        "source_types": [EntityType.VULNERABILITY.value, EntityType.MISCONFIGURATION.value],
        "target_types": [EntityType.PACKAGE.value, EntityType.SERVER.value, EntityType.CONTAINER.value],
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
        "source_types": [EntityType.USER.value, EntityType.GROUP.value, EntityType.SERVICE_ACCOUNT.value],
        "target_types": [EntityType.AGENT.value, EntityType.FLEET.value, EntityType.ENVIRONMENT.value],
        "traversable": True,
    },
    RelationshipType.OWNS.value: {
        "category": "governance",
        "direction": "directed",
        "source_types": [EntityType.USER.value, EntityType.GROUP.value, EntityType.SERVICE_ACCOUNT.value],
        "target_types": [EntityType.ENVIRONMENT.value, EntityType.CLOUD_RESOURCE.value, EntityType.AGENT.value],
        "traversable": True,
    },
    RelationshipType.PART_OF.value: {
        "category": "governance",
        "direction": "directed",
        "source_types": [EntityType.AGENT.value, EntityType.SERVER.value, EntityType.CONTAINER.value],
        "target_types": [EntityType.FLEET.value, EntityType.CLUSTER.value, EntityType.ENVIRONMENT.value],
        "traversable": True,
    },
    RelationshipType.MEMBER_OF.value: {
        "category": "governance",
        "direction": "directed",
        "source_types": [EntityType.USER.value, EntityType.SERVICE_ACCOUNT.value, EntityType.AGENT.value],
        "target_types": [EntityType.GROUP.value, EntityType.AGENT.value, EntityType.FLEET.value],
        "traversable": True,
    },
    RelationshipType.INVOKED.value: {
        "category": "runtime",
        "direction": "directed",
        "source_types": [EntityType.AGENT.value],
        "target_types": [EntityType.TOOL.value],
        "traversable": True,
    },
    RelationshipType.ACCESSED.value: {
        "category": "runtime",
        "direction": "directed",
        "source_types": [EntityType.TOOL.value],
        "target_types": [EntityType.CLOUD_RESOURCE.value, EntityType.DATASET.value, EntityType.CREDENTIAL.value],
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
