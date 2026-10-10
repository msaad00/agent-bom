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
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any, Callable, Literal, Optional, TypeVar, cast

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.routing import APIRoute
from starlette.responses import JSONResponse, Response

from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.api.graph_compromise import GraphCompromiseRequest, GraphCompromiseResponse, assess_snapshot
from agent_bom.api.graph_contracts import (
    _ATTACK_PATH_ITEM_OPENAPI_SCHEMA as _ATTACK_PATH_ITEM_OPENAPI_SCHEMA,
)
from agent_bom.api.graph_contracts import (
    _ATTACK_PATHS_OPENAPI_RESPONSE as _ATTACK_PATHS_OPENAPI_RESPONSE,
)
from agent_bom.api.graph_contracts import (
    _EXPOSURE_PATH_OPENAPI_SCHEMA as _EXPOSURE_PATH_OPENAPI_SCHEMA,
)
from agent_bom.api.graph_contracts import (
    _FIX_FIRST_VIEW_OPENAPI_RESPONSE as _FIX_FIRST_VIEW_OPENAPI_RESPONSE,
)
from agent_bom.api.graph_contracts import (
    _TECHNIQUE_MAPPING_OPENAPI_SCHEMA as _TECHNIQUE_MAPPING_OPENAPI_SCHEMA,
)
from agent_bom.api.graph_contracts import (
    GraphCompletenessResponse as GraphCompletenessResponse,
)
from agent_bom.api.graph_contracts import (
    GraphDeployDecisionRequest as GraphDeployDecisionRequest,
)
from agent_bom.api.graph_contracts import (
    GraphIdentifier as GraphIdentifier,
)
from agent_bom.api.graph_contracts import (
    GraphScopeDescriptor as GraphScopeDescriptor,
)
from agent_bom.api.graph_contracts import (
    IncidentEdgePageCompleteness as IncidentEdgePageCompleteness,
)
from agent_bom.api.graph_contracts import (
    IncidentEdgePageResponse as IncidentEdgePageResponse,
)
from agent_bom.api.graph_contracts import (
    PresetCreate as PresetCreate,
)
from agent_bom.api.graph_contracts import (
    ScopedGraphCompleteness as ScopedGraphCompleteness,
)
from agent_bom.api.graph_contracts import (
    ScopedGraphResponse as ScopedGraphResponse,
)
from agent_bom.api.graph_generation import optional_generation, pin_generation, verify_generation
from agent_bom.api.graph_page_context import containment_ancestors, page_attack_context
from agent_bom.api.graph_paging import _coalesce_alias, _enforce_node_offset_cap, _page_meta, _paginate
from agent_bom.api.graph_presentation import (
    _finding_ids_for_path as _finding_ids_for_path,
)
from agent_bom.api.graph_presentation import (
    _finding_labels_for_path as _finding_labels_for_path,
)
from agent_bom.api.graph_presentation import (
    _first_href_for_agent as _first_href_for_agent,
)
from agent_bom.api.graph_presentation import (
    _fix_first_card_for_path as _fix_first_card_for_path,
)
from agent_bom.api.graph_presentation import (
    _identity_finding_ids_for_path as _identity_finding_ids_for_path,
)
from agent_bom.api.graph_presentation import (
    _next_actions_for_path as _next_actions_for_path,
)
from agent_bom.api.graph_presentation import (
    _node_ids_for_types as _node_ids_for_types,
)
from agent_bom.api.graph_presentation import (
    _node_labels_for_types as _node_labels_for_types,
)
from agent_bom.api.graph_presentation import (
    _path_identity as _path_identity,
)
from agent_bom.api.graph_presentation import (
    _path_matches_focus as _path_matches_focus,
)
from agent_bom.api.graph_presentation import (
    _path_semantic_key as _path_semantic_key,
)
from agent_bom.api.graph_presentation import (
    _risk_reasons_for_path as _risk_reasons_for_path,
)
from agent_bom.api.graph_presentation import (
    _serialize_attack_path as _serialize_attack_path,
)
from agent_bom.api.graph_presentation import (
    _serialize_attack_path_batch as _serialize_attack_path_batch,
)
from agent_bom.api.graph_query import GraphQueryRequest, _filtered_query_graph, query_payload
from agent_bom.api.graph_store import containment_drilldown_graph
from agent_bom.api.neptune_graph import NeptuneGraphStore, NeptuneGraphStoreUnsupportedOperationError
from agent_bom.api.stores import _get_graph_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.cloud.runtime_graph_evidence import _enrich_loaded_graph_runtime_evidence
from agent_bom.config import GRAPH_INVESTIGATION_NODE_BUDGET
from agent_bom.graph import (
    SEVERITY_RANK,
    AttackPath,
    EntityType,
    GraphFilterOptions,
    GraphSemanticLayer,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)
from agent_bom.graph.analysis import analysis_status_map_to_dict
from agent_bom.graph.completeness import graph_completeness
from agent_bom.graph.exposure import _exposure_path_for_attack_path as _exposure_path_for_attack_path
from agent_bom.graph.exposure import _exposure_ref_for_node as _exposure_ref_for_node
from agent_bom.graph.exposure import _finding_ids_for_nodes as _finding_ids_for_nodes
from agent_bom.graph.path_derivation import (
    _build_edge_lookup,
    _rel_value,
)
from agent_bom.graph.path_derivation import _derived_attack_paths as _derived_attack_paths
from agent_bom.graph.path_derivation import _derived_governance_attack_paths as _derived_governance_attack_paths
from agent_bom.graph.path_derivation import _derived_toxic_combination_paths as _derived_toxic_combination_paths
from agent_bom.graph.path_derivation import _fusion_signals_for_path as _fusion_signals_for_path
from agent_bom.graph.rollup import ROLLUP_RELATIONSHIPS
from agent_bom.graph.scope import GraphScopeKind, select_observed_scope
from agent_bom.graph.semantic_clusters import SEMANTIC_CLUSTER_KINDS
from agent_bom.graph.view_payloads import _graph_rollup_payload, _semantic_cluster_payload
from agent_bom.mcp_errors import CODE_UNSUPPORTED_BACKEND, CODE_UPSTREAM_UNAVAILABLE
from agent_bom.security import sanitize_error

if TYPE_CHECKING:
    from agent_bom.api.graph_store import GraphStoreProtocol

_GraphCallResult = TypeVar("_GraphCallResult")

logger = logging.getLogger(__name__)
_graph_request_admitted: ContextVar[bool] = ContextVar("graph_request_admitted", default=False)


class _GraphAdmissionRoute(APIRoute):
    """Reserve capacity for the whole request, before any graph work starts.

    Per-operation admission could reject serialization after a slow store read
    had already consumed the expensive work. Nested store/compute calls reuse
    this request's reservation; subsequent requests are rejected before reads.
    Authentication and tenant enforcement remain in the existing middleware
    and route dependencies.
    """

    def get_route_handler(self) -> Callable[[Request], Any]:
        handler = super().get_route_handler()

        async def admitted_handler(request: Request) -> Response:
            try:
                async with adaptive_backpressure("graph"):
                    token = _graph_request_admitted.set(True)
                    try:
                        with finding_read_scope():
                            return await handler(request)
                    finally:
                        _graph_request_admitted.reset(token)
            except BackpressureRejectedError as exc:
                raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc

        return admitted_handler


# PostgreSQL text cannot contain NUL; reject identifiers at the API boundary.

router = APIRouter(route_class=_GraphAdmissionRoute)


@router.post("/graph/compromise", response_model=GraphCompromiseResponse, tags=["graph"])
async def post_graph_compromise(request: Request, body: GraphCompromiseRequest) -> GraphCompromiseResponse:
    """Assess explicit control assumptions against one authorized immutable revision."""
    try:
        return await _graph_compute_call(assess_snapshot, _get_graph_store_or_503(), body, tenant_id=_tenant(request))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Compromise assessment is temporarily unavailable.") from exc


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
_FILTERED_GRAPH_ATTACK_PATH_LIMIT = 100
_GOVERNANCE_EDGE_LIMIT = 5_000
_GOVERNANCE_ATTACK_PATH_LIMIT = 100


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


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════


def _get_graph_store_or_503() -> GraphStoreProtocol:
    """Resolve the active graph store backend."""
    return _get_graph_store()


def _tenant(request: Request) -> str:
    """Extract tenant_id from request (set by auth middleware)."""
    return require_request_tenant_id(request)


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


def _joined_edges(*groups: list[UnifiedEdge]) -> list[UnifiedEdge]:
    """Concatenate edge lists without listing the same edge twice.

    The containment-ancestor walk starts from the page's own edge list, so an
    edge reaching the page from a parent outside it is found there *and* stays
    in ``paged_edges`` — concatenating the two returned it twice. The key is the
    one ``UnifiedGraph.add_edge`` already uses, so the response cannot disagree
    with the graph about what makes an edge the same edge.
    """
    seen: set[tuple[str, str, str]] = set()
    joined: list[UnifiedEdge] = []
    for group in groups:
        for edge in group:
            key = (edge.source, edge.target, _rel_value(edge))
            if key in seen:
                continue
            seen.add(key)
            joined.append(edge)
    return joined


def _boundary_edge_count(edges: list[UnifiedEdge], node_ids: set[str]) -> int:
    """How many returned edges have an endpoint the response did not return.

    ``edges_for_node_ids`` matches ``source OR target`` deliberately: a page is
    ranked by severity, so on a dense finding page the asset each finding hangs
    off is usually not on the page, and dropping those edges would hand back a
    scatter of unattached findings (and would break the containment-ancestor
    walk, which finds parents precisely by looking at edges reaching in from
    outside). So the payload is *not* an induced subgraph — but a client that
    assumes it is will silently drop these edges or invent phantom endpoints.
    Counting them is the fail-closed half: the response says how much of its
    edge list reaches past its node list instead of leaving it to be discovered.
    """
    return sum(1 for edge in edges if edge.source not in node_ids or edge.target not in node_ids)


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


async def _graph_store_call(fn: Callable[..., _GraphCallResult], /, *args: Any, **kwargs: Any) -> _GraphCallResult:
    """Run sync graph store methods off the event loop.

    A ``scan_id`` that names one of the caller's scan jobs is resolved to the
    snapshot id its report was stored under, so every graph read accepts the
    job id a push or scan response returned.
    """
    if kwargs.get("scan_id") and "tenant_id" in kwargs:
        from agent_bom.api.graph_scan_ids import resolve_graph_scan_id

        kwargs["scan_id"] = await asyncio.to_thread(resolve_graph_scan_id, str(kwargs["tenant_id"] or ""), str(kwargs["scan_id"]))
    try:
        if _graph_request_admitted.get():
            return await asyncio.to_thread(fn, *args, **kwargs)
        async with adaptive_backpressure("graph"):
            return await asyncio.to_thread(fn, *args, **kwargs)
    except BackpressureRejectedError as exc:
        raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc
    except NeptuneGraphStoreUnsupportedOperationError as exc:
        raise HTTPException(status_code=501, detail=sanitize_error(exc)) from exc


async def _load_graph_for_investigation(
    graph_store: Any,
    *,
    scan_id: str | None,
    tenant_id: str,
    **load_kwargs: Any,
) -> Any:
    """load_graph + runtime-evidence enrich for investigation surfaces."""
    graph = await _graph_store_call(
        graph_store.load_graph,
        scan_id=scan_id or "",
        tenant_id=tenant_id,
        **load_kwargs,
    )
    return await _graph_compute_call(_enrich_loaded_graph_runtime_evidence, graph, tenant_id)


async def _graph_compute_call(fn: Callable[..., _GraphCallResult], /, *args: Any, **kwargs: Any) -> _GraphCallResult:
    """Run CPU-heavy graph derivation and serialization off the event loop."""
    try:
        if _graph_request_admitted.get():
            return await asyncio.to_thread(fn, *args, **kwargs)
        async with adaptive_backpressure("graph"):
            return await asyncio.to_thread(fn, *args, **kwargs)
    except BackpressureRejectedError as exc:
        raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc
    except NeptuneGraphStoreUnsupportedOperationError as exc:
        raise HTTPException(status_code=501, detail=sanitize_error(exc)) from exc


def _encoded_graph_response(payload: dict[str, Any]) -> Response:
    """Encode graph JSON off-loop; FastAPI otherwise revisits every nested field."""
    if str(payload.get("scan_id", "")).startswith("current-estate:"):
        payload = {**payload, "evidence_scope": "current_estate"}
    return JSONResponse(content=jsonable_encoder(payload))


def _sync_attack_path_stats(
    stats: dict[str, Any],
    *,
    total: int,
    paths: list[AttackPath],
) -> dict[str, Any]:
    """Align ``attack_path_count`` / ``max_attack_path_risk`` with derived paths.

    Topology-only snapshots store zero rows in ``attack_paths`` while serve
    surfaces derive paths on read. Without this sync, ``/v1/graph`` can report
    ``attack_path_count: 0`` next to a non-empty ``/attack-paths`` queue.
    """
    if total and int(stats.get("attack_path_count") or 0) == 0:
        return {
            **stats,
            "attack_path_count": total,
            "max_attack_path_risk": max((path.composite_risk for path in paths), default=0.0),
        }
    return stats


def _ensure_attack_campaigns(graph: UnifiedGraph, paths: list[AttackPath] | None = None) -> None:
    """Materialise crown-jewel campaigns on the serve path when the store has none.

    Campaigns are computed at build-time fusion but not persisted today, so
    store-backed graphs always load ``attack_campaigns=[]``. Recompute from
    jewel-terminating paths when possible; otherwise run the bounded partitioned
    engine when the estate actually has crown jewels. Empty stays empty — no
    fabrication when there is no sensitivity signal.
    """
    if getattr(graph, "attack_campaigns", None):
        return
    try:
        from agent_bom.graph.attack_path_campaigns import compute_partitioned_campaigns
        from agent_bom.graph.attack_path_fusion import _cluster_small_graph_campaigns, _is_crown_jewel

        candidate_paths = list(paths) if paths is not None else list(graph.attack_paths)
        jewel_paths = [path for path in candidate_paths if (node := graph.nodes.get(path.target)) is not None and _is_crown_jewel(node)]
        if jewel_paths:
            graph.attack_campaigns = _cluster_small_graph_campaigns(graph, jewel_paths)
            return
        if any(_is_crown_jewel(node) for node in graph.nodes.values()):
            result = compute_partitioned_campaigns(graph)
            graph.attack_campaigns = list(result.campaigns)
    except Exception:  # noqa: BLE001 — campaigns are additive; never break investigation reads
        logger.debug("attack campaign serve-path materialisation skipped", exc_info=False)


def _filtered_graph_response(graph: UnifiedGraph, *, offset: int, limit: int) -> dict[str, Any]:
    derived_paths = _derived_attack_paths(graph)
    _ensure_attack_campaigns(graph, derived_paths)
    stats = _sync_attack_path_stats(graph.stats(), total=len(derived_paths), paths=derived_paths)
    all_nodes = list(graph.nodes.values())
    paged_nodes, pagination = _paginate(all_nodes, offset, limit)

    paged_ids = {n.id for n in paged_nodes}
    paged_edges = [e for e in graph.edges if e.source in paged_ids and e.target in paged_ids]
    matching_paths = [p for p in derived_paths if p.hops and p.hops[0] in paged_ids]
    kept_paths = matching_paths[:_FILTERED_GRAPH_ATTACK_PATH_LIMIT]
    off_page_hops = {hop for p in kept_paths for hop in p.hops} - paged_ids
    nodes_by_id = {n.id: n for n in paged_nodes}
    nodes_by_id.update({hop: graph.nodes[hop] for hop in off_page_hops if hop in graph.nodes})
    attack_paths = _serialize_attack_path_batch(
        kept_paths,
        graph.edges,
        nodes_by_id=nodes_by_id,
        scan_id=graph.scan_id,
    )
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
        "attack_campaigns": [c.to_dict() for c in graph.attack_campaigns],
        "interaction_risks": interaction_risks,
        "stats": stats,
        "pagination": pagination,
        # Two independent reasons a response can be partial: the page limit,
        # and a snapshot that was already bounded at load time. The load-time
        # cap is reported first because it is the wider omission — the page is
        # a window onto whatever survived it.
        "completeness": graph_completeness(
            returned=len(paged_nodes),
            total=graph.completeness.total_nodes if graph.completeness.truncated else len(all_nodes),
            truncated=graph.completeness.truncated or pagination["has_more"],
            reason=("node_budget" if graph.completeness.truncated else "node_page_limit" if pagination["has_more"] else ""),
        ),
        "attack_path_pagination": {
            "total": len(matching_paths),
            "limit": _FILTERED_GRAPH_ATTACK_PATH_LIMIT,
            "has_more": len(matching_paths) > _FILTERED_GRAPH_ATTACK_PATH_LIMIT,
        },
    }


def _overlay_filter_and_respond(
    graph: UnifiedGraph,
    *,
    tenant: str,
    apply_overlay: bool,
    filters: Any,
    offset: int,
    limit: int,
) -> dict[str, Any]:
    """Overlay governance, apply the scoped filter, and serialize — all off-loop.

    Consolidates the governance overlay, ``filtered_view`` derivation and
    response build into one synchronous unit so ``get_graph`` runs zero heavy
    work on the event loop between offloaded calls.

    The overlay is applied BEFORE the scoped filter so governance edges are
    subject to the relationship filter and governance nodes left unconnected in a
    scoped view are pruned with everything else. Best-effort; never breaks read.
    """
    if apply_overlay:
        try:
            from agent_bom.graph.governance_overlay import apply_governance_overlay

            apply_governance_overlay(graph, tenant_id=tenant)
        except Exception:  # noqa: BLE001
            logger.warning("governance overlay failed", exc_info=False)
    filtered = graph.filtered_view(filters)
    return _filtered_graph_response(filtered, offset=offset, limit=limit)


def _fix_first_graph_view_payload(graph: UnifiedGraph, *, cve: str, package: str, agent: str, limit: int) -> dict[str, Any]:
    from agent_bom.graph.path_ranking import criticality_rank_meta, path_rank_tuple

    available_paths = _derived_attack_paths(graph)
    _ensure_attack_campaigns(graph, available_paths)
    ranked_paths = sorted(
        (path for path in available_paths if _path_matches_focus(graph, path, cve=cve, package=package, agent=agent)),
        key=lambda path: path_rank_tuple(graph, path),
        reverse=True,
    )
    presentation_paths: list[tuple[AttackPath, list[AttackPath]]] = []
    presentation_index: dict[str, int] = {}
    for path in ranked_paths:
        semantic_key = _path_semantic_key(graph, path)
        existing = presentation_index.get(semantic_key)
        if existing is None:
            presentation_index[semantic_key] = len(presentation_paths)
            presentation_paths.append((path, [path]))
        else:
            presentation_paths[existing][1].append(path)

    cards = []
    edge_lookup = _build_edge_lookup(graph.edges)
    for index, (path, occurrence_paths) in enumerate(presentation_paths[:limit]):
        card = _fix_first_card_for_path(
            graph,
            path,
            index + 1,
            edge_lookup=edge_lookup,
            occurrence_paths=occurrence_paths,
        )
        card["rank_meta"] = criticality_rank_meta(graph, path)
        cards.append(card)
    covered_findings = {finding for card in cards for finding in card["affected"]["findings"]}
    # Crown-jewel fusion campaigns (not remediation ticket campaigns).
    campaigns = [campaign.to_dict() for campaign in getattr(graph, "attack_campaigns", [])[:12]]
    return {
        "scan_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "created_at": graph.created_at,
        "cards": cards,
        "attack_campaigns": campaigns,
        "summary": {
            "total_paths": len(available_paths),
            "matched_paths": len(ranked_paths),
            "presentation_paths": len(presentation_paths),
            "collapsed_occurrences": len(ranked_paths) - len(presentation_paths),
            "returned_paths": len(cards),
            "highest_risk": cards[0]["attack_path"]["composite_risk"] if cards else 0.0,
            "covered_findings": len(covered_findings),
            "campaign_count": len(getattr(graph, "attack_campaigns", [])),
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
        },
        "focus": {
            "cve": cve,
            "package": package,
            "agent": agent,
        },
        "completeness": graph_completeness(
            returned=len(cards),
            total=len(presentation_paths),
            truncated=len(presentation_paths) > len(cards),
            reason="path_card_limit" if len(presentation_paths) > len(cards) else "",
        ),
    }


def _derived_attack_path_page(graph: UnifiedGraph, *, offset: int, limit: int, filters: Any = None) -> Any:
    from agent_bom.api.attack_path_queue import ranked_derived_path_page

    return ranked_derived_path_page(graph, _derived_attack_paths(graph), offset=offset, limit=limit, filters=filters)


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
    path_source: str,
    materialized_paths: int,
    derived_paths: int,
    ranked: Any = None,
    filters: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from agent_bom.graph.attack_path_queue_rank import with_rank_fields

    snapshot_total = ranked.snapshot_total if ranked is not None else total
    nodes_by_id = {node.id: node for node in nodes}
    # Keep consecutive-hop witnesses, including reverse traversal of recorded
    # bidirectional edges. Exclude unrelated chords and reversed directed edges.
    path_pairs = {pair for path in paths for pair in zip(path.hops, path.hops[1:], strict=False)}
    path_edges = [
        edge
        for edge in path_edges
        if (edge.source, edge.target) in path_pairs or (edge.is_bidirectional and (edge.target, edge.source) in path_pairs)
    ]
    stats = _sync_attack_path_stats(stats, total=snapshot_total, paths=paths)
    completeness = graph_completeness(
        returned=len(paths),
        total=total,
        truncated=offset + len(paths) < total,
        reason="path_page_limit" if offset + len(paths) < total else "",
    )
    return {
        "scan_id": scan_id,
        "tenant_id": tenant,
        "created_at": created_at,
        "nodes": [node.to_dict() for node in nodes],
        "edges": [edge.to_dict() for edge in path_edges],
        "attack_paths": with_rank_fields(
            paths,
            _serialize_attack_path_batch(paths, path_edges, nodes_by_id=nodes_by_id, scan_id=scan_id, rank_offset=offset),
            nodes_by_id,
        ),
        "interaction_risks": [],
        "stats": stats,
        "pagination": _page_meta(total, offset, limit),
        "completeness": completeness,
        "count_metadata": {
            "definition": "Ranked persisted attack paths when available, otherwise paths derived from traversable graph topology.",
            "source": path_source,
            "scope": "tenant graph snapshot",
            "window": {"snapshot_created_at": created_at},
            "filters": {"scan_id": scan_id, "offset": offset, "limit": limit, **(filters or {})},
            "returned": len(paths),
            "total": total,
            # Additive, explicitly named counts let clients distinguish the
            # snapshot's source rows from the page transferred over HTTP and
            # from the smaller subset they may choose to render.
            "snapshot_total": snapshot_total,
            "materialized_paths": materialized_paths,
            "derived_paths": derived_paths,
            "returned_rows": len(paths),
            "completeness": completeness,
            **({"ranking": ranked.ranking} if ranked is not None and ranked.ranking else {}),
        },
    }


def _governance_graph_payload(
    graph: UnifiedGraph,
    *,
    tenant_id: str,
    overlay_stats: dict[str, Any],
    node_limit: int,
    edge_limit: int,
    attack_path_limit: int,
) -> dict[str, Any]:
    governance_types = {
        EntityType.MANAGED_IDENTITY,
        EntityType.ACCESS_GRANT,
        EntityType.ACCESS_POLICY,
        EntityType.DRIFT_INCIDENT,
    }
    governance_ids = {node.id for node in graph.nodes.values() if node.entity_type in governance_types}
    keep_edges = [e for e in graph.edges if e.source in governance_ids or e.target in governance_ids]
    keep_ids = set(governance_ids)
    for edge in keep_edges:
        keep_ids.add(edge.source)
        keep_ids.add(edge.target)
    nodes = [graph.nodes[nid].to_dict() for nid in keep_ids if nid in graph.nodes][:node_limit]
    node_id_window = {n["id"] for n in nodes}
    candidate_edges = [e for e in keep_edges if e.source in node_id_window and e.target in node_id_window]
    edges = candidate_edges[:edge_limit]

    matching_paths = [p for p in _derived_attack_paths(graph) if p.hops and any(hop in governance_ids for hop in p.hops)]
    attack_paths = _serialize_attack_path_batch(
        matching_paths[:attack_path_limit],
        keep_edges,
        nodes_by_id=graph.nodes,
        scan_id=graph.scan_id,
    )
    counts: dict[str, int] = {}
    for node in graph.nodes.values():
        if node.entity_type in governance_types:
            counts[node.entity_type.value] = counts.get(node.entity_type.value, 0) + 1
    governance_truncated = len(nodes) < len(keep_ids) or len(edges) < len(candidate_edges) or len(attack_paths) < len(matching_paths)
    return {
        "scan_id": graph.scan_id,
        "tenant_id": tenant_id,
        "created_at": graph.created_at,
        "nodes": nodes,
        "edges": [e.to_dict() for e in edges],
        "attack_paths": attack_paths,
        "overlay": overlay_stats,
        "governance_counts": counts,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "analysis_status": analysis_status_map_to_dict(graph.analysis_status),
        },
        "edge_pagination": {
            "total": len(candidate_edges),
            "limit": edge_limit,
            "has_more": len(candidate_edges) > edge_limit,
        },
        "attack_path_pagination": {
            "total": len(matching_paths),
            "limit": attack_path_limit,
            "has_more": len(matching_paths) > attack_path_limit,
        },
        "completeness": graph_completeness(
            returned=len(nodes),
            total=len(keep_ids),
            truncated=governance_truncated,
            reason="governance_budget" if governance_truncated else "",
        ),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Preset model
# ═══════════════════════════════════════════════════════════════════════════


def _candidate_to_string(candidate: str | dict[str, Any]) -> str:
    if isinstance(candidate, str):
        return candidate.strip()
    return json.dumps(candidate, sort_keys=True, separators=(",", ":"), default=str)


def _raise_mcp_error_as_http(payload: dict[str, Any]) -> None:
    error = payload.get("error")
    if not isinstance(error, dict):
        return
    category = str(error.get("category") or "internal")
    if error.get("code") == CODE_UPSTREAM_UNAVAILABLE:
        raise HTTPException(status_code=503, detail=error)
    if error.get("code") == CODE_UNSUPPORTED_BACKEND:
        # Same status the direct store calls use for a backend capability gap.
        raise HTTPException(status_code=501, detail=error)
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


# ═══════════════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════════════


def _scoped_graph_response(
    graph: UnifiedGraph,
    *,
    scope: GraphScopeKind,
    scope_id: str | None,
    max_depth: int,
    limit: int,
) -> dict[str, Any]:
    selected = select_observed_scope(
        graph,
        kind=scope,
        scope_id=scope_id,
        max_depth=max_depth,
        max_nodes=limit,
        max_edges=min(limit * 10, _GRAPH_QUERY_ABSOLUTE_LIMITS["max_edges"]),
    )
    scoped = selected.graph
    result_truncated = selected.node_truncated or graph.completeness.truncated
    node_reason = "source_node_budget" if graph.completeness.truncated else selected.reason if selected.node_truncated else ""
    result_total = None if graph.completeness.truncated else selected.total_nodes
    edge_total = None if graph.completeness.truncated else selected.total_edges
    edge_truncated = graph.completeness.truncated or selected.edge_truncated
    return {
        "scan_id": scoped.scan_id,
        "tenant_id": scoped.tenant_id,
        "created_at": scoped.created_at,
        "scope": {
            "kind": scope,
            "id": scope_id,
            "observed": selected.observed,
            "basis": selected.basis,
        },
        "nodes": [node.to_dict() for node in scoped.nodes.values()],
        "edges": [edge.to_dict() for edge in scoped.edges],
        "stats": scoped.stats(),
        "completeness": {
            "source": graph.completeness.to_dict(),
            "result": graph_completeness(
                returned=len(scoped.nodes),
                total=result_total,
                truncated=result_truncated,
                reason=node_reason,
            ),
            "edges": graph_completeness(
                returned=len(scoped.edges),
                total=edge_total,
                truncated=edge_truncated,
                reason=("source_node_budget" if graph.completeness.truncated else selected.reason if edge_truncated else ""),
            ),
        },
    }


@router.get(
    "/graph/scoped",
    tags=["graph"],
    response_model=ScopedGraphResponse,
)
async def get_scoped_graph(
    request: Request,
    scope: GraphScopeKind = Query(..., description="Observed graph scope"),
    scope_id: str | None = Query(
        None,
        max_length=512,
        description="Observed account, repository, environment, or root-node identifier",
    ),
    scan_id: str | None = Query(None, description="Persisted graph snapshot ID"),
    max_depth: int = Query(4, ge=1, le=10, description="Investigation traversal depth"),
    limit: int = Query(500, ge=1, le=5000, description="Maximum nodes in the scoped working set"),
) -> dict[str, Any]:
    """Return a bounded graph scope backed only by persisted UnifiedGraph evidence."""
    from agent_bom.api.managed_trial import managed_trial_enabled

    if scope != "estate" and not scope_id:
        raise HTTPException(status_code=422, detail="scope_id is required for this graph scope")
    if managed_trial_enabled() and scope != "account":
        raise HTTPException(status_code=403, detail="Managed trial graph scopes are account-scoped.")

    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    if not scan_id and not await _graph_store_call(
        graph_store.latest_snapshot_id,
        tenant_id=tenant,
        snapshot_kind="scan",
    ):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")
    graph = await _load_graph_for_investigation(
        graph_store,
        scan_id=scan_id,
        tenant_id=tenant,
        node_budget=GRAPH_INVESTIGATION_NODE_BUDGET,
    )
    return await _graph_compute_call(
        _scoped_graph_response,
        graph,
        scope=scope,
        scope_id=scope_id,
        max_depth=max_depth,
        limit=limit,
    )


_NODE_PAGE_EDGE_LIMIT = 1000


def _encode_node_page(
    *,
    snapshot_stats: dict,
    total: int,
    paged_nodes: list[UnifiedNode],
    ancestor_nodes: list[UnifiedNode],
    paged_edges: list[UnifiedEdge],
    ancestor_edges: list[UnifiedEdge],
    edges_truncated: bool,
    next_cursor: str | None,
    offset: int,
    limit: int,
    identity: tuple[str, str] | None,
    effective_scan_id: str,
    tenant: str,
    created_at: str,
    source_attack_paths: list[AttackPath],
    nodes_by_id: dict[str, UnifiedNode],
    cursor: str | None,
) -> Response:
    # This branch pages a fully-counted snapshot rather than loading it under a
    # budget, so the estate total IS the stats total. Emitting the field anyway
    # keeps one stats shape across both branches — clients never have to know
    # which path answered them.
    page_stats = {
        **snapshot_stats,
        "total_nodes_source": max(int(snapshot_stats.get("total_nodes", 0)), total),
    }
    response_nodes = [*paged_nodes, *ancestor_nodes]
    response_node_ids = {node.id for node in response_nodes}
    response_edges = _joined_edges(paged_edges, ancestor_edges)
    page_truncated = bool(next_cursor) or offset + len(paged_nodes) < total
    payload = {
        "snapshot_generation": identity[1] if identity else None,
        "scan_id": effective_scan_id,
        "tenant_id": tenant,
        "created_at": created_at,
        "collection_coverage": snapshot_stats.get("collection_coverage", {"status": "unknown"}),
        "nodes": [n.to_dict() for n in response_nodes],
        "edges": [e.to_dict() for e in response_edges],
        "attack_paths": _serialize_attack_path_batch(
            source_attack_paths,
            paged_edges,
            nodes_by_id=nodes_by_id,
            scan_id=effective_scan_id,
        ),
        "interaction_risks": [],
        "stats": page_stats,
        "pagination": _page_meta(total, offset, limit, cursor=cursor, next_cursor=next_cursor),
        "completeness": {
            **graph_completeness(
                returned=len(response_nodes),
                total=total,
                truncated=page_truncated or edges_truncated,
                reason="incident_edge_limit" if edges_truncated else "node_page_limit" if page_truncated else "",
            ),
            # ``returned`` counts every node in the payload; ``pagination`` counts
            # only the ranked page. Containment ancestors are added on top of the
            # page, so without naming them the two numbers cannot be reconciled
            # and the extra nodes read as a paging bug.
            "ranked": len(paged_nodes),
            "context_nodes": len(ancestor_nodes),
            "edges_truncated": edges_truncated,
            "edge_limit": _NODE_PAGE_EDGE_LIMIT,
            "edge_returned": len(paged_edges),
            "edge_expansion_endpoint": "/v1/graph/incident-edges",
            # See ``_boundary_edge_count``: the edge list deliberately reaches
            # one hop past the node list, so say by how much rather than letting
            # a client read the payload as an induced subgraph.
            "boundary_edges": _boundary_edge_count(response_edges, response_node_ids),
        },
    }

    return _encoded_graph_response(payload)


@router.get("/graph", tags=["graph"], response_model=dict)
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
    snapshot_generation: Optional[str] = Query(None, max_length=128, description="Read revision from the first page"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset node pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset for nodes"),
    limit: int = Query(500, ge=1, le=5000, description="Max nodes to return"),
) -> Response:
    """Load the unified graph with filters and pagination.

    Nodes are paginated (offset/limit). ``edges`` carries up to 1,000 edges
    incident to the ranked page, plus containment context. Omitted relationships
    are declared by ``completeness.edges_truncated`` and remain pageable through
    ``/v1/graph/incident-edges`` at the same revision. Edges may reach nodes
    outside the page; this is not the subgraph induced by ``nodes``;
    ``completeness.boundary_edges`` counts the edges that cross the boundary.

    ``stats`` describe the graph this response was computed from, NOT the page:
    ``stats.total_nodes`` is every node that survived loading, and
    ``stats.total_nodes_source`` is the estate total before any load-time node
    budget applied. The two are equal on an unbounded load. Read
    ``completeness`` for whether the load was bounded and why —
    ``completeness.total`` always reconciles with ``stats.total_nodes_source``.
    """
    from agent_bom.graph import SEVERITY_RANK

    _enforce_node_offset_cap(offset, cursor)
    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    requested_scan_id = _coalesce_alias(scan_id, scan, primary_name="scan_id", alias_name="scan")

    if not requested_scan_id and not await _graph_store_call(
        graph_store.latest_snapshot_id,
        tenant_id=tenant,
    ):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    identity = await _graph_store_call(
        optional_generation,
        graph_store,
        tenant=tenant,
        scan_id=requested_scan_id,
        generation=snapshot_generation,
        offset=offset or int(bool(cursor)),
    )
    if identity is not None:
        requested_scan_id = identity[0]

    et_set = _parse_entity_type_filter(entity_types)

    min_rank = 0
    if min_severity:
        min_rank = SEVERITY_RANK.get(min_severity.lower(), 0)

    if relationships or static_only or dynamic_only:
        # This branch materializes the whole snapshot. Bound it: at 200k nodes
        # an uncapped load measured ~783 MB and 8.3s, and several of these can
        # run concurrently. The budget keeps the highest-risk nodes and the
        # response declares what was left out.
        graph = await _load_graph_for_investigation(
            graph_store,
            scan_id=requested_scan_id,
            tenant_id=tenant,
            entity_types=et_set,
            min_severity_rank=min_rank,
            node_budget=GRAPH_INVESTIGATION_NODE_BUDGET,
        )
        rel_set = _parse_relationship_filter(relationships)
        filters = GraphFilterOptions(
            relationship_types=rel_set,
            static_only=static_only,
            dynamic_only=dynamic_only,
            max_depth=max_depth or 6,
        )
        # Governance overlay, scoped-filter derivation, and response
        # serialization are all CPU-bound; fold them into ONE off-loop hop so no
        # heavy work runs between offloaded calls on the event loop.
        payload = await _graph_compute_call(
            _overlay_filter_and_respond,
            graph,
            tenant=tenant,
            apply_overlay=not et_set,
            filters=filters,
            offset=offset,
            limit=limit,
        )
        receipt = await _graph_store_call(graph_store.snapshot_stats, tenant_id=tenant, scan_id=requested_scan_id)
        payload["collection_coverage"] = receipt.get("collection_coverage", {"status": "unknown"})
        if identity is not None:
            await _graph_store_call(verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(payload.get("nodes")))
            payload["snapshot_generation"] = identity[1]
        return await _graph_compute_call(_encoded_graph_response, payload)

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
        limit=_NODE_PAGE_EDGE_LIMIT + 1,
    )
    edges_truncated = len(paged_edges) > _NODE_PAGE_EDGE_LIMIT
    paged_edges = paged_edges[:_NODE_PAGE_EDGE_LIMIT]
    source_attack_paths, attack_path_nodes = await page_attack_context(
        graph_store, scan_id=effective_scan_id, tenant_id=tenant, node_ids=paged_ids, call_store=_graph_store_call
    )
    ancestor_nodes, ancestor_edges = await containment_ancestors(
        graph_store,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=paged_ids,
        call_store=_graph_store_call,
    )
    nodes_by_id = {node.id: node for node in [*paged_nodes, *attack_path_nodes, *ancestor_nodes]}
    snapshot_stats = await _graph_store_call(
        graph_store.snapshot_stats,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        entity_types=et_set,
        min_severity_rank=min_rank,
    )

    if identity is not None:
        await _graph_store_call(verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(nodes_by_id))
    return await _graph_compute_call(
        _encode_node_page,
        snapshot_stats=snapshot_stats,
        total=total,
        paged_nodes=paged_nodes,
        ancestor_nodes=ancestor_nodes,
        paged_edges=paged_edges,
        ancestor_edges=ancestor_edges,
        edges_truncated=edges_truncated,
        next_cursor=next_cursor,
        offset=offset,
        limit=limit,
        identity=identity,
        effective_scan_id=effective_scan_id,
        tenant=tenant,
        created_at=created_at,
        source_attack_paths=source_attack_paths,
        nodes_by_id=nodes_by_id,
        cursor=cursor,
    )


@router.get("/graph/views/fix-first", tags=["graph"], responses={200: _FIX_FIRST_VIEW_OPENAPI_RESPONSE})
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

    if not requested_scan_id and not await _graph_store_call(
        graph_store.latest_snapshot_id,
        tenant_id=tenant,
        snapshot_kind="scan",
    ):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    graph = await _load_graph_for_investigation(
        graph_store,
        scan_id=requested_scan_id,
        tenant_id=tenant,
    )
    return await _graph_compute_call(_fix_first_graph_view_payload, graph, cve=cve, package=package, agent=agent, limit=limit)


def _diff_entry_node_id(entry: Any) -> str | None:
    """Node id for a diff entry, tolerating both dict and bare-id shapes."""
    if isinstance(entry, dict):
        nid = entry.get("id")
        return str(nid) if nid is not None else None
    if entry is None:
        return None
    return str(entry)


def _diff_entry_edge_key(entry: Any) -> str:
    """Stable ``source|target|relationship`` key for a diff edge entry.

    Handles the three shapes the stores emit: ``(source, target, relationship)``
    tuples for added/removed edges, and ``{"before"|"after": edge}`` wrappers
    (or a bare edge dict) for changed edges.
    """
    if isinstance(entry, dict):
        edge = entry.get("after") or entry.get("before") or entry
        src = edge.get("source_id") or edge.get("source") or ""
        tgt = edge.get("target_id") or edge.get("target") or ""
        rel = edge.get("relationship") or ""
        return f"{src}|{tgt}|{rel}"
    if isinstance(entry, (list, tuple)) and len(entry) >= 3:
        return f"{entry[0]}|{entry[1]}|{entry[2]}"
    return str(entry)


def _tag_diff_change_kinds(diff: dict[str, Any]) -> dict[str, Any]:
    """Tag each diff node/edge with a ``change_kind`` for the drift UI lens.

    Adds an in-place ``change_kind`` (``new`` | ``removed`` | ``changed``) to
    every dict-shaped node/edge entry (leaving any pre-existing value intact)
    and attaches a ``change_kind_index`` mapping node ids and edge keys to
    their kind so the client can classify the rendered graph without having to
    reconcile the three heterogeneous entry shapes. Entries not present in the
    index are treated as ``unchanged`` by consumers.
    """
    if not isinstance(diff, dict):
        return diff

    node_kinds: dict[str, str] = {}
    for kind, key in (("new", "nodes_added"), ("removed", "nodes_removed"), ("changed", "nodes_changed")):
        for entry in diff.get(key) or []:
            nid = _diff_entry_node_id(entry)
            if nid is None:
                continue
            node_kinds[nid] = kind
            if isinstance(entry, dict):
                entry.setdefault("change_kind", kind)

    edge_kinds: dict[str, str] = {}
    for kind, key in (("new", "edges_added"), ("removed", "edges_removed"), ("changed", "edges_changed")):
        for entry in diff.get(key) or []:
            edge_kinds[_diff_entry_edge_key(entry)] = kind
            if isinstance(entry, dict):
                entry.setdefault("change_kind", kind)

    diff["change_kind_index"] = {"nodes": node_kinds, "edges": edge_kinds}
    return diff


@router.get("/graph/diff", tags=["graph"])
async def get_graph_diff(
    request: Request,
    old: str = Query(..., description="Old scan ID"),
    new: str = Query(..., description="New scan ID"),
) -> dict:
    """Diff two scan snapshots — nodes/edges added, removed, changed."""
    diff = await _graph_store_call(_get_graph_store_or_503().diff_snapshots, old, new, tenant_id=_tenant(request))
    diff = _tag_diff_change_kinds(diff)
    diff["completeness"] = graph_completeness(returned=1, total=1)
    return diff


@router.get("/graph/edges/active", tags=["graph"])
async def get_active_graph_edges(
    request: Request,
    at: str = Query(..., description="ISO timestamp for replay lookup"),
) -> list[dict]:
    """Return edge versions active at a timestamp for replay views."""
    edges = await _graph_store_call(_get_graph_store_or_503().active_edges_at, at, tenant_id=_tenant(request))
    # Preserve the historical list response shape; callers receive all edges
    # selected by the timestamp query and no page-level sampling is applied.
    return edges


@router.get("/graph/edges/changes", tags=["graph"])
async def get_graph_edge_changes(
    request: Request,
    old: str = Query(..., description="Old scan ID"),
    new: str = Query(..., description="New scan ID"),
) -> dict:
    """Return edge lifecycle changes between two scan snapshots."""
    changes = await _graph_store_call(_get_graph_store_or_503().changed_edges_between_scans, old, new, tenant_id=_tenant(request))
    if isinstance(changes, dict):
        changes["completeness"] = graph_completeness(returned=1, total=1)
    return changes


@router.get("/graph/attack-paths", tags=["graph"], responses={200: _ATTACK_PATHS_OPENAPI_RESPONSE})
async def get_graph_attack_paths(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    snapshot_generation: Optional[str] = Query(
        None, max_length=128, description="Generation from the first page; required for continuation"
    ),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Max attack paths"),
    min_severity: Optional[Literal["critical", "high", "medium", "low"]] = Query(
        None, description="Only paths whose worst on-path finding is at least this severity"
    ),
    has_credential: Optional[bool] = Query(None, description="Only paths that do (true) or do not (false) expose a credential"),
    source_type: Optional[str] = Query(None, max_length=64, description="Only paths whose entrypoint node has this entity type"),
) -> dict:
    """Return the global attack-path queue independent of node pagination.

    `/v1/graph` intentionally windows nodes and therefore cannot be the source
    of truth for fix-first triage. This endpoint ranks paths across the whole
    snapshot by on-path exploitability evidence, then stored composite risk
    (see ``graph.attack_path_queue_rank``), and hydrates only the hop nodes
    needed to render the selected queue page.
    """
    from agent_bom.api.attack_path_queue import AttackPathFilters, ranked_persisted_path_page

    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    identity = await _graph_store_call(
        pin_generation, graph_store, tenant=tenant, scan_id=scan_id or "", generation=snapshot_generation, offset=offset
    )
    filters = AttackPathFilters(min_severity=min_severity, has_credential=has_credential, source_type=source_type)
    page_args = {"offset": offset, "limit": limit, "filters": filters}
    ranked = await _graph_store_call(ranked_persisted_path_page, graph_store, scan_id=identity[0], tenant_id=tenant, **page_args)
    materialized_paths, derived_paths, path_source = ranked.snapshot_total, 0, "persisted_graph_paths"
    if ranked.snapshot_total == 0:
        graph = await _load_graph_for_investigation(graph_store, scan_id=ranked.scan_id, tenant_id=tenant)
        ranked = await _graph_compute_call(_derived_attack_path_page, graph, **page_args)
        derived_paths, path_source = ranked.snapshot_total, "derived_graph_paths"
    effective_scan_id = ranked.scan_id
    hop_ids = {hop for path in ranked.paths for hop in path.hops}
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
    payload = await _graph_compute_call(
        _serialize_attack_path_queue,
        scan_id=effective_scan_id,
        tenant=tenant,
        created_at=ranked.created_at,
        nodes=nodes,
        path_edges=path_edges,
        paths=ranked.paths,
        total=ranked.total,
        offset=offset,
        limit=limit,
        stats=stats,
        path_source=path_source,
        materialized_paths=materialized_paths,
        derived_paths=derived_paths,
        ranked=ranked,
        filters=filters.active(),
    )

    await _graph_store_call(verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(nodes or ranked.paths))
    payload["snapshot_generation"] = identity[1]
    return payload


@router.get("/graph/governance", tags=["graph"])
async def get_graph_governance(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    limit: int = Query(2000, ge=1, le=10000, description="Max nodes to return"),
    edge_limit: int = Query(_GOVERNANCE_EDGE_LIMIT, ge=1, le=25_000, description="Max governance edges to return"),
    attack_path_limit: int = Query(
        _GOVERNANCE_ATTACK_PATH_LIMIT,
        ge=1,
        le=1000,
        description="Max governance attack paths to embed",
    ),
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
    return await _graph_compute_call(
        _governance_graph_payload,
        graph,
        tenant_id=tenant,
        overlay_stats=overlay_stats,
        node_limit=limit,
        edge_limit=edge_limit,
        attack_path_limit=attack_path_limit,
    )


@router.get("/graph/nhi/governance", tags=["graph"])
async def get_nhi_governance(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
) -> dict:
    """Return the non-human-identity governance posture for the latest graph.

    Loads the latest unified graph, projects the live governance control plane
    and resolves effective permissions, then computes the three core NHI governance
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


@router.get("/graph/exposure-paths", tags=["graph"])
async def get_graph_exposure_paths(
    request: Request,
    tenant_id: Optional[str] = Query(None, include_in_schema=False),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    limit: int = Query(5, ge=1, le=100, description="Maximum ExposurePaths"),
    min_risk: float = Query(0.0, ge=0, le=100, description="Minimum ExposurePath risk score"),
    cursor: Optional[str] = Query(None, max_length=4096, description="Continuation cursor pinned to the snapshot and risk filter"),
) -> dict:
    """Return the MCP-compatible ExposurePath queue over REST for SDK consumers."""
    del tenant_id  # SDK compatibility only; request tenant scope is authoritative.
    from agent_bom.mcp_tools.graph import exposure_paths_for_tenant

    graph_store = _get_graph_store_or_503()
    raw = await exposure_paths_for_tenant(
        tenant_id=_tenant(request),
        scan_id=scan_id,
        limit=limit,
        min_risk=min_risk,
        cursor=cursor,
        _get_graph_store=lambda: graph_store,
        _truncate_response=lambda value: value,
    )
    payload = json.loads(raw)
    _raise_mcp_error_as_http(payload)
    return cast("dict[str, Any]", payload)


@router.post("/graph/should-i-deploy", tags=["graph"])
async def post_graph_should_i_deploy(request: Request, body: GraphDeployDecisionRequest) -> dict:
    """Return the MCP-compatible allow/warn/block deploy decision over REST."""
    _ = (body.tenant_id, body.context)  # SDK compatibility/future policy context; request tenant scope is authoritative today.
    from agent_bom.mcp_tools.graph import deploy_decision_for_tenant

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
    raw = await deploy_decision_for_tenant(
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
    return cast("dict[str, Any]", payload)


def _paths_truncation_reason(traversal_truncated: bool, page_truncated: bool, depth_limited: bool = False) -> str:
    """Name the *stronger* loss first.

    A traversal budget is a harder limit than a depth cap, which is harder than
    a page limit: paging further cannot recover the nodes the walk never
    reached, and raising ``max_depth`` cannot recover the nodes the node budget
    never let it visit. So the deeper reason must not be masked by the shallower
    one.
    """
    if traversal_truncated:
        return "traversal_budget"
    if depth_limited:
        return "depth_limit"
    return "path_page_limit" if page_truncated else ""


@router.get("/graph/paths", tags=["graph"])
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

    all_paths, reachable, traversal_truncated, depth_limited = await _graph_store_call(
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

    result = {
        "source": source_node_id,
        "source_id": source_node_id,
        "max_depth": max_depth,
        "reachable_count": len(reachable),
        "reachable_nodes": sorted(reachable),
        "paths": [{"target": p[-1], "hops": p, "depth": len(p) - 1} for p in paged_paths],
        "attack_paths": _serialize_attack_path_batch(
            [ap for ap in attack_paths if ap.source == source_node_id],
            path_edges,
            nodes_by_id=nodes_by_id,
            scan_id=requested_scan_id,
        ),
        "pagination": pagination,
        "truncated": traversal_truncated,
        "depth_limited": depth_limited,
        # A bounded BFS knows neither the reachable set nor the path count, so
        # it cannot report a total: `len(all_paths)` is the bound, not the
        # answer. Reporting it as `total` told a client that paged to exhaustion
        # it had everything. `max_depth` bounds it exactly as the node budget
        # does — it defaults to 4 and is the server's choice when the caller
        # passes nothing — so a walk that stopped with reachable nodes still
        # unwalked is no more complete than one that ran out of budget.
        "completeness": graph_completeness(
            returned=len(paged_paths),
            total=None if (traversal_truncated or depth_limited) else len(all_paths),
            truncated=traversal_truncated or depth_limited or pagination["has_more"],
            reason=_paths_truncation_reason(traversal_truncated, pagination["has_more"], depth_limited),
        ),
    }
    from agent_bom.db.adoption_events import record_adoption_event_best_effort

    record_adoption_event_best_effort("investigation_started", channel="control_plane")
    return result


@router.get("/graph/impact", tags=["graph"])
async def get_graph_impact(
    request: Request,
    node: str = Query(..., description="Node ID to compute impact for"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    snapshot_generation: Optional[str] = Query(None, max_length=128),
    max_depth: int = Query(4, ge=1, le=10, description="Maximum reverse BFS depth"),
) -> dict:
    """Compute blast radius of a node — what depends on it?"""
    graph_store = _get_graph_store_or_503()
    tenant_id = _tenant(request)
    identity = await _graph_store_call(
        optional_generation, graph_store, tenant=tenant_id, scan_id=scan_id or "", generation=snapshot_generation, offset=0
    )
    impact = await _graph_store_call(
        graph_store.impact_of,
        scan_id=identity[0] if identity else scan_id or "",
        tenant_id=tenant_id,
        node_id=node,
        max_depth=max_depth,
    )
    if impact is None:
        raise HTTPException(status_code=404, detail=f"Node '{node}' not found")
    if identity:
        await _graph_store_call(verify_generation, graph_store, tenant=tenant_id, identity=identity, has_rows=True)
    return {
        **impact,
        "scan_id": identity[0] if identity else scan_id or "",
        "tenant_id": tenant_id,
        "snapshot_generation": identity[1] if identity else None,
        "interpretation": {
            "basis": "recorded_reverse_reachability",
            "execution": "not_established",
            "collection_coverage": "unknown",
            "traversable_only": False,
            "max_depth": max_depth,
        },
    }


@router.get("/graph/search", tags=["graph"])
async def search_graph(
    request: Request,
    q: str = Query(..., min_length=1, description="Search query"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    entity_types: Optional[str] = Query(None, description="Comma-separated entity types"),
    min_severity: Optional[str] = Query(None, description="Minimum severity (critical/high/medium/low)"),
    compliance_prefixes: Optional[str] = Query(None, description="Comma-separated compliance prefixes"),
    data_sources: Optional[str] = Query(None, description="Comma-separated data sources"),
    snapshot_generation: Optional[str] = Query(None, max_length=128, description="Read revision from the first page"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset search pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> dict:
    """Search graph nodes by label, type, tags, and attributes."""
    _enforce_node_offset_cap(offset, cursor)
    graph_store = _get_graph_store_or_503()
    tenant_id = _tenant(request)
    identity = await _graph_store_call(
        optional_generation,
        graph_store,
        tenant=tenant_id,
        scan_id=scan_id or "",
        generation=snapshot_generation,
        offset=offset or int(bool(cursor)),
    )
    if identity is not None:
        scan_id = identity[0]
    entity_type_filters = _parse_entity_type_filter(entity_types)
    min_rank = SEVERITY_RANK.get(min_severity.lower(), 0) if min_severity else 0
    prefix_filters = {value.strip().upper() for value in compliance_prefixes.split(",") if value.strip()} if compliance_prefixes else None
    data_source_filters = {value.strip() for value in data_sources.split(",") if value.strip()} if data_sources else None
    try:
        results, total, next_cursor = await _graph_store_call(
            graph_store.search_nodes,
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
    if identity is not None:
        await _graph_store_call(verify_generation, graph_store, tenant=tenant_id, identity=identity, has_rows=bool(results))
    return {
        "snapshot_generation": identity[1] if identity else None,
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
        "completeness": graph_completeness(
            returned=len(results),
            total=total,
            truncated=bool(next_cursor) or offset + len(results) < total,
            reason="search_page_limit" if bool(next_cursor) or offset + len(results) < total else "",
        ),
    }


@router.get("/graph/clusters", tags=["graph"])
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
    if not requested_scan_id and not await _graph_store_call(
        graph_store.latest_snapshot_id,
        tenant_id=tenant,
        snapshot_kind="scan",
    ):
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


@router.get("/graph/agents", tags=["graph"])
async def list_graph_agents(
    request: Request,
    q: str = Query("", description="Optional agent label/id search"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    snapshot_generation: Optional[str] = Query(None, max_length=128, description="Read revision from the first page"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Max agents"),
) -> dict:
    """List agent nodes for large-graph selectors without loading the full graph."""
    _enforce_node_offset_cap(offset, cursor)
    graph_store = _get_graph_store_or_503()
    tenant_id = _tenant(request)
    identity = await _graph_store_call(
        optional_generation,
        graph_store,
        tenant=tenant_id,
        scan_id=scan_id or "",
        generation=snapshot_generation,
        offset=offset or int(bool(cursor)),
    )
    if identity is not None:
        scan_id = identity[0]
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
        effective_scan_id = scan_id or await _graph_store_call(
            graph_store.latest_snapshot_id,
            tenant_id=tenant_id,
            snapshot_kind="scan",
        )
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
    if identity is not None:
        await _graph_store_call(verify_generation, graph_store, tenant=tenant_id, identity=identity, has_rows=bool(agents))
    return {
        "snapshot_generation": identity[1] if identity else None,
        "scan_id": effective_scan_id,
        "tenant_id": tenant_id,
        "created_at": created_at,
        "agents": [
            {
                "id": node.id,
                "label": node.label,
                "risk_score": node.risk_score,
                "risk_assessment": node.risk_assessment,
                "severity": node.severity,
                "status": node.status.value if hasattr(node.status, "value") else str(node.status),
                "data_sources": node.data_sources,
                "first_seen": node.first_seen,
                "last_seen": node.last_seen,
            }
            for node in agents
        ],
        "pagination": _page_meta(total, offset, limit, cursor=cursor, next_cursor=next_cursor),
        "completeness": graph_completeness(
            returned=len(agents),
            total=total,
            truncated=bool(next_cursor) or offset + len(agents) < total,
            reason="agent_page_limit" if bool(next_cursor) or offset + len(agents) < total else "",
        ),
    }


@router.post("/graph/query", tags=["graph"])
async def query_graph(request: Request, body: GraphQueryRequest) -> dict:
    """Run a bounded programmable traversal over the canonical graph."""
    graph_store = _get_graph_store_or_503()
    tenant_id = _tenant(request)
    identity = await _graph_store_call(
        optional_generation, graph_store, tenant=tenant_id, scan_id=body.scan_id or "", generation=body.snapshot_generation, offset=0
    )
    scan_id = identity[0] if identity else body.scan_id or ""
    budget = _enforce_graph_query_budget(body)
    root_nodes = await _graph_store_call(
        graph_store.nodes_by_ids,
        scan_id=scan_id,
        tenant_id=tenant_id,
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
        scan_id=scan_id,
        tenant_id=tenant_id,
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

    depth_limited = bool(getattr(traversal_graph.completeness, "depth_limited", False))
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
            scan_id=scan_id,
            tenant_id=tenant_id,
            source_ids=set(body.roots),
        )
        # Keep every path rooted at a queried node, even when intermediate hops
        # were excluded by the traversal limits or the entity/severity/
        # compliance/data-source filters. Dropping a path because one hop is
        # off-graph silently hides real attack paths (same pagination-drop
        # class as the paged sibling above). Backfill the missing hop nodes so
        # exposure-path labels still resolve.
        root_paths = [ap for ap in root_attack_paths if ap.source in body.roots]
        missing_hop_ids = {hop for ap in root_paths for hop in ap.hops} - set(filtered_graph.nodes)
        backfilled_nodes = await _graph_store_call(
            graph_store.nodes_by_ids,
            scan_id=scan_id,
            tenant_id=tenant_id,
            node_ids=missing_hop_ids,
        )
        nodes_by_id = {**filtered_graph.nodes, **{node.id: node for node in backfilled_nodes}}
        attack_paths = _serialize_attack_path_batch(
            root_paths,
            filtered_graph.edges,
            nodes_by_id=nodes_by_id,
            scan_id=filtered_graph.scan_id,
        )

    if identity:
        await _graph_store_call(verify_generation, graph_store, tenant=tenant_id, identity=identity, has_rows=bool(filtered_graph.nodes))
    return query_payload(
        body, filtered_graph, depth_by_node, truncated, depth_limited, attack_paths, budget, rel_types, identity[1] if identity else None
    )


@router.get("/graph/node-context", tags=["graph"])
@router.get("/graph/node/{node_id}", tags=["graph"])
async def get_graph_node(
    request: Request,
    node_id: GraphIdentifier,
    scan_id: Optional[GraphIdentifier] = Query(None, description="Scan ID"),
    snapshot_generation: Optional[str] = Query(None, max_length=128),
) -> dict:
    """Get a single node with its edges, neighbors, and impact stats."""
    graph_store = _get_graph_store_or_503()
    tenant_id = _tenant(request)
    identity = await _graph_store_call(
        optional_generation, graph_store, tenant=tenant_id, scan_id=scan_id or "", generation=snapshot_generation, offset=0
    )
    node_context = await _graph_store_call(
        graph_store.node_context,
        scan_id=identity[0] if identity else scan_id or "",
        tenant_id=tenant_id,
        node_id=node_id,
    )
    if node_context is None:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    if identity:
        await _graph_store_call(verify_generation, graph_store, tenant=tenant_id, identity=identity, has_rows=True)
    return {
        "scan_id": identity[0] if identity else scan_id or "",
        "tenant_id": tenant_id,
        "snapshot_generation": identity[1] if identity else None,
        "node": node_context["node"].to_dict(),
        "edges_out": [edge.to_dict() for edge in node_context["edges_out"]],
        "edges_in": [edge.to_dict() for edge in node_context["edges_in"]],
        "neighbors": node_context["neighbors"],
        "sources": node_context["sources"],
        "impact": node_context["impact"],
        "completeness": node_context.get("completeness") or graph_completeness(returned=1, total=1),
    }


@router.get("/graph/incident-edges", tags=["graph"], response_model=IncidentEdgePageResponse)
async def get_graph_incident_edges(
    request: Request,
    node_id: GraphIdentifier = Query(..., min_length=1, max_length=4096, pattern=r"^[^\x00]*$", description="Exact canonical node ID"),
    scan_id: GraphIdentifier | None = Query(
        None,
        max_length=4096,
        description=(
            "Historical scan ID; omitted selects the current tenant estate. Reuse the returned ID and generation for subsequent pages."
        ),
    ),
    snapshot_generation: str | None = Query(
        None, pattern="^[a-f0-9]{32}$", description="Expected generation returned by the initial page; reuse on every node expansion."
    ),
    direction: Literal["in", "out", "both"] = Query(
        "both", description="Filter recorded target/source endpoints; not effective permissions."
    ),
    limit: int = Query(24, ge=1, le=100, description="Maximum recorded relationships, not distinct neighbors"),
    cursor: str | None = Query(
        None, min_length=1, max_length=8192, description="Opaque next_cursor from the same tenant, snapshot, node and direction"
    ),
) -> dict[str, Any]:
    """Page recorded incident relationships without loading the full neighborhood.

    Reuse scan_id and snapshot_generation on every node expansion to avoid mixing
    snapshots. Keep node_id and direction fixed while following next_cursor.
    Snapshot replacement invalidates cursors; restart from the first page on 400.
    Completeness describes only recorded page rows, never source collection,
    permissions, execution, or the whole estate. Total relationship count is unknown.
    """
    store = _get_graph_store_or_503()
    if isinstance(store, NeptuneGraphStore):
        raise HTTPException(status_code=501, detail="Incident relationship paging is not supported by this graph backend")
    try:
        page = await _graph_store_call(
            store.incident_edges_page,
            tenant_id=_tenant(request),
            scan_id=scan_id or "",
            node_id=node_id,
            direction=direction,
            limit=limit,
            cursor=cursor,
            snapshot_generation=snapshot_generation,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid or stale incident relationship page; restart from the first page") from exc
    if page is None:
        return {
            "scan_id": scan_id or "",
            "snapshot_generation": None,
            "node_id": node_id,
            "found": False,
            "direction": direction,
            "limit": limit,
            "node": None,
            "nodes": [],
            "edges": [],
            "next_cursor": None,
            "completeness": {
                **graph_completeness(returned=0, truncated=True, reason="node_or_snapshot_not_found"),
                "scope": "incident_edge_page",
                "missing_endpoint_count": 0,
            },
        }
    return {
        "scan_id": page["scan_id"],
        "evidence_scope": "current_estate" if page["scan_id"].startswith("current-estate:") else "historical_scan",
        "snapshot_generation": page["snapshot_generation"],
        "node_id": node_id,
        "found": True,
        "direction": direction,
        "limit": limit,
        "node": page["node"].to_dict(),
        "nodes": [node.to_dict() for node in page["nodes"]],
        "edges": [edge.to_dict() for edge in page["edges"]],
        "next_cursor": page["next_cursor"],
        "completeness": page["completeness"],
    }


@router.get("/graph/node-neighbors", tags=["graph"])
@router.get("/graph/node/{node_id}/neighbors", tags=["graph"])
async def get_graph_node_neighbors(
    request: Request,
    node_id: GraphIdentifier,
    scan_id: Optional[GraphIdentifier] = Query(None, description="Scan ID; latest if omitted"),
    limit: int = Query(24, ge=1, le=100, description="Max neighbors returned per expand"),
    direction: str = Query("both", description="out=dependencies, in=dependents, both=either"),
) -> dict:
    """Return a bounded set of a node's direct graph neighbors for inline expand.

    This is the read side of the dashboard's progressive-disclosure attack-path
    view: expanding one hop loads only that hop's direct neighbors instead of the
    whole graph. It is deliberately lazy and bounded — fan-out is capped by
    ``limit``; ``total_neighbors`` is null when source evidence is incomplete.
    A completely read high-degree neighborhood reports its known total with
    ``truncated`` set, so the UI can render a "+N more" affordance rather than
    exploding the view. Neighbor node metadata (entity type, label, severity)
    travels with the payload so the client never needs a second round trip per
    neighbor id. An unknown node id returns an empty payload (200, ``found``
    false) instead of raising, so a stale client id degrades quietly in-place.
    """
    normalized_direction = direction.strip().lower()
    if normalized_direction not in {"out", "in", "both"}:
        normalized_direction = "both"

    tenant = _tenant(request)
    store = _get_graph_store_or_503()
    if isinstance(store, NeptuneGraphStore):
        # Unsupported traversal stays 501 even when the backend has no snapshot.
        # The adapter owns the capability error; the wrapper sanitizes it.
        await _graph_store_call(store.node_context, scan_id=scan_id or "", tenant_id=tenant, node_id=node_id)
    effective_scan_id = scan_id or await _graph_store_call(store.latest_snapshot_id, tenant_id=tenant)
    context = (
        await _graph_store_call(store.node_context, scan_id=effective_scan_id, tenant_id=tenant, node_id=node_id)
        if effective_scan_id
        else None
    )
    if context is None:
        return {
            "node_id": node_id,
            "scan_id": effective_scan_id or "",
            "found": False,
            "direction": normalized_direction,
            "limit": limit,
            "total_neighbors": None,
            "truncated": True,
            "neighbors": [],
            "edges": [],
            # The node was not found, so zero returned neighbors is not proof
            # that the node has a complete zero-degree neighborhood.
            "completeness": graph_completeness(
                returned=0,
                total=None,
                truncated=True,
                reason="node_not_found" if effective_scan_id else "snapshot_not_found",
            ),
        }

    selected_edges: list = []
    if normalized_direction in {"out", "both"}:
        selected_edges.extend(context["edges_out"])
    if normalized_direction in {"in", "both"}:
        selected_edges.extend(context["edges_in"])

    # Deterministic, de-duplicated neighbor ordering keeps the cap stable across
    # repeated expands (same class of pagination-drop guard used elsewhere).
    edges_by_neighbor: dict[str, list] = {}
    neighbor_ids: list[str] = []
    seen: set[str] = set()
    for edge in selected_edges:
        neighbor_id = edge.target if edge.source == node_id else edge.source
        if neighbor_id == node_id:
            continue
        edges_by_neighbor.setdefault(neighbor_id, []).append(edge)
        if neighbor_id not in seen:
            seen.add(neighbor_id)
            neighbor_ids.append(neighbor_id)

    neighbor_ids.sort()
    total_neighbors = len(neighbor_ids)
    bounded_ids = neighbor_ids[:limit]
    truncated = total_neighbors > len(bounded_ids)

    neighbor_nodes = await _graph_store_call(
        store.nodes_by_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=set(bounded_ids),
    )
    nodes_by_id = {node.id: node for node in neighbor_nodes}
    ordered_nodes = [nodes_by_id[node_id_] for node_id_ in bounded_ids if node_id_ in nodes_by_id]
    missing_endpoints = len(ordered_nodes) != len(bounded_ids)
    bounded_edges = [edge for node_id_ in bounded_ids if node_id_ in nodes_by_id for edge in edges_by_neighbor.get(node_id_, [])]
    upstream = context.get("completeness") or {}
    upstream_incomplete = bool(
        upstream.get("truncated")
        or upstream.get("sampled")
        or upstream.get("complete") is False
        or upstream.get("status") in {"truncated", "sampled"}
    )
    total_known = not upstream_incomplete and not missing_endpoints
    truncated = truncated or bool(upstream.get("truncated")) or missing_endpoints
    reason = (
        str(upstream.get("reason") or "upstream_incomplete")
        if upstream_incomplete
        else "missing_neighbor_endpoints"
        if missing_endpoints
        else "neighbor_limit"
        if truncated
        else ""
    )
    completeness = graph_completeness(
        returned=len(ordered_nodes),
        total=total_neighbors if total_known else None,
        truncated=truncated or (upstream_incomplete and not upstream.get("sampled")),
        sampled=bool(upstream.get("sampled")),
        reason=reason,
    )
    if upstream_incomplete:
        completeness["source_completeness"] = upstream
    if missing_endpoints:
        completeness["missing_neighbor_endpoints"] = True

    return {
        "node_id": node_id,
        "scan_id": effective_scan_id or "",
        "found": True,
        "direction": normalized_direction,
        "limit": limit,
        "total_neighbors": total_neighbors if total_known else None,
        "truncated": not completeness["complete"],
        "neighbors": [node.to_dict() for node in ordered_nodes],
        "edges": [edge.to_dict() for edge in bounded_edges],
        "completeness": completeness,
    }


@router.get("/graph/snapshots", tags=["graph"])
async def get_graph_snapshots(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Max snapshots"),
    window_days: int | None = Query(None, ge=0, description="Default read-window in days; 0 = all retained history"),
) -> list[dict]:
    """List persisted scan snapshots ordered by creation time.

    Defaults to the last ``AGENT_BOM_RETENTION_DAYS`` (≈90d) so the picker shows
    recent, non-stale history; pass ``?window_days=0`` to widen to all retained
    snapshots (#4009).

    A snapshot's ``risk_summary`` is a per-scan count of *graph nodes* carrying
    each severity — a distinct metric from the exec open-finding headline
    (``/v1/overview`` / ``/v1/posture/counts``), which counts deduped findings
    across the estate. Each row is tagged ``severity_basis: "graph_nodes"`` so a
    consumer never mistakes the graph-node tally for the reconciled exec
    severity count (#3961).
    """
    from agent_bom.api import time_window

    since = time_window.window_since_iso(time_window.normalize_window_days(window_days))
    snapshots = await _graph_store_call(_get_graph_store_or_503().list_snapshots, tenant_id=_tenant(request), limit=limit, since=since)
    for snapshot in snapshots:
        if isinstance(snapshot, dict) and "risk_summary" in snapshot:
            snapshot["severity_basis"] = "graph_nodes"
    return snapshots


@router.get("/graph/history", tags=["graph"])
async def get_graph_history(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Max snapshots"),
    window_days: int | None = Query(None, ge=0, description="Default read-window in days; 0 = all retained history"),
) -> dict:
    """Return retained graph history and adjacent diff summaries for the request tenant.

    Defaults to the last ``AGENT_BOM_RETENTION_DAYS`` (≈90d); the applied window
    is echoed under ``window`` so clients can label it honestly (#4009).
    """
    from agent_bom.api import time_window

    resolved = time_window.normalize_window_days(window_days)
    since = time_window.window_since_iso(resolved)
    history = await _graph_store_call(_get_graph_store_or_503().graph_history, tenant_id=_tenant(request), limit=limit, since=since)
    if isinstance(history, dict):
        history["window"] = time_window.window_metadata(resolved)
    return history


@router.get("/graph/evidence-manifest", tags=["graph"])
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


@router.get("/graph/compliance", tags=["graph"])
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


@router.get("/graph/legend", tags=["graph"], deprecated=True)
def get_graph_legend() -> dict:
    """Return entity and relationship legends for UI rendering.

    Soft-deprecated: no UI/CLI/MCP product consumer (#3666 Phase 2).
    """
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
    EntityType.EXTERNAL_IMPORT.value: (
        ["code_graph"],
        "Reserved for source-code import topology; static supply-chain scans do not emit import nodes yet.",
    ),
}


_RESERVED_GRAPH_EDGE_KINDS: dict[str, tuple[list[str], str]] = {
    RelationshipType.IMPORTS.value: (
        ["code_graph"],
        "Reserved for source-code topology linking files, modules, packages, and imports.",
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
    # Managed front-doors read from live cloud inventory (AWS API Gateway, Azure
    # API Management, GCP API Gateway/Apigee) — not a static scan. They carry the
    # PROTECTS edge that refines a fronted resource's exposure verdict.
    EntityType.API_GATEWAY.value: ["cloud_inventory"],
    EntityType.TOOL_CALL.value: ["runtime_proxy", "gateway_event_projection"],
    EntityType.RESOURCE.value: ["runtime_proxy", "gateway_event_projection", "cnapp_overlay"],
    EntityType.FRAMEWORK.value: ["ai_inventory", "framework_agents"],
    # Repository folder/file-structure nodes emitted by the repo-structure
    # overlay for a code / project scan (directory tree + manifest files).
    EntityType.DIRECTORY.value: ["repo_structure_overlay"],
    EntityType.SOURCE_FILE.value: ["repo_structure_overlay"],
    EntityType.CONFIG_FILE.value: ["repo_structure_overlay"],
    EntityType.CODE_MODULE.value: ["code_graph_overlay"],
    EntityType.CI_JOB.value: ["ci_graph_overlay", "github_actions"],
}


_EMITTED_GRAPH_EDGE_SURFACES: dict[str, list[str]] = {
    # The account → resource ownership backbone. Emitted on every cloud scan by
    # ``_add_account_resource_hierarchy`` (alongside CONTAINS), plus org → policy
    # ownership from AWS Organizations / GCP org policies and the Snowflake
    # account → agent/principal lanes.
    RelationshipType.OWNS.value: ["cloud_inventory", "aws_organizations", "gcp_organizations", "snowflake"],
    RelationshipType.CALLED.value: ["runtime_proxy", "gateway_event_projection"],
    RelationshipType.USED_CREDENTIAL.value: ["runtime_proxy", "gateway_event_projection"],
    RelationshipType.USES_FRAMEWORK.value: ["ai_inventory", "framework_agents"],
    RelationshipType.OBSERVES.value: ["ai_inventory"],
    RelationshipType.DEFINES.value: ["code_graph_overlay"],
    RelationshipType.RUNS.value: ["ci_graph_overlay", "github_actions"],
    RelationshipType.CONFIGURES.value: ["ci_graph_overlay", "github_actions"],
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
    RelationshipType.USES_FRAMEWORK.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [EntityType.AGENT.value],
        "target_types": [EntityType.FRAMEWORK.value],
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
            EntityType.FRAMEWORK.value,
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
        "source_types": [EntityType.SERVER.value, EntityType.AGENT.value, EntityType.FRAMEWORK.value],
        "target_types": [EntityType.MODEL.value],
        "traversable": True,
    },
    RelationshipType.OBSERVES.value: {
        "category": "inventory",
        "direction": "directed",
        "source_types": [EntityType.FRAMEWORK.value],
        "target_types": [EntityType.AGENT.value, EntityType.SERVER.value],
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


@router.get("/graph/schema", tags=["graph"])
def get_graph_schema() -> dict:
    """Canonical graph entity/edge taxonomy — single source of truth.

    Drives the TypeScript codegen at ``ui/scripts/codegen-graph-schema.mjs``,
    which materialises ``ui/lib/graph-schema.generated.ts``.  CI fails the
    build when the checked-in generated file drifts from what this endpoint
    would emit, so adding a new ``EntityType`` or ``RelationshipType`` in
    Python automatically forces a regen + commit on the UI side.
    """
    from agent_bom.graph import ENTITY_LEGEND, ENTITY_OCSF_MAP, RELATIONSHIP_LEGEND
    from agent_bom.graph.integration_contract import GRAPH_COMPATIBILITY
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
        "interchange": GRAPH_COMPATIBILITY,
        "semantic_layers": [{"key": layer.value, "label": _SEMANTIC_LAYER_LABELS[layer.value]} for layer in GraphSemanticLayer],
        "node_kinds": sorted(node_kinds, key=lambda d: d["key"]),
        "edge_kinds": sorted(edge_kinds, key=lambda d: d["key"]),
        "node_types": sorted(entity.value for entity in EntityType),
        "edge_types": sorted(rel.value for rel in RelationshipType),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Saved filter presets
# ═══════════════════════════════════════════════════════════════════════════


@router.post("/graph/presets", tags=["graph"])
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


@router.get("/graph/presets", tags=["graph"])
async def list_presets(request: Request) -> list[dict]:
    """List saved filter presets for the current tenant."""
    return await _graph_store_call(_get_graph_store_or_503().list_presets, tenant_id=_tenant(request))


@router.delete("/graph/presets/{name}", tags=["graph"])
async def delete_preset(request: Request, name: str) -> dict:
    """Delete a saved filter preset."""
    deleted = await _graph_store_call(_get_graph_store_or_503().delete_preset, tenant_id=_tenant(request), name=name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Preset '{name}' not found")
    return {"name": name, "status": "deleted"}


# ═══════════════════════════════════════════════════════════════════════════
# Estate-scale roll-up (CONTAINS) — backend for the UI graph-nav drill-down
# ═══════════════════════════════════════════════════════════════════════════

# Edge load for /v1/graph/rollup (default mode). Taken from the roll-up itself
# rather than restated here, so the set fetched can never be narrower than the
# set rolled up — which is precisely what a containment-only fetch made it: the
# roll-up draws the NON-containment edges, so it received nothing to draw.
_ROLLUP_RELATIONSHIPS = ROLLUP_RELATIONSHIPS
_ROLLUP_DRILLDOWN_DEFAULT_LIMIT = 200
_ROLLUP_DRILLDOWN_MAX_LIMIT = 1000


@router.get("/graph/rollup", tags=["graph"])
async def get_graph_rollup(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
    snapshot_generation: Optional[str] = Query(None, max_length=128, description="Read revision from the first drill-down page"),
    node: Optional[str] = Query(None, description="Drill down into a container node's direct children"),
    min_severity: Optional[str] = Query(None, description="Only roll up descendants at/above this severity"),
    exposed: bool = Query(False, description="Only roll up internet-exposed descendants"),
    toxic: bool = Query(False, description="Only roll up toxic-combination descendants"),
    mode: Literal["rollup", "attack_path"] = Query("rollup", description="rollup (default) or attack_path-first view"),
    offset: int = Query(0, ge=0, le=1_000_000, description="Drill-down only: ranked-children page offset"),
    limit: int = Query(
        _ROLLUP_DRILLDOWN_DEFAULT_LIMIT,
        ge=1,
        le=_ROLLUP_DRILLDOWN_MAX_LIMIT,
        description="Drill-down only: maximum direct children returned per page",
    ),
) -> dict:
    """Collapse the estate along ``CONTAINS`` into a small, readable view.

    Past a few hundred nodes the raw topology is an unreadable hairball. This
    endpoint rolls the graph up along the containment hierarchy
    (org -> account/project -> app -> resource) so a 1000+ node estate renders
    as a handful of top-level containers, each carrying aggregate descendant
    counts, worst-severity, a per-severity histogram, and exposure / toxic
    flags. ``?node=<id>`` returns one level of direct children for on-demand
    drill-down, paged by ``offset``/``limit`` with ``pagination`` and truthful
    ``completeness``; ``?mode=attack_path`` returns the nodes/edges on materialised
    attack paths first with the rest collapsed.

    Backend for the UI graph-navigation surface. Read-only: never mutates the
    source graph.
    """
    tenant = _tenant(request)
    graph_store = _get_graph_store_or_503()
    requested_scan_id = scan_id or ""

    if not requested_scan_id and not await _graph_store_call(
        graph_store.latest_snapshot_id,
        tenant_id=tenant,
        snapshot_kind="scan",
    ):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    if min_severity and min_severity.lower() not in SEVERITY_RANK:
        raise HTTPException(status_code=422, detail=f"Unsupported severity: {min_severity}")

    # Cache the small summary, never the hydrated estate. Durable generation
    # prevents same-ID replacement from replaying counts from an older snapshot.
    from agent_bom.api import graph_rollup_cache

    identity = await _graph_store_call(
        optional_generation,
        graph_store,
        tenant=tenant,
        scan_id=requested_scan_id,
        generation=snapshot_generation,
        offset=offset if node else 0,
    )
    cache_key = None
    if identity and identity[1]:
        cache_key = (
            id(graph_store),
            tenant,
            identity,
            getattr(request.state, "api_key_id", ""),
            getattr(request.state, "api_key_name", ""),
            getattr(request.state, "api_key_role", ""),
            tuple(sorted(getattr(request.state, "api_key_scopes", []) or [])),
            node,
            min_severity,
            exposed,
            toxic,
            mode,
            offset if node else 0,
            limit if node else 0,
        )
        cached = graph_rollup_cache.get(cache_key)
        if cached is not None:
            return cached
        requested_scan_id = identity[0]

    try:
        if node:
            # A drill-down reads one container's subtree, so that subtree is all
            # this request fetches. Loading the whole snapshot to return twenty
            # children made the cost of the answer track estate size rather than
            # answer size (5k nodes 54ms -> 80k nodes 1169ms, twenty children
            # either way).
            graph = await _graph_store_call(
                containment_drilldown_graph,
                graph_store,
                node_id=node,
                scan_id=requested_scan_id,
                tenant_id=tenant,
            )
        else:
            load_kwargs: dict[str, Any] = {
                "scan_id": requested_scan_id,
                "tenant_id": tenant,
            }
            if mode != "attack_path":
                load_kwargs["relationship_types"] = _ROLLUP_RELATIONSHIPS
            # SQLite can avoid hydrating evidence JSON for an aggregate-only
            # view. Other stores retain the full, equivalent load. Attack-path
            # mode always needs the complete evidence records.
            rollup_loader = getattr(graph_store, "load_rollup_graph", None)
            if mode == "rollup" and callable(rollup_loader):
                graph = await _graph_store_call(rollup_loader, scan_id=requested_scan_id, tenant_id=tenant)
            else:
                graph = await _graph_store_call(graph_store.load_graph, **load_kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    try:
        payload = await _graph_compute_call(
            _graph_rollup_payload,
            graph,
            node=node,
            min_severity=(min_severity or "").lower(),
            exposed=exposed,
            toxic=toxic,
            mode=mode,
            offset=offset,
            limit=limit,
        )
        if identity is not None:
            await _graph_store_call(verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(graph.nodes))
            payload["snapshot_generation"] = identity[1]
        if cache_key:
            graph_rollup_cache.put(cache_key, payload)
        return payload
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Never leak internal exception detail in the response (CodeQL lesson).
        logger.warning("graph rollup failed", exc_info=False)
        raise HTTPException(status_code=500, detail="Failed to compute graph roll-up") from exc
