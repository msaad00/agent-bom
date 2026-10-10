"""Graph-native MCP tools for headless agent consumers."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import sqlite3
import uuid
from typing import Any

from agent_bom.cloud.runtime_graph_evidence import _enrich_loaded_graph_runtime_evidence
from agent_bom.config import GRAPH_INVESTIGATION_NODE_BUDGET, MCP_MAX_RESPONSE_CHARS
from agent_bom.graph.completeness import graph_completeness
from agent_bom.graph.edge_lookup import _build_edge_lookup, _EdgeLookup
from agent_bom.graph.exposure import _exposure_path_for_attack_path, _exposure_ref_for_node, _exposure_relationships_for_path
from agent_bom.graph.exposure_cursor import decode_exposure_cursor
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.mcp_errors import (
    CODE_INTERNAL_UNEXPECTED,
    CODE_NOT_FOUND_RESOURCE,
    CODE_UNSUPPORTED_BACKEND,
    CODE_UPSTREAM_UNAVAILABLE,
    CODE_VALIDATION_INVALID_ARGUMENT,
    CODE_VALIDATION_MISSING_REQUIRED,
    mcp_error_json,
)
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.storage import default_graph_store

logger = logging.getLogger(__name__)

_STORAGE_UNAVAILABLE_ERRORS: tuple[type[Exception], ...] = (OSError, sqlite3.OperationalError)
try:
    from psycopg import OperationalError as _PostgresOperationalError
except ImportError:
    pass  # Postgres is an optional deployment extra.
else:
    _STORAGE_UNAVAILABLE_ERRORS += (_PostgresOperationalError,)


def _graph_read_error(exc: Exception) -> str:
    if isinstance(exc, _STORAGE_UNAVAILABLE_ERRORS):
        return mcp_error_json(CODE_UPSTREAM_UNAVAILABLE, "Graph storage is temporarily unavailable; retry the request.")
    logger.error("MCP graph tool error; internal details withheld")
    return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "An internal error has occurred.")


async def graph_correlate_impl(
    *,
    name: str,
    scan_ids: list[str],
    max_age_hours: int,
    idempotency_key: str,
    reason: str,
    allow_stale: bool = False,
    tenant_id: str = "default",
    _service=None,
    _truncate_response=None,
    _authenticated_actor: str = "",
    **_audit: str,
) -> str:
    """Create a tenant-scoped immutable graph correlation."""
    from agent_bom.graph.correlation_service import CorrelationRequest, CorrelationServiceError, get_graph_correlation_service

    if not name.strip():
        return mcp_error_json(CODE_VALIDATION_MISSING_REQUIRED, "name is required", details={"argument": "name"})
    if not idempotency_key.strip():
        return mcp_error_json(
            CODE_VALIDATION_MISSING_REQUIRED,
            "idempotency_key is required",
            details={"argument": "idempotency_key"},
        )
    if len(reason.strip()) < 8:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "reason must be at least 8 characters",
            details={"argument": "reason"},
        )
    if not 2 <= len(scan_ids) <= 32 or len(set(scan_ids)) != len(scan_ids) or any(not item.strip() for item in scan_ids):
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "scan_ids must contain between 2 and 32 distinct non-empty snapshot ids",
            details={"argument": "scan_ids"},
        )
    if not 1 <= max_age_hours <= 8760:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "max_age_hours must be between 1 and 8760",
            details={"argument": "max_age_hours", "value": max_age_hours},
        )
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    try:
        if _service is None:
            _get_graph_store = default_graph_store

            _service = await get_graph_correlation_service(_get_graph_store(), tenant_id)
        run = await _service.submit(
            CorrelationRequest(
                correlation_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                idempotency_key=idempotency_key,
                name=name.strip(),
                scan_ids=tuple(scan_ids),
                max_age_hours=max_age_hours,
                allow_stale=allow_stale,
            )
        )
        from agent_bom.api.audit_log import log_action

        log_action(
            "graph.correlation.create",
            actor=(_authenticated_actor or "mcp-operator").strip(),
            resource=f"graph/correlation/{run.correlation_id}",
            tenant_id=tenant_id,
            source_count=len(run.input_manifest),
            max_age_hours=run.max_age_hours,
            allow_stale=run.allow_stale,
            reason_provided=True,
        )
        encoded = json.dumps(run.to_dict(), indent=2, default=str)
        return _truncate_response(encoded) if _truncate_response is not None else encoded
    except CorrelationServiceError as exc:
        code = CODE_NOT_FOUND_RESOURCE if exc.code == "input_snapshot_not_found" else CODE_VALIDATION_INVALID_ARGUMENT
        return mcp_error_json(code, exc.code)
    except ValueError:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "idempotency_key_conflict")
    except Exception:
        logger.error("MCP graph correlation creation failed; internal details withheld")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "An internal error has occurred.")


async def graph_correlation_status_impl(
    correlation_id: str,
    *,
    tenant_id: str = "default",
    _get_graph_store=None,
    _truncate_response=None,
) -> str:
    """Read one tenant-scoped graph correlation run."""

    if not correlation_id.strip():
        return mcp_error_json(
            CODE_VALIDATION_MISSING_REQUIRED,
            "correlation_id is required",
            details={"argument": "correlation_id"},
        )
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    try:
        if _get_graph_store is None:
            _get_graph_store = default_graph_store
        run = await asyncio.to_thread(
            _get_graph_store().get_correlation_run,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
        )
        if run is None:
            return mcp_error_json(CODE_NOT_FOUND_RESOURCE, "correlation_not_found")
        from agent_bom.api.audit_log import log_action

        log_action(
            "graph.correlation.read",
            actor="mcp-reader",
            resource=f"graph/correlation/{correlation_id}",
            tenant_id=tenant_id,
            status=run.status.value,
        )
        encoded = json.dumps(run.to_dict(), indent=2, default=str)
        return _truncate_response(encoded) if _truncate_response is not None else encoded
    except Exception:
        logger.error("MCP graph correlation status failed; internal details withheld")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "An internal error has occurred.")


# Retain private compatibility helpers while keeping the projection canonical.
_node_ref = _exposure_ref_for_node
_relationship_refs = _exposure_relationships_for_path


def _exposure_path_payload(
    path: Any,
    *,
    nodes_by_id: dict[str, Any],
    edges: list[Any],
    rank: int,
    scan_id: str,
    edge_lookup: _EdgeLookup | None = None,
) -> dict[str, Any]:
    payload = _exposure_path_for_attack_path(
        path,
        nodes_by_id=nodes_by_id,
        edges=edges,
        rank=rank,
        scan_id=scan_id,
        edge_lookup=edge_lookup,
    )
    payload["provenance"] = {"source": "mcp_exposure_paths", "scanId": scan_id}
    return payload


def _project_exposure_page(
    paths: list[Any],
    *,
    nodes: list[Any],
    edges: list[Any],
    offset: int,
    scan_id: str,
) -> list[dict[str, Any]]:
    """Index hydrated evidence once, then project only each path's hop edges."""
    nodes_by_id = {node.id: node for node in nodes}
    edge_lookup = _build_edge_lookup(edges)
    return [
        _exposure_path_payload(
            path,
            nodes_by_id=nodes_by_id,
            edges=edges,
            rank=offset + index + 1,
            scan_id=scan_id,
            edge_lookup=edge_lookup,
        )
        for index, path in enumerate(paths)
    ]


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
            haystack.extend(str(value.get(key, "")) for key in ("id", "label", "role", "entityType"))
    for hop in path.get("hops", []):
        if isinstance(hop, dict):
            haystack.extend(str(hop.get(key, "")) for key in ("id", "label", "role", "entityType"))
    return any(needle in value.lower() for value in haystack)


def _decision_for_risk(risk: float, *, warn_risk: float, block_risk: float) -> str:
    if risk >= block_risk:
        return "block"
    if risk >= warn_risk:
        return "warn"
    return "allow"


def _empty_exposure_paths_message(*, total: int, min_risk: float) -> str | None:
    if total == 0:
        return "No exposure paths were recorded or derived for this snapshot. This does not establish that its assets are safe."
    if min_risk > 0:
        return f"0 paths matched min_risk={min_risk}; lower min_risk to inspect lower-risk ExposurePaths."
    return "0 paths matched the current filters."


def _graph_evidence_scope(scan_id: str, generation: str | None, source: dict[str, Any]) -> dict[str, Any]:
    return {
        "scan_id": scan_id,
        "evidence_scope": source.get("evidence_scope", "current_estate" if scan_id.startswith("current-estate:") else "scan_snapshot"),
        "snapshot_generation": generation,
        "collection_coverage": source.get("collection_coverage", {"status": "unknown"}),
    }


async def exposure_paths_impl(
    *,
    tenant_id: str = "default",
    scan_id: str | None = None,
    limit: int = 5,
    min_risk: float = 0.0,
    cursor: str | None = None,
    _get_graph_store=None,
    _truncate_response=None,
) -> str:
    return await exposure_paths_for_tenant(
        tenant_id=resolve_mcp_tool_tenant_id(tenant_id),
        scan_id=scan_id,
        limit=limit,
        min_risk=min_risk,
        cursor=cursor,
        _get_graph_store=_get_graph_store,
        _truncate_response=_truncate_response,
    )


async def _resolve_exposure_snapshot(tenant_id: str, scan_id: str | None) -> tuple[str | None, str | None]:
    if not scan_id:
        return scan_id, None
    from agent_bom.api.graph_scan_ids import resolve_graph_scan_id

    try:
        return await asyncio.to_thread(resolve_graph_scan_id, tenant_id, scan_id), None
    except _STORAGE_UNAVAILABLE_ERRORS as exc:
        return None, _graph_read_error(exc)


async def exposure_paths_for_tenant(
    *,
    tenant_id: str,
    scan_id: str | None = None,
    limit: int = 5,
    min_risk: float = 0.0,
    cursor: str | None = None,
    _get_graph_store=None,
    _truncate_response=None,
) -> str:
    """Return ranked ExposurePath JSON for an already-authenticated tenant.

    Callers must pass a tenant established by their own authentication (the
    REST request principal); MCP tools go through ``exposure_paths_impl``.
    """
    if limit < 1 or limit > 100:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "limit must be between 1 and 100",
            details={"argument": "limit", "value": limit},
        )
    if not 0 <= min_risk <= 100:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            "min_risk must be between 0 and 100",
            details={"argument": "min_risk", "value": min_risk},
        )

    if scan_id and "\x00" in scan_id:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Invalid graph snapshot identifier.")
    scan_id, resolution_error = await _resolve_exposure_snapshot(tenant_id, scan_id)
    if resolution_error:
        return resolution_error

    # Cursors locate evidence; authorization always comes from the caller's
    # tenant. Pin the snapshot and filter so a new scan cannot shift page two.
    scope = hashlib.sha256(json.dumps([tenant_id, float(min_risk)]).encode()).hexdigest()
    continuation: dict[str, Any] = {}
    offset = 0
    if cursor:
        try:
            continuation = decode_exposure_cursor(cursor, scope=scope, scan_id=scan_id)
            scan_id, offset = continuation["scan"], continuation["offset"]
        except (ValueError, TypeError, KeyError):
            return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Invalid exposure cursor; restart the query.")

    try:
        if _get_graph_store is None:
            _get_graph_store = default_graph_store

        store = _get_graph_store()
        try:
            pinned_scan_id, generation = await asyncio.to_thread(
                store.snapshot_identity, tenant_id=tenant_id, scan_id=scan_id or "", for_paging=True
            )
        except NotImplementedError:
            return mcp_error_json(
                CODE_UNSUPPORTED_BACKEND,
                "Exposure paths require generation-pinned graph reads, which this graph backend does not support.",
            )
        effective_scan_id, created_at, paths, total = await asyncio.to_thread(
            store.attack_paths,
            tenant_id=tenant_id,
            scan_id=pinned_scan_id,
            offset=offset,
            limit=limit + 1,
        )
        path_source = "persisted_graph_paths"
        derivation_truncated = False
        derived_revision = ""
        if total == 0:
            # Keep the same topology semantics as the dashboard without importing
            # its optional FastAPI routes into the MCP-only installation.
            graph = await asyncio.to_thread(
                store.load_graph,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                node_budget=GRAPH_INVESTIGATION_NODE_BUDGET,
            )
            graph = await asyncio.to_thread(_enrich_loaded_graph_runtime_evidence, graph, tenant_id)
            paths = await asyncio.to_thread(_derived_attack_paths, graph)
            effective_scan_id, created_at = graph.scan_id, graph.created_at
            total = len(paths)
            derived_revision = hashlib.sha256(
                json.dumps([(p.hops, p.edges, p.composite_risk, p.reachability) for p in paths], sort_keys=True).encode()
            ).hexdigest()
            paths = paths[offset : offset + limit + 1]
            path_source = "derived_graph_paths"
            derivation_truncated = graph.completeness.truncated
        revision = hashlib.sha256(
            json.dumps([path_source, effective_scan_id, generation, created_at, total, derived_revision], default=str).encode()
        ).hexdigest()
        if continuation and continuation["revision"] != revision:
            return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Exposure snapshot changed; restart the query.")
        eligible_paths = [path for path in paths if float(getattr(path, "composite_risk", 0.0) or 0.0) >= min_risk]
        ranked_paths = eligible_paths[:limit]
        hop_ids = {hop for path in ranked_paths for hop in (getattr(path, "hops", []) or [])}
        nodes = await asyncio.to_thread(store.nodes_by_ids, tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=hop_ids)
        edges = await asyncio.to_thread(
            store.edges_for_node_ids, tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=hop_ids, induced_only=True
        )
        stats = await asyncio.to_thread(store.snapshot_stats, tenant_id=tenant_id, scan_id=effective_scan_id)
        final_identity = await asyncio.to_thread(store.snapshot_identity, tenant_id=tenant_id, scan_id=pinned_scan_id, for_paging=True)
        if final_identity != (pinned_scan_id, generation) or (paths and not generation):
            return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "Exposure snapshot changed; restart the query.")
        payload = {
            "schema_version": "v1",
            "tool": "exposure_paths",
            "tenant_id": tenant_id,
            **_graph_evidence_scope(effective_scan_id, generation, stats),
            "created_at": created_at,
            "count": len(ranked_paths),
            "total": total,
            "count_metadata": {"source": path_source, "total_is_lower_bound": derivation_truncated},
            "filters": {"limit": limit, "min_risk": min_risk},
            "paths": _project_exposure_page(ranked_paths, nodes=nodes, edges=edges, offset=offset, scan_id=effective_scan_id),
            "nodes": [node.to_dict() for node in nodes],
            "edges": [edge.to_dict() for edge in edges],
            "stats": stats,
            "completeness": graph_completeness(
                returned=len(ranked_paths),
                total=None if derivation_truncated else total,
                truncated=derivation_truncated or len(ranked_paths) < total,
                reason="node_budget" if derivation_truncated else "path_limit_or_filter" if len(ranked_paths) < total else "",
            ),
        }
        if not ranked_paths:
            payload["message"] = (
                "No paths found within the graph node budget. No conclusion about the full snapshot can be drawn."
                if derivation_truncated
                else _empty_exposure_paths_message(total=total, min_risk=min_risk)
            )
        # Fit complete path objects rather than returning a sliced JSON preview.
        # Every omitted path remains reachable through the continuation cursor.
        while True:
            returned = len(payload["paths"])
            has_more = len(eligible_paths) > returned
            next_cursor = None
            if has_more and returned:
                next_cursor = base64.urlsafe_b64encode(
                    json.dumps(
                        {"v": 1, "scope": scope, "scan": effective_scan_id, "offset": offset + returned, "revision": revision},
                        separators=(",", ":"),
                    ).encode()
                ).decode()
            selected_nodes = {node_id for path in payload["paths"] for node_id in path["nodeIds"]}
            selected_edges = {edge_id for path in payload["paths"] for edge_id in path["edgeIds"]}
            payload["nodes"] = [node.to_dict() for node in nodes if node.id in selected_nodes]
            payload["edges"] = [edge.to_dict() for edge in edges if edge.id in selected_edges]
            payload["count"] = returned
            payload["pagination"] = {
                "offset": offset,
                "limit": limit,
                "returned": returned,
                "has_more": has_more,
                "next_cursor": next_cursor,
            }
            payload["completeness"] = graph_completeness(
                returned=returned,
                total=None if derivation_truncated else total,
                truncated=derivation_truncated or offset > 0 or returned < total,
                reason="node_budget" if derivation_truncated else "path_limit_or_filter" if offset > 0 or returned < total else "",
            )
            encoded = json.dumps(payload, separators=(",", ":"), default=str)
            if len(encoded) <= MCP_MAX_RESPONSE_CHARS:
                return _truncate_response(encoded) if _truncate_response is not None else encoded
            if returned <= 1:
                return mcp_error_json(
                    CODE_VALIDATION_INVALID_ARGUMENT,
                    "One exposure path exceeds the response budget; inspect its snapshot through bounded graph node endpoints.",
                )
            payload["paths"] = payload["paths"][: max(1, returned // 2)]
    except Exception as exc:
        return _graph_read_error(exc)


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
    return await deploy_decision_for_tenant(
        candidate=candidate,
        tenant_id=resolve_mcp_tool_tenant_id(tenant_id),
        scan_id=scan_id,
        limit=limit,
        warn_risk=warn_risk,
        block_risk=block_risk,
        _get_graph_store=_get_graph_store,
        _truncate_response=_truncate_response,
    )


async def deploy_decision_for_tenant(
    *,
    candidate: str,
    tenant_id: str,
    scan_id: str | None = None,
    limit: int = 5,
    warn_risk: float = 40.0,
    block_risk: float = 80.0,
    _get_graph_store=None,
    _truncate_response=None,
) -> str:
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

    response = await exposure_paths_for_tenant(
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
    max_risk = max((float(path.get("riskScore", 0.0) or 0.0) for path in matched_paths), default=None)
    decision = _decision_for_risk(max_risk, warn_risk=warn_risk, block_risk=block_risk) if max_risk is not None else "warn"
    evidence_evaluated = bool(matched_paths) and all(path.get("reachability") in {"likely", "confirmed"} for path in matched_paths)
    evidence_complete = payload.get("completeness", {}).get("complete", False)
    if decision == "allow" and (not evidence_evaluated or not evidence_complete):
        decision = "warn"
    reasons: list[str] = []
    if matched_paths:
        top = matched_paths[0]
        reasons.append(f"Top matched exposure path risk is {top.get('riskScore', 0)} for {top.get('label') or top.get('id')}.")
        findings = sorted({str(finding) for path in matched_paths for finding in path.get("findings", []) if finding})
        if findings:
            reasons.append(f"Matched findings: {', '.join(findings[:5])}.")
        if not evidence_evaluated or not evidence_complete:
            reasons.append("Reachability is unverified or path evidence is incomplete; this is not an approval to deploy.")
    else:
        reasons.append("No matching exposure path evidence was found for the candidate; this is not an approval to deploy.")

    # Deliberately two-valued. A CI gate that needs to tell "no paths matched"
    # from "paths matched but reachability is unverified" reads matchedPathCount
    # alongside this; adding a third value here would break every consumer that
    # switches on the two.
    evidence_status = "evaluated" if evidence_evaluated and evidence_complete else "not_evaluated"

    encoded = json.dumps(
        {
            "schema_version": "v1",
            "tool": "should_i_deploy",
            "tenant_id": tenant_id,
            **_graph_evidence_scope(payload.get("scan_id", scan_id or ""), payload.get("snapshot_generation"), payload),
            "candidate": {"value": candidate_value},
            "decision": decision,
            "maxRisk": max_risk,
            "evidenceStatus": evidence_status,
            "thresholds": {"warnRisk": warn_risk, "blockRisk": block_risk},
            "reasons": reasons,
            "matchedPathCount": len(matched_paths),
            "matchedPaths": matched_paths,
            "provenance": {
                "source": "mcp_should_i_deploy",
                "basis": "exposure_paths" if matched_paths else "no_matching_exposure_path_evidence",
            },
        },
        indent=2,
        default=str,
    )
    return _truncate_response(encoded) if _truncate_response is not None else encoded
