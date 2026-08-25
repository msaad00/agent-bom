"""Saved, snapshot-pinned proposed graph scenarios and deterministic comparison."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timezone
from typing import Annotated, Any, Literal, Union
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from agent_bom.api.graph_scenario_store import GraphScenarioConflictError
from agent_bom.api.neptune_graph import NeptuneGraphStore, NeptuneGraphStoreUnsupportedOperationError
from agent_bom.api.stores import _get_graph_scenario_store, _get_graph_store
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.graph import EntityType, RelationshipType
from agent_bom.security import sanitize_error

router = APIRouter()

_SCENARIO_SCHEMA = "graph.scenarios.v1"
_COMPARISON_SCHEMA = "graph.scenario-comparison.v1"
_MAX_OPERATIONS = 500
_MAX_PAYLOAD_BYTES = 512 * 1024
_COMPARISON_NODE_BUDGET = 2_000
_COMPARISON_PATH_BUDGET = 5_000
_SEVERITIES = Literal["", "critical", "high", "medium", "low", "info", "unknown"]
ScenarioAssumption = Annotated[str, Field(max_length=1_000)]


class _ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScenarioNodeAttributes(_ClosedModel):
    """Presentation and posture attributes scenarios may model."""

    description: str | None = Field(None, max_length=2_000)
    environment: str | None = Field(None, max_length=128)
    owner: str | None = Field(None, max_length=256)
    provider: str | None = Field(None, max_length=128)
    region: str | None = Field(None, max_length=128)
    account_id: str | None = Field(None, max_length=256)
    repository: str | None = Field(None, max_length=512)
    fix_status: Literal["fixable", "not_fixable", "unknown"] | None = None
    disposition: Literal["open", "accepted", "mitigated", "resolved", "unknown"] | None = None
    reachability: Literal["confirmed", "likely", "unlikely", "unknown"] | None = None


class ScenarioNodePatch(_ClosedModel):
    label: str | None = Field(None, min_length=1, max_length=512)
    status: Literal["active", "inactive", "unknown"] | None = None
    risk_score: float | None = Field(None, ge=0.0, le=10.0)
    severity: _SEVERITIES | None = None
    attributes: ScenarioNodeAttributes | None = None
    compliance_tags: list[str] | None = Field(None, max_length=100)
    data_sources: list[str] | None = Field(None, max_length=100)


class AddNodeOperation(_ClosedModel):
    kind: Literal["add_node"]
    key: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    entity_type: EntityType
    label: str = Field(min_length=1, max_length=512)
    presentation: ScenarioNodePatch = Field(default=ScenarioNodePatch(label=None, risk_score=None, compliance_tags=None, data_sources=None))
    assumption: str = Field("", max_length=1_000)
    rationale: str = Field("", max_length=2_000)


class RemoveNodeOperation(_ClosedModel):
    kind: Literal["remove_node"]
    node_id: str = Field(min_length=1, max_length=512)


class PatchNodeOperation(_ClosedModel):
    kind: Literal["patch_node"]
    node_id: str = Field(min_length=1, max_length=512)
    patch: ScenarioNodePatch


class AddEdgeOperation(_ClosedModel):
    kind: Literal["add_edge"]
    source: str = Field(min_length=1, max_length=512)
    target: str = Field(min_length=1, max_length=512)
    relationship: RelationshipType
    direction: Literal["directed", "bidirectional"] = "directed"
    weight: float = Field(1.0, ge=0.0, le=10.0)
    traversable: bool = True
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    assumption: str = Field("", max_length=1_000)
    rationale: str = Field("", max_length=2_000)


class RemoveEdgeOperation(_ClosedModel):
    kind: Literal["remove_edge"]
    source: str = Field(min_length=1, max_length=512)
    target: str = Field(min_length=1, max_length=512)
    relationship: RelationshipType


ScenarioOperation = Annotated[
    Union[AddNodeOperation, RemoveNodeOperation, PatchNodeOperation, AddEdgeOperation, RemoveEdgeOperation],
    Field(discriminator="kind"),
]
_OPERATION_ADAPTER = TypeAdapter(list[ScenarioOperation])


class GraphScenarioCreate(_ClosedModel):
    name: str = Field(min_length=1, max_length=160)
    description: str = Field("", max_length=2_000)
    base_scan_id: str = Field(min_length=1, max_length=512)
    changes: list[ScenarioOperation] = Field(default_factory=list, max_length=_MAX_OPERATIONS)
    assumptions: list[ScenarioAssumption] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def _unique_additions(self) -> GraphScenarioCreate:
        _validate_unique_additions(self.changes)
        return self


class GraphScenarioUpdate(_ClosedModel):
    scenario_id: str = Field(min_length=1, max_length=512)
    expected_revision: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=160)
    description: str = Field("", max_length=2_000)
    changes: list[ScenarioOperation] = Field(default_factory=list, max_length=_MAX_OPERATIONS)
    assumptions: list[ScenarioAssumption] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def _unique_additions(self) -> GraphScenarioUpdate:
        _validate_unique_additions(self.changes)
        return self


def _validate_unique_additions(changes: list[ScenarioOperation]) -> None:
    node_keys = [change.key for change in changes if isinstance(change, AddNodeOperation)]
    if len(node_keys) != len(set(node_keys)):
        raise ValueError("add_node changes must use unique key values")
    proposed_keys = set(node_keys)
    for change in changes:
        if isinstance(change, (PatchNodeOperation, RemoveNodeOperation)) and change.node_id.startswith("proposal:"):
            raise ValueError("patch_node and remove_node may target only observed node IDs")
        if isinstance(change, (AddEdgeOperation, RemoveEdgeOperation)):
            for reference in (change.source, change.target):
                if reference.startswith("proposal:") and reference.removeprefix("proposal:") not in proposed_keys:
                    raise ValueError(f"unknown proposed node reference {reference!r}")
    mutated_nodes = [change.node_id for change in changes if isinstance(change, (PatchNodeOperation, RemoveNodeOperation))]
    if len(mutated_nodes) != len(set(mutated_nodes)):
        raise ValueError("an observed node may be patched or removed only once per scenario")
    edge_ids = [(change.source, change.target, change.relationship.value) for change in changes if isinstance(change, AddEdgeOperation)]
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("add_edge changes must use unique semantic edge identities")
    removed_edge_ids = {
        (change.source, change.target, change.relationship.value) for change in changes if isinstance(change, RemoveEdgeOperation)
    }
    if set(edge_ids).intersection(removed_edge_ids):
        raise ValueError("the same edge cannot be both added and removed")
    removed_nodes = {change.node_id for change in changes if isinstance(change, RemoveNodeOperation)}
    if any(
        reference in removed_nodes
        for change in changes
        if isinstance(change, AddEdgeOperation)
        for reference in (change.source, change.target)
    ):
        raise ValueError("an added edge cannot reference a node removed by the same scenario")


def _canonical_changes(changes: list[ScenarioOperation]) -> list[dict[str, Any]]:
    phase = {"add_node": 0, "patch_node": 1, "add_edge": 2, "remove_edge": 3, "remove_node": 4}
    dumped = [change.model_dump(mode="json") for change in changes]

    def key(change: dict[str, Any]) -> tuple[Any, ...]:
        return (
            phase[str(change["kind"])],
            str(change.get("key") or change.get("node_id") or change.get("source") or ""),
            str(change.get("target") or ""),
            str(change.get("relationship") or ""),
        )

    return sorted(dumped, key=key)


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded_body(body: BaseModel) -> None:
    if len(body.model_dump_json().encode("utf-8")) > _MAX_PAYLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Graph scenario payload exceeds 512 KiB")


async def _store_call(fn: Any, /, *args: Any, **kwargs: Any) -> Any:
    try:
        return await asyncio.to_thread(fn, *args, **kwargs)
    except GraphScenarioConflictError as exc:
        raise HTTPException(status_code=409, detail=sanitize_error(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Graph scenario not found") from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc


def _ensure_supported_graph_backend() -> Any:
    graph_store = _get_graph_store()
    if isinstance(graph_store, NeptuneGraphStore):
        raise HTTPException(status_code=501, detail="Graph scenarios are not supported by the experimental Neptune backend")
    return graph_store


async def _snapshot_state(graph_store: Any, tenant_id: str, scan_id: str) -> tuple[bool, bool, str]:
    try:
        snapshots = await asyncio.to_thread(graph_store.list_snapshots, tenant_id=tenant_id, limit=10_000)
        latest = await asyncio.to_thread(graph_store.latest_snapshot_id, tenant_id=tenant_id)
    except NeptuneGraphStoreUnsupportedOperationError as exc:
        raise HTTPException(status_code=501, detail=sanitize_error(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc
    available = any(str(snapshot.get("scan_id", "")) == scan_id for snapshot in snapshots)
    return available, bool(available and latest and latest != scan_id), latest


def _created_by(request: Request) -> str:
    return str(
        getattr(request.state, "principal_id", "")
        or getattr(request.state, "scim_subject_id", "")
        or getattr(request.state, "api_key_name", "")
        or "authenticated_operator"
    )[:256]


def _provenance(scenario_id: str, base_scan_id: str, created_by: str) -> dict[str, Any]:
    return {
        "kind": "proposed",
        "modeled": True,
        "evidence_state": "proposed",
        "observed": False,
        "deployed": False,
        "scenario_id": scenario_id,
        "base_scan_id": base_scan_id,
        "authority": "operator_authored_scenario",
        "created_by": created_by,
    }


def _new_record(tenant_id: str, body: GraphScenarioCreate, *, created_by: str) -> dict[str, Any]:
    scenario_id = str(uuid4())
    now = _now()
    return {
        "id": scenario_id,
        "tenant_id": tenant_id,
        "base_scan_id": body.base_scan_id,
        "revision": 1,
        "name": body.name,
        "description": body.description,
        "operations": _canonical_changes(body.changes),
        "assumptions": list(body.assumptions),
        "created_by": created_by,
        "provenance": _provenance(scenario_id, body.base_scan_id, created_by),
        "created_at": now,
        "updated_at": now,
    }


def _updated_record(current: dict[str, Any], body: GraphScenarioUpdate) -> dict[str, Any]:
    return {
        **current,
        "revision": body.expected_revision + 1,
        "name": body.name,
        "description": body.description,
        "operations": _canonical_changes(body.changes),
        "assumptions": list(body.assumptions),
        # Server-owned provenance and the exact base snapshot are immutable.
        "provenance": dict(current["provenance"]),
        "updated_at": _now(),
    }


def _public_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    """Map the persistence record to the stable UI/API contract."""
    return {
        "scenario_id": scenario["id"],
        "tenant_id": scenario["tenant_id"],
        "base_scan_id": scenario["base_scan_id"],
        "revision": scenario["revision"],
        "name": scenario["name"],
        "description": scenario["description"],
        "changes": scenario.get("operations") or [],
        "assumptions": scenario.get("assumptions") or [],
        "created_by": scenario.get("created_by") or scenario.get("provenance", {}).get("created_by", ""),
        "provenance": scenario["provenance"],
        "created_at": scenario["created_at"],
        "updated_at": scenario["updated_at"],
    }


def _deny_managed_trial_write() -> None:
    from agent_bom.api.managed_trial import managed_trial_enabled

    if managed_trial_enabled():
        raise HTTPException(status_code=403, detail="Managed trial graph scenarios are read-only")


def _edge_key(source: str, target: str, relationship: str) -> tuple[str, str, str]:
    return source, target, relationship


def _path_id(path: Any) -> str:
    payload = f"{path.source}\0{path.target}\0{'|'.join(path.hops)}".encode()
    return "path:" + hashlib.sha256(payload).hexdigest()[:24]


def _patch_node(node: dict[str, Any], patch: ScenarioNodePatch, provenance: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(node))
    changes = patch.model_dump(exclude_none=True)
    attrs = changes.pop("attributes", None)
    for key, value in changes.items():
        result[key] = value
    if attrs is not None:
        result["attributes"] = {**dict(result.get("attributes") or {}), **attrs}
    result["scenario_provenance"] = provenance
    return result


def _resolve_node_reference(scenario_id: str, reference: str) -> str:
    if not reference.startswith("proposal:"):
        return reference
    key = reference.removeprefix("proposal:")
    return f"proposal:{scenario_id}:{key}"


def _entity_provenance(scenario: dict[str, Any], operation: Any) -> dict[str, Any]:
    base = dict(scenario["provenance"])
    scenario_assumptions = scenario.get("assumptions") or []
    return {
        **base,
        "revision": int(scenario["revision"]),
        "author": scenario.get("created_by", ""),
        "assumption": str(getattr(operation, "assumption", "") or (scenario_assumptions[0] if scenario_assumptions else "")),
        "rationale": str(getattr(operation, "rationale", "") or scenario.get("description", "")),
    }


def _apply_operations(
    *,
    scenario: dict[str, Any],
    graph: Any,
    exact_node_count: int,
    exact_edge_count: int,
    attack_paths: list[Any],
) -> dict[str, Any]:
    nodes = {node.id: node.to_dict() for node in graph.nodes.values()}
    edges = {_edge_key(edge.source, edge.target, edge.relationship.value): edge.to_dict() for edge in graph.edges}
    operations = _OPERATION_ADAPTER.validate_python(scenario.get("operations") or [])
    nodes_added: list[str] = []
    nodes_removed: list[str] = []
    nodes_changed: list[str] = []
    edges_added: list[str] = []
    edges_removed: list[str] = []
    touched_nodes: set[str] = set()

    for operation in operations:
        if isinstance(operation, AddNodeOperation):
            node_id = f"proposal:{scenario['id']}:{operation.key}"
            provenance = _entity_provenance(scenario, operation)
            if node_id in nodes:
                raise ValueError(f"add_node conflicts with existing node {node_id!r}")
            node: dict[str, Any] = {
                "id": node_id,
                "canonical_id": node_id,
                "entity_type": operation.entity_type.value,
                "label": operation.label,
                "status": "active",
                "risk_score": 0.0,
                "severity": "",
                "attributes": {},
                "compliance_tags": [],
                "data_sources": [],
                "dimensions": {},
            }
            node = _patch_node(node, operation.presentation, provenance)
            nodes[node_id] = node
            nodes_added.append(node_id)
            touched_nodes.add(node_id)
        elif isinstance(operation, RemoveNodeOperation):
            if operation.node_id not in nodes:
                raise ValueError(f"remove_node references unavailable node {operation.node_id!r}")
            del nodes[operation.node_id]
            removed_edges = [key for key in edges if operation.node_id in key[:2]]
            for key in removed_edges:
                del edges[key]
                edges_removed.append(f"{key[2]}:{key[0]}:{key[1]}")
            nodes_removed.append(operation.node_id)
            touched_nodes.add(operation.node_id)
        elif isinstance(operation, PatchNodeOperation):
            if operation.node_id not in nodes:
                raise ValueError(f"patch_node references unavailable node {operation.node_id!r}")
            nodes[operation.node_id] = _patch_node(nodes[operation.node_id], operation.patch, _entity_provenance(scenario, operation))
            nodes_changed.append(operation.node_id)
            touched_nodes.add(operation.node_id)
        elif isinstance(operation, AddEdgeOperation):
            provenance = _entity_provenance(scenario, operation)
            relationship = operation.relationship.value
            source = _resolve_node_reference(scenario["id"], operation.source)
            target = _resolve_node_reference(scenario["id"], operation.target)
            key = _edge_key(source, target, relationship)
            if source not in nodes or target not in nodes:
                raise ValueError("add_edge endpoints must exist in the pinned or proposed graph")
            if key in edges:
                raise ValueError("add_edge conflicts with an existing edge")
            edge_id = f"{relationship}:{source}:{target}"
            edges[key] = {
                "id": edge_id,
                "canonical_id": edge_id,
                "source": source,
                "target": target,
                "source_id": source,
                "target_id": target,
                "relationship": relationship,
                "direction": operation.direction,
                "weight": operation.weight,
                "traversable": operation.traversable,
                "confidence": operation.confidence,
                "provenance": provenance,
                "source_scan_id": scenario["base_scan_id"],
                "evidence": {},
            }
            edges_added.append(edge_id)
            touched_nodes.update((source, target))
        elif isinstance(operation, RemoveEdgeOperation):
            relationship = operation.relationship.value
            source = _resolve_node_reference(scenario["id"], operation.source)
            target = _resolve_node_reference(scenario["id"], operation.target)
            key = _edge_key(source, target, relationship)
            if key not in edges:
                raise ValueError("remove_edge references an unavailable edge")
            del edges[key]
            edges_removed.append(f"{relationship}:{source}:{target}")
            touched_nodes.update((source, target))

    removed_node_edge_ids = set(edges_removed)
    explicit_added = len(edges_added)
    explicit_removed = len(removed_node_edge_ids)
    touched_paths = sorted(
        {
            _path_id(path)
            for path in attack_paths
            if touched_nodes.intersection(path.hops) or path.source in touched_nodes or path.target in touched_nodes
        }
    )
    return {
        "proposed": {
            "node_count": max(0, exact_node_count + len(set(nodes_added)) - len(set(nodes_removed))),
            "edge_count": max(0, exact_edge_count + explicit_added - explicit_removed),
            "modeled": True,
            "completeness": graph.completeness.to_dict(),
            "nodes": [nodes[node_id] for node_id in sorted(nodes)],
            "edges": [edges[key] for key in sorted(edges)],
        },
        "difference": {
            "nodes_added": sorted(set(nodes_added)),
            "nodes_removed": sorted(set(nodes_removed)),
            "nodes_changed": sorted(set(nodes_changed)),
            "edges_added": sorted(set(edges_added)),
            "edges_removed": sorted(removed_node_edge_ids),
            "touched_observed_path_count": len(touched_paths),
            "touched_observed_path_ids": touched_paths,
        },
    }


def _empty_difference() -> dict[str, Any]:
    return {
        "nodes_added": [],
        "nodes_removed": [],
        "nodes_changed": [],
        "edges_added": [],
        "edges_removed": [],
        "touched_observed_path_count": 0,
        "touched_observed_path_ids": [],
    }


def _observed_references(scenario: dict[str, Any]) -> set[str]:
    references: set[str] = set()
    for operation in _OPERATION_ADAPTER.validate_python(scenario.get("operations") or []):
        if isinstance(operation, AddNodeOperation):
            references.add(f"proposal:{scenario['id']}:{operation.key}")
        elif isinstance(operation, (PatchNodeOperation, RemoveNodeOperation)):
            references.add(operation.node_id)
        elif isinstance(operation, (AddEdgeOperation, RemoveEdgeOperation)):
            references.update(reference for reference in (operation.source, operation.target) if not reference.startswith("proposal:"))
    return references


@router.get("/graph/scenarios", tags=["graph"])
async def list_graph_scenarios(request: Request) -> dict[str, Any]:
    _ensure_supported_graph_backend()
    scenarios = await _store_call(_get_graph_scenario_store().list, _tenant(request), limit=100)
    return {"schema": _SCENARIO_SCHEMA, "count": len(scenarios), "scenarios": [_public_scenario(item) for item in scenarios]}


@router.post("/graph/scenarios", tags=["graph"], status_code=201)
async def create_graph_scenario(request: Request, body: GraphScenarioCreate) -> dict[str, Any]:
    _bounded_body(body)
    _deny_managed_trial_write()
    tenant_id = _tenant(request)
    graph_store = _ensure_supported_graph_backend()
    available, _stale, _latest = await _snapshot_state(graph_store, tenant_id, body.base_scan_id)
    if not available:
        raise HTTPException(status_code=409, detail="Base graph snapshot is unavailable")
    scenario = await _store_call(
        _get_graph_scenario_store().create,
        tenant_id,
        _new_record(tenant_id, body, created_by=_created_by(request)),
    )
    return {"schema": _SCENARIO_SCHEMA, "scenario": _public_scenario(scenario)}


@router.get("/graph/scenarios/{scenario_id}", tags=["graph"])
async def get_graph_scenario(request: Request, scenario_id: str) -> dict[str, Any]:
    _ensure_supported_graph_backend()
    scenario = await _store_call(_get_graph_scenario_store().get, _tenant(request), scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Graph scenario not found")
    return {"schema": _SCENARIO_SCHEMA, "scenario": _public_scenario(scenario)}


@router.put("/graph/scenarios/{scenario_id}", tags=["graph"])
async def update_graph_scenario(request: Request, scenario_id: str, body: GraphScenarioUpdate) -> dict[str, Any]:
    _bounded_body(body)
    _deny_managed_trial_write()
    if body.scenario_id != scenario_id:
        raise HTTPException(status_code=409, detail="Body scenario_id must match the route scenario_id")
    _ensure_supported_graph_backend()
    tenant_id = _tenant(request)
    store = _get_graph_scenario_store()
    current = await _store_call(store.get, tenant_id, scenario_id)
    if current is None:
        raise HTTPException(status_code=404, detail="Graph scenario not found")
    scenario = await _store_call(
        store.update,
        tenant_id,
        scenario_id,
        expected_revision=body.expected_revision,
        scenario=_updated_record(current, body),
    )
    return {"schema": _SCENARIO_SCHEMA, "scenario": _public_scenario(scenario)}


@router.delete("/graph/scenarios/{scenario_id}", tags=["graph"], status_code=204)
async def delete_graph_scenario(
    request: Request,
    scenario_id: str,
    expected_revision: int = Query(..., ge=1),
) -> Response:
    _deny_managed_trial_write()
    _ensure_supported_graph_backend()
    deleted = await _store_call(
        _get_graph_scenario_store().delete,
        _tenant(request),
        scenario_id,
        expected_revision=expected_revision,
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Graph scenario not found")
    return Response(status_code=204)


@router.get("/graph/scenarios/{scenario_id}/comparison", tags=["graph"])
async def compare_graph_scenario(
    request: Request,
    scenario_id: str,
    scan_id: str = Query(..., min_length=1, max_length=512, description="Exact pinned base snapshot ID"),
) -> dict[str, Any]:
    tenant_id = _tenant(request)
    graph_store = _ensure_supported_graph_backend()
    scenario = await _store_call(_get_graph_scenario_store().get, tenant_id, scenario_id)
    if scenario is None:
        raise HTTPException(status_code=404, detail="Graph scenario not found")
    if scan_id != scenario["base_scan_id"]:
        return {
            "schema": _COMPARISON_SCHEMA,
            "scenario": {**_public_scenario(scenario), "base_status": "unavailable"},
            "current": {
                "scan_id": scan_id,
                "node_count": 0,
                "edge_count": 0,
                "completeness": {
                    "status": "unavailable",
                    "complete": False,
                    "truncated": False,
                    "returned": 0,
                    "total": 0,
                    "reason": "selected_snapshot_mismatch",
                },
                "base_status": "unavailable",
                "latest_scan_id": None,
            },
            "proposed": {
                "node_count": 0,
                "edge_count": 0,
                "modeled": True,
                "nodes": [],
                "edges": [],
                "completeness": {"complete": False, "truncated": False, "reason": "selected_snapshot_mismatch"},
            },
            "difference": _empty_difference(),
            "available": False,
            "unavailable_reason": "selected_snapshot_mismatch",
            "base_status": "unavailable",
            "stale": False,
        }

    available, stale, latest = await _snapshot_state(graph_store, tenant_id, scan_id)
    status = "stale" if stale else "available"
    current: dict[str, Any] = {
        "scan_id": scan_id,
        "node_count": 0,
        "edge_count": 0,
        "completeness": {
            "status": "unavailable" if not available else "complete",
            "complete": False if not available else True,
            "truncated": False,
            "returned": 0,
            "total": 0,
            "reason": "base_snapshot_unavailable" if not available else None,
        },
        "base_status": "unavailable" if not available else status,
        "latest_scan_id": latest or None,
    }
    if not available:
        return {
            "schema": _COMPARISON_SCHEMA,
            "scenario": {**_public_scenario(scenario), "base_status": "unavailable"},
            "current": current,
            "proposed": {
                "node_count": 0,
                "edge_count": 0,
                "modeled": True,
                "nodes": [],
                "edges": [],
                "completeness": {"complete": False, "truncated": False, "reason": "base_snapshot_unavailable"},
            },
            "difference": _empty_difference(),
            "available": False,
            "unavailable_reason": "base_snapshot_unavailable",
            "base_status": "unavailable",
            "stale": False,
        }

    try:
        stats, graph, paths_result = await asyncio.gather(
            asyncio.to_thread(graph_store.snapshot_stats, tenant_id=tenant_id, scan_id=scan_id),
            asyncio.to_thread(graph_store.load_graph, tenant_id=tenant_id, scan_id=scan_id, node_budget=_COMPARISON_NODE_BUDGET),
            asyncio.to_thread(graph_store.attack_paths, tenant_id=tenant_id, scan_id=scan_id, offset=0, limit=_COMPARISON_PATH_BUDGET),
        )
    except NeptuneGraphStoreUnsupportedOperationError as exc:
        raise HTTPException(status_code=501, detail=sanitize_error(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc

    current["node_count"] = int(stats.get("total_nodes", 0))
    current["edge_count"] = int(stats.get("total_edges", 0))
    source_completeness = graph.completeness.to_dict()
    observed_refs = _observed_references(scenario)
    if observed_refs:
        try:
            referenced_nodes, incident_edges = await asyncio.gather(
                asyncio.to_thread(
                    graph_store.nodes_by_ids,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    node_ids=observed_refs,
                ),
                asyncio.to_thread(
                    graph_store.edges_for_node_ids,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    node_ids=observed_refs,
                ),
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail=sanitize_error(exc, generic=True)) from exc
        for node in referenced_nodes:
            graph.add_node(node)
        for edge in incident_edges:
            graph.add_edge(edge)
    current["completeness"] = {
        **source_completeness,
        "returned": len(graph.nodes),
        "total": current["node_count"],
        "complete": not bool(source_completeness.get("truncated")),
        "edge_returned": len(graph.edges),
        "edge_total": current["edge_count"],
    }
    path_total = int(paths_result[3])
    current["path_completeness"] = {
        "returned": len(paths_result[2]),
        "total": path_total,
        "complete": len(paths_result[2]) >= path_total,
        "truncated": len(paths_result[2]) < path_total,
        "reason": "path_budget" if len(paths_result[2]) < path_total else None,
    }
    try:
        applied = _apply_operations(
            scenario=scenario,
            graph=graph,
            exact_node_count=current["node_count"],
            exact_edge_count=current["edge_count"],
            attack_paths=paths_result[2],
        )
    except (TypeError, ValueError) as exc:
        return {
            "schema": _COMPARISON_SCHEMA,
            "scenario": {**_public_scenario(scenario), "base_status": status},
            "current": current,
            "proposed": {
                "node_count": 0,
                "edge_count": 0,
                "modeled": True,
                "nodes": [],
                "edges": [],
                "completeness": {"complete": False, "truncated": False, "reason": "invalid_scenario"},
            },
            "difference": _empty_difference(),
            "available": False,
            "unavailable_reason": sanitize_error(exc),
            "base_status": status,
            "stale": stale,
        }
    proposed = applied["proposed"]
    proposed["completeness"] = {
        "returned": len(proposed["nodes"]),
        "total": proposed["node_count"],
        "complete": len(proposed["nodes"]) >= proposed["node_count"],
        "truncated": len(proposed["nodes"]) < proposed["node_count"],
        "reason": "node_budget" if len(proposed["nodes"]) < proposed["node_count"] else None,
        "edge_returned": len(proposed["edges"]),
        "edge_total": proposed["edge_count"],
        "edge_truncated": len(proposed["edges"]) < proposed["edge_count"],
    }
    applied["difference"]["touched_observed_paths_completeness"] = current["path_completeness"]
    return {
        "schema": _COMPARISON_SCHEMA,
        "scenario": {**_public_scenario(scenario), "base_status": status},
        "current": current,
        **applied,
        "available": True,
        "unavailable_reason": None,
        "base_status": status,
        "stale": stale,
    }


__all__ = [
    "AddEdgeOperation",
    "AddNodeOperation",
    "GraphScenarioCreate",
    "GraphScenarioUpdate",
    "PatchNodeOperation",
    "RemoveEdgeOperation",
    "RemoveNodeOperation",
    "ScenarioNodePatch",
    "compare_graph_scenario",
    "router",
]
