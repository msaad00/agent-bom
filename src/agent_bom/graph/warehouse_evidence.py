"""Map bounded warehouse-export rows to recorded graph evidence without SQL access."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, TypeAdapter

from agent_bom.graph import EntityType, NodeDimensions, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.container import GraphCompleteness

Text = Annotated[str, Field(strict=True, min_length=1, max_length=1024, pattern=r"^[^\x00-\x1f\x7f]+$")]
_TIMESTAMP = TypeAdapter(AwareDatetime)


class NodeColumns(BaseModel):
    """Column names, never SQL expressions or executable transformations."""

    model_config = ConfigDict(extra="forbid")
    id: Text = "id"
    entity_type: Text = "entity_type"
    label: Text = "label"
    observed_at: Text = "observed_at"
    cloud_provider: Text = "cloud_provider"
    account_id: Text = "account_id"
    organization_id: Text = "organization_id"
    environment: Text = "environment"
    repository: Text = "repository"


class EdgeColumns(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Text = "source"
    target: Text = "target"
    relationship: Text = "relationship"
    observed_at: Text = "observed_at"
    traversable: Text = "traversable"


class WarehouseMapping(BaseModel):
    """Versioned export mapping; source identity is independent of observation time."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["agent-bom.warehouse-mapping/v1"]
    provider: Literal["snowflake", "databricks", "clickhouse", "bigquery"]
    source_instance: Text
    exported_at: AwareDatetime
    nodes: NodeColumns = Field(default_factory=NodeColumns)
    edges: EdgeColumns = Field(default_factory=EdgeColumns)


def _text(row: dict[str, Any], column: str, *, optional: bool = False) -> str:
    value = row.get(column)
    if optional and value is None:
        return ""
    if not isinstance(value, str) or not value.strip() or len(value) > 1024 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid warehouse text cell")
    return value


def _observed(row: dict[str, Any], column: str) -> str:
    value = _text(row, column)
    return _TIMESTAMP.validate_python(value).isoformat()


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _node(row: dict[str, Any], mapping: WarehouseMapping, tenant: str, receipt: dict[str, Any]) -> tuple[str, UnifiedNode]:
    columns = mapping.nodes
    native = _text(row, columns.id)
    entity_type = EntityType(_text(row, columns.entity_type))
    identity = "warehouse:" + _digest([tenant, mapping.provider, mapping.source_instance, native])
    observed = _observed(row, columns.observed_at)
    context = {
        name: _text(row, getattr(columns, name), optional=True)
        for name in ("cloud_provider", "account_id", "organization_id", "environment", "repository")
    }
    return native, UnifiedNode(
        id=identity,
        entity_type=entity_type,
        label=_text(row, columns.label),
        first_seen=observed,
        last_seen=observed,
        data_sources=[f"warehouse-export:{mapping.provider}"],
        dimensions=NodeDimensions(cloud_provider=context["cloud_provider"], environment=context["environment"]),
        attributes={**context, "native_id": native, "evidence_tier": "recorded", "warehouse_receipt": receipt},
    )


def _edge(row: dict[str, Any], mapping: WarehouseMapping, identities: dict[str, str], receipt: dict[str, Any]) -> UnifiedEdge:
    columns = mapping.edges
    source, target = _text(row, columns.source), _text(row, columns.target)
    if source not in identities or target not in identities:
        raise ValueError("Warehouse relationship references an absent entity")
    traversable = row.get(columns.traversable, False)
    if not isinstance(traversable, bool):
        raise ValueError("Warehouse traversable must be a boolean")
    observed = _observed(row, columns.observed_at)
    return UnifiedEdge(
        source=identities[source],
        target=identities[target],
        relationship=RelationshipType(_text(row, columns.relationship)),
        traversable=traversable,
        first_seen=observed,
        last_seen=observed,
        valid_from=observed,
        provenance={"source": f"warehouse-export:{mapping.provider}", "evidence_tier": "recorded", "warehouse_receipt": receipt},
        evidence={"source": "warehouse-export", "execution": "not_established", "traversability_basis": "source_declared"},
    )


def build_warehouse_graph(rows: dict[str, Any], mapping: dict[str, Any], *, tenant_id: str, max_rows: int = 20_000) -> UnifiedGraph:
    """Validate all rows before returning; never truncate or invent observations."""
    tenant = _text({"tenant": tenant_id}, "tenant")
    config = WarehouseMapping.model_validate(mapping)
    if not isinstance(rows, dict) or set(rows) != {"nodes", "edges"}:
        raise ValueError("Warehouse export requires nodes and edges arrays")
    nodes, edges = rows["nodes"], rows["edges"]
    if not isinstance(nodes, list) or not isinstance(edges, list) or not all(isinstance(row, dict) for row in nodes + edges):
        raise ValueError("Warehouse export requires object rows")
    if not 1 <= max_rows <= 20_000 or len(nodes) + len(edges) > max_rows:
        raise ValueError("Warehouse row budget exceeded")
    receipt = {
        "mapping_schema": config.schema_version,
        "provider": config.provider,
        "source_instance": config.source_instance,
        "exported_at": config.exported_at.isoformat(),
        "artifact_sha256": _digest(rows),
        "mapping_sha256": _digest(mapping),
        "integrity": "unsigned_local_digest",
        "collection_coverage": "unknown",
        "execution": "not_established",
    }
    graph = UnifiedGraph(
        tenant_id=tenant,
        scan_id="warehouse:" + _digest([tenant, receipt]),
        created_at=config.exported_at.isoformat(),
        analysis_status={
            "warehouse_collection": GraphAnalysisStatus(
                GraphAnalysisState.NOT_RECORDED,
                reason_codes=("source_collection_not_verified",),
                observed={"node_rows": len(nodes), "edge_rows": len(edges)},
            )
        },
    )
    identities: dict[str, str] = {}
    for row in nodes:
        native, node = _node(row, config, tenant, receipt)
        if native in identities:
            raise ValueError("Duplicate warehouse entity identifier")
        identities[native] = node.id
        graph.add_node(node)
    seen = set()
    for row in edges:
        edge = _edge(row, config, identities, receipt)
        key = (edge.source, edge.target, edge.relationship)
        if key in seen:
            raise ValueError("Duplicate warehouse relationship")
        seen.add(key)
        graph.add_edge(edge)
    graph.completeness = GraphCompleteness(total_nodes=len(nodes), returned_nodes=len(nodes))
    return graph
