"""Amazon Neptune graph store adapter.

The adapter is intentionally optional: importing agent-bom must not require
Gremlin, AWS credentials, or a reachable Neptune cluster. Production callers
select it explicitly through ``AGENT_BOM_GRAPH_BACKEND=neptune`` and an
endpoint; tests can inject a small Gremlin-compatible client.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, NoReturn, Protocol

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode


class NeptuneGraphStoreError(RuntimeError):
    """Base error for Neptune graph backend failures."""


class NeptuneGraphStoreConfigError(NeptuneGraphStoreError):
    """Raised when the Neptune backend is selected without required config."""


class NeptuneGraphStoreUnsupportedOperationError(NeptuneGraphStoreError):
    """Raised for GraphStoreProtocol operations not yet implemented by Neptune."""


class GremlinClientProtocol(Protocol):
    """Small gremlin-python-compatible surface used by the adapter."""

    def submit(self, query: str, bindings: dict[str, Any] | None = None) -> Any: ...


@dataclass(frozen=True, slots=True)
class NeptuneGraphConfig:
    """Connection settings for a Neptune Gremlin endpoint."""

    endpoint: str
    traversal_source: str = "g"

    @classmethod
    def from_env(cls) -> "NeptuneGraphConfig":
        endpoint = os.environ.get("AGENT_BOM_NEPTUNE_ENDPOINT", "").strip()
        if not endpoint:
            raise NeptuneGraphStoreConfigError(
                "AGENT_BOM_GRAPH_BACKEND=neptune requires AGENT_BOM_NEPTUNE_ENDPOINT; SQLite/Postgres remain the default graph backends."
            )
        traversal_source = os.environ.get("AGENT_BOM_NEPTUNE_TRAVERSAL_SOURCE", "g").strip() or "g"
        return cls(endpoint=endpoint, traversal_source=traversal_source)


def _client_from_config(config: NeptuneGraphConfig) -> GremlinClientProtocol:
    try:
        from gremlin_python.driver.client import Client
        from gremlin_python.driver.serializer import GraphSONSerializersV3d0
    except ImportError as exc:  # pragma: no cover - exercised via config tests without optional dependency
        raise NeptuneGraphStoreConfigError(
            "Neptune graph backend requires gremlin-python. Install it in the control-plane environment "
            "or inject a Gremlin client in tests."
        ) from exc
    return Client(
        config.endpoint,
        config.traversal_source,
        message_serializer=GraphSONSerializersV3d0(),
    )


def _graph_key(*parts: str) -> str:
    return "|".join(part.replace("|", "%7C") for part in parts)


def _relationship_value(value: RelationshipType | str) -> str:
    return value.value if isinstance(value, RelationshipType) else str(value)


def _normalize_result(result: Any) -> list[Any]:
    """Normalize gremlin-python futures and simple fake-client lists."""

    if hasattr(result, "all"):
        result = result.all()
    if hasattr(result, "result"):
        result = result.result()
    if result is None:
        return []
    if isinstance(result, list):
        return result
    return [result]


def _first(value: Any, default: Any = "") -> Any:
    if isinstance(value, list):
        return value[0] if value else default
    return default if value is None else value


def _json_loads(value: Any, default: Any) -> Any:
    value = _first(value, value)
    if value in (None, ""):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(str(value))
    except (TypeError, ValueError):
        return default


def _bool_value(value: Any, default: bool = False) -> bool:
    value = _first(value, value)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes"}
    return default


class NeptuneGraphStore:
    """Gremlin-backed graph store for Amazon Neptune.

    This first implementation supports graph snapshot write/read, snapshot
    listing, and bitemporal edge inspection. Traversal-heavy API methods stay
    fail-closed until they are implemented with bounded Gremlin queries.
    """

    def __init__(self, config: NeptuneGraphConfig | None = None, client: GremlinClientProtocol | None = None) -> None:
        self.config = config or NeptuneGraphConfig.from_env()
        self._client = client or _client_from_config(self.config)

    def _submit(self, query: str, bindings: dict[str, Any] | None = None) -> list[Any]:
        return _normalize_result(self._client.submit(query, bindings or {}))

    def save_graph(self, graph: UnifiedGraph) -> None:
        tenant_id = graph.tenant_id or "default"
        scan_id = graph.scan_id
        created_at = graph.created_at
        for node in graph.nodes.values():
            payload = node.to_dict()
            self._submit(
                """
                g.V().has('abom_key', node_key).fold().
                  coalesce(unfold(), addV('abom_node').property('abom_key', node_key)).
                  property('tenant_id', tenant_id).
                  property('scan_id', scan_id).
                  property('node_id', node_id).
                  property('entity_type', entity_type).
                  property('label', label).
                  property('payload_json', payload_json)
                """,
                {
                    "node_key": _graph_key(tenant_id, scan_id, node.id),
                    "tenant_id": tenant_id,
                    "scan_id": scan_id,
                    "node_id": node.id,
                    "entity_type": payload["entity_type"],
                    "label": node.label,
                    "payload_json": json.dumps(payload, sort_keys=True),
                },
            )
        for edge in graph.edges:
            rel = _relationship_value(edge.relationship)
            payload = edge.to_dict()
            edge_key = _graph_key(tenant_id, scan_id, edge.source, rel, edge.target)
            self._submit(
                """
                g.E().has('abom_edge_key', edge_key).fold().
                  coalesce(
                    unfold(),
                    V().has('abom_key', source_key).addE(edge_label).to(V().has('abom_key', target_key)).
                      property('abom_edge_key', edge_key)
                  ).
                  property('tenant_id', tenant_id).
                  property('scan_id', scan_id).
                  property('source_id', source_id).
                  property('target_id', target_id).
                  property('relationship', relationship).
                  property('valid_from', valid_from).
                  property('valid_to', valid_to).
                  property('payload_json', payload_json)
                """,
                {
                    "edge_key": edge_key,
                    "source_key": _graph_key(tenant_id, scan_id, edge.source),
                    "target_key": _graph_key(tenant_id, scan_id, edge.target),
                    "edge_label": rel,
                    "tenant_id": tenant_id,
                    "scan_id": scan_id,
                    "source_id": edge.source,
                    "target_id": edge.target,
                    "relationship": rel,
                    "valid_from": edge.valid_from or edge.first_seen,
                    "valid_to": edge.valid_to or "",
                    "payload_json": json.dumps(payload, sort_keys=True),
                },
            )
        self._submit(
            """
            g.V().has('abom_key', snapshot_key).fold().
              coalesce(unfold(), addV('abom_snapshot').property('abom_key', snapshot_key)).
              property('tenant_id', tenant_id).
              property('scan_id', scan_id).
              property('created_at', created_at).
              property('node_count', node_count).
              property('edge_count', edge_count).
              property('risk_summary_json', risk_summary_json)
            """,
            {
                "snapshot_key": _graph_key(tenant_id, scan_id, "snapshot"),
                "tenant_id": tenant_id,
                "scan_id": scan_id,
                "created_at": created_at,
                "node_count": len(graph.nodes),
                "edge_count": len(graph.edges),
                "risk_summary_json": json.dumps(graph.stats(), sort_keys=True),
            },
        )

    def latest_snapshot_id(self, *, tenant_id: str = "") -> str:
        snapshots = self.list_snapshots(tenant_id=tenant_id, limit=1)
        return snapshots[0]["scan_id"] if snapshots else ""

    def previous_snapshot_id(self, *, tenant_id: str = "", before_scan_id: str = "") -> str:
        snapshots = self.list_snapshots(tenant_id=tenant_id, limit=1000)
        for index, snapshot in enumerate(snapshots):
            if snapshot["scan_id"] == before_scan_id and index + 1 < len(snapshots):
                return snapshots[index + 1]["scan_id"]
        return ""

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
        rows = self._submit(
            """
            g.V().hasLabel('abom_snapshot').has('tenant_id', tenant_id).
              order().by('created_at', desc).limit(limit).valueMap()
            """,
            {"tenant_id": tenant_id or "default", "limit": int(limit)},
        )
        return [self._snapshot_from_record(row) for row in rows]

    def load_graph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> UnifiedGraph:
        tenant = tenant_id or "default"
        scan = scan_id or self.latest_snapshot_id(tenant_id=tenant)
        graph = UnifiedGraph(scan_id=scan, tenant_id=tenant)
        node_rows = self._submit(
            "g.V().hasLabel('abom_node').has('tenant_id', tenant_id).has('scan_id', scan_id).valueMap()",
            {"tenant_id": tenant, "scan_id": scan},
        )
        for row in node_rows:
            node = self._node_from_record(row)
            entity_value = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
            if entity_types and entity_value not in entity_types:
                continue
            if min_severity_rank and int(node.severity_id or 0) < min_severity_rank:
                continue
            graph.add_node(node)
        edge_rows = self._edge_rows(tenant_id=tenant, scan_id=scan)
        for row in edge_rows:
            edge = self._edge_from_record(row)
            if edge.source in graph.nodes and edge.target in graph.nodes:
                graph.add_edge(edge)
        return graph

    def active_edges_at(self, at: str, *, tenant_id: str = "") -> list[dict[str, Any]]:
        rows = self._submit(
            """
            g.E().has('tenant_id', tenant_id).
              has('valid_from', lte(at)).
              or(has('valid_to', ''), has('valid_to', gt(at))).
              valueMap()
            """,
            {"tenant_id": tenant_id or "default", "at": at},
        )
        return [self._edge_from_record(row).to_dict() for row in rows]

    def changed_edges_between_scans(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        old_edges = {self._edge_identity(edge): edge for edge in self.load_graph(tenant_id=tenant_id, scan_id=scan_id_old).edges}
        new_edges = {self._edge_identity(edge): edge for edge in self.load_graph(tenant_id=tenant_id, scan_id=scan_id_new).edges}
        added = [edge.to_dict() for key, edge in new_edges.items() if key not in old_edges]
        removed = [edge.to_dict() for key, edge in old_edges.items() if key not in new_edges]
        unchanged: list[dict[str, Any]] = []
        changed: list[dict[str, Any]] = []
        for key in sorted(old_edges.keys() & new_edges.keys()):
            before = old_edges[key].to_dict()
            after = new_edges[key].to_dict()
            if before == after:
                unchanged.append(after)
            else:
                changed.append({"before": before, "after": after})
        return {
            "old_scan_id": scan_id_old,
            "new_scan_id": scan_id_new,
            "summary": {
                "added": len(added),
                "removed": len(removed),
                "changed": len(changed),
                "unchanged": len(unchanged),
            },
            "edges_added": added,
            "edges_removed": removed,
            "edges_changed": changed,
            "edges_unchanged": unchanged,
        }

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        old = self.load_graph(tenant_id=tenant_id, scan_id=scan_id_old)
        new = self.load_graph(tenant_id=tenant_id, scan_id=scan_id_new)
        old_nodes = set(old.nodes)
        new_nodes = set(new.nodes)
        return {
            "old_scan_id": scan_id_old,
            "new_scan_id": scan_id_new,
            "nodes_added": sorted(new_nodes - old_nodes),
            "nodes_removed": sorted(old_nodes - new_nodes),
            "edges": self.changed_edges_between_scans(scan_id_old, scan_id_new, tenant_id=tenant_id)["summary"],
        }

    def delete_tenant(self, *, tenant_id: str = "") -> int:
        rows = self._submit(
            """
            g.V().has('tenant_id', tenant_id).fold().
              project('count').by(count(local)).
              sideEffect(unfold().drop())
            """,
            {"tenant_id": tenant_id or "default"},
        )
        if not rows:
            return 0
        count = rows[0].get("count", 0) if isinstance(rows[0], dict) else rows[0]
        return int(_first(count, 0) or 0)

    def snapshot_stats(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> dict[str, Any]:
        graph = self.load_graph(
            tenant_id=tenant_id,
            scan_id=scan_id,
            entity_types=entity_types,
            min_severity_rank=min_severity_rank,
        )
        return {
            "scan_id": graph.scan_id,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "severity_counts": graph.stats().get("severity_counts", {}),
        }

    def _edge_rows(self, *, tenant_id: str, scan_id: str) -> list[Any]:
        return self._submit(
            "g.E().has('tenant_id', tenant_id).has('scan_id', scan_id).valueMap()",
            {"tenant_id": tenant_id or "default", "scan_id": scan_id},
        )

    @staticmethod
    def _edge_identity(edge: UnifiedEdge) -> tuple[str, str, str]:
        return (edge.source, edge.target, _relationship_value(edge.relationship))

    @staticmethod
    def _snapshot_from_record(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "scan_id": str(_first(row.get("scan_id"))),
            "tenant_id": str(_first(row.get("tenant_id"), "default")),
            "created_at": str(_first(row.get("created_at"))),
            "node_count": int(_first(row.get("node_count"), 0) or 0),
            "edge_count": int(_first(row.get("edge_count"), 0) or 0),
            "risk_summary": _json_loads(row.get("risk_summary_json"), {}),
        }

    @staticmethod
    def _node_from_record(row: dict[str, Any]) -> UnifiedNode:
        payload = _json_loads(row.get("payload_json"), {})
        if payload:
            return UnifiedNode.from_dict(payload)
        return UnifiedNode(
            id=str(_first(row.get("node_id"))),
            entity_type=EntityType(str(_first(row.get("entity_type")))),
            label=str(_first(row.get("label"))),
        )

    @staticmethod
    def _edge_from_record(row: dict[str, Any]) -> UnifiedEdge:
        payload = _json_loads(row.get("payload_json"), {})
        if payload:
            return UnifiedEdge.from_dict(payload)
        return UnifiedEdge(
            source=str(_first(row.get("source_id"))),
            target=str(_first(row.get("target_id"))),
            relationship=RelationshipType(str(_first(row.get("relationship")))),
            traversable=_bool_value(row.get("traversable"), True),
            valid_from=str(_first(row.get("valid_from"))),
            valid_to=str(_first(row.get("valid_to"))) or None,
        )

    def _unsupported(self, name: str) -> NoReturn:
        raise NeptuneGraphStoreUnsupportedOperationError(
            f"Neptune graph backend does not yet implement {name}; use SQLite/Postgres for this API surface."
        )

    def page_nodes(self, **_kwargs: Any) -> tuple[str, str, list[UnifiedNode], int, str | None]:
        self._unsupported("page_nodes")

    def edges_for_node_ids(self, **_kwargs: Any) -> list[Any]:
        self._unsupported("edges_for_node_ids")

    def search_nodes(self, **_kwargs: Any) -> tuple[list[UnifiedNode], int, str | None]:
        self._unsupported("search_nodes")

    def nodes_by_ids(self, **_kwargs: Any) -> list[UnifiedNode]:
        self._unsupported("nodes_by_ids")

    def bfs_paths(self, **_kwargs: Any) -> tuple[list[list[str]], set[str]]:
        self._unsupported("bfs_paths")

    def impact_of(self, **_kwargs: Any) -> dict[str, Any] | None:
        self._unsupported("impact_of")

    def traverse_subgraph(self, **_kwargs: Any) -> tuple[UnifiedGraph, dict[str, int], bool]:
        self._unsupported("traverse_subgraph")

    def attack_paths_for_sources(self, **_kwargs: Any) -> list[Any]:
        self._unsupported("attack_paths_for_sources")

    def attack_paths(self, **_kwargs: Any) -> tuple[str, str, list[Any], int]:
        self._unsupported("attack_paths")

    def node_context(self, **_kwargs: Any) -> dict[str, Any] | None:
        self._unsupported("node_context")

    def compliance_summary(self, **_kwargs: Any) -> dict[str, Any]:
        self._unsupported("compliance_summary")

    def save_preset(self, **_kwargs: Any) -> None:
        self._unsupported("save_preset")

    def list_presets(self, **_kwargs: Any) -> list[dict[str, Any]]:
        self._unsupported("list_presets")

    def delete_preset(self, **_kwargs: Any) -> bool:
        self._unsupported("delete_preset")
