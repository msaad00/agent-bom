"""Row decoding and bounded traversal queries for the Postgres graph store."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Sequence, cast

if TYPE_CHECKING:
    from agent_bom.graph import RelationshipType, UnifiedNode

from agent_bom.api.graph_store import (
    _DYNAMIC_RELATIONSHIP_VALUES,
)
from agent_bom.db.graph_store import (
    normalize_graph_tenant_id,
)
from agent_bom.graph.completeness import (
    bounded_walk_reason,
    impact_completeness,
)

from .postgres_common import (
    _tenant_connection,
)
from .postgres_graph_snapshots import PostgresGraphSnapshotsMixin
from .postgres_graph_support import (
    _decode_json_array,
    _decode_json_object,
)


class PostgresGraphTraversalMixin(PostgresGraphSnapshotsMixin):
    """Decode node/edge rows and run bounded BFS, impact and subgraph walks."""

    @staticmethod
    def _node_from_row(row: Sequence[Any]) -> UnifiedNode:
        from agent_bom.graph import EntityType, NodeDimensions, NodeStatus, UnifiedNode

        return UnifiedNode(
            id=row[0],
            entity_type=EntityType(row[1]),
            label=row[2],
            category_uid=row[3],
            class_uid=row[4],
            type_uid=row[5],
            status=NodeStatus(row[6]),
            risk_score=row[7],
            severity=row[8] or "",
            severity_id=row[9],
            first_seen=row[10],
            last_seen=row[11],
            attributes=_decode_json_object(row[12], field="node attributes"),
            compliance_tags=_decode_json_array(row[13], field="node compliance tags"),
            data_sources=_decode_json_array(row[14], field="node data sources"),
            dimensions=NodeDimensions.from_dict(_decode_json_object(row[15], field="node dimensions")),
        )

    def nodes_by_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[Any]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        if not node_ids:
            return []
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return []
        placeholders = ",".join(["%s"] * len(node_ids))
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"""
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                FROM graph_nodes
                WHERE tenant_id = %s AND scan_id = %s AND id IN ({placeholders})
                """,  # nosec B608 - placeholders are generated internally
                [tenant_id, effective_scan_id, *sorted(node_ids)],
            ).fetchall()
        return [self._node_from_row(row) for row in rows]

    @staticmethod
    def _edge_from_row(row: Sequence[Any]) -> Any:
        from agent_bom.graph import RelationshipType, UnifiedEdge

        return UnifiedEdge(
            source=row[0],
            target=row[1],
            relationship=RelationshipType(row[2]),
            direction=row[3],
            weight=row[4],
            traversable=bool(row[5]),
            first_seen=row[6],
            last_seen=row[7],
            valid_from=row[8] or row[6],
            valid_to=row[9],
            confidence=row[10],
            provenance=_decode_json_object(row[11], field="edge provenance"),
            source_scan_id=row[12] or row[16],
            source_run_id=row[13] or "",
            evidence=_decode_json_object(row[14], field="edge evidence"),
            activity_id=row[15],
        )

    @staticmethod
    def _reverse_edge(edge: Any) -> Any:
        from agent_bom.graph import UnifiedEdge

        return UnifiedEdge(
            source=edge.target,
            target=edge.source,
            relationship=edge.relationship,
            direction=edge.direction,
            weight=edge.weight,
            traversable=edge.traversable,
            first_seen=edge.first_seen,
            last_seen=edge.last_seen,
            valid_from=edge.valid_from,
            valid_to=edge.valid_to,
            confidence=edge.confidence,
            provenance=edge.provenance,
            source_scan_id=edge.source_scan_id,
            source_run_id=edge.source_run_id,
            evidence=edge.evidence,
            activity_id=edge.activity_id,
        )

    def _filtered_edge_rows(
        self,
        conn: Any,
        *,
        tenant_id: str,
        scan_id: str,
        frontier: set[str],
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
        limit: int = 25_001,
    ) -> tuple[list[Sequence[Any]], bool]:
        if not frontier:
            return [], False
        placeholders = ",".join("%s" for _ in frontier)
        where = [
            "tenant_id = %s",
            "scan_id = %s",
            f"(source_id IN ({placeholders}) OR target_id IN ({placeholders}))",
        ]
        params: list[Any] = [tenant_id, scan_id, *sorted(frontier), *sorted(frontier)]
        if traversable_only:
            where.append("traversable = 1")
        if relationship_types:
            values = sorted(rel.value if hasattr(rel, "value") else str(rel) for rel in relationship_types)
            rel_placeholders = ",".join("%s" for _ in values)
            where.append(f"relationship IN ({rel_placeholders})")
            params.extend(values)
        if static_only:
            dynamic_placeholders = ",".join("%s" for _ in _DYNAMIC_RELATIONSHIP_VALUES)
            where.append(f"relationship NOT IN ({dynamic_placeholders})")
            params.extend(sorted(_DYNAMIC_RELATIONSHIP_VALUES))
        if dynamic_only:
            dynamic_placeholders = ",".join("%s" for _ in _DYNAMIC_RELATIONSHIP_VALUES)
            where.append(f"relationship IN ({dynamic_placeholders})")
            params.extend(sorted(_DYNAMIC_RELATIONSHIP_VALUES))
        bounded_limit = max(1, int(limit))
        params.append(bounded_limit + 1)
        rows = cast(
            "list[Sequence[Any]]",
            conn.execute(
                f"""
                SELECT source_id, target_id, relationship, direction, weight, traversable,
                       first_seen, last_seen, valid_from, valid_to, confidence, provenance,
                       source_scan_id, source_run_id, evidence, activity_id, scan_id
                FROM graph_edges
                WHERE {" AND ".join(where)}
                ORDER BY source_id, target_id, relationship
                LIMIT %s
                """,  # nosec B608 - clauses and placeholders are generated internally
                params,
            ).fetchall(),
        )
        return rows[:bounded_limit], len(rows) > bounded_limit

    def bfs_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> tuple[list[list[str]], set[str], bool, bool]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        timeout_ms = self._search_timeout_ms()
        deadline = time.monotonic() + (timeout_ms / 1000) if timeout_ms else None
        with _tenant_connection(self._pool) as conn:
            self._apply_search_timeout(conn)
            _, _, visited, _, _, parents, order, truncated, depth_limited = self._walk_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                roots=[source],
                direction="forward",
                max_depth=max_depth,
                max_nodes=5000,
                max_edges=25_000,
                deadline_monotonic=deadline,
                traversable_only=traversable_only,
                relationship_types=None,
                static_only=False,
                dynamic_only=False,
                include_roots=True,
            )
        if source not in visited:
            return [], set(), truncated, depth_limited
        paths: list[list[str]] = []
        for node_id in order:
            path = [node_id]
            current = node_id
            while current in parents:
                current = parents[current]
                path.append(current)
            path.reverse()
            if path and path[0] == source:
                paths.append(path)
        visited.discard(source)
        return paths, visited, truncated, depth_limited

    def impact_of(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
        max_depth: int = 4,
    ) -> dict[str, Any] | None:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        timeout_ms = self._search_timeout_ms()
        deadline = time.monotonic() + (timeout_ms / 1000) if timeout_ms else None
        with _tenant_connection(self._pool) as conn:
            self._apply_search_timeout(conn)
            effective_scan_id, _, visited, depths, _, _, _, truncated, depth_limited = self._walk_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                roots=[node_id],
                direction="reverse",
                max_depth=max_depth,
                max_nodes=5000,
                max_edges=25_000,
                deadline_monotonic=deadline,
                traversable_only=False,
                relationship_types=None,
                static_only=False,
                dynamic_only=False,
                include_roots=True,
            )
        if node_id not in visited:
            return None
        affected = sorted(visited - {node_id})
        rows = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=set(affected))
        by_type: dict[str, int] = {}
        for node in rows:
            entity_type = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
            by_type[entity_type] = by_type.get(entity_type, 0) + 1
        return {
            "node_id": node_id,
            "affected_nodes": affected,
            "affected_by_type": by_type,
            "affected_count": len(affected),
            "max_depth_reached": max((depths.get(value, 0) for value in affected), default=0),
            # Was a bare "partial"/"complete" string here and absent entirely on
            # SQLite: one field, two shapes, neither of which said that a
            # depth-capped reverse walk had left ancestors unvisited.
            "completeness": impact_completeness(
                affected_count=len(affected),
                truncated=truncated,
                depth_limited=depth_limited,
            ),
        }

    def traverse_subgraph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        roots: list[str],
        direction: str = "forward",
        max_depth: int = 4,
        max_nodes: int = 500,
        max_edges: int = 10_000,
        deadline_monotonic: float | None = None,
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
        include_roots: bool = True,
    ) -> tuple[Any, dict[str, int], bool]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        timeout_ms = self._search_timeout_ms()
        query_deadline = time.monotonic() + (timeout_ms / 1000) if timeout_ms else None
        if deadline_monotonic is not None:
            query_deadline = min(query_deadline, deadline_monotonic) if query_deadline is not None else deadline_monotonic
        with _tenant_connection(self._pool) as conn:
            self._apply_search_timeout(conn)
            effective_scan_id, created_at, visited, depths, edges, _, _, truncated, depth_limited = self._walk_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                roots=roots,
                direction=direction,
                max_depth=max_depth,
                max_nodes=max_nodes,
                max_edges=max_edges,
                deadline_monotonic=query_deadline,
                traversable_only=traversable_only,
                relationship_types=relationship_types,
                static_only=static_only,
                dynamic_only=dynamic_only,
                include_roots=include_roots,
            )
            # Snapshot size for the completeness denominator. A single-row
            # primary-key lookup on (tenant_id, scan_id) — never a COUNT over
            # graph_nodes, which would put an O(snapshot) scan on every
            # traversal.
            snapshot_nodes = 0
            if effective_scan_id:
                row = conn.execute(
                    "SELECT node_count FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
                    (tenant_id, effective_scan_id),
                ).fetchone()
                snapshot_nodes = int(row[0] or 0) if row else 0
        from agent_bom.graph import UnifiedGraph

        graph = UnifiedGraph(scan_id=effective_scan_id, tenant_id=tenant_id, created_at=created_at)
        for node in self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=visited):
            graph.add_node(node)
        for edge in edges.values():
            if edge.source in graph.nodes and edge.target in graph.nodes:
                graph.add_edge(edge)
        # A bounded walk must say so, and `returned` must be what we returned.
        # Reporting `returned: 0` beside a non-empty node set was the shipped
        # self-contradiction; matching the in-memory container's shape keeps a
        # store swap from changing what a client is told.
        graph.completeness.truncated = truncated
        graph.completeness.depth_limited = depth_limited
        graph.completeness.reason = bounded_walk_reason(truncated=truncated, depth_limited=depth_limited)
        graph.completeness.node_budget = max_nodes if truncated else None
        graph.completeness.total_nodes = snapshot_nodes or len(graph.nodes)
        graph.completeness.returned_nodes = len(graph.nodes)
        return graph, depths, truncated
