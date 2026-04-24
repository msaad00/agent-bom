"""Unified graph store backends for API persistence and querying.

This module gives the API a pluggable graph persistence layer so unified
graph reads/writes follow the same backend selection model as the rest of
the control plane. SQLite remains the default local backend; Postgres can
provide the same contract for multi-tenant API deployments.
"""

from __future__ import annotations

import base64
import json
import re
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, Protocol

from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph import AttackPath, EntityType, NodeDimensions, NodeStatus, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

_CREATE_PRESET_TABLE_SQLITE = """\
CREATE TABLE IF NOT EXISTS graph_filter_presets (
    name TEXT NOT NULL,
    tenant_id TEXT DEFAULT '',
    description TEXT DEFAULT '',
    filters TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (name, tenant_id)
)
"""

_CREATE_SEARCH_TABLE_SQLITE = """\
CREATE VIRTUAL TABLE IF NOT EXISTS graph_node_search
USING fts5(
    tenant_id UNINDEXED,
    scan_id UNINDEXED,
    node_id UNINDEXED,
    entity_type,
    severity,
    compliance_tags,
    data_sources,
    search_text
)
"""


def _escape_like_query(query: str) -> str:
    """Escape SQL LIKE wildcards so search terms are treated literally."""
    return query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _node_search_text(node: UnifiedNode) -> str:
    parts: list[str] = [
        node.id,
        node.label,
        node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type),
        node.severity or "",
        " ".join(node.compliance_tags),
        " ".join(node.data_sources),
        json.dumps(node.attributes, default=str, sort_keys=True),
        json.dumps(node.dimensions.to_dict(), sort_keys=True),
    ]
    return " ".join(part for part in parts if part).lower()


def _node_sort_key(node: UnifiedNode) -> tuple[int, float, str, str]:
    return (int(node.severity_id or 0), float(node.risk_score or 0.0), node.label or "", node.id)


def encode_graph_cursor(node: UnifiedNode) -> str:
    payload = json.dumps(list(_node_sort_key(node)), separators=(",", ":"), ensure_ascii=True).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def decode_graph_cursor(cursor: str) -> tuple[int, float, str, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        values = json.loads(raw)
        if not isinstance(values, list) or len(values) != 4:
            raise ValueError
        severity_id, risk_score, label, node_id = values
        return int(severity_id), float(risk_score), str(label), str(node_id)
    except Exception as exc:  # pragma: no cover - normalized into ValueError for route handling
        raise ValueError("Invalid graph cursor") from exc


_DYNAMIC_RELATIONSHIP_VALUES = {
    RelationshipType.INVOKED.value,
    RelationshipType.ACCESSED.value,
    RelationshipType.DELEGATED_TO.value,
}


class GraphStoreProtocol(Protocol):
    """Shared graph store contract used by the API pipeline and routes."""

    def latest_snapshot_id(self, *, tenant_id: str = "") -> str: ...

    def previous_snapshot_id(self, *, tenant_id: str = "", before_scan_id: str = "") -> str: ...

    def save_graph(self, graph: UnifiedGraph) -> None: ...

    def load_graph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> UnifiedGraph: ...

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]: ...

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50) -> list[dict[str, Any]]: ...

    def snapshot_stats(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> dict[str, Any]: ...

    def page_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> tuple[str, str, list[UnifiedNode], int, str | None]: ...

    def edges_for_node_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[Any]: ...

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        compliance_prefixes: set[str] | None = None,
        data_sources: set[str] | None = None,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[UnifiedNode], int, str | None]: ...

    def nodes_by_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[UnifiedNode]: ...

    def bfs_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> tuple[list[list[str]], set[str]]: ...

    def impact_of(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
        max_depth: int = 4,
    ) -> dict[str, Any] | None: ...

    def traverse_subgraph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        roots: list[str],
        direction: str = "forward",
        max_depth: int = 4,
        max_nodes: int = 500,
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
        include_roots: bool = True,
    ) -> tuple[UnifiedGraph, dict[str, int], bool]: ...

    def attack_paths_for_sources(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str],
    ) -> list[AttackPath]: ...

    def node_context(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
    ) -> dict[str, Any] | None: ...

    def compliance_summary(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        framework: str = "",
    ) -> dict[str, Any]: ...

    def save_preset(self, *, tenant_id: str, name: str, description: str, filters: dict[str, Any], created_at: str) -> None: ...

    def list_presets(self, *, tenant_id: str) -> list[dict[str, Any]]: ...

    def delete_preset(self, *, tenant_id: str, name: str) -> bool: ...


class SQLiteGraphStore:
    """SQLite-backed graph store wrapper around the low-level graph DB helpers."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path or sqlite_graph_store.default_graph_db_path()).expanduser()

    def _exists(self) -> bool:
        return self._db_path.exists()

    def _ensure_parent(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

    def _open_rw_conn(self) -> sqlite3.Connection:
        self._ensure_parent()
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        sqlite_graph_store._init_db(conn)
        conn.execute(_CREATE_PRESET_TABLE_SQLITE)
        conn.execute(_CREATE_SEARCH_TABLE_SQLITE)
        conn.commit()
        return conn

    def _open_ro_conn(self) -> sqlite3.Connection | None:
        if not self._exists():
            return None
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        sqlite_graph_store._init_db(conn)
        conn.execute(_CREATE_PRESET_TABLE_SQLITE)
        conn.execute(_CREATE_SEARCH_TABLE_SQLITE)
        conn.commit()
        return conn

    @staticmethod
    def _search_query_expression(query: str) -> str:
        tokens = [token.strip() for token in re.findall(r"[A-Za-z0-9_.:-]+", query) if token.strip()]
        if not tokens:
            return ""
        escaped = [token.replace('"', '""') for token in tokens]
        return " AND ".join(f'"{token}"*' for token in escaped)

    @staticmethod
    def _should_use_fts(query: str) -> bool:
        return any(char.isalnum() for char in query)

    @staticmethod
    def _matches_compliance_prefixes(node: UnifiedNode, prefixes: set[str]) -> bool:
        if not prefixes:
            return True
        node_prefixes = {tag.split("-")[0].upper() if "-" in tag else tag.upper() for tag in node.compliance_tags}
        return bool(node_prefixes.intersection(prefixes))

    @staticmethod
    def _space_token_filter(column: str, token: str) -> tuple[str, list[Any]]:
        escaped = _escape_like_query(token.lower())
        clause = f"({column} = ? OR {column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\')"
        params = [escaped, f"{escaped} %", f"% {escaped}", f"% {escaped} %"]
        return clause, params

    @staticmethod
    def _compliance_prefix_filter(column: str, prefix: str) -> tuple[str, list[Any]]:
        escaped = _escape_like_query(prefix.lower())
        clause = (
            f"({column} = ? OR {column} LIKE ? ESCAPE '\\' OR "
            f"{column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\')"
        )
        params = [escaped, f"{escaped}-%", f"{escaped} %", f"% {escaped}-%", f"% {escaped} %"]
        return clause, params

    def _refresh_snapshot_search_index(self, conn: sqlite3.Connection, *, tenant_id: str, scan_id: str) -> None:
        conn.execute("DELETE FROM graph_node_search WHERE tenant_id = ? AND scan_id = ?", (tenant_id, scan_id))
        rows = conn.execute(
            """
            SELECT
                id, entity_type, label, category_uid, class_uid, type_uid,
                status, risk_score, severity, severity_id, first_seen, last_seen,
                attributes, compliance_tags, data_sources, dimensions
            FROM graph_nodes
            WHERE tenant_id = ? AND scan_id = ?
            """,
            (tenant_id, scan_id),
        ).fetchall()
        for row in rows:
            node = self._node_from_row(row)
            conn.execute(
                """
                INSERT INTO graph_node_search (
                    tenant_id, scan_id, node_id, entity_type, severity, compliance_tags, data_sources, search_text
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    scan_id,
                    node.id,
                    node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type),
                    node.severity.lower(),
                    " ".join(node.compliance_tags).lower(),
                    " ".join(node.data_sources).lower(),
                    _node_search_text(node),
                ),
            )

    @staticmethod
    def _node_from_row(row: sqlite3.Row) -> UnifiedNode:
        return UnifiedNode(
            id=row["id"],
            entity_type=EntityType(row["entity_type"]),
            label=row["label"],
            category_uid=row["category_uid"],
            class_uid=row["class_uid"],
            type_uid=row["type_uid"],
            status=NodeStatus(row["status"]),
            risk_score=row["risk_score"],
            severity=row["severity"] or "",
            severity_id=row["severity_id"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            attributes=json.loads(row["attributes"]),
            compliance_tags=json.loads(row["compliance_tags"]),
            data_sources=json.loads(row["data_sources"]),
            dimensions=NodeDimensions.from_dict(json.loads(row["dimensions"])),
        )

    @staticmethod
    def _edge_from_row(row: sqlite3.Row) -> UnifiedEdge:
        return UnifiedEdge(
            source=row["source_id"],
            target=row["target_id"],
            relationship=RelationshipType(row["relationship"]),
            direction=row["direction"],
            weight=row["weight"],
            traversable=bool(row["traversable"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            evidence=json.loads(row["evidence"]),
            activity_id=row["activity_id"],
        )

    @staticmethod
    def _reverse_edge(edge: UnifiedEdge) -> UnifiedEdge:
        return UnifiedEdge(
            source=edge.target,
            target=edge.source,
            relationship=edge.relationship,
            direction=edge.direction,
            weight=edge.weight,
            traversable=edge.traversable,
            first_seen=edge.first_seen,
            last_seen=edge.last_seen,
            evidence=edge.evidence,
            activity_id=edge.activity_id,
        )

    def _filtered_edge_rows(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        scan_id: str,
        frontier: set[str],
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
    ) -> list[sqlite3.Row]:
        if not frontier:
            return []
        placeholders = ",".join("?" for _ in frontier)
        where = [
            "tenant_id = ?",
            "scan_id = ?",
            f"(source_id IN ({placeholders}) OR target_id IN ({placeholders}))",
        ]
        params: list[Any] = [tenant_id, scan_id, *frontier, *frontier]
        if traversable_only:
            where.append("traversable = 1")
        if relationship_types:
            rel_values = sorted(rel.value if isinstance(rel, RelationshipType) else str(rel) for rel in relationship_types)
            rel_placeholders = ",".join("?" for _ in rel_values)
            where.append(f"relationship IN ({rel_placeholders})")
            params.extend(rel_values)
        if static_only:
            dynamic_placeholders = ",".join("?" for _ in _DYNAMIC_RELATIONSHIP_VALUES)
            where.append(f"relationship NOT IN ({dynamic_placeholders})")
            params.extend(sorted(_DYNAMIC_RELATIONSHIP_VALUES))
        if dynamic_only:
            dynamic_placeholders = ",".join("?" for _ in _DYNAMIC_RELATIONSHIP_VALUES)
            where.append(f"relationship IN ({dynamic_placeholders})")
            params.extend(sorted(_DYNAMIC_RELATIONSHIP_VALUES))
        return conn.execute(
            f"""
            SELECT source_id, target_id, relationship, direction, weight, traversable, first_seen, last_seen, evidence, activity_id
            FROM graph_edges
            WHERE {" AND ".join(where)}
            """,  # nosec B608 - clause fragments and placeholders are generated internally
            params,
        ).fetchall()

    def nodes_by_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[UnifiedNode]:
        if not node_ids:
            return []
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return []
            placeholders = ",".join("?" for _ in node_ids)
            rows = conn.execute(
                f"""
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                FROM graph_nodes
                WHERE tenant_id = ? AND scan_id = ? AND id IN ({placeholders})
                """,  # nosec B608 - placeholders are generated internally
                [tenant_id, effective_scan_id, *node_ids],
            ).fetchall()
            return [self._node_from_row(row) for row in rows]
        finally:
            conn.close()

    def _walk_graph(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        scan_id: str,
        roots: list[str],
        direction: str,
        max_depth: int,
        max_nodes: int,
        traversable_only: bool,
        relationship_types: set[RelationshipType] | None,
        static_only: bool,
        dynamic_only: bool,
        include_roots: bool,
    ) -> tuple[str, str, set[str], dict[str, int], dict[tuple[str, str, str], UnifiedEdge], dict[str, str], list[str], bool]:
        effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
        if not effective_scan_id:
            return scan_id, "", set(), {}, {}, {}, [], False

        existing_roots = {node.id for node in self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=set(roots))}
        visited: set[str] = set()
        depth_by_node: dict[str, int] = {}
        traversed_edges: dict[tuple[str, str, str], UnifiedEdge] = {}
        parent_by_node: dict[str, str] = {}
        discovery_order: list[str] = []
        truncated = False

        queue: list[tuple[str, int]] = []
        for root in roots:
            if root not in existing_roots:
                continue
            queue.append((root, 0))
            depth_by_node[root] = 0
            if include_roots:
                visited.add(root)

        index = 0
        while index < len(queue):
            current, depth = queue[index]
            index += 1
            if depth >= max_depth:
                continue
            for row in self._filtered_edge_rows(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                frontier={current},
                traversable_only=traversable_only,
                relationship_types=relationship_types,
                static_only=static_only,
                dynamic_only=dynamic_only,
            ):
                edge = self._edge_from_row(row)
                candidates: list[str] = []
                if direction in {"forward", "both"}:
                    if edge.source == current:
                        candidates.append(edge.target)
                    elif edge.is_bidirectional and edge.target == current:
                        candidates.append(edge.source)
                if direction in {"reverse", "both"}:
                    if edge.target == current:
                        candidates.append(edge.source)
                    elif edge.is_bidirectional and edge.source == current:
                        candidates.append(edge.target)
                if not candidates:
                    continue

                rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
                traversed_edges.setdefault((edge.source, edge.target, rel), edge)

                for neighbor in candidates:
                    if neighbor in visited:
                        continue
                    if len(visited) >= max_nodes:
                        truncated = True
                        continue
                    visited.add(neighbor)
                    depth_by_node[neighbor] = depth + 1
                    parent_by_node.setdefault(neighbor, current)
                    discovery_order.append(neighbor)
                    queue.append((neighbor, depth + 1))

        if include_roots:
            visited.update(existing_roots)

        return effective_scan_id, created_at, visited, depth_by_node, traversed_edges, parent_by_node, discovery_order, truncated

    def bfs_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> tuple[list[list[str]], set[str]]:
        conn = self._open_ro_conn()
        if conn is None:
            return [], set()
        try:
            (
                _effective_scan_id,
                _created_at,
                visited,
                _depth_by_node,
                _edges,
                parent_by_node,
                discovery_order,
                _truncated,
            ) = self._walk_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                roots=[source],
                direction="forward",
                max_depth=max_depth,
                max_nodes=5000,
                traversable_only=traversable_only,
                relationship_types=None,
                static_only=False,
                dynamic_only=False,
                include_roots=True,
            )
            if source not in visited:
                return [], set()

            paths: list[list[str]] = []
            for node_id in discovery_order:
                if node_id == source:
                    continue
                path = [node_id]
                current = node_id
                while current in parent_by_node:
                    current = parent_by_node[current]
                    path.append(current)
                path.reverse()
                if path and path[0] == source:
                    paths.append(path)
            reachable = set(visited)
            reachable.discard(source)
            return paths, reachable
        finally:
            conn.close()

    def impact_of(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
        max_depth: int = 4,
    ) -> dict[str, Any] | None:
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            effective_scan_id, _created_at, visited, depth_by_node, _edges, _parents, _order, _truncated = self._walk_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                roots=[node_id],
                direction="reverse",
                max_depth=max_depth,
                max_nodes=5000,
                traversable_only=False,
                relationship_types=None,
                static_only=False,
                dynamic_only=False,
                include_roots=True,
            )
            if not effective_scan_id or node_id not in visited:
                return None

            affected_nodes = sorted(node for node in visited if node != node_id)
            affected_node_rows = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=set(affected_nodes))
            affected_by_type: dict[str, int] = {}
            for node in affected_node_rows:
                entity_type = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
                affected_by_type[entity_type] = affected_by_type.get(entity_type, 0) + 1

            return {
                "node_id": node_id,
                "affected_nodes": affected_nodes,
                "affected_by_type": affected_by_type,
                "affected_count": len(affected_nodes),
                "max_depth_reached": max((depth_by_node.get(node, 0) for node in affected_nodes), default=0),
            }
        finally:
            conn.close()

    def traverse_subgraph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        roots: list[str],
        direction: str = "forward",
        max_depth: int = 4,
        max_nodes: int = 500,
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
        include_roots: bool = True,
    ) -> tuple[UnifiedGraph, dict[str, int], bool]:
        conn = self._open_ro_conn()
        if conn is None:
            return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id), {}, False
        try:
            effective_scan_id, created_at, visited, depth_by_node, traversed_edges, _parents, _order, truncated = self._walk_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                roots=roots,
                direction=direction,
                max_depth=max_depth,
                max_nodes=max_nodes,
                traversable_only=traversable_only,
                relationship_types=relationship_types,
                static_only=static_only,
                dynamic_only=dynamic_only,
                include_roots=include_roots,
            )
            graph = UnifiedGraph(scan_id=effective_scan_id, tenant_id=tenant_id, created_at=created_at)
            if not effective_scan_id:
                return graph, {}, False
            node_rows = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=visited)
            for node in node_rows:
                graph.add_node(node)
            for edge in traversed_edges.values():
                if edge.source in graph.nodes and edge.target in graph.nodes:
                    graph.add_edge(edge)
            return graph, depth_by_node, truncated
        finally:
            conn.close()

    def attack_paths_for_sources(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str],
    ) -> list[AttackPath]:
        if not source_ids:
            return []
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return []
            placeholders = ",".join("?" for _ in source_ids)
            rows = conn.execute(
                f"""
                SELECT source_node, target_node, path_nodes, path_edges, composite_risk, credential_exposure, vuln_ids
                FROM attack_paths
                WHERE tenant_id = ? AND scan_id = ? AND source_node IN ({placeholders})
                """,  # nosec B608 - placeholders are generated internally
                [tenant_id, effective_scan_id, *source_ids],
            ).fetchall()
            return [
                AttackPath(
                    source=row["source_node"],
                    target=row["target_node"],
                    hops=json.loads(row["path_nodes"]),
                    edges=json.loads(row["path_edges"]),
                    composite_risk=row["composite_risk"],
                    credential_exposure=json.loads(row["credential_exposure"]),
                    vuln_ids=json.loads(row["vuln_ids"]),
                )
                for row in rows
            ]
        finally:
            conn.close()

    def node_context(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
    ) -> dict[str, Any] | None:
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return None
            nodes = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids={node_id})
            if not nodes:
                return None
            rows = conn.execute(
                """
                SELECT source_id, target_id, relationship, direction, weight, traversable, first_seen, last_seen, evidence, activity_id
                FROM graph_edges
                WHERE tenant_id = ? AND scan_id = ? AND (source_id = ? OR target_id = ?)
                ORDER BY source_id ASC, target_id ASC, relationship ASC
                """,
                [tenant_id, effective_scan_id, node_id, node_id],
            ).fetchall()

            edges_out: list[UnifiedEdge] = []
            edges_in: list[UnifiedEdge] = []
            neighbors: list[str] = []
            sources: list[str] = []

            for row in rows:
                edge = self._edge_from_row(row)
                if edge.source == node_id:
                    edges_out.append(edge)
                    neighbors.append(edge.target)
                    if edge.is_bidirectional:
                        reverse = self._reverse_edge(edge)
                        edges_in.append(reverse)
                        sources.append(edge.target)
                if edge.target == node_id:
                    edges_in.append(edge)
                    sources.append(edge.source)
                    if edge.is_bidirectional:
                        reverse = self._reverse_edge(edge)
                        edges_out.append(reverse)
                        neighbors.append(edge.source)

            return {
                "node": nodes[0],
                "edges_out": edges_out,
                "edges_in": edges_in,
                "neighbors": neighbors,
                "sources": sources,
                "impact": self.impact_of(tenant_id=tenant_id, scan_id=effective_scan_id, node_id=node_id),
            }
        finally:
            conn.close()

    def compliance_summary(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        framework: str = "",
    ) -> dict[str, Any]:
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "scan_id": scan_id,
                "framework_count": 0,
                "total_tagged_findings": 0,
                "frameworks": {},
            }
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return {
                    "scan_id": scan_id,
                    "framework_count": 0,
                    "total_tagged_findings": 0,
                    "frameworks": {},
                }

            rows = conn.execute(
                """
                SELECT id, entity_type, severity, compliance_tags
                FROM graph_nodes
                WHERE tenant_id = ? AND scan_id = ? AND json_array_length(compliance_tags) > 0
                ORDER BY id ASC
                """,
                [tenant_id, effective_scan_id],
            ).fetchall()

            framework_filter = framework.upper()
            framework_stats: dict[str, dict[str, Any]] = defaultdict(
                lambda: {
                    "total_findings": 0,
                    "by_severity": defaultdict(int),
                    "by_entity_type": defaultdict(int),
                    "tags": set(),
                    "node_ids": [],
                }
            )

            for row in rows:
                tags = json.loads(row["compliance_tags"])
                if not tags:
                    continue
                for tag in tags:
                    prefix = tag.split("-")[0].upper() if "-" in tag else tag.upper()
                    if framework_filter and framework_filter != prefix:
                        continue
                    stats = framework_stats[prefix]
                    stats["total_findings"] += 1
                    stats["by_severity"][row["severity"] or "unknown"] += 1
                    stats["by_entity_type"][row["entity_type"]] += 1
                    stats["tags"].add(tag)
                    if row["id"] not in stats["node_ids"]:
                        stats["node_ids"].append(row["id"])

            frameworks: dict[str, Any] = {}
            for name, stats in sorted(framework_stats.items()):
                frameworks[name] = {
                    "total_findings": stats["total_findings"],
                    "by_severity": dict(stats["by_severity"]),
                    "by_entity_type": dict(stats["by_entity_type"]),
                    "tags": sorted(stats["tags"]),
                    "node_count": len(stats["node_ids"]),
                    "node_ids": stats["node_ids"][:100],
                }

            return {
                "scan_id": effective_scan_id,
                "framework_count": len(frameworks),
                "total_tagged_findings": sum(stats["total_findings"] for stats in frameworks.values()),
                "frameworks": frameworks,
            }
        finally:
            conn.close()

    def latest_snapshot_id(self, *, tenant_id: str = "") -> str:
        conn = self._open_ro_conn()
        if conn is None:
            return ""
        try:
            return sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
        finally:
            conn.close()

    def previous_snapshot_id(self, *, tenant_id: str = "", before_scan_id: str = "") -> str:
        conn = self._open_ro_conn()
        if conn is None:
            return ""
        try:
            return sqlite_graph_store.previous_snapshot_id(conn, tenant_id=tenant_id, before_scan_id=before_scan_id)
        finally:
            conn.close()

    def save_graph(self, graph: UnifiedGraph) -> None:
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            conn.execute(_CREATE_PRESET_TABLE_SQLITE)
            conn.execute(_CREATE_SEARCH_TABLE_SQLITE)
            sqlite_graph_store.save_graph(conn, graph)
            self._refresh_snapshot_search_index(conn, tenant_id=graph.tenant_id, scan_id=graph.scan_id)
            conn.commit()

    def load_graph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> UnifiedGraph:
        conn = self._open_ro_conn()
        if conn is None:
            return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
        try:
            return sqlite_graph_store.load_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                entity_types=entity_types,
                min_severity_rank=min_severity_rank,
            )
        finally:
            conn.close()

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "nodes_added": [],
                "nodes_removed": [],
                "nodes_changed": [],
                "edges_added": [],
                "edges_removed": [],
            }
        try:
            return sqlite_graph_store.diff_snapshots(conn, scan_id_old, scan_id_new, tenant_id=tenant_id)
        finally:
            conn.close()

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            return sqlite_graph_store.list_snapshots(conn, tenant_id=tenant_id, limit=limit)
        finally:
            conn.close()

    def snapshot_stats(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> dict[str, Any]:
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "total_nodes": 0,
                "total_edges": 0,
                "node_types": {},
                "severity_counts": {},
                "relationship_types": {},
                "attack_path_count": 0,
                "interaction_risk_count": 0,
                "max_attack_path_risk": 0.0,
                "highest_interaction_risk": 0.0,
            }
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return {
                    "total_nodes": 0,
                    "total_edges": 0,
                    "node_types": {},
                    "severity_counts": {},
                    "relationship_types": {},
                    "attack_path_count": 0,
                    "interaction_risk_count": 0,
                    "max_attack_path_risk": 0.0,
                    "highest_interaction_risk": 0.0,
                }

            node_where = ["tenant_id = ?", "scan_id = ?"]
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join("?" for _ in entity_types)
                node_where.append(f"entity_type IN ({placeholders})")
                params.extend(sorted(entity_types))
            if min_severity_rank:
                node_where.append("severity_id >= ?")
                params.append(min_severity_rank)
            where_sql = " AND ".join(node_where)

            total_nodes = conn.execute(
                f"SELECT COUNT(*) FROM graph_nodes WHERE {where_sql}",  # nosec B608 - where_sql is built from static clause fragments
                params,
            ).fetchone()[0]
            node_type_rows = conn.execute(
                f"SELECT entity_type, COUNT(*) FROM graph_nodes WHERE {where_sql} GROUP BY entity_type",  # nosec B608 - where_sql is built from static clause fragments
                params,
            ).fetchall()
            severity_rows = conn.execute(
                f"SELECT severity, COUNT(*) FROM graph_nodes WHERE {where_sql} AND severity <> '' GROUP BY severity",  # nosec B608 - where_sql is built from static clause fragments
                params,
            ).fetchall()
            total_edges = conn.execute(
                f"""
                SELECT COUNT(*)
                FROM graph_edges
                WHERE tenant_id = ? AND scan_id = ?
                  AND source_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                  AND target_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                """,  # nosec B608 - where_sql is built from static clause fragments
                [tenant_id, effective_scan_id, *params, *params],
            ).fetchone()[0]
            rel_rows = conn.execute(
                f"""
                SELECT relationship, COUNT(*)
                FROM graph_edges
                WHERE tenant_id = ? AND scan_id = ?
                  AND source_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                  AND target_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                GROUP BY relationship
                """,  # nosec B608 - where_sql is built from static clause fragments
                [tenant_id, effective_scan_id, *params, *params],
            ).fetchall()
            attack_row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(composite_risk), 0.0) FROM attack_paths WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()
            interaction_row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(risk_score), 0.0) FROM interaction_risks WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()
            return {
                "total_nodes": int(total_nodes or 0),
                "total_edges": int(total_edges or 0),
                "node_types": {str(row[0]): int(row[1]) for row in node_type_rows},
                "severity_counts": {str(row[0]): int(row[1]) for row in severity_rows},
                "relationship_types": {str(row[0]): int(row[1]) for row in rel_rows},
                "attack_path_count": int((attack_row[0] if attack_row else 0) or 0),
                "interaction_risk_count": int((interaction_row[0] if interaction_row else 0) or 0),
                "max_attack_path_risk": float((attack_row[1] if attack_row else 0.0) or 0.0),
                "highest_interaction_risk": float((interaction_row[1] if interaction_row else 0.0) or 0.0),
            }
        finally:
            conn.close()

    def page_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> tuple[str, str, list[UnifiedNode], int, str | None]:
        conn = self._open_ro_conn()
        if conn is None:
            return scan_id, "", [], 0, None
        try:
            effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return scan_id, "", [], 0, None
            where = ["tenant_id = ?", "scan_id = ?"]
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join("?" for _ in entity_types)
                where.append(f"entity_type IN ({placeholders})")
                params.extend(sorted(entity_types))
            if min_severity_rank:
                where.append("severity_id >= ?")
                params.append(min_severity_rank)
            where_sql = " AND ".join(where)
            total = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM graph_nodes WHERE {where_sql}",  # nosec B608 - where_sql is built from static clause fragments
                    params,
                ).fetchone()[0]
                or 0
            )
            row_params = list(params)
            cursor_clause = ""
            if cursor:
                severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                cursor_clause = """
                AND (
                    severity_id < ?
                    OR (severity_id = ? AND risk_score < ?)
                    OR (severity_id = ? AND risk_score = ? AND label > ?)
                    OR (severity_id = ? AND risk_score = ? AND label = ? AND id > ?)
                )
                """
                row_params.extend(
                    [severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id]
                )
            rows = conn.execute(
                f"""
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                FROM graph_nodes
                WHERE {where_sql}
                {cursor_clause}
                ORDER BY severity_id DESC, risk_score DESC, label ASC, id ASC
                LIMIT ? OFFSET ?
                """,  # nosec B608 - where_sql is built from static clause fragments
                [*row_params, limit + 1 if cursor else limit, 0 if cursor else offset],
            ).fetchall()
            has_more = len(rows) > limit if cursor else offset + limit < total
            rows = rows[:limit]
            nodes = [self._node_from_row(row) for row in rows]
            next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None
            return effective_scan_id, created_at, nodes, total, next_cursor
        finally:
            conn.close()

    def edges_for_node_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[Any]:
        if not node_ids:
            return []
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            effective_scan_id = scan_id or sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
            if not effective_scan_id:
                return []
            placeholders = ",".join("?" for _ in node_ids)
            rows = conn.execute(
                f"""
                SELECT source_id, target_id, relationship, direction, weight, traversable, first_seen, last_seen, evidence, activity_id
                FROM graph_edges
                WHERE tenant_id = ? AND scan_id = ?
                  AND source_id IN ({placeholders})
                  AND target_id IN ({placeholders})
                """,  # nosec B608 - placeholders are generated solely from "?" markers
                [tenant_id, effective_scan_id, *node_ids, *node_ids],
            ).fetchall()
            from agent_bom.graph import RelationshipType, UnifiedEdge

            return [
                UnifiedEdge(
                    source=row["source_id"],
                    target=row["target_id"],
                    relationship=RelationshipType(row["relationship"]),
                    direction=row["direction"],
                    weight=row["weight"],
                    traversable=bool(row["traversable"]),
                    first_seen=row["first_seen"],
                    last_seen=row["last_seen"],
                    evidence=json.loads(row["evidence"]),
                    activity_id=row["activity_id"],
                )
                for row in rows
            ]
        finally:
            conn.close()

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        compliance_prefixes: set[str] | None = None,
        data_sources: set[str] | None = None,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[UnifiedNode], int, str | None]:
        conn = self._open_ro_conn()
        if conn is None:
            return [], 0, None
        try:
            conn_ro: sqlite3.Connection = conn
            effective_scan_id = scan_id or sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
            if not effective_scan_id:
                return [], 0, None
            fts_query = self._search_query_expression(query)
            search_where = [
                "gns.tenant_id = ?",
                "gns.scan_id = ?",
            ]
            params: list[Any] = [tenant_id, effective_scan_id]
            like_query = f"%{_escape_like_query(query.lower())}%"

            def _run_search(*, use_fts: bool) -> tuple[list[UnifiedNode], int, str | None]:
                local_where = list(search_where)
                local_params = list(params)
                if use_fts:
                    local_where.append("gns.graph_node_search MATCH ?")
                    local_params.append(fts_query)
                else:
                    local_where.append("gns.search_text LIKE ? ESCAPE '\\'")
                    local_params.append(like_query)
                if entity_types:
                    placeholders = ",".join("?" for _ in entity_types)
                    local_where.append(f"gn.entity_type IN ({placeholders})")
                    local_params.extend(sorted(entity_types))
                if min_severity_rank:
                    local_where.append("gn.severity_id >= ?")
                    local_params.append(min_severity_rank)
                if compliance_prefixes:
                    prefix_filters = []
                    for prefix in sorted(compliance_prefixes):
                        clause, clause_params = self._compliance_prefix_filter("gns.compliance_tags", prefix)
                        prefix_filters.append(clause)
                        local_params.extend(clause_params)
                    local_where.append("(" + " OR ".join(prefix_filters) + ")")
                if data_sources:
                    source_filters = []
                    for source in sorted(data_sources):
                        clause, clause_params = self._space_token_filter("gns.data_sources", source)
                        source_filters.append(clause)
                        local_params.extend(clause_params)
                    local_where.append("(" + " OR ".join(source_filters) + ")")
                row_params = list(local_params)
                cursor_clause = ""
                if cursor:
                    severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                    cursor_clause = """
                    AND (
                        gn.severity_id < ?
                        OR (gn.severity_id = ? AND gn.risk_score < ?)
                        OR (gn.severity_id = ? AND gn.risk_score = ? AND gn.label > ?)
                        OR (gn.severity_id = ? AND gn.risk_score = ? AND gn.label = ? AND gn.id > ?)
                    )
                    """
                    row_params.extend(
                        [severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id]
                    )

                where_sql = " AND ".join(local_where)
                total = int(
                    conn_ro.execute(
                        "SELECT COUNT(*) " + from_clause + " WHERE " + where_sql,
                        local_params,
                    ).fetchone()[0]
                    or 0
                )
                if total == 0:
                    return [], 0, None
                rows = conn_ro.execute(
                    """
                    SELECT
                        gn.id, gn.entity_type, gn.label, gn.category_uid, gn.class_uid, gn.type_uid,
                        gn.status, gn.risk_score, gn.severity, gn.severity_id, gn.first_seen, gn.last_seen,
                        gn.attributes, gn.compliance_tags, gn.data_sources, gn.dimensions
                    """
                    + from_clause
                    + " WHERE "
                    + where_sql
                    + cursor_clause
                    + " ORDER BY gn.severity_id DESC, gn.risk_score DESC, gn.label ASC, gn.id ASC LIMIT ? OFFSET ?",
                    [*row_params, limit + 1 if cursor else limit, 0 if cursor else offset],
                ).fetchall()
                has_more = len(rows) > limit if cursor else offset + limit < total
                rows = rows[:limit]
                nodes = [self._node_from_row(row) for row in rows]
                next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None
                return nodes, total, next_cursor

            from_clause = """
                FROM graph_node_search gns
                JOIN graph_nodes gn
                  ON gn.id = gns.node_id
                 AND gn.scan_id = gns.scan_id
                 AND gn.tenant_id = gns.tenant_id
            """
            use_fts = bool(fts_query and self._should_use_fts(query))
            try:
                return _run_search(use_fts=use_fts)
            except sqlite3.OperationalError:
                if not use_fts:
                    raise
                return _run_search(use_fts=False)
        finally:
            conn.close()

    def save_preset(self, *, tenant_id: str, name: str, description: str, filters: dict[str, Any], created_at: str) -> None:
        conn = self._open_rw_conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO graph_filter_presets VALUES (?, ?, ?, ?, ?)",
                (name, tenant_id, description, json.dumps(filters), created_at),
            )
            conn.commit()
        finally:
            conn.close()

    def list_presets(self, *, tenant_id: str) -> list[dict[str, Any]]:
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            rows = conn.execute(
                "SELECT name, description, filters, created_at FROM graph_filter_presets WHERE tenant_id = ? ORDER BY name",
                (tenant_id,),
            ).fetchall()
            return [
                {
                    "name": row["name"],
                    "description": row["description"],
                    "filters": json.loads(row["filters"]),
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        finally:
            conn.close()

    def delete_preset(self, *, tenant_id: str, name: str) -> bool:
        conn = self._open_rw_conn()
        try:
            cursor = conn.execute(
                "DELETE FROM graph_filter_presets WHERE name = ? AND tenant_id = ?",
                (name, tenant_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
