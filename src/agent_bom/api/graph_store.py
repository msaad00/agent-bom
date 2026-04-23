"""Unified graph store backends for API persistence and querying.

This module gives the API a pluggable graph persistence layer so unified
graph reads/writes follow the same backend selection model as the rest of
the control plane. SQLite remains the default local backend; Postgres can
provide the same contract for multi-tenant API deployments.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Protocol

from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph import EntityType, NodeDimensions, NodeStatus, UnifiedGraph, UnifiedNode

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
        offset: int = 0,
        limit: int = 500,
    ) -> tuple[str, str, list[UnifiedNode], int]: ...

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
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[UnifiedNode], int]: ...

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
        offset: int = 0,
        limit: int = 500,
    ) -> tuple[str, str, list[UnifiedNode], int]:
        conn = self._open_ro_conn()
        if conn is None:
            return scan_id, "", [], 0
        try:
            effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return scan_id, "", [], 0
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
            rows = conn.execute(
                f"""
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                FROM graph_nodes
                WHERE {where_sql}
                ORDER BY severity_id DESC, risk_score DESC, label ASC, id ASC
                LIMIT ? OFFSET ?
                """,  # nosec B608 - where_sql is built from static clause fragments
                [*params, limit, offset],
            ).fetchall()
            return effective_scan_id, created_at, [self._node_from_row(row) for row in rows], total
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
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[UnifiedNode], int]:
        conn = self._open_ro_conn()
        if conn is None:
            return [], 0
        try:
            conn_ro: sqlite3.Connection = conn
            effective_scan_id = scan_id or sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
            if not effective_scan_id:
                return [], 0
            fts_query = self._search_query_expression(query)
            search_where = [
                "gns.tenant_id = ?",
                "gns.scan_id = ?",
            ]
            params: list[Any] = [tenant_id, effective_scan_id]
            like_query = f"%{_escape_like_query(query.lower())}%"

            def _run_search(*, use_fts: bool) -> tuple[list[UnifiedNode], int]:
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

                where_sql = " AND ".join(local_where)
                total = int(
                    conn_ro.execute(
                        "SELECT COUNT(*) " + from_clause + " WHERE " + where_sql,
                        local_params,
                    ).fetchone()[0]
                    or 0
                )
                if total == 0:
                    return [], 0
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
                    + " ORDER BY gn.severity_id DESC, gn.risk_score DESC, gn.label ASC, gn.id ASC LIMIT ? OFFSET ?",
                    [*local_params, limit, offset],
                ).fetchall()
                return [self._node_from_row(row) for row in rows], total

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
