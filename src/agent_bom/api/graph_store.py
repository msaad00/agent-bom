"""Unified graph store backends for API persistence and querying.

This module gives the API a pluggable graph persistence layer so unified
graph reads/writes follow the same backend selection model as the rest of
the control plane. SQLite remains the default local backend; Postgres can
provide the same contract for multi-tenant API deployments.
"""

from __future__ import annotations

import json
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

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
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
        conn.commit()
        return conn

    def _open_ro_conn(self) -> sqlite3.Connection | None:
        if not self._exists():
            return None
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        sqlite_graph_store._init_db(conn)
        conn.execute(_CREATE_PRESET_TABLE_SQLITE)
        conn.commit()
        return conn

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
            sqlite_graph_store.save_graph(conn, graph)

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

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[UnifiedNode], int]:
        conn = self._open_ro_conn()
        if conn is None:
            return [], 0
        try:
            effective_scan_id = scan_id or sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
            if not effective_scan_id:
                return [], 0

            like = f"%{query.lower()}%"
            where = """
                FROM graph_nodes
                WHERE tenant_id = ? AND scan_id = ?
                  AND (
                    lower(id) LIKE ? OR
                    lower(label) LIKE ? OR
                    lower(entity_type) LIKE ? OR
                    lower(severity) LIKE ? OR
                    lower(compliance_tags) LIKE ? OR
                    lower(data_sources) LIKE ? OR
                    lower(attributes) LIKE ? OR
                    lower(dimensions) LIKE ?
                  )
            """
            params: list[Any] = [tenant_id, effective_scan_id, like, like, like, like, like, like, like, like]
            total_row = conn.execute("SELECT COUNT(*) " + where, params).fetchone()
            rows = conn.execute(
                """
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                """
                + where
                + """
                ORDER BY severity_id DESC, risk_score DESC, label ASC
                LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
            return [self._node_from_row(row) for row in rows], int(total_row[0] if total_row else 0)
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
