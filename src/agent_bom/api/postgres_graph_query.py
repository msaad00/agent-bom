"""Paged node, edge and filter-preset queries for the Postgres graph store."""

from __future__ import annotations

import json
from typing import Any

from agent_bom.api.graph_edge_query import edge_query
from agent_bom.api.graph_store import (
    _assert_offset_within_cap,
    _escape_like_query,
    decode_graph_cursor,
    encode_graph_cursor,
)
from agent_bom.db.graph_store import (
    normalize_graph_tenant_id,
)
from agent_bom.graph.severity_floor import severity_floor_sql

from .postgres_common import (
    _tenant_connection,
)
from .postgres_graph_support import (
    _assert_allowed_entity_types,
    _decode_json_object,
)
from .postgres_graph_traversal import PostgresGraphTraversalMixin


class PostgresGraphQueryMixin(PostgresGraphTraversalMixin):
    """Page nodes and edges, assemble inventory page context and manage presets."""

    @staticmethod
    def _space_token_filter(column: str, token: str) -> tuple[str, list[str]]:
        escaped = _escape_like_query(token.lower())
        clause = f"({column} = %s OR {column} LIKE %s ESCAPE '\\' OR {column} LIKE %s ESCAPE '\\' OR {column} LIKE %s ESCAPE '\\')"
        return clause, [escaped, f"{escaped} %%", f"%% {escaped}", f"%% {escaped} %%"]

    @staticmethod
    def _compliance_prefix_filter(column: str, prefix: str) -> tuple[str, list[str]]:
        escaped = _escape_like_query(prefix.lower())
        clause = (
            f"({column} = %s OR {column} LIKE %s ESCAPE '\\' OR "
            f"{column} LIKE %s ESCAPE '\\' OR {column} LIKE %s ESCAPE '\\' OR {column} LIKE %s ESCAPE '\\')"
        )
        return clause, [escaped, f"{escaped}-%%", f"{escaped} %%", f"%% {escaped}-%%", f"%% {escaped} %%"]

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
    ) -> tuple[str, str, list[Any], int, str | None]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        _assert_allowed_entity_types(entity_types)
        _assert_offset_within_cap(offset, cursor)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return scan_id, "", [], 0, None
        with _tenant_connection(self._pool) as conn:
            created_row = conn.execute(
                "SELECT created_at FROM graph_snapshots WHERE scan_id = %s AND tenant_id = %s",
                (effective_scan_id, tenant_id),
            ).fetchone()
            where = ["tenant_id = %s", "scan_id = %s"]
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join(["%s"] * len(entity_types))
                where.append(f"entity_type IN ({placeholders})")
                params.extend(sorted(entity_types))
            sev_sql, sev_params = severity_floor_sql(min_severity_rank, placeholder="%s")
            if sev_sql:
                where.append(sev_sql)
                params.extend(sev_params)
            where_sql = " AND ".join(where)
            total_row = conn.execute(
                f"SELECT COUNT(*) FROM graph_nodes WHERE {where_sql}",  # nosec B608 - where_sql is built from static clause fragments
                params,
            ).fetchone()
            total = int((total_row[0] if total_row else 0) or 0)
            row_params = list(params)
            cursor_clause = ""
            if cursor:
                severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                cursor_clause = """
                AND (
                    severity_id < %s
                    OR (severity_id = %s AND risk_score < %s)
                    OR (severity_id = %s AND risk_score = %s AND label > %s)
                    OR (severity_id = %s AND risk_score = %s AND label = %s AND id > %s)
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
                LIMIT %s OFFSET %s
                """,  # nosec B608 - where_sql is built from static clause fragments
                [*row_params, limit + 1 if cursor else limit, 0 if cursor else offset],
            ).fetchall()
            has_more = len(rows) > limit if cursor else offset + limit < total
            rows = rows[:limit]
            nodes = [self._node_from_row(row) for row in rows]
            next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None
            return effective_scan_id, str(created_row[0]) if created_row else "", nodes, total, next_cursor

    @staticmethod
    def _empty_inventory_result(*, scan_id: str) -> dict[str, Any]:
        return {
            "scan_id": scan_id,
            "created_at": "",
            "nodes": [],
            "total": 0,
            "next_cursor": None,
            "facets": {name: [] for name in ("type", "source", "provider", "environment", "severity")},
            "finding_summaries": {},
            "relationship_counts": {},
            "finding_count": 0,
        }

    def _inventory_page_context(
        self,
        conn: Any,
        *,
        tenant_id: str,
        scan_id: str,
        node_ids: set[str],
        finding_types: list[str],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
        if not node_ids:
            return {}, {}
        nodes = sorted(node_ids)
        node_marks = ",".join("%s" for _ in nodes)
        finding_marks = ",".join("%s" for _ in finding_types)
        rows = conn.execute(
            f"""SELECT a.id, f.id, CASE LOWER(COALESCE(f.severity, ''))
                         WHEN 'informational' THEN 'info' ELSE LOWER(COALESCE(f.severity, '')) END
                  FROM graph_nodes a JOIN graph_edges e ON e.tenant_id = a.tenant_id AND e.scan_id = a.scan_id
                   AND (e.source_id = a.id OR e.target_id = a.id)
                  JOIN graph_nodes f ON f.tenant_id = e.tenant_id AND f.scan_id = e.scan_id
                   AND f.id = CASE WHEN e.source_id = a.id THEN e.target_id ELSE e.source_id END
                 WHERE a.tenant_id = %s AND a.scan_id = %s AND a.id IN ({node_marks})
                   AND f.entity_type IN ({finding_marks})
                 GROUP BY a.id, f.id, f.severity, f.severity_id
                 ORDER BY a.id, f.severity_id DESC, f.id""",  # nosec B608 - placeholder lists only
            [tenant_id, scan_id, *nodes, *finding_types],
        ).fetchall()
        summaries: dict[str, dict[str, Any]] = {}
        for asset_id, finding_id, finding_severity in rows:
            summary = summaries.setdefault(str(asset_id), {"total": 0, "by_severity": {}, "ids": [], "top_severity": ""})
            summary["total"] += 1
            summary["ids"].append(str(finding_id))
            if finding_severity:
                summary["by_severity"][str(finding_severity)] = int(summary["by_severity"].get(str(finding_severity), 0)) + 1
                if not summary["top_severity"]:
                    summary["top_severity"] = str(finding_severity)
        rel_rows = conn.execute(
            f"""SELECT node_id, COUNT(*) FROM (
                  SELECT source_id AS node_id, source_id, target_id, relationship FROM graph_edges
                    WHERE tenant_id = %s AND scan_id = %s AND source_id IN ({node_marks})
                  UNION
                  SELECT target_id AS node_id, source_id, target_id, relationship FROM graph_edges
                    WHERE tenant_id = %s AND scan_id = %s AND target_id IN ({node_marks})
                ) relationships GROUP BY node_id""",  # nosec B608 - placeholder lists only
            [tenant_id, scan_id, *nodes, tenant_id, scan_id, *nodes],
        ).fetchall()
        return summaries, {str(row[0]): int(row[1]) for row in rel_rows}

    def edges_for_node_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
        induced_only: bool = False,
        direction: str = "both",
        relationships: set[str] | None = None,
        limit: int | None = None,
    ) -> list[Any]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        if not node_ids:
            return []
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return []
        query, params = edge_query(
            tenant_id=tenant_id,
            scan_id=effective_scan_id,
            node_ids=node_ids,
            dialect="postgres",
            induced_only=induced_only,
            direction=direction,
            relationships=relationships,
            limit=limit,
        )
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._edge_from_row(row) for row in rows]

    def save_preset(self, *, tenant_id: str, name: str, description: str, filters: dict[str, Any], created_at: str) -> None:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            conn.execute(
                """
                INSERT INTO graph_filter_presets (name, tenant_id, description, filters, created_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (name, tenant_id) DO UPDATE SET
                    description = EXCLUDED.description,
                    filters = EXCLUDED.filters,
                    created_at = EXCLUDED.created_at
                """,
                (name, tenant_id, description, json.dumps(filters), created_at),
            )
            conn.commit()

    def list_presets(self, *, tenant_id: str) -> list[dict[str, Any]]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                "SELECT name, description, filters, created_at FROM graph_filter_presets WHERE tenant_id = %s ORDER BY name",
                (tenant_id,),
            ).fetchall()
            return [
                {
                    "name": row[0],
                    "description": row[1],
                    "filters": _decode_json_object(row[2], field="graph preset filters"),
                    "created_at": row[3],
                }
                for row in rows
            ]

    def delete_preset(self, *, tenant_id: str, name: str) -> bool:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            cursor = conn.execute(
                "DELETE FROM graph_filter_presets WHERE name = %s AND tenant_id = %s",
                (name, tenant_id),
            )
            conn.commit()
            return (cursor.rowcount or 0) > 0
