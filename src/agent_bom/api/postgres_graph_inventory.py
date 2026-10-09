"""Inventory and snapshot-statistics reads for the Postgres graph store."""

from __future__ import annotations

from typing import Any

from agent_bom.api.graph_store import (
    _FINDING_ENTITY_TYPE_VALUES,
    _assert_offset_within_cap,
    _escape_like_query,
    decode_graph_cursor,
    encode_graph_cursor,
)
from agent_bom.db.graph_store import normalize_graph_tenant_id
from agent_bom.graph.analysis import analysis_status_map_from_dict, analysis_status_map_to_dict
from agent_bom.graph.severity_floor import severity_floor_sql

from .postgres_common import _tenant_connection
from .postgres_graph_query import PostgresGraphQueryMixin
from .postgres_graph_support import _assert_allowed_entity_types, _decode_json_object

_INVENTORY_FACET_COLUMNS = {
    "type": "entity_type",
    "environment": "inventory_environment",
    "provider": "inventory_provider",
    "severity": "finding_severity",
}
_INVENTORY_FACET_NAMES = ("type", "source", "provider", "environment", "severity")


def _inventory_cte(*, finding_marks: str, asset_marks: str) -> str:
    return f"""
                WITH finding_links AS (
                    SELECT e.source_id AS asset_id, f.severity_id
                    FROM graph_edges e JOIN graph_nodes f
                      ON f.tenant_id = e.tenant_id AND f.scan_id = e.scan_id AND f.id = e.target_id
                    WHERE e.tenant_id = %s AND e.scan_id = %s AND f.entity_type IN ({finding_marks})
                    UNION ALL
                    SELECT e.target_id AS asset_id, f.severity_id
                    FROM graph_edges e JOIN graph_nodes f
                      ON f.tenant_id = e.tenant_id AND f.scan_id = e.scan_id AND f.id = e.source_id
                    WHERE e.tenant_id = %s AND e.scan_id = %s AND f.entity_type IN ({finding_marks})
                ), finding_rollup AS (
                    SELECT asset_id, MAX(COALESCE(severity_id, 0)) AS finding_severity_rank
                    FROM finding_links GROUP BY asset_id
                ), assets_raw AS (
                    SELECT n.*,
                           NULLIF(LOWER(COALESCE(n.dimensions::jsonb ->> 'environment',
                                                  n.attributes::jsonb ->> 'environment', '')), '') AS inventory_environment,
                           NULLIF(LOWER(COALESCE(n.dimensions::jsonb ->> 'cloud_provider',
                                                  n.attributes::jsonb ->> 'provider',
                                                  n.attributes::jsonb ->> 'cloud_provider', '')), '') AS inventory_provider,
                           NULLIF(LOWER(COALESCE(n.dimensions::jsonb ->> 'ecosystem',
                                                  n.attributes::jsonb ->> 'ecosystem', '')), '') AS inventory_ecosystem,
                           finding_rollup.finding_severity_rank
                    FROM graph_nodes n
                    LEFT JOIN finding_rollup ON finding_rollup.asset_id = n.id
                    WHERE n.tenant_id = %s AND n.scan_id = %s
                      AND n.entity_type IN ({asset_marks})
                ), assets AS (
                    SELECT *, CASE finding_severity_rank
                        WHEN 5 THEN 'critical' WHEN 4 THEN 'high' WHEN 3 THEN 'medium'
                        WHEN 2 THEN 'low' WHEN 1 THEN 'info' ELSE NULL END AS finding_severity
                    FROM assets_raw
                )
            """  # nosec B608 - placeholder lists only


def _inventory_where(
    *,
    entity_types: set[str] | None,
    search: str,
    normalized: dict[str, str],
    min_severity_rank: int,
    exclude: str = "",
) -> tuple[str, list[Any]]:
    """Build the inventory filter, optionally leaving out one facet's own filter."""
    clauses: list[str] = []
    params: list[Any] = []
    if entity_types and exclude != "type":
        values = sorted(entity_types)
        clauses.append(f"entity_type IN ({','.join('%s' for _ in values)})")
        params.extend(values)
    if search.strip():
        clauses.append("(LOWER(label) LIKE %s ESCAPE '\\' OR LOWER(attributes) LIKE %s ESCAPE '\\')")
        token = f"%{_escape_like_query(search.strip().lower())}%"
        params.extend([token, token])
    if normalized["environment"] and exclude != "environment":
        clauses.append("inventory_environment = %s")
        params.append(normalized["environment"])
    if normalized["provider"] and exclude != "provider":
        clauses.append("inventory_provider = %s")
        params.append(normalized["provider"])
    if normalized["source"] and exclude != "source":
        clauses.append(
            "EXISTS (SELECT 1 FROM jsonb_array_elements_text(assets.data_sources::jsonb) src(value) WHERE LOWER(src.value) = %s)"
        )
        params.append(normalized["source"])
    if normalized["severity"] and exclude != "severity":
        clauses.append("finding_severity = %s")
        params.append(normalized["severity"])
    if min_severity_rank and exclude != "severity":
        clauses.append("COALESCE(finding_severity_rank, 0) >= %s")
        params.append(min_severity_rank)
    return (" AND ".join(clauses) if clauses else "1 = 1"), params


def _inventory_facets(
    conn: Any, *, cte: str, cte_params: list[Any], filters: dict[str, Any]
) -> tuple[dict[str, list[dict[str, Any]]], int]:
    """Count every facet bucket (each ignoring its own filter) plus the filtered total."""
    where_sql, where_params = _inventory_where(**filters)
    facet_sql = [
        f"SELECT '__total__' AS facet, NULL::text AS value, COUNT(*) AS count FROM assets WHERE {where_sql}"  # nosec B608 - generated clauses only
    ]
    facet_params: list[Any] = [*where_params]
    for facet, column in _INVENTORY_FACET_COLUMNS.items():
        facet_where, current_params = _inventory_where(**filters, exclude=facet)
        facet_sql.append(
            f"SELECT '{facet}', {column}, COUNT(*) FROM assets WHERE {facet_where} GROUP BY {column}"  # nosec B608 - static mapping
        )
        facet_params.extend(current_params)
    source_where, source_params = _inventory_where(**filters, exclude="source")
    facet_sql.append(
        f"""SELECT 'source', value, COUNT(DISTINCT id) FROM (
                       SELECT assets.id, NULLIF(LOWER(src.value), '') AS value
                       FROM assets CROSS JOIN LATERAL jsonb_array_elements_text(assets.data_sources::jsonb) src(value)
                       WHERE {source_where}
                       UNION ALL SELECT assets.id, NULL FROM assets
                       WHERE {source_where} AND jsonb_array_length(data_sources::jsonb) = 0
                     ) source_buckets GROUP BY value"""  # nosec B608 - generated clauses only
    )
    facet_params.extend([*source_params, *source_params])
    facet_rows = conn.execute(cte + " UNION ALL ".join(facet_sql), [*cte_params, *facet_params]).fetchall()
    facets: dict[str, list[dict[str, Any]]] = {name: [] for name in _INVENTORY_FACET_NAMES}
    total = 0
    for facet, value, count in facet_rows:
        if facet == "__total__":
            total = int(count or 0)
            continue
        facets[str(facet)].append({"value": value if value not in {"", None} else None, "count": int(count)})
    for buckets in facets.values():
        buckets.sort(key=lambda bucket: (-int(bucket["count"]), "" if bucket["value"] is None else str(bucket["value"])))
    return facets, total


def _inventory_rows(
    conn: Any, *, cte: str, row_params: list[Any], where_sql: str, cursor: str | None, offset: int, limit: int
) -> list[Any]:
    cursor_clause = ""
    if cursor:
        severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
        cursor_clause = """
                    AND (severity_id < %s OR (severity_id = %s AND risk_score < %s)
                      OR (severity_id = %s AND risk_score = %s AND label > %s)
                      OR (severity_id = %s AND risk_score = %s AND label = %s AND id > %s))
                """
        row_params.extend([severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id])
    return list(
        conn.execute(
            cte
            + f""" SELECT id, entity_type, label, category_uid, class_uid, type_uid,
                                status, risk_score, severity, severity_id, first_seen, last_seen,
                                attributes, compliance_tags, data_sources, dimensions
                           FROM assets WHERE {where_sql} {cursor_clause}
                          ORDER BY severity_id DESC, risk_score DESC, label ASC, id ASC
                          LIMIT %s OFFSET %s""",  # nosec B608 - generated clauses only
            [*row_params, limit + 1, 0 if cursor else offset],
        ).fetchall()
    )


def _empty_snapshot_stats() -> dict[str, Any]:
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
        "analysis_status": {},
    }


def _snapshot_stats_filter(*, tenant_id: str, scan_id: str, entity_types: set[str] | None, min_severity_rank: int) -> tuple[str, list[Any]]:
    node_where = ["tenant_id = %s", "scan_id = %s"]
    params: list[Any] = [tenant_id, scan_id]
    if entity_types:
        placeholders = ",".join(["%s"] * len(entity_types))
        node_where.append(f"entity_type IN ({placeholders})")
        params.extend(sorted(entity_types))
    sev_sql, sev_params = severity_floor_sql(min_severity_rank, placeholder="%s")
    if sev_sql:
        node_where.append(sev_sql)
        params.extend(sev_params)
    return " AND ".join(node_where), params


def _stored_snapshot_counts(
    conn: Any, *, tenant_id: str, scan_id: str
) -> tuple[int | None, int | None, dict[str, int] | None, dict[str, int] | None]:
    """Read the totals and breakdowns materialised on the snapshot row at write time."""
    stored_node_count: int | None = None
    stored_edge_count: int | None = None
    cached_node_types: dict[str, int] | None = None
    cached_severity_counts: dict[str, int] | None = None
    snap_row = conn.execute(
        "SELECT node_count, edge_count, risk_summary, node_type_counts FROM graph_snapshots WHERE scan_id = %s AND tenant_id = %s",
        (scan_id, tenant_id),
    ).fetchone()
    if snap_row is not None:
        stored_node_count = snap_row[0] if snap_row[0] is not None else None
        stored_edge_count = snap_row[1] if snap_row[1] is not None else None
        if snap_row[3] is not None:
            cached_node_types = {str(k): int(v) for k, v in _decode_json_object(snap_row[3]).items()}
            cached_severity_counts = {str(k): int(v) for k, v in _decode_json_object(snap_row[2]).items() if k}
    return stored_node_count, stored_edge_count, cached_node_types, cached_severity_counts


def _node_breakdowns(
    conn: Any,
    *,
    where_sql: str,
    params: list[Any],
    stored: tuple[int | None, int | None, dict[str, int] | None, dict[str, int] | None],
) -> tuple[int, dict[str, int], dict[str, int]]:
    """Node total, per-type and per-severity counts: stored values first, live GROUP BY otherwise."""
    stored_node_count, _stored_edge_count, cached_node_types, cached_severity_counts = stored
    if stored_node_count is not None:
        total_nodes = int(stored_node_count)
    else:
        total_nodes_row = conn.execute(
            f"SELECT COUNT(*) FROM graph_nodes WHERE {where_sql}",  # nosec B608 - where_sql is built from static clause fragments
            params,
        ).fetchone()
        total_nodes = int((total_nodes_row[0] if total_nodes_row else 0) or 0)
    if cached_node_types is not None:
        node_types = cached_node_types
    else:
        node_type_rows = conn.execute(
            f"SELECT entity_type, COUNT(*) FROM graph_nodes WHERE {where_sql} GROUP BY entity_type",  # nosec B608 - where_sql is built from static clause fragments
            params,
        ).fetchall()
        node_types = {str(row[0]): int(row[1]) for row in node_type_rows}
    if cached_severity_counts is not None:
        severity_counts = cached_severity_counts
    else:
        severity_rows = conn.execute(
            f"SELECT severity, COUNT(*) FROM graph_nodes WHERE {where_sql} AND severity <> '' GROUP BY severity",  # nosec B608 - where_sql is built from static clause fragments
            params,
        ).fetchall()
        severity_counts = {str(row[0]): int(row[1]) for row in severity_rows}
    return total_nodes, node_types, severity_counts


def _edge_breakdowns(
    conn: Any,
    *,
    tenant_id: str,
    scan_id: str,
    where_sql: str,
    params: list[Any],
    stored_edge_count: int | None,
    filters_active: bool,
) -> tuple[int, list[Any]]:
    """Edge total and per-relationship rows for the (optionally filtered) snapshot."""
    effective_scan_id = scan_id
    if stored_edge_count is not None:
        total_edges = int(stored_edge_count)
    else:
        total_edges_row = conn.execute(
            f"""
                    SELECT COUNT(*)
                    FROM graph_edges
                    WHERE tenant_id = %s AND scan_id = %s
                      AND source_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                      AND target_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                    """,  # nosec B608 - where_sql is built from static clause fragments
            [tenant_id, effective_scan_id, *params, *params],
        ).fetchone()
        total_edges = int((total_edges_row[0] if total_edges_row else 0) or 0)
    if not filters_active:
        # Persisted snapshots already validate their topology while
        # writing. Avoid two redundant graph_nodes membership scans on
        # the common unfiltered stats path; the snapshot-key index can
        # serve this bounded edge aggregation directly.
        rel_rows = conn.execute(
            """
                    SELECT relationship, COUNT(*)
                    FROM graph_edges
                    WHERE tenant_id = %s AND scan_id = %s
                    GROUP BY relationship
                    """,
            (tenant_id, effective_scan_id),
        ).fetchall()
    else:
        rel_rows = conn.execute(
            f"""
                    SELECT relationship, COUNT(*)
                    FROM graph_edges
                    WHERE tenant_id = %s AND scan_id = %s
                      AND source_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                      AND target_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                    GROUP BY relationship
                    """,  # nosec B608 - where_sql is built from static clause fragments
            [tenant_id, effective_scan_id, *params, *params],
        ).fetchall()
    return total_edges, list(rel_rows)


class PostgresGraphInventoryMixin(PostgresGraphQueryMixin):
    """Answer the inventory contract and snapshot statistics from Postgres."""

    def snapshot_stats(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> dict[str, Any]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        _assert_allowed_entity_types(entity_types)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return _empty_snapshot_stats()
        where_sql, params = _snapshot_stats_filter(
            tenant_id=tenant_id, scan_id=effective_scan_id, entity_types=entity_types, min_severity_rank=min_severity_rank
        )

        with _tenant_connection(self._pool) as conn:
            analysis_row = conn.execute(
                "SELECT analysis_status FROM graph_snapshots WHERE scan_id = %s AND tenant_id = %s",
                (effective_scan_id, tenant_id),
            ).fetchone()
            analysis_status = analysis_status_map_to_dict(
                analysis_status_map_from_dict(_decode_json_object(analysis_row[0] if analysis_row else None))
            )
            # Unfiltered node/edge totals AND the entity-type / severity breakdowns
            # are materialised on the snapshot row at write time. Re-deriving them
            # here costs two GROUP BYs over graph_nodes plus a double id-membership
            # edge subquery on every paged /v1/graph call — O(estate) per page view
            # of an estate that only grows. Read the stored values and fall back to
            # the live queries only when the snapshot row is missing or the
            # breakdown was never populated (snapshots older than the column). Any
            # active entity-type or severity filter narrows the set, so the
            # recompute path still runs then. Kept identical to the SQLite backend:
            # a count that depends on which store answered is not a count.
            filters_active = bool(entity_types) or bool(min_severity_rank)
            stored: tuple[int | None, int | None, dict[str, int] | None, dict[str, int] | None] = (None, None, None, None)
            if not filters_active:
                stored = _stored_snapshot_counts(conn, tenant_id=tenant_id, scan_id=effective_scan_id)
            total_nodes, node_types, severity_counts = _node_breakdowns(conn, where_sql=where_sql, params=params, stored=stored)
            total_edges, rel_rows = _edge_breakdowns(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                where_sql=where_sql,
                params=params,
                stored_edge_count=stored[1],
                filters_active=filters_active,
            )
            attack_row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(composite_risk), 0.0) FROM attack_paths WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            interaction_row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(risk_score), 0.0) FROM interaction_risks WHERE tenant_id = %s AND scan_id = %s",
                (tenant_id, effective_scan_id),
            ).fetchone()
            return {
                "total_nodes": total_nodes,
                "total_edges": total_edges,
                "node_types": node_types,
                "severity_counts": severity_counts,
                "relationship_types": {str(row[0]): int(row[1]) for row in rel_rows},
                "attack_path_count": int((attack_row[0] if attack_row else 0) or 0),
                "interaction_risk_count": int((interaction_row[0] if interaction_row else 0) or 0),
                "max_attack_path_risk": float((attack_row[1] if attack_row else 0.0) or 0.0),
                "highest_interaction_risk": float((interaction_row[1] if interaction_row else 0.0) or 0.0),
                "analysis_status": analysis_status,
            }

    def query_inventory(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        asset_entity_types: set[str],
        entity_types: set[str] | None = None,
        search: str = "",
        environment: str = "",
        provider: str = "",
        source: str = "",
        severity: str = "",
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Postgres-native parity for the exact inventory query contract."""
        tenant_id = normalize_graph_tenant_id(tenant_id)
        _assert_offset_within_cap(offset, cursor)
        # Resolve the snapshot and every projection under one MVCC view so a
        # concurrent replacement cannot mix facets, rows and finding context.
        with _tenant_connection(self._pool, repeatable_read=True) as conn:
            snapshot_row = self._inventory_snapshot_row(conn, tenant_id=tenant_id, scan_id=scan_id)
            if snapshot_row is None:
                return self._empty_inventory_result(scan_id="")
            effective_scan_id = str(snapshot_row[0])
            asset_types = sorted(asset_entity_types)
            finding_types = sorted(_FINDING_ENTITY_TYPE_VALUES)
            finding_marks = ",".join("%s" for _ in finding_types)
            cte = _inventory_cte(finding_marks=finding_marks, asset_marks=",".join("%s" for _ in asset_types))
            scope = [tenant_id, effective_scan_id]
            cte_params: list[Any] = [*scope, *finding_types, *scope, *finding_types, *scope, *asset_types]
            normalized = {
                "environment": environment.strip().lower(),
                "provider": provider.strip().lower(),
                "source": source.strip().lower(),
                "severity": severity.strip().lower(),
            }
            filters: dict[str, Any] = {
                "entity_types": entity_types,
                "search": search,
                "normalized": normalized,
                "min_severity_rank": min_severity_rank,
            }
            where_sql, where_params = _inventory_where(**filters)
            facets, total = _inventory_facets(conn, cte=cte, cte_params=cte_params, filters=filters)
            rows = _inventory_rows(
                conn, cte=cte, row_params=[*cte_params, *where_params], where_sql=where_sql, cursor=cursor, offset=offset, limit=limit
            )
            has_more = len(rows) > limit or (not cursor and offset + limit < total)
            nodes = [self._node_from_row(row) for row in rows[:limit]]
            next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None

            finding_summaries, relationship_counts = self._inventory_page_context(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                node_ids={node.id for node in nodes},
                finding_types=finding_types,
            )
            finding_count_row = conn.execute(
                f"SELECT COUNT(*) FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s AND entity_type IN ({finding_marks})",  # nosec B608 - placeholders only
                [tenant_id, effective_scan_id, *finding_types],
            ).fetchone()
            return {
                "scan_id": effective_scan_id,
                "created_at": str(snapshot_row[1]),
                "nodes": nodes,
                "total": total,
                "next_cursor": next_cursor,
                "facets": facets,
                "finding_summaries": finding_summaries,
                "relationship_counts": relationship_counts,
                "finding_count": int((finding_count_row[0] if finding_count_row else 0) or 0),
            }

    @staticmethod
    def _inventory_snapshot_row(conn: Any, *, tenant_id: str, scan_id: str) -> Any:
        if scan_id:
            return conn.execute(
                "SELECT scan_id, created_at FROM graph_snapshots WHERE scan_id = %s AND tenant_id = %s",
                (scan_id, tenant_id),
            ).fetchone()
        return conn.execute(
            """SELECT scan_id, created_at FROM graph_snapshots
                       WHERE tenant_id = %s AND snapshot_kind = 'scan'
                       ORDER BY created_at DESC, scan_id DESC LIMIT 1""",
            (tenant_id,),
        ).fetchone()
