"""Snapshot lifecycle for the Postgres graph store: identity, retention and deletion."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.graph.delta_digest import PriorSnapshotDigest

from agent_bom.db.graph_revision import read_snapshot_identity
from agent_bom.db.graph_store import (
    normalize_graph_tenant_id,
    normalize_snapshot_kind,
)
from agent_bom.graph.analysis import analysis_status_map_from_dict, analysis_status_map_to_dict
from agent_bom.security import sanitize_text

from .postgres_common import (
    _tenant_connection,
)
from .postgres_graph_support import (
    _GRAPH_RETENTION_PURGE_TABLES,
    PostgresGraphStoreBase,
    _decode_json_array,
    _decode_json_object,
    logger,
    select_expired_snapshot_ids,
)


class PostgresGraphSnapshotsMixin(PostgresGraphStoreBase):
    """Resolve, list, purge and delete persisted graph snapshots."""

    def snapshot_identity(self, *, tenant_id: str = "", scan_id: str = "", for_paging: bool = False) -> tuple[str, str]:
        """Resolve a generation within the authenticated tenant's connection."""
        tenant_id = normalize_graph_tenant_id(tenant_id)
        with _tenant_connection(self._pool) as conn:
            return read_snapshot_identity(conn, tenant_id, scan_id, for_paging, "%s")

    def latest_snapshot_id(self, *, tenant_id: str = "", snapshot_kind: str = "scan") -> str:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        snapshot_kind = normalize_snapshot_kind(snapshot_kind)
        with _tenant_connection(self._pool) as conn:
            row = conn.execute(
                """
                SELECT scan_id
                FROM graph_snapshots
                WHERE tenant_id = %s AND snapshot_kind = %s
                ORDER BY created_at DESC, scan_id DESC
                LIMIT 1
                """,
                (tenant_id, snapshot_kind),
            ).fetchone()
            return str(row[0]) if row else ""

    def previous_snapshot_id(
        self,
        *,
        tenant_id: str = "",
        before_scan_id: str = "",
        snapshot_kind: str = "scan",
    ) -> str:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        snapshot_kind = normalize_snapshot_kind(snapshot_kind)
        if not before_scan_id:
            return ""
        with _tenant_connection(self._pool) as conn:
            current = conn.execute(
                "SELECT created_at FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s AND snapshot_kind = %s",
                (tenant_id, before_scan_id, snapshot_kind),
            ).fetchone()
            if not current:
                return ""
            row = conn.execute(
                """
                SELECT scan_id
                FROM graph_snapshots
                WHERE tenant_id = %s AND snapshot_kind = %s AND created_at < %s
                ORDER BY created_at DESC, scan_id DESC
                LIMIT 1
                """,
                (tenant_id, snapshot_kind, current[0]),
            ).fetchone()
            return str(row[0]) if row else ""

    def delete_tenant(self, *, tenant_id: str = "") -> int:
        """Delete graph rows for one tenant and return the number of rows removed."""
        tenant_id = normalize_graph_tenant_id(tenant_id)
        total = 0
        with _tenant_connection(self._pool) as conn:
            for table in (
                "graph_node_search",
                "attack_paths",
                "interaction_risks",
                "graph_edges",
                "graph_nodes",
                "graph_snapshots",
                "graph_filter_presets",
            ):
                cursor = conn.execute(f"DELETE FROM {table} WHERE tenant_id = %s", (tenant_id,))  # nosec B608 - table list is static
                total += max(int(cursor.rowcount or 0), 0)
            conn.commit()
        return total

    def delete_snapshot(self, *, tenant_id: str, scan_id: str, expected_generation: str | None = None) -> int:
        """Atomically remove one tenant-scoped snapshot and all projections."""
        tenant_id = normalize_graph_tenant_id(tenant_id)
        total = 0
        with _tenant_connection(self._pool) as conn:
            # Match save_graph_streaming's lock before checking or deleting any
            # projection; a row lock alone cannot protect a missing snapshot.
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"{tenant_id}\x1f{scan_id}",),
            )
            if expected_generation is not None:
                row = conn.execute(
                    "SELECT snapshot_generation FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
                    (tenant_id, scan_id),
                ).fetchone()
                if not expected_generation or row is None or row[0] != expected_generation:
                    return 0
            for table in (
                "graph_node_search",
                "attack_paths",
                "interaction_risks",
                "graph_edges",
                "graph_nodes",
                "graph_snapshots",
            ):
                cursor = conn.execute(
                    f"DELETE FROM {table} WHERE tenant_id = %s AND scan_id = %s",  # nosec B608 - table list is static
                    (tenant_id, scan_id),
                )
                total += max(int(cursor.rowcount or 0), 0)
            conn.commit()
        return total

    def prior_delta_digest(self, *, tenant_id: str = "", scan_id: str = "") -> "PriorSnapshotDigest":
        """Bounded prior-snapshot digest for delta alerts (see #4055/#4075).

        Streams only the columns ``compute_delta_alerts`` reads from the prior
        graph — node ids, agent refs, and attack-path / interaction-risk keys —
        rather than loading a full ``UnifiedGraph``.
        """
        from agent_bom.graph.delta_digest import PriorSnapshotDigestBuilder

        tenant = normalize_graph_tenant_id(tenant_id)
        builder = PriorSnapshotDigestBuilder()
        if not scan_id:
            return builder.build()
        with _tenant_connection(self._pool) as conn:
            for row in conn.execute(
                "SELECT id, entity_type, label, severity, status, risk_score, "
                "CASE WHEN entity_type = 'agent' THEN attributes::jsonb -> 'risk_assessment' END "
                "FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s",
                (tenant, scan_id),
            ):
                builder.add_node(
                    row[0],
                    row[1],
                    label=row[2],
                    severity=row[3] or "",
                    status=row[4],
                    risk_score=row[5],
                    risk_assessment=row[6],
                )
            for row in conn.execute(
                "SELECT source_node, target_node FROM attack_paths WHERE tenant_id = %s AND scan_id = %s",
                (tenant, scan_id),
            ):
                builder.add_attack_path(row[0], row[1])
            for row in conn.execute(
                "SELECT pattern, agents FROM interaction_risks WHERE tenant_id = %s AND scan_id = %s",
                (tenant, scan_id),
            ):
                builder.add_interaction_risk(row[0], _decode_json_array(row[1], field="interaction risk agents"))
        return builder.build()

    def _purge_expired_snapshots(self, conn: Any, tenant: str) -> None:
        """Delete this tenant's graph snapshots older than the retention window.

        Age-based purge keyed on ``graph_snapshots.created_at`` and scoped to the
        tenant being saved. Fail-closed on unparseable timestamps (retained,
        never deleted) and cascades to child rows in FK-safe order.
        """
        from agent_bom.api.tenant_graph_retention import resolve_graph_retention_days

        try:
            rows = conn.execute(
                "SELECT scan_id, created_at FROM graph_snapshots WHERE tenant_id = %s",
                (tenant,),
            ).fetchall()
            triples = [(str(row[0]), tenant, row[1]) for row in rows]
            expired = select_expired_snapshot_ids(
                triples,
                now=datetime.now(timezone.utc),
                resolve_days=resolve_graph_retention_days,
            )
            if not expired:
                return
            delete_params = [(tenant_id, scan_id) for scan_id, tenant_id in expired]
            for table in _GRAPH_RETENTION_PURGE_TABLES:
                conn.executemany(
                    f"DELETE FROM {table} WHERE tenant_id = %s AND scan_id = %s",  # nosec B608 - table names are static internal schema metadata
                    delete_params,
                )
            conn.commit()
            logger.info("Purged %d expired graph snapshot(s) (tenant=%s)", len(expired), tenant)
        except Exception as exc:
            conn.rollback()
            logger.warning("Graph snapshot retention purge skipped: %s", sanitize_text(str(exc)))

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50, since: str | None = None) -> list[dict[str, Any]]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        where = "WHERE tenant_id = %s"
        params: list[Any] = [tenant_id]
        if since:
            where += " AND created_at >= %s"
            params.append(since)
        params.append(limit)
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                f"""
                SELECT scan_id, created_at, node_count, edge_count, risk_summary, analysis_status,
                       snapshot_kind, correlation_id, evidence_manifest_sha256
                FROM graph_snapshots
                {where}
                ORDER BY created_at DESC
                LIMIT %s
                """,  # nosec B608 - where clause is composed from static fragments only
                params,
            ).fetchall()
            return [
                {
                    "scan_id": row[0],
                    "created_at": row[1],
                    "node_count": row[2],
                    "edge_count": row[3],
                    "risk_summary": _decode_json_object(row[4]),
                    "analysis_status": analysis_status_map_to_dict(analysis_status_map_from_dict(_decode_json_object(row[5]))),
                    "snapshot_kind": row[6] or "scan",
                    "correlation_id": row[7] or "",
                    "evidence_manifest_sha256": row[8] or "",
                }
                for row in rows
            ]

    def snapshots_by_ids(self, *, tenant_id: str, scan_ids: set[str]) -> list[dict[str, Any]]:
        tenant = normalize_graph_tenant_id(tenant_id)
        selected = sorted({scan_id.strip() for scan_id in scan_ids if scan_id.strip()})
        if not selected:
            return []
        if len(selected) > 32:
            raise ValueError("at most 32 snapshot IDs may be selected")
        with _tenant_connection(self._pool) as conn:
            rows = conn.execute(
                """
                SELECT scan_id, created_at, node_count, edge_count, risk_summary, analysis_status,
                       snapshot_kind, correlation_id, evidence_manifest_sha256
                FROM graph_snapshots
                WHERE tenant_id = %s AND scan_id = ANY(%s)
                ORDER BY scan_id
                """,
                (tenant, selected),
            ).fetchall()
        return [
            {
                "scan_id": row[0],
                "created_at": row[1],
                "node_count": row[2],
                "edge_count": row[3],
                "risk_summary": _decode_json_object(row[4]),
                "analysis_status": analysis_status_map_to_dict(analysis_status_map_from_dict(_decode_json_object(row[5]))),
                "snapshot_kind": row[6] or "scan",
                "correlation_id": row[7] or "",
                "evidence_manifest_sha256": row[8] or "",
            }
            for row in rows
        ]
