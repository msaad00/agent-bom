"""Shared constants, row helpers and the mixin base for the Postgres graph store."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, Mapping, Sequence

if TYPE_CHECKING:
    from agent_bom.graph import RelationshipType
    from agent_bom.graph.analysis import GraphAnalysisStatus

from agent_bom.db.graph_store import DEFAULT_GRAPH_TENANT_ID
from agent_bom.graph import EntityType
from agent_bom.graph.correlation import GraphCorrelationRun

# Keep the historical logger name so log routing and filters are unchanged.
logger = logging.getLogger("agent_bom.api.postgres_graph")
_GRAPH_STORAGE_SCHEMA_VERSION = 6
_DB_NOW_ISO = "to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')"
_DB_LEASE_ISO = "to_char(now() AT TIME ZONE 'UTC' + (%s * INTERVAL '1 second'), 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')"


def select_expired_snapshot_ids(
    rows: Iterable[Sequence[Any]],
    *,
    now: datetime,
    resolve_days: "Callable[[str], int]",
) -> list[tuple[str, str]]:
    """Select ``(scan_id, tenant_id)`` snapshots older than their retention window.

    Pure, side-effect-free core of the age-based snapshot purge, extracted so the
    bounded-retention guarantee is unit-testable without a live Postgres. ``rows``
    are ``(scan_id, tenant_id, created_at)`` triples. Fail-closed: any snapshot
    whose ``created_at`` cannot be parsed as ISO-8601 is retained, never deleted.
    """
    from agent_bom.db.graph_store import _parse_iso_timestamp

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    expired: list[tuple[str, str]] = []
    cutoffs: dict[str, datetime] = {}
    for row in rows:
        scan_id, tenant_id, created_raw = str(row[0]), str(row[1]), row[2]
        cutoff = cutoffs.get(tenant_id)
        if cutoff is None:
            cutoff = now - timedelta(days=max(1, int(resolve_days(tenant_id))))
            cutoffs[tenant_id] = cutoff
        created = _parse_iso_timestamp(created_raw)
        if created is not None and created < cutoff:
            expired.append((scan_id, tenant_id))
    return expired


_ALLOWED_ENTITY_TYPES = {entity_type.value for entity_type in EntityType}
_FINDING_ENTITY_TYPES = {
    EntityType.VULNERABILITY.value,
    EntityType.MISCONFIGURATION.value,
    EntityType.DRIFT_INCIDENT.value,
}
_GRAPH_EVIDENCE_INCLUDED_TABLES = [
    "graph_snapshots",
    "graph_nodes",
    "graph_edges",
    "attack_paths",
    "interaction_risks",
]
_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS = [
    "graph_nodes.attributes",
    "graph_edges.provenance",
    "graph_edges.evidence",
    "attack_paths.credential_exposure",
]
_DEFAULT_GRAPH_WRITE_BATCH_SIZE = 1000
# Tables purged (children before parents) when a graph snapshot ages out of the
# retention window, so a partial failure never orphans rows under a deleted
# snapshot. Mirrors ``graph_store._GRAPH_PURGEABLE_TABLES`` plus the search index.
_GRAPH_RETENTION_PURGE_TABLES = (
    "graph_node_search",
    "attack_paths",
    "interaction_risks",
    "graph_edges",
    "graph_nodes",
    "graph_snapshots",
)
_GRAPH_TENANT_TABLE_KEYS: dict[str, tuple[str, ...]] = {
    "graph_nodes": ("id", "scan_id"),
    "graph_edges": ("source_id", "target_id", "relationship", "scan_id"),
    "graph_snapshots": ("scan_id",),
    "graph_correlation_runs": ("correlation_id",),
    "attack_paths": ("source_node", "target_node", "scan_id"),
    "interaction_risks": ("pattern", "agents", "scan_id"),
    "graph_filter_presets": ("name",),
    "graph_node_search": ("node_id", "scan_id"),
}


def _batched_rows(rows: Iterable[Sequence[Any]], batch_size: int) -> Iterator[list[Sequence[Any]]]:
    batch: list[Sequence[Any]] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= batch_size:
            yield batch
            batch = []
    if batch:
        yield batch


def _execute_many_batched(conn: Any, sql: str, rows: Iterable[Sequence[Any]], *, batch_size: int) -> int:
    """Execute DML rows in bounded batches.

    psycopg connections expose ``cursor().executemany``. Tests and light mocks
    often only expose ``execute`` or ``executemany`` directly, so keep a small
    compatibility fallback while preserving bounded memory behavior.
    """
    total = 0
    for batch in _batched_rows(rows, batch_size):
        if hasattr(conn, "executemany"):
            conn.executemany(sql, batch)
        elif hasattr(conn, "cursor"):
            with conn.cursor() as cur:
                cur.executemany(sql, batch)
        else:
            for row in batch:
                conn.execute(sql, row)
        total += len(batch)
    return total


def _assert_allowed_entity_types(entity_types: set[str] | None) -> None:
    if not entity_types:
        return
    invalid = sorted(entity_types - _ALLOWED_ENTITY_TYPES)
    if invalid:
        raise ValueError(f"Unsupported graph entity type: {invalid[0]}")


def _digest_payload(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _decode_json_object(value: Any, *, field: str = "snapshot") -> dict[str, Any]:
    """Decode a JSON object from either TEXT or psycopg's native JSONB value."""
    if value is None or value == "" or value == b"":
        return {}
    decoded = json.loads(value) if isinstance(value, (str, bytes, bytearray)) else value
    if not isinstance(decoded, Mapping):
        raise ValueError(f"Persisted graph {field} JSON must be an object")
    return dict(decoded)


def _decode_json_array(value: Any, *, field: str) -> list[Any]:
    """Decode a JSON array from either TEXT or psycopg's native JSONB value."""
    if value is None or value == "" or value == b"":
        return []
    decoded = json.loads(value) if isinstance(value, (str, bytes, bytearray)) else value
    if not isinstance(decoded, list):
        raise ValueError(f"Persisted graph {field} JSON must be an array")
    return list(decoded)


_CORRELATION_RUN_COLUMNS = """
    correlation_id, tenant_id, idempotency_key, name, status,
    max_age_hours, allow_stale, input_manifest, manifest_sha256, result_manifest,
    output_scan_id, failure_code, created_at, started_at, completed_at,
    execution_owner, execution_lease_expires_at
"""


def _correlation_run_from_row(row: Sequence[Any]) -> GraphCorrelationRun:
    return GraphCorrelationRun.from_mapping(
        {
            "correlation_id": row[0],
            "tenant_id": row[1],
            "idempotency_key": row[2],
            "name": row[3],
            "status": row[4],
            "max_age_hours": row[5],
            "allow_stale": bool(row[6]),
            "input_manifest": _decode_json_array(row[7], field="input_manifest"),
            "manifest_sha256": row[8],
            "result_manifest": _decode_json_object(row[9], field="result_manifest"),
            "output_scan_id": row[10],
            "failure_code": row[11],
            "created_at": row[12],
            "started_at": row[13],
            "completed_at": row[14],
            "execution_owner": row[15],
            "execution_lease_expires_at": row[16],
        }
    )


def _diff_summary_counts(diff: dict[str, Any]) -> dict[str, int]:
    return {
        "nodes_added": len(diff.get("nodes_added") or []),
        "nodes_removed": len(diff.get("nodes_removed") or []),
        "nodes_changed": len(diff.get("nodes_changed") or []),
        "edges_added": len(diff.get("edges_added") or []),
        "edges_removed": len(diff.get("edges_removed") or []),
        "edges_changed": len(diff.get("edges_changed") or []),
    }


def _backfill_empty_tenant_ids(conn: Any) -> None:
    for table, key_columns in _GRAPH_TENANT_TABLE_KEYS.items():
        key_match = " AND ".join(f"existing.{column} = legacy.{column}" for column in key_columns)
        conn.execute(
            f"""
            DELETE FROM {table} legacy
            WHERE legacy.tenant_id = ''
              AND EXISTS (
                SELECT 1
                FROM {table} existing
                WHERE existing.tenant_id = %s
                  AND {key_match}
              )
            """,  # nosec B608 - table/key names are static internal schema metadata
            (DEFAULT_GRAPH_TENANT_ID,),
        )
        conn.execute(
            f"UPDATE {table} SET tenant_id = %s WHERE tenant_id = ''",  # nosec B608 - table names are static internal schema metadata
            (DEFAULT_GRAPH_TENANT_ID,),
        )


class PostgresGraphStoreBase:
    """Shared state and cross-mixin hooks of ``PostgresGraphStore``.

    The concrete store sets the pools and implements the hooks; the
    ``TYPE_CHECKING`` declarations only let each mixin type-check its calls
    into sibling mixins without changing runtime method resolution.
    """

    _pool: Any
    _maintenance_pool: Any

    if TYPE_CHECKING:

        def _search_timeout_ms(self) -> int: ...

        def _apply_search_timeout(self, conn: Any) -> None: ...

        def save_graph_streaming(
            self,
            *,
            scan_id: str,
            tenant_id: str = "",
            nodes: Iterable[Any],
            edges: Iterable[Any],
            attack_paths: Iterable[Any] = (),
            interaction_risks: Iterable[Any] = (),
            analysis_status: Mapping[str, GraphAnalysisStatus] | None = None,
            created_at: str = "",
            snapshot_kind: str = "scan",
            correlation_id: str = "",
            evidence_manifest_sha256: str = "",
            write_generation: str = "",
            correlation_result_manifest: Mapping[str, Any] | None = None,
            correlation_completed_at: str = "",
            correlation_execution_owner: str = "",
        ) -> dict[str, int]: ...

        def _walk_graph(
            self,
            conn: Any,
            *,
            tenant_id: str,
            scan_id: str,
            roots: list[str],
            direction: str,
            max_depth: int,
            max_nodes: int,
            max_edges: int,
            deadline_monotonic: float | None,
            traversable_only: bool,
            relationship_types: set[RelationshipType] | None,
            static_only: bool,
            dynamic_only: bool,
            include_roots: bool,
        ) -> tuple[str, str, set[str], dict[str, int], dict[tuple[str, str, str], Any], dict[str, str], list[str], bool, bool]: ...

        def _snapshot_digests(self, conn: Any, *, tenant_id: str, scan_id: str) -> tuple[str, str, dict[str, int]]: ...
