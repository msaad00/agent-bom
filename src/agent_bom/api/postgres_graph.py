"""PostgreSQL-backed graph and cache stores.

The store is composed from cohesive mixins (snapshots, history, correlation,
traversal, attack paths, paged queries); this module keeps the write path,
schema bootstrap and the heavy read paths, and re-exports every name callers
and tests import or patch."""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Iterable, Mapping

if TYPE_CHECKING:
    from agent_bom.graph import RelationshipType, UnifiedGraph, UnifiedNode

from agent_bom.api.graph_store import (
    _assert_offset_within_cap,
    _escape_like_query,
    decode_graph_cursor,
    encode_graph_cursor,
)
from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.config import POSTGRES_GRAPH_SEARCH_TIMEOUT_MS, POSTGRES_STATEMENT_TIMEOUT_MS
from agent_bom.db.graph_revision import ensure_postgres_read_revision, revision_tokens
from agent_bom.db.graph_store import (
    normalize_graph_tenant_id,
)
from agent_bom.graph import technique_mappings_from_json
from agent_bom.graph.analysis import GraphAnalysisStatus, analysis_status_map_from_dict, analysis_status_map_to_dict
from agent_bom.graph.completeness import (
    COMPLIANCE_NODE_BUDGET,
    graph_completeness,
)
from agent_bom.graph.observation_scope import comparable_observation_sql
from agent_bom.graph.severity_floor import severity_floor_sql

from .postgres_common import (
    _apply_tenant_session,
    _ensure_tenant_rls,
    _get_pool,
    _maintenance_connection,
    _tenant_connection,
    bypass_tenant_rls,
)
from .postgres_graph_correlation import PostgresGraphCorrelationMixin
from .postgres_graph_history import PostgresGraphHistoryMixin
from .postgres_graph_inventory import PostgresGraphInventoryMixin
from .postgres_graph_paths import PostgresGraphPathsMixin
from .postgres_graph_schema import _GRAPH_TABLES_DDL, _GRAPH_TABLES_MIGRATION_DDL
from .postgres_graph_support import (
    _ALLOWED_ENTITY_TYPES,
    _DB_LEASE_ISO,
    _DB_NOW_ISO,
    _DEFAULT_GRAPH_WRITE_BATCH_SIZE,
    _FINDING_ENTITY_TYPES,
    _GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS,
    _GRAPH_EVIDENCE_INCLUDED_TABLES,
    _GRAPH_RETENTION_PURGE_TABLES,
    _GRAPH_STORAGE_SCHEMA_VERSION,
    _GRAPH_TENANT_TABLE_KEYS,
    _assert_allowed_entity_types,
    _backfill_empty_tenant_ids,
    _batched_rows,
    _decode_json_array,
    _decode_json_object,
    _diff_summary_counts,
    _digest_payload,
    _execute_many_batched,
    select_expired_snapshot_ids,
)
from .postgres_graph_write import (
    _ATTACK_PATH_UPSERT_SQL,
    _INTERACTION_RISK_UPSERT_SQL,
    _SNAPSHOT_UPSERT_SQL,
    _attack_path_rows,
    _complete_correlation_in_write,
    _edge_rows,
    _edge_upsert_sql,
    _interaction_risk_rows,
    _reserve_snapshot,
    _write_nodes,
)
from .postgres_scan_cache import PostgresScanCache

logger = logging.getLogger(__name__)


def _graph_write_batch_size() -> int:
    raw = os.environ.get("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", str(_DEFAULT_GRAPH_WRITE_BATCH_SIZE))
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_GRAPH_WRITE_BATCH_SIZE


def _graph_search_timeout_ms() -> int:
    """Return the per-query Postgres graph search timeout.

    The graph search budget is allowed to be lower than the general Postgres
    statement timeout, but not higher. Operators can disable the search-specific
    timeout by setting it to 0.
    """
    if POSTGRES_GRAPH_SEARCH_TIMEOUT_MS <= 0:
        return 0
    if POSTGRES_STATEMENT_TIMEOUT_MS <= 0:
        return max(1, POSTGRES_GRAPH_SEARCH_TIMEOUT_MS)
    return max(1, min(POSTGRES_GRAPH_SEARCH_TIMEOUT_MS, POSTGRES_STATEMENT_TIMEOUT_MS))


def _apply_graph_search_timeout(conn: Any) -> None:
    timeout_ms = _graph_search_timeout_ms()
    if timeout_ms > 0:
        conn.execute("SELECT set_config('statement_timeout', %s, true)", (str(timeout_ms),))


__all__ = [
    "PostgresGraphStore",
    "PostgresScanCache",
    "_ALLOWED_ENTITY_TYPES",
    "_DB_LEASE_ISO",
    "_DB_NOW_ISO",
    "_GRAPH_EVIDENCE_EXCLUDED_PRIVATE_FIELDS",
    "_GRAPH_EVIDENCE_INCLUDED_TABLES",
    "_GRAPH_RETENTION_PURGE_TABLES",
    "_GRAPH_TENANT_TABLE_KEYS",
    "_batched_rows",
    "_diff_summary_counts",
    "select_expired_snapshot_ids",
]


class PostgresGraphStore(
    PostgresGraphPathsMixin,
    PostgresGraphInventoryMixin,
    PostgresGraphHistoryMixin,
    PostgresGraphCorrelationMixin,
):
    """PostgreSQL-backed unified graph persistence and query store."""

    @staticmethod
    def _search_timeout_ms() -> int:
        # Resolved through this module so patched timeout settings apply to every mixin.
        return _graph_search_timeout_ms()

    @staticmethod
    def _apply_search_timeout(conn: Any) -> None:
        _apply_graph_search_timeout(conn)

    def __init__(self, pool: Any = None, maintenance_pool: Any = None) -> None:
        self._pool = pool or _get_pool()
        self._maintenance_pool = maintenance_pool
        self._init_tables()

    def check_readiness(self) -> None:
        """Probe graph tables without loading rows or migrating on every check."""
        with self._pool.connection() as conn:
            conn.execute("SET LOCAL statement_timeout = '1000ms'")
            conn.execute("SELECT scan_id, tenant_id FROM graph_snapshots LIMIT 0")
            conn.execute("SELECT id, tenant_id FROM graph_nodes LIMIT 0")
            conn.execute("SELECT source_id, target_id, tenant_id FROM graph_edges LIMIT 0")

    def _init_tables(self) -> None:
        with self._pool.connection() as conn:
            if not ensure_postgres_schema_version(conn, "graph", _GRAPH_STORAGE_SCHEMA_VERSION):
                return
            for statement in _GRAPH_TABLES_DDL:
                conn.execute(statement)
            # Additive and nullable, matching the SQLite column: snapshots written
            # before it existed read NULL and fall back to the live GROUP BY.
            ensure_postgres_read_revision(conn)
            for statement in _GRAPH_TABLES_MIGRATION_DDL:
                conn.execute(statement)
            # Make the DDL visible before the separate maintenance principal
            # repairs legacy empty tenant ids. The app connection is never
            # elevated; only the dedicated marker-bearing login can activate
            # the scoped bypass.
            conn.commit()
            with bypass_tenant_rls(audit=False), _maintenance_connection(self._maintenance_pool) as maintenance_conn:
                _backfill_empty_tenant_ids(maintenance_conn)
                maintenance_conn.execute(
                    "UPDATE graph_snapshots SET snapshot_generation = replace(gen_random_uuid()::text, '-', '') "
                    "WHERE snapshot_generation = ''"
                )
                maintenance_conn.commit()
            _apply_tenant_session(conn)
            _ensure_tenant_rls(conn, "graph_nodes", "tenant_id")
            _ensure_tenant_rls(conn, "graph_edges", "tenant_id")
            _ensure_tenant_rls(conn, "graph_snapshots", "tenant_id")
            _ensure_tenant_rls(conn, "graph_correlation_runs", "tenant_id")
            _ensure_tenant_rls(conn, "attack_paths", "tenant_id")
            _ensure_tenant_rls(conn, "interaction_risks", "tenant_id")
            _ensure_tenant_rls(conn, "graph_filter_presets", "tenant_id")
            _ensure_tenant_rls(conn, "graph_node_search", "tenant_id")
            _ensure_tenant_rls(conn, "graph_build_workspace_nodes", "tenant_id")
            _ensure_tenant_rls(conn, "graph_build_workspace_edges", "tenant_id")
            conn.commit()
        self._init_optional_search_indexes()

    def _init_optional_search_indexes(self) -> None:
        """Install optional trigram search acceleration without risking schema bootstrap."""
        with self._pool.connection() as conn:
            try:
                conn.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_pg_graph_node_search_trgm
                    ON graph_node_search USING gin (search_text gin_trgm_ops)
                    """
                )
                conn.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_pg_graph_node_search_lower_trgm
                    ON graph_node_search USING gin (LOWER(search_text) gin_trgm_ops)
                    """
                )
                conn.commit()
            except Exception as exc:
                # Some managed Postgres environments restrict extension installs.
                conn.rollback()
                logger.warning("Skipping optional Postgres graph trigram indexes: %s", type(exc).__name__)

    def save_graph(self, graph: UnifiedGraph) -> None:
        """Persist a fully built ``UnifiedGraph`` via the streamed write path."""
        self.save_graph_streaming(
            scan_id=graph.scan_id or "",
            tenant_id=graph.tenant_id,
            nodes=graph.nodes.values(),
            edges=graph.edges,
            attack_paths=graph.attack_paths,
            interaction_risks=graph.interaction_risks,
            analysis_status=graph.analysis_status,
            created_at=graph.created_at,
        )

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
    ) -> dict[str, int]:
        """Persist a snapshot from node/edge iterables without materialising a graph.

        Bounded-memory equivalent of :meth:`save_graph` (#4055/#4075). The single
        producer over ``nodes`` is consumed exactly once and fans out to BOTH the
        ``graph_nodes`` row and its ``graph_node_search`` mirror in interleaved,
        bounded batches — so a lazy producer never needs a second pass and peak
        RSS is decoupled from graph size. Node/edge/severity tallies accumulate
        incrementally in place of ``graph.stats()`` over a materialised graph, so
        the persisted snapshot row is byte-identical to :meth:`save_graph`.
        """
        scan = scan_id or ""
        tenant = normalize_graph_tenant_id(tenant_id)
        now = created_at or datetime.now(timezone.utc).isoformat()
        if snapshot_kind not in {"scan", "correlation"}:
            raise ValueError("snapshot_kind must be 'scan' or 'correlation'")
        if snapshot_kind == "correlation" and correlation_id != scan:
            raise ValueError("correlation snapshot ID must equal correlation_id")
        batch_size = _graph_write_batch_size()

        with _tenant_connection(self._pool) as conn:
            previous_scan = _reserve_snapshot(conn, tenant=tenant, scan=scan, snapshot_kind=snapshot_kind)
            node_count, severity_counts, type_counts = _write_nodes(conn, nodes, scan=scan, tenant=tenant, batch_size=batch_size)
            edge_counter = [0]
            scope_predicate = comparable_observation_sql(dialect="postgres", previous="previous", current="incoming")
            edge_rows = _edge_rows(edges, scan=scan, tenant=tenant, now=now, previous_scan=previous_scan, counter=edge_counter)
            _execute_many_batched(conn, _edge_upsert_sql(scope_predicate), edge_rows, batch_size=batch_size)
            # Collection absence does not prove native revocation. Keep prior
            # observations intact; only source-supplied interval ends are stored.
            path_rows = _attack_path_rows(attack_paths, scan=scan, tenant=tenant, now=now)
            _execute_many_batched(conn, _ATTACK_PATH_UPSERT_SQL, path_rows, batch_size=batch_size)
            risk_rows = _interaction_risk_rows(interaction_risks, scan=scan, tenant=tenant)
            _execute_many_batched(conn, _INTERACTION_RISK_UPSERT_SQL, risk_rows, batch_size=batch_size)
            edge_count = edge_counter[0]

            conn.execute(
                _SNAPSHOT_UPSERT_SQL,
                (
                    scan,
                    tenant,
                    now,
                    node_count,
                    edge_count,
                    json.dumps(dict(severity_counts)),
                    json.dumps(dict(type_counts)),
                    json.dumps(analysis_status_map_to_dict(analysis_status or {})),
                    snapshot_kind,
                    correlation_id or None,
                    evidence_manifest_sha256,
                    *revision_tokens(write_generation),
                ),
            )
            if correlation_result_manifest is not None:
                _complete_correlation_in_write(
                    conn,
                    tenant=tenant,
                    scan=scan,
                    correlation_id=correlation_id,
                    evidence_manifest_sha256=evidence_manifest_sha256,
                    result_manifest=correlation_result_manifest,
                    completed_at=correlation_completed_at or now,
                    execution_owner=correlation_execution_owner,
                )
            conn.commit()

            # Mirror the SQLite backend's age-based retention purge so Postgres
            # snapshot history does not grow unbounded. Best-effort: a purge
            # failure must never fail the durable save that already committed.
            self._purge_expired_snapshots(conn, tenant)

            # Planner statistics are maintained by PostgreSQL autovacuum and a
            # separately privileged maintenance job; the application role is
            # DML-only, so ANALYZE is never issued from here.

        return {"nodes": node_count, "edges": edge_count}

    def load_graph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        relationship_types: frozenset[str] | None = None,
        node_budget: int | None = None,
    ) -> UnifiedGraph:
        """Materialize a snapshot.

        ``node_budget`` caps how many nodes are read. It defaults to unbounded
        because callers that compute differences (snapshot diff, compare) are
        only correct on a whole graph — a trimmed one reads as deletions that
        never happened. Read paths that only display a graph pass a budget and
        surface ``graph.completeness`` so a trimmed view is never mistaken for
        a small one. When a budget applies, the highest-risk nodes are kept.
        """
        tenant_id = normalize_graph_tenant_id(tenant_id)
        _assert_allowed_entity_types(entity_types)
        from agent_bom.graph import (
            AttackPath,
            InteractionRisk,
            RelationshipType,
            UnifiedEdge,
            UnifiedGraph,
        )
        from agent_bom.graph.container import GraphCompleteness, resolve_node_budget

        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)

        with _tenant_connection(self._pool) as conn:
            snapshot_row = conn.execute(
                "SELECT created_at, analysis_status FROM graph_snapshots WHERE scan_id = %s AND tenant_id = %s",
                (effective_scan_id, tenant_id),
            ).fetchone()
            graph = UnifiedGraph(scan_id=effective_scan_id, tenant_id=tenant_id, created_at=str(snapshot_row[0]) if snapshot_row else "")
            if snapshot_row:
                graph.analysis_status = analysis_status_map_from_dict(_decode_json_object(snapshot_row[1]))

            query = (
                "SELECT id, entity_type, label, category_uid, class_uid, type_uid, status, risk_score, severity, severity_id, "
                "first_seen, last_seen, attributes, compliance_tags, data_sources, dimensions "
                "FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s"
            )
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join(["%s"] * len(entity_types))
                query += f" AND entity_type IN ({placeholders})"
                params.extend(sorted(entity_types))
            # The floor belongs in the WHERE clause, not after the LIMIT: a
            # post-filter both deletes the topology the findings hang off and
            # spends the budget on rows it then discards, so the page comes back
            # short of its own budget and `total` counts a different population.
            sev_sql, sev_params = severity_floor_sql(min_severity_rank, placeholder="%s")
            if sev_sql:
                query += f" AND {sev_sql}"
                params.extend(sev_params)

            budget = resolve_node_budget(node_budget)
            total_nodes = 0
            if budget is not None:
                count_query = query.replace(
                    "SELECT id, entity_type, label, category_uid, class_uid, type_uid, status, risk_score, severity, severity_id, "
                    "first_seen, last_seen, attributes, compliance_tags, data_sources, dimensions ",
                    "SELECT COUNT(*) ",
                    1,
                )
                count_row = conn.execute(count_query, params).fetchone()
                total_nodes = int(count_row[0]) if count_row else 0
                # Risk-ranked so a trimmed view keeps what matters, not an
                # arbitrary slice; id breaks ties so paging stays deterministic.
                query += " ORDER BY risk_score DESC NULLS LAST, id LIMIT %s"
                params.append(budget)
            else:
                query += " ORDER BY id"

            node_ids: set[str] = set()
            for row in conn.execute(query, params).fetchall():
                graph.add_node(self._node_from_row(row))
                node_ids.add(row[0])

            returned_nodes = len(node_ids)
            if budget is None:
                total_nodes = returned_nodes
            graph.completeness = GraphCompleteness(
                truncated=budget is not None and total_nodes > returned_nodes,
                node_budget=budget,
                total_nodes=total_nodes,
                returned_nodes=returned_nodes,
                reason="node_budget" if budget is not None and total_nodes > returned_nodes else "",
            )

            edge_query = """
                SELECT source_id, target_id, relationship, direction, weight, traversable,
                       first_seen, last_seen, valid_from, valid_to, confidence, provenance,
                       source_scan_id, source_run_id, evidence, activity_id, scan_id
                FROM graph_edges
                WHERE tenant_id = %s AND scan_id = %s
            """
            edge_params: list[Any] = [tenant_id, effective_scan_id]
            if relationship_types:
                placeholders = ",".join(["%s"] * len(relationship_types))
                edge_query += f" AND relationship IN ({placeholders})"
                edge_params.extend(sorted(relationship_types))
            edge_query += " ORDER BY source_id, target_id, relationship, source_run_id NULLS FIRST, activity_id NULLS FIRST"

            for row in conn.execute(edge_query, edge_params).fetchall():
                if row[0] not in node_ids or row[1] not in node_ids:
                    continue
                graph.add_edge(
                    UnifiedEdge(
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
                )

            if not relationship_types:
                for row in conn.execute(
                    """
                    SELECT source_node, target_node, path_nodes, path_edges, composite_risk,
                           summary, credential_exposure, tool_exposure, vuln_ids,
                           reachability, reachability_basis, technique_mappings,
                           hop_evidence, analysis
                    FROM attack_paths
                    WHERE tenant_id = %s AND scan_id = %s
                    ORDER BY source_node, target_node, composite_risk DESC, path_nodes
                    """,
                    (tenant_id, effective_scan_id),
                ).fetchall():
                    graph.attack_paths.append(
                        AttackPath(
                            source=row[0],
                            target=row[1],
                            hops=_decode_json_array(row[2], field="attack path nodes"),
                            edges=_decode_json_array(row[3], field="attack path edges"),
                            composite_risk=row[4],
                            summary=row[5] or "",
                            credential_exposure=_decode_json_array(row[6], field="attack path credential exposure"),
                            tool_exposure=_decode_json_array(row[7], field="attack path tool exposure"),
                            vuln_ids=_decode_json_array(row[8], field="attack path vulnerability IDs"),
                            reachability=row[9] or "unknown",
                            reachability_basis=_decode_json_array(row[10], field="attack path reachability basis"),
                            hop_evidence=[
                                dict(item)
                                for item in _decode_json_array(row[12], field="attack path hop evidence")
                                if isinstance(item, dict)
                            ],
                            analysis=_decode_json_object(row[13], field="attack path analysis"),
                            technique_mappings=technique_mappings_from_json(row[11]),
                        )
                    )

                for row in conn.execute(
                    """
                    SELECT pattern, agents, risk_score, description, owasp_agentic_tag
                    FROM interaction_risks
                    WHERE tenant_id = %s AND scan_id = %s
                    ORDER BY pattern, agents
                    """,
                    (tenant_id, effective_scan_id),
                ).fetchall():
                    graph.interaction_risks.append(
                        InteractionRisk(
                            pattern=row[0],
                            agents=_decode_json_array(row[1], field="interaction risk agents"),
                            risk_score=row[2],
                            description=row[3],
                            owasp_agentic_tag=row[4],
                        )
                    )

            return graph

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
    ) -> tuple[str, str, set[str], dict[str, int], dict[tuple[str, str, str], Any], dict[str, str], list[str], bool, bool]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        effective_scan_id = scan_id
        if not effective_scan_id:
            latest = conn.execute(
                """
                SELECT scan_id
                FROM graph_snapshots
                WHERE tenant_id = %s
                ORDER BY created_at DESC, scan_id DESC
                LIMIT 1
                """,
                (tenant_id,),
            ).fetchone()
            effective_scan_id = str(latest[0]) if latest else ""
        if not effective_scan_id:
            return scan_id, "", set(), {}, {}, {}, [], False, False
        snapshot = conn.execute(
            "SELECT created_at FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
            (tenant_id, effective_scan_id),
        ).fetchone()
        placeholders = ",".join("%s" for _ in roots)
        existing_roots: set[str] = set()
        if roots:
            existing_roots = {
                str(row[0])
                for row in conn.execute(
                    f"SELECT id FROM graph_nodes WHERE tenant_id = %s AND scan_id = %s AND id IN ({placeholders})",  # nosec B608
                    [tenant_id, effective_scan_id, *roots],
                ).fetchall()
            }

        visited: set[str] = set()
        depth_by_node: dict[str, int] = {}
        traversed_edges: dict[tuple[str, str, str], Any] = {}
        parent_by_node: dict[str, str] = {}
        discovery_order: list[str] = []
        queue: list[tuple[str, int]] = []
        for root in roots:
            if root not in existing_roots:
                continue
            queue.append((root, 0))
            depth_by_node[root] = 0
            if include_roots:
                visited.add(root)

        truncated = False
        depth_limited = False
        edge_count = 0

        def _neighbors(node_id: str) -> list[str]:
            found: list[str] = []
            neighbor_rows, _hit = self._filtered_edge_rows(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                frontier={node_id},
                traversable_only=traversable_only,
                relationship_types=relationship_types,
                static_only=static_only,
                dynamic_only=dynamic_only,
                limit=max_edges,
            )
            for neighbor_row in neighbor_rows:
                edge = self._edge_from_row(neighbor_row)
                if direction in {"forward", "both"}:
                    if edge.source == node_id:
                        found.append(edge.target)
                    elif edge.is_bidirectional and edge.target == node_id:
                        found.append(edge.source)
                if direction in {"reverse", "both"}:
                    if edge.target == node_id:
                        found.append(edge.source)
                    elif edge.is_bidirectional and edge.source == node_id:
                        found.append(edge.target)
            return found

        index = 0
        while index < len(queue):
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                truncated = True
                break
            current, depth = queue[index]
            index += 1
            if depth >= max_depth:
                # Frontier node: only a *demonstrably* unwalked neighbour makes
                # this an incomplete answer. Costs one edge lookup per frontier
                # node, and only until the first one that leaves work behind.
                if not depth_limited and any(neighbor not in visited for neighbor in _neighbors(current)):
                    depth_limited = True
                continue
            rows, hit_limit = self._filtered_edge_rows(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                frontier={current},
                traversable_only=traversable_only,
                relationship_types=relationship_types,
                static_only=static_only,
                dynamic_only=dynamic_only,
                limit=max_edges - edge_count + 1,
            )
            if hit_limit:
                truncated = True
            for row in rows:
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
                edge_count += 1
                if edge_count > max_edges:
                    truncated = True
                    break
                relationship = edge.relationship.value if hasattr(edge.relationship, "value") else str(edge.relationship)
                traversed_edges.setdefault((edge.source, edge.target, relationship), edge)
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
            if hit_limit:
                break
            if truncated and (edge_count > max_edges or (deadline_monotonic is not None and time.monotonic() >= deadline_monotonic)):
                break

        if include_roots:
            visited.update(existing_roots)
        return (
            effective_scan_id,
            str(snapshot[0]) if snapshot else "",
            visited,
            depth_by_node,
            traversed_edges,
            parent_by_node,
            discovery_order,
            truncated,
            depth_limited,
        )

    def compliance_summary(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        framework: str = "",
    ) -> dict[str, Any]:
        tenant_id = normalize_graph_tenant_id(tenant_id)
        from collections import defaultdict

        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return {
                "scan_id": scan_id,
                "framework_count": 0,
                "total_tagged_findings": 0,
                "frameworks": {},
                "completeness": {
                    **graph_completeness(returned=0),
                    "node_budget": COMPLIANCE_NODE_BUDGET,
                },
            }
        compliance_node_budget = COMPLIANCE_NODE_BUDGET
        with _tenant_connection(self._pool) as conn:
            _apply_graph_search_timeout(conn)
            rows = conn.execute(
                """
                SELECT id, entity_type, severity, compliance_tags
                FROM graph_nodes
                WHERE tenant_id = %s AND scan_id = %s
                  AND compliance_tags IS NOT NULL
                  AND compliance_tags <> '[]'
                ORDER BY id
                LIMIT %s
                """,
                (tenant_id, effective_scan_id, compliance_node_budget + 1),
            ).fetchall()
        truncated = len(rows) > compliance_node_budget
        framework_stats: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "total_findings": 0,
                "by_severity": defaultdict(int),
                "by_entity_type": defaultdict(int),
                "tags": set(),
                "node_ids": [],
            }
        )

        for row in rows[:compliance_node_budget]:
            tags = _decode_json_array(row[3], field="node compliance tags")
            if not tags:
                continue
            for tag_value in tags:
                tag = str(tag_value)
                prefix = tag.split("-")[0].upper() if "-" in tag else tag.upper()
                if framework and framework.upper() != prefix:
                    continue
                stats = framework_stats[prefix]
                stats["total_findings"] += 1
                stats["by_severity"][row[2] or "unknown"] += 1
                stats["by_entity_type"][str(row[1])] += 1
                stats["tags"].add(tag)
                if row[0] not in stats["node_ids"]:
                    stats["node_ids"].append(row[0])

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
            "completeness": {
                **graph_completeness(
                    returned=min(len(rows), compliance_node_budget),
                    truncated=truncated,
                    reason="node_budget" if truncated else "",
                ),
                "node_budget": compliance_node_budget,
            },
        }

    def _snapshot_digests(self, conn: Any, *, tenant_id: str, scan_id: str) -> tuple[str, str, dict[str, int]]:
        graph_rows: dict[str, list[dict[str, Any]]] = {"nodes": [], "edges": []}
        finding_rows: dict[str, list[dict[str, Any]]] = {"findings": [], "attack_paths": [], "compliance": []}

        for row in conn.execute(
            """
            SELECT id, entity_type, label, status, severity, severity_id, risk_score,
                   compliance_tags, data_sources
            FROM graph_nodes
            WHERE tenant_id = %s AND scan_id = %s
            ORDER BY id
            """,
            (tenant_id, scan_id),
        ).fetchall():
            node = {
                "id": row[0],
                "entity_type": row[1],
                "label": row[2],
                "status": row[3],
                "severity": row[4] or "",
                "severity_id": int(row[5] or 0),
                "risk_score": float(row[6] or 0.0),
                "compliance_tags": _decode_json_array(row[7], field="node compliance tags"),
                "data_sources": _decode_json_array(row[8], field="node data sources"),
            }
            graph_rows["nodes"].append(node)
            if row[1] in _FINDING_ENTITY_TYPES:
                finding_rows["findings"].append(node)
            for tag in node["compliance_tags"]:
                finding_rows["compliance"].append({"node_id": row[0], "tag": tag})

        for row in conn.execute(
            """
            SELECT source_id, target_id, relationship, direction, weight, traversable,
                   valid_from, valid_to, confidence, activity_id
            FROM graph_edges
            WHERE tenant_id = %s AND scan_id = %s
            ORDER BY source_id, target_id, relationship
            """,
            (tenant_id, scan_id),
        ).fetchall():
            graph_rows["edges"].append(
                {
                    "source_id": row[0],
                    "target_id": row[1],
                    "relationship": row[2],
                    "direction": row[3],
                    "weight": float(row[4] or 0.0),
                    "traversable": bool(row[5]),
                    "valid_from": row[6] or "",
                    "valid_to": row[7] or "",
                    "confidence": float(row[8] if row[8] is not None else 1.0),
                    "activity_id": int(row[9] or 1),
                }
            )

        for row in conn.execute(
            """
            SELECT source_node, target_node, hop_count, composite_risk, summary,
                   path_nodes, path_edges, credential_exposure, tool_exposure, vuln_ids,
                   reachability, reachability_basis, technique_mappings, hop_evidence, analysis
            FROM attack_paths
            WHERE tenant_id = %s AND scan_id = %s
            ORDER BY source_node, target_node
            """,
            (tenant_id, scan_id),
        ).fetchall():
            finding_rows["attack_paths"].append(
                {
                    "source_node": row[0],
                    "target_node": row[1],
                    "hop_count": int(row[2] or 0),
                    "composite_risk": float(row[3] or 0.0),
                    "summary": row[4] or "",
                    "path_nodes": _decode_json_array(row[5], field="attack path nodes"),
                    "path_edges": _decode_json_array(row[6], field="attack path edges"),
                    "credential_exposure": _decode_json_array(row[7], field="attack path credential exposure"),
                    "tool_exposure": _decode_json_array(row[8], field="attack path tool exposure"),
                    "vuln_ids": _decode_json_array(row[9], field="attack path vulnerability IDs"),
                    "reachability": row[10] or "unknown",
                    "reachability_basis": _decode_json_array(row[11], field="attack path reachability basis"),
                    "technique_mappings": _decode_json_array(row[12], field="attack path technique mappings"),
                    "hop_evidence": _decode_json_array(row[13], field="attack path hop evidence"),
                    "analysis": _decode_json_object(row[14], field="attack path analysis"),
                }
            )

        counts = {
            "nodes": len(graph_rows["nodes"]),
            "edges": len(graph_rows["edges"]),
            "findings": len(finding_rows["findings"]),
            "attack_paths": len(finding_rows["attack_paths"]),
            "compliance_tags": len(finding_rows["compliance"]),
        }
        return _digest_payload(graph_rows), _digest_payload(finding_rows), counts

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
        tenant_id = normalize_graph_tenant_id(tenant_id)
        _assert_allowed_entity_types(entity_types)
        _assert_offset_within_cap(offset, cursor)
        effective_scan_id = scan_id or self.latest_snapshot_id(tenant_id=tenant_id)
        if not effective_scan_id:
            return [], 0, None

        with _tenant_connection(self._pool) as conn:
            _apply_graph_search_timeout(conn)
            search_where = [
                "gns.tenant_id = %s",
                "gns.scan_id = %s",
                "gns.search_text LIKE %s ESCAPE '\\'",
            ]
            params: list[Any] = [tenant_id, effective_scan_id, f"%{_escape_like_query(query.lower())}%"]
            if entity_types:
                placeholders = ",".join(["%s"] * len(entity_types))
                search_where.append(f"gn.entity_type IN ({placeholders})")
                params.extend(sorted(entity_types))
            sev_sql, sev_params = severity_floor_sql(
                min_severity_rank, column="gn.severity_id", entity_column="gn.entity_type", placeholder="%s"
            )
            if sev_sql:
                search_where.append(sev_sql)
                params.extend(sev_params)
            if compliance_prefixes:
                prefix_filters = []
                for prefix in sorted(compliance_prefixes):
                    clause, clause_params = self._compliance_prefix_filter("gns.compliance_tags", prefix)
                    prefix_filters.append(clause)
                    params.extend(clause_params)
                search_where.append("(" + " OR ".join(prefix_filters) + ")")
            if data_sources:
                source_filters = []
                for source in sorted(data_sources):
                    clause, clause_params = self._space_token_filter("gns.data_sources", source)
                    source_filters.append(clause)
                    params.extend(clause_params)
                search_where.append("(" + " OR ".join(source_filters) + ")")
            from_clause = """
                FROM graph_node_search gns
                JOIN graph_nodes gn
                  ON gn.id = gns.node_id
                 AND gn.scan_id = gns.scan_id
                 AND gn.tenant_id = gns.tenant_id
            """
            where_sql = " AND ".join(search_where)
            total_row = conn.execute("SELECT COUNT(*) " + from_clause + " WHERE " + where_sql, params).fetchone()
            total = int((total_row[0] if total_row else 0) or 0)
            if total == 0:
                return [], 0, None
            row_params = list(params)
            cursor_clause = ""
            if cursor:
                severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                cursor_clause = """
                AND (
                    gn.severity_id < %s
                    OR (gn.severity_id = %s AND gn.risk_score < %s)
                    OR (gn.severity_id = %s AND gn.risk_score = %s AND gn.label > %s)
                    OR (gn.severity_id = %s AND gn.risk_score = %s AND gn.label = %s AND gn.id > %s)
                )
                """
                row_params.extend(
                    [severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id]
                )
            rows = conn.execute(
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
                + " ORDER BY gn.severity_id DESC, gn.risk_score DESC, gn.label ASC, gn.id ASC LIMIT %s OFFSET %s",
                [*row_params, limit + 1 if cursor else limit, 0 if cursor else offset],
            ).fetchall()
            has_more = len(rows) > limit if cursor else offset + limit < total
            rows = rows[:limit]
            nodes = [self._node_from_row(row) for row in rows]
            next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None
            return nodes, total, next_cursor
