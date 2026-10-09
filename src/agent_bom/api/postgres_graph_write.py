"""Streamed snapshot write path for the Postgres graph store.

Each helper owns one phase of :meth:`PostgresGraphStore.save_graph_streaming`
so the single transaction reads top to bottom: reserve the snapshot identity,
stream nodes, edges, attack paths and interaction risks in bounded batches,
then upsert the snapshot tally and (for correlations) complete the run.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Iterable, Iterator, Mapping

from agent_bom.api.graph_store import _node_search_text
from agent_bom.graph import RelationshipType
from agent_bom.graph.correlation import CorrelationRunStatus, validate_correlation_update

from .postgres_graph_support import _CORRELATION_RUN_COLUMNS, _correlation_run_from_row, _execute_many_batched

_NODE_UPSERT_SQL = """
            INSERT INTO graph_nodes (
                id, entity_type, label, category_uid, class_uid, type_uid,
                status, risk_score, severity, severity_id,
                first_seen, last_seen, attributes, compliance_tags,
                data_sources, dimensions, scan_id, tenant_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id, scan_id, tenant_id) DO UPDATE SET
                entity_type = EXCLUDED.entity_type,
                label = EXCLUDED.label,
                category_uid = EXCLUDED.category_uid,
                class_uid = EXCLUDED.class_uid,
                type_uid = EXCLUDED.type_uid,
                status = EXCLUDED.status,
                risk_score = EXCLUDED.risk_score,
                severity = EXCLUDED.severity,
                severity_id = EXCLUDED.severity_id,
                first_seen = EXCLUDED.first_seen,
                last_seen = EXCLUDED.last_seen,
                attributes = EXCLUDED.attributes,
                compliance_tags = EXCLUDED.compliance_tags,
                data_sources = EXCLUDED.data_sources,
                dimensions = EXCLUDED.dimensions
            """

_NODE_SEARCH_UPSERT_SQL = """
            INSERT INTO graph_node_search (
                node_id, tenant_id, scan_id, entity_type, severity, compliance_tags, data_sources, search_text
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (node_id, scan_id, tenant_id) DO UPDATE SET
                entity_type = EXCLUDED.entity_type,
                severity = EXCLUDED.severity,
                compliance_tags = EXCLUDED.compliance_tags,
                data_sources = EXCLUDED.data_sources,
                search_text = EXCLUDED.search_text
            """

_ATTACK_PATH_UPSERT_SQL = """
                INSERT INTO attack_paths (
                    source_node, target_node, hop_count, composite_risk,
                    summary, path_nodes, path_edges, credential_exposure,
                    tool_exposure, vuln_ids, reachability, reachability_basis,
                    technique_mappings, hop_evidence, analysis, scan_id, tenant_id, computed_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (source_node, target_node, scan_id, tenant_id) DO UPDATE SET
                    hop_count = EXCLUDED.hop_count,
                    composite_risk = EXCLUDED.composite_risk,
                    summary = EXCLUDED.summary,
                    path_nodes = EXCLUDED.path_nodes,
                    path_edges = EXCLUDED.path_edges,
                    credential_exposure = EXCLUDED.credential_exposure,
                    tool_exposure = EXCLUDED.tool_exposure,
                    vuln_ids = EXCLUDED.vuln_ids,
                    reachability = EXCLUDED.reachability,
                    reachability_basis = EXCLUDED.reachability_basis,
                    technique_mappings = EXCLUDED.technique_mappings,
                    hop_evidence = EXCLUDED.hop_evidence,
                    analysis = EXCLUDED.analysis,
                    computed_at = EXCLUDED.computed_at
                """

_INTERACTION_RISK_UPSERT_SQL = """
                INSERT INTO interaction_risks (
                    pattern, agents, risk_score, description,
                    owasp_agentic_tag, scan_id, tenant_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (pattern, agents, scan_id, tenant_id) DO UPDATE SET
                    risk_score = EXCLUDED.risk_score,
                    description = EXCLUDED.description,
                    owasp_agentic_tag = EXCLUDED.owasp_agentic_tag
                """

_SNAPSHOT_UPSERT_SQL = """
                INSERT INTO graph_snapshots
                    (scan_id, tenant_id, created_at, node_count, edge_count, risk_summary,
                     node_type_counts, analysis_status, snapshot_kind, correlation_id,
                     evidence_manifest_sha256, snapshot_generation, read_revision)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (scan_id, tenant_id) DO UPDATE SET
                    created_at = EXCLUDED.created_at,
                    node_count = EXCLUDED.node_count,
                    edge_count = EXCLUDED.edge_count,
                    risk_summary = EXCLUDED.risk_summary,
                    node_type_counts = EXCLUDED.node_type_counts,
                    analysis_status = EXCLUDED.analysis_status,
                    snapshot_kind = EXCLUDED.snapshot_kind,
                    correlation_id = EXCLUDED.correlation_id,
                    evidence_manifest_sha256 = EXCLUDED.evidence_manifest_sha256,
                    (snapshot_generation, read_revision) = (EXCLUDED.snapshot_generation, EXCLUDED.read_revision)
                """

_COMPLETE_CORRELATION_SQL = """
                    UPDATE graph_correlation_runs
                    SET status = %s, manifest_sha256 = %s, result_manifest = %s,
                        output_scan_id = %s, failure_code = %s, completed_at = %s
                    WHERE tenant_id = %s AND correlation_id = %s AND status = %s
                      AND (%s = '' OR execution_owner = %s)
                    RETURNING correlation_id
                    """

# A scan id represents a complete immutable snapshot. A retry is a replacement,
# not a merge; these tables are cleared (children first) inside the write
# transaction before the new one-shot producers are consumed.
_SNAPSHOT_REPLACE_TABLES = (
    "graph_node_search",
    "attack_paths",
    "interaction_risks",
    "graph_edges",
    "graph_nodes",
    "graph_snapshots",
)


def _edge_upsert_sql(scope_predicate: str) -> str:
    return f"""
                INSERT INTO graph_edges (
                    source_id, target_id, relationship, direction, weight,
                    traversable, first_seen, last_seen, valid_from, valid_to,
                    confidence, provenance, source_scan_id, source_run_id,
                    evidence, activity_id, scan_id, tenant_id
                )
                SELECT
                    incoming.source_id,
                    incoming.target_id,
                    incoming.relationship,
                    incoming.direction,
                    incoming.weight,
                    incoming.traversable,
                    COALESCE(NULLIF(previous.first_seen, ''), incoming.first_seen),
                    incoming.last_seen,
                    COALESCE(
                        NULLIF(previous.valid_from, ''),
                        NULLIF(previous.first_seen, ''),
                        incoming.valid_from
                    ),
                    incoming.valid_to,
                    incoming.confidence,
                    incoming.provenance,
                    incoming.source_scan_id,
                    incoming.source_run_id,
                    incoming.evidence::jsonb,
                    incoming.activity_id,
                    incoming.scan_id,
                    incoming.tenant_id
                FROM (
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ) AS incoming (
                    source_id, target_id, relationship, direction, weight,
                    traversable, first_seen, last_seen, valid_from, valid_to,
                    confidence, provenance, source_scan_id, source_run_id,
                    evidence, activity_id, scan_id, tenant_id
                )
                LEFT JOIN graph_edges AS previous
                  ON previous.tenant_id = incoming.tenant_id
                 AND previous.scan_id = %s
                 AND previous.source_id = incoming.source_id
                 AND previous.target_id = incoming.target_id
                 AND previous.relationship = incoming.relationship
                 AND (previous.valid_to IS NULL OR previous.valid_to = '')
                 AND {scope_predicate}
                ON CONFLICT (source_id, target_id, relationship, scan_id, tenant_id) DO UPDATE SET
                    direction = EXCLUDED.direction,
                    weight = EXCLUDED.weight,
                    traversable = EXCLUDED.traversable,
                    first_seen = EXCLUDED.first_seen,
                    last_seen = EXCLUDED.last_seen,
                    valid_from = EXCLUDED.valid_from,
                    valid_to = EXCLUDED.valid_to,
                    confidence = EXCLUDED.confidence,
                    provenance = EXCLUDED.provenance,
                    source_scan_id = EXCLUDED.source_scan_id,
                    source_run_id = EXCLUDED.source_run_id,
                    evidence = EXCLUDED.evidence,
                    activity_id = EXCLUDED.activity_id
                """  # nosec B608 - static aliases and internally generated SQL predicates


def _guard_snapshot_identity(conn: Any, *, tenant: str, scan: str, snapshot_kind: str) -> None:
    # Serialize retries and concurrent writers for one logical
    # snapshot. Without a transaction-scoped lock, disjoint producers
    # can interleave their upserts and leave rows that disagree with
    # whichever graph_snapshots tally commits last.
    conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
        (f"{tenant}\x1f{scan}",),
    )
    existing_snapshot = conn.execute(
        "SELECT snapshot_kind FROM graph_snapshots WHERE tenant_id = %s AND scan_id = %s",
        (tenant, scan),
    ).fetchone()
    if existing_snapshot is not None:
        if str(existing_snapshot[0] or "scan") == "correlation":
            raise ValueError("correlation snapshot is immutable")
        if snapshot_kind == "correlation":
            raise ValueError("correlation snapshot ID collides with an existing scan")
    reserved_correlation = conn.execute(
        "SELECT correlation_id FROM graph_correlation_runs WHERE tenant_id = %s AND correlation_id = %s",
        (tenant, scan),
    ).fetchone()
    if reserved_correlation is not None and snapshot_kind != "correlation":
        raise ValueError("correlation output identifier is reserved")


def _previous_scan_id(conn: Any, *, tenant: str, scan: str) -> str | None:
    """Return the ordinary scan this write supersedes (skipping a retried ``scan``)."""
    previous_row = conn.execute(
        """
                    SELECT scan_id, created_at
                    FROM graph_snapshots
                    WHERE tenant_id = %s AND snapshot_kind = 'scan'
                    ORDER BY created_at DESC, scan_id DESC
                    LIMIT 1
                    """,
        (tenant,),
    ).fetchone()
    previous_scan = str(previous_row[0]) if previous_row else None
    if previous_row and previous_scan == scan:
        prior_row = conn.execute(
            """
                        SELECT scan_id
                        FROM graph_snapshots
                        WHERE tenant_id = %s AND snapshot_kind = 'scan' AND created_at < %s
                        ORDER BY created_at DESC, scan_id DESC
                        LIMIT 1
                        """,
            (tenant, previous_row[1]),
        ).fetchone()
        previous_scan = str(prior_row[0]) if prior_row else None
    return previous_scan


def _reserve_snapshot(conn: Any, *, tenant: str, scan: str, snapshot_kind: str) -> str | None:
    """Lock and validate the snapshot identity, clear a retried scan, return its predecessor."""
    _guard_snapshot_identity(conn, tenant=tenant, scan=scan, snapshot_kind=snapshot_kind)
    # Only ordinary scans advance ordinary scan history. Derived
    # correlations preserve their source observations and remain
    # immutable when later scans (or scan retries) are persisted.
    previous_scan: str | None = None
    if snapshot_kind == "scan":
        previous_scan = _previous_scan_id(conn, tenant=tenant, scan=scan)
    for table in _SNAPSHOT_REPLACE_TABLES:
        conn.execute(
            f"DELETE FROM {table} WHERE tenant_id = %s AND scan_id = %s",  # nosec B608 - static table list
            (tenant, scan),
        )
    return previous_scan


def _node_row(node: Any, *, scan: str, tenant: str) -> tuple[Any, ...]:
    et = node.entity_type.value if hasattr(node.entity_type, "value") else node.entity_type
    return (
        node.id,
        et,
        node.label,
        node.category_uid,
        node.class_uid,
        node.type_uid,
        node.status.value if hasattr(node.status, "value") else node.status,
        node.risk_score,
        node.severity,
        node.severity_id,
        node.first_seen,
        node.last_seen,
        json.dumps(node.attributes, default=str),
        json.dumps(node.compliance_tags),
        json.dumps(node.data_sources),
        json.dumps(node.dimensions.to_dict()),
        scan,
        tenant,
    )


def _node_search_row(node: Any, *, scan: str, tenant: str) -> tuple[Any, ...]:
    et_search = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
    return (
        node.id,
        tenant,
        scan,
        et_search,
        (node.severity or "").lower(),
        " ".join(node.compliance_tags).lower(),
        " ".join(node.data_sources).lower(),
        _node_search_text(node),
    )


def _write_nodes(conn: Any, nodes: Iterable[Any], *, scan: str, tenant: str, batch_size: int) -> tuple[int, dict[str, int], dict[str, int]]:
    """Stream nodes and their search mirror in one pass; return count, severity and type tallies.

    The producer is consumed exactly once; each node contributes one
    graph_nodes row and one graph_node_search row, flushed together when
    the batch fills, so at most ``batch_size`` rows of each are buffered.
    Mirrors UnifiedGraph.stats(): severity_counts covers only rated nodes,
    type_counts covers every node.
    """
    node_count = 0
    severity_counts: dict[str, int] = defaultdict(int)
    type_counts: dict[str, int] = defaultdict(int)
    node_batch: list[tuple[Any, ...]] = []
    search_batch: list[tuple[Any, ...]] = []

    def _flush_nodes() -> None:
        if node_batch:
            _execute_many_batched(conn, _NODE_UPSERT_SQL, node_batch, batch_size=batch_size)
            node_batch.clear()
        if search_batch:
            _execute_many_batched(conn, _NODE_SEARCH_UPSERT_SQL, search_batch, batch_size=batch_size)
            search_batch.clear()

    for node in nodes:
        node_count += 1
        et = node.entity_type.value if hasattr(node.entity_type, "value") else node.entity_type
        type_counts[str(et)] += 1
        if node.severity:
            severity_counts[node.severity] += 1
        node_batch.append(_node_row(node, scan=scan, tenant=tenant))
        search_batch.append(_node_search_row(node, scan=scan, tenant=tenant))
        if len(node_batch) >= batch_size:
            _flush_nodes()
    _flush_nodes()
    return node_count, severity_counts, type_counts


def _edge_rows(
    edges: Iterable[Any], *, scan: str, tenant: str, now: str, previous_scan: str | None, counter: list[int]
) -> Iterator[tuple[Any, ...]]:
    """Yield edge upsert rows, counting consumed edges into ``counter[0]``."""
    for edge in edges:
        counter[0] += 1
        rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
        # A snapshot may record a future grant or observation. Backdating
        # its start changes temporal traversal and correlation receipts.
        valid_from = edge.valid_from or edge.first_seen or now
        yield (
            edge.source,
            edge.target,
            rel,
            edge.direction,
            edge.weight,
            1 if edge.traversable else 0,
            edge.first_seen,
            edge.last_seen,
            valid_from,
            edge.valid_to,
            edge.confidence,
            json.dumps(edge.provenance, default=str),
            edge.source_scan_id or scan,
            edge.source_run_id,
            json.dumps(edge.evidence, default=str),
            edge.activity_id,
            scan,
            tenant,
            previous_scan,
        )


def _attack_path_rows(attack_paths: Iterable[Any], *, scan: str, tenant: str, now: str) -> Iterator[tuple[Any, ...]]:
    for ap in attack_paths:
        yield (
            ap.source,
            ap.target,
            len(ap.hops),
            ap.composite_risk,
            ap.summary,
            json.dumps(ap.hops),
            json.dumps(ap.edges),
            json.dumps(ap.credential_exposure),
            json.dumps(ap.tool_exposure),
            json.dumps(ap.vuln_ids),
            ap.reachability,
            json.dumps(ap.reachability_basis),
            json.dumps([m.to_dict() for m in ap.technique_mappings]),
            json.dumps(ap.hop_evidence, sort_keys=True),
            json.dumps(ap.analysis, sort_keys=True),
            scan,
            tenant,
            now,
        )


def _interaction_risk_rows(interaction_risks: Iterable[Any], *, scan: str, tenant: str) -> Iterator[tuple[Any, ...]]:
    for ir in interaction_risks:
        yield (
            ir.pattern,
            json.dumps(sorted(ir.agents)),
            ir.risk_score,
            ir.description,
            ir.owasp_agentic_tag,
            scan,
            tenant,
        )


def _complete_correlation_in_write(
    conn: Any,
    *,
    tenant: str,
    scan: str,
    correlation_id: str,
    evidence_manifest_sha256: str,
    result_manifest: Mapping[str, Any],
    completed_at: str,
    execution_owner: str,
) -> None:
    """Complete the correlation run atomically with the snapshot that it produced."""
    row = conn.execute(
        f"SELECT {_CORRELATION_RUN_COLUMNS} FROM graph_correlation_runs WHERE tenant_id = %s AND correlation_id = %s FOR UPDATE",  # nosec B608 - static internal column list
        (tenant, correlation_id),
    ).fetchone()
    if row is None:
        raise KeyError("correlation run not found")
    existing = _correlation_run_from_row(row)
    resolved_hash, resolved_result, resolved_output, resolved_failure = validate_correlation_update(
        existing,
        status=CorrelationRunStatus.COMPLETE,
        manifest_sha256=evidence_manifest_sha256,
        result_manifest=result_manifest,
        output_scan_id=scan,
    )
    updated = conn.execute(
        _COMPLETE_CORRELATION_SQL,
        (
            CorrelationRunStatus.COMPLETE.value,
            resolved_hash,
            json.dumps(resolved_result, sort_keys=True, separators=(",", ":")),
            resolved_output,
            resolved_failure,
            completed_at,
            tenant,
            correlation_id,
            existing.status.value,
            execution_owner,
            execution_owner,
        ),
    ).fetchone()
    if updated is None:
        raise RuntimeError("correlation run changed during atomic completion")
