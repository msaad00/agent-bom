"""Derived correlations do not advance scan history or rewrite their sources."""

from __future__ import annotations

import json
import os
import uuid

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.correlation import (
    CorrelationRunStatus,
    GraphCorrelationRun,
    correlation_graph_digest,
    correlation_manifest_digest,
)

T1 = "2026-09-20T01:00:00+00:00"
T2 = "2026-09-20T02:00:00+00:00"
T3 = "2026-09-20T03:00:00+00:00"
T4 = "2026-09-20T04:00:00+00:00"


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    if request.param == "sqlite":
        yield SQLiteGraphStore(tmp_path / "graph.db")
        return
    dsn = os.environ.get("AGENT_BOM_POSTGRES_URL")
    if not dsn:
        pytest.skip("AGENT_BOM_POSTGRES_URL not set")
    from psycopg_pool import ConnectionPool

    from agent_bom.api.postgres_common import reset_current_tenant, resolve_postgres_secret, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    password = resolve_postgres_secret()
    kwargs = {"password": password} if password is not None else {}
    with ConnectionPool(dsn, kwargs=kwargs, min_size=1, max_size=2) as pool:
        token = set_current_tenant(request.node.name)
        try:
            yield PostgresGraphStore(pool=pool)
        finally:
            with pool.connection() as conn:
                conn.execute("SELECT set_config('app.current_tenant', %s, true)", (request.node.name,))
                for table in (
                    "graph_node_search",
                    "attack_paths",
                    "interaction_risks",
                    "graph_edges",
                    "graph_nodes",
                    "graph_snapshots",
                    "graph_correlation_runs",
                ):
                    conn.execute(f"DELETE FROM {table} WHERE tenant_id = %s", (request.node.name,))  # nosec B608 - static table names
            reset_current_tenant(token)


def _graph(scan_id, tenant_id, created_at, targets):
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id, created_at=created_at)
    for node_id in ("agent", *targets):
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.AGENT,
                label=node_id,
                first_seen=created_at,
                last_seen=created_at,
                attributes={"cloud_provider": "fixture", "account_id": "account1"},
            )
        )
    for target in targets:
        graph.add_edge(
            UnifiedEdge(
                source="agent",
                target=target,
                relationship=RelationshipType.USES,
                first_seen=created_at,
                last_seen=created_at,
                valid_from=created_at,
                evidence={"source": "fixture-collector", "recorded_in": scan_id},
            )
        )
    return graph


def _complete(store, graph):
    run = GraphCorrelationRun(
        correlation_id=graph.scan_id,
        tenant_id=graph.tenant_id,
        idempotency_key=uuid.uuid4().hex,
        name="source preservation",
        status=CorrelationRunStatus.PENDING,
        max_age_hours=24,
        allow_stale=False,
        input_manifest=[{"scan_id": "source-a"}, {"scan_id": "source-b"}],
        created_at=T3,
    )
    store.create_correlation_run(run)
    store.update_correlation_run(
        tenant_id=graph.tenant_id, correlation_id=graph.scan_id, status=CorrelationRunStatus.RUNNING, started_at=T3
    )
    manifest = {
        "correlation_id": graph.scan_id,
        "output": {
            "scan_id": graph.scan_id,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "graph_digest_sha256": correlation_graph_digest(graph),
        },
    }
    completed = store.complete_correlation_run(
        graph, result_manifest=manifest, manifest_sha256=correlation_manifest_digest(manifest), completed_at=T3
    )
    assert completed.status is CorrelationRunStatus.COMPLETE
    return manifest


def _bytes(store, graph):
    restored = store.load_graph(tenant_id=graph.tenant_id, scan_id=graph.scan_id)
    return json.dumps(restored.to_dict(), sort_keys=True, separators=(",", ":")).encode()


def test_completion_preserves_source_snapshots_and_output_manifest(store, request):
    tenant = request.node.name
    inputs = [_graph("source-a", tenant, T1, ["kept", "retired"]), _graph("source-b", tenant, T2, ["kept", "retired"])]
    for graph in inputs:
        store.save_graph(graph)
    before = [_bytes(store, graph) for graph in inputs]
    output = _graph("correlation", tenant, T3, ["kept", "derived-only"])
    manifest = _complete(store, output)

    assert [_bytes(store, graph) for graph in inputs] == before
    restored = store.load_graph(tenant_id=tenant, scan_id=output.scan_id)
    assert correlation_graph_digest(restored) == manifest["output"]["graph_digest_sha256"]
    assert all(edge.first_seen == T3 and edge.valid_from == T3 for edge in restored.edges)


@pytest.mark.parametrize("retry", [False, True])
def test_ordinary_scan_continuity_skips_derived_snapshots(store, request, retry):
    tenant = request.node.name
    source = _graph("source-a", tenant, T1, ["kept", "retired"])
    store.save_graph(source)
    correlation = _graph("correlation", tenant, T3, ["kept", "derived-only"])
    _complete(store, correlation)
    correlation_before = _bytes(store, correlation)
    current = _graph("source-b", tenant, T4, ["kept"])
    store.save_graph(current)
    if retry:
        store.save_graph(current)

    assert _bytes(store, correlation) == correlation_before
    current_edge = store.load_graph(tenant_id=tenant, scan_id="source-b").edges[0]
    assert current_edge.first_seen == T1
    assert current_edge.valid_from == T1
    retired = next(edge for edge in store.load_graph(tenant_id=tenant, scan_id="source-a").edges if edge.target == "retired")
    assert retired.valid_to is None
    assert retired.activity_id == 1
