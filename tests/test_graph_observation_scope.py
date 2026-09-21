"""Scan observation intervals require exact source and account comparability."""

from __future__ import annotations

import os
import uuid
from contextlib import ExitStack
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.correlation import correlation_graph_digest

T1 = "2026-09-20T01:00:00+00:00"
T2 = "2026-09-20T02:00:00+00:00"
T3 = "2026-09-20T03:00:00+00:00"


@pytest.fixture(params=["sqlite", "postgres"])
def scope_store(request, tmp_path):
    tenant = "scope-" + uuid.uuid4().hex
    with ExitStack() as stack:
        if request.param == "sqlite":
            store = SQLiteGraphStore(tmp_path / "scope.db")
        else:
            dsn = os.environ.get("AGENT_BOM_POSTGRES_URL")
            if not dsn:
                pytest.skip("AGENT_BOM_POSTGRES_URL not set")
            from psycopg_pool import ConnectionPool

            from agent_bom.api.postgres_common import reset_current_tenant, resolve_postgres_secret, set_current_tenant
            from agent_bom.api.postgres_graph import PostgresGraphStore

            password = resolve_postgres_secret()
            pool = stack.enter_context(ConnectionPool(dsn, kwargs={"password": password} if password else {}, min_size=1, max_size=2))
            token = set_current_tenant(tenant)
            stack.callback(reset_current_tenant, token)
            store = PostgresGraphStore(pool=pool)

            def clean():
                with pool.connection() as conn:
                    conn.execute("SELECT set_config('app.current_tenant', %s, true)", (tenant,))
                    for table in (
                        "graph_node_search",
                        "attack_paths",
                        "interaction_risks",
                        "graph_edges",
                        "graph_nodes",
                        "graph_snapshots",
                    ):
                        conn.execute(f"DELETE FROM {table} WHERE tenant_id = %s", (tenant,))  # nosec B608 - static table names

            stack.callback(clean)
        original_graph, original_keys = stores._graph_store, get_key_store()
        stack.callback(stores.set_graph_store, original_graph)
        stack.callback(set_key_store, original_keys)
        stores.set_graph_store(store)
        keys = KeyStore()
        raw, key = create_api_key("scope observation tests", Role.ANALYST, tenant_id=tenant, scopes=["graph:read"])
        keys.add(key)
        set_key_store(keys)
        yield SimpleNamespace(store=store, tenant=tenant, client=TestClient(app), headers={"Authorization": f"Bearer {raw}"})


def _graph(ctx, account, *, scan="first", at=T1, name="ORDERS", status="ok", warnings=(), authority=True):
    payload = {
        "status": status,
        "account": account,
        "warnings": list(warnings),
        "objects": [{"fqn": f"DB.PUBLIC.{name}", "object_type": "table"}],
        "grants": [{"role": name + "_ROLE", "privilege": "SELECT", "object_fqn": f"DB.PUBLIC.{name}", "object_type": "table"}],
        "role_memberships": [{"user": name + "_USER", "role": name + "_ROLE"}],
    }
    if not authority:
        payload["grants"] = []
        payload["role_memberships"] = []
    graph = build_unified_graph_from_report({"snowflake_object_graph": payload}, scan_id=scan, tenant_id=ctx.tenant)
    graph.created_at = at
    for node in graph.nodes.values():
        node.first_seen = node.last_seen = at
    for edge in graph.edges:
        edge.first_seen = edge.last_seen = edge.valid_from = at
    return graph


def _load(ctx, scan):
    return ctx.store.load_graph(tenant_id=ctx.tenant, scan_id=scan)


def _api(ctx, path, **params):
    response = ctx.client.get(path, params=params, headers=ctx.headers)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize("same_names", [False, True])
def test_unrelated_accounts_do_not_retire_or_inherit_relationship_intervals(scope_store, same_names):
    ctx = scope_store
    first = _graph(ctx, "ACCT1")
    second = _graph(ctx, "ACCT2", scan="second", at=T2, name="ORDERS" if same_names else "CUSTOMERS")
    ctx.store.save_graph(first)
    before = correlation_graph_digest(_load(ctx, "first"))
    ctx.store.save_graph(second)
    assert correlation_graph_digest(_load(ctx, "first")) == before
    assert all(edge.first_seen == T2 and edge.valid_from == T2 for edge in _load(ctx, "second").edges)
    active = _api(ctx, "/v1/graph/edges/active", at=T3)
    grants = [edge for edge in active if edge["relationship"] == "has_permission"]
    assert {edge["evidence"]["grant_receipts"][0]["account"] for edge in grants} == {"ACCT1", "ACCT2"}
    assert all(edge["valid_to"] is None and edge["activity_id"] == 1 for edge in grants)


@pytest.mark.parametrize("status,warnings", [("denied", ()), ("ok", ("SHOW GRANTS unavailable",)), ("ok", ("collector truncated",))])
def test_missing_partial_or_denied_collection_does_not_end_authority(scope_store, status, warnings):
    ctx = scope_store
    ctx.store.save_graph(_graph(ctx, "ACCT1"))
    before = correlation_graph_digest(_load(ctx, "first"))
    current = _graph(ctx, "ACCT1", scan="second", at=T2, status=status, warnings=warnings, authority=False)
    ctx.store.save_graph(current)
    assert correlation_graph_digest(_load(ctx, "first")) == before
    assert any(edge["relationship"] == "has_permission" for edge in _api(ctx, "/v1/graph/edges/active", at=T3))


def test_positive_exact_scope_reobservation_keeps_first_observed_time(scope_store):
    ctx = scope_store
    ctx.store.save_graph(_graph(ctx, "ACCT1"))
    before = correlation_graph_digest(_load(ctx, "first"))
    ctx.store.save_graph(_graph(ctx, "ACCT1", scan="second", at=T2))
    assert correlation_graph_digest(_load(ctx, "first")) == before
    assert all(edge.first_seen == T1 and edge.valid_from == T1 for edge in _load(ctx, "second").edges)
    grants = [edge for edge in _api(ctx, "/v1/graph/edges/active", at=T3) if edge["relationship"] == "has_permission"]
    assert len(grants) == 1 and grants[0]["scan_id"] == "second"


@pytest.mark.parametrize(
    "change",
    [
        "legacy_unknown",
        "other_provider",
        "other_source",
        "malformed_scope",
        "malformed_provider",
        "conflicting_provider",
        "malformed_source",
    ],
)
def test_missing_or_conflicting_scope_does_not_inherit_timestamps(scope_store, change):
    ctx = scope_store
    graphs = [_graph(ctx, "ACCT1"), _graph(ctx, "ACCT1", scan="second", at=T2)]
    for graph in graphs:
        for node in graph.nodes.values():
            if change == "legacy_unknown":
                node.attributes.pop("account_id", None)
            elif change == "malformed_scope":
                node.attributes["account_id"] = 42
            elif change == "malformed_provider":
                node.attributes["cloud_provider"] = False
            elif change == "conflicting_provider":
                node.attributes["cloud_provider"] = "different-provider"
            elif change == "other_provider" and graph.scan_id == "second":
                node.attributes["cloud_provider"] = node.dimensions.cloud_provider = "different-provider"
        if change == "other_source" and graph.scan_id == "second":
            for edge in graph.edges:
                edge.evidence["source"] = "different-collector"
        if change == "malformed_source":
            for edge in graph.edges:
                edge.evidence["source"] = {"collector": "untyped"}
        ctx.store.save_graph(graph)
    assert all(edge.first_seen == T2 and edge.valid_from == T2 for edge in _load(ctx, "second").edges)
    grants = [edge for edge in _api(ctx, "/v1/graph/edges/active", at=T3) if edge["relationship"] == "has_permission"]
    assert len(grants) == 2


def test_source_recorded_expiry_is_preserved_without_extending_new_observation(scope_store):
    ctx = scope_store
    first = _graph(ctx, "ACCT1")
    for edge in first.edges:
        edge.valid_to = "2026-09-20T01:30:00+00:00"
    ctx.store.save_graph(first)
    ctx.store.save_graph(_graph(ctx, "ACCT1", scan="second", at=T2))
    assert all(edge.valid_to == "2026-09-20T01:30:00+00:00" for edge in _load(ctx, "first").edges)
    assert all(edge.first_seen == T2 and edge.valid_from == T2 for edge in _load(ctx, "second").edges)


def test_mixed_source_snapshot_remains_unchanged_when_one_account_is_rescanned(scope_store):
    ctx = scope_store
    mixed = build_unified_graph_from_report(
        {
            "snowflake_object_graph": {
                "status": "ok",
                "account": "ACCT1",
                "objects": [{"fqn": "DB.PUBLIC.ORDERS"}],
                "grants": [{"role": "ANALYST", "privilege": "SELECT", "object_fqn": "DB.PUBLIC.ORDERS"}],
            },
            "snowflake_governance": {
                "status": "ok",
                "account": "ACCT2",
                "access_records": [{"user_name": "ALICE", "object_name": "DB.PUBLIC.ORDERS", "is_write": False, "operation": "READ"}],
            },
        },
        scan_id="mixed",
        tenant_id=ctx.tenant,
    )
    mixed.created_at = T1
    for edge in mixed.edges:
        edge.first_seen = edge.last_seen = edge.valid_from = T1
    ctx.store.save_graph(mixed)
    before = correlation_graph_digest(_load(ctx, "mixed"))
    ctx.store.save_graph(_graph(ctx, "ACCT1", scan="partial", at=T2, authority=False, warnings=("grant collection denied",)))
    assert correlation_graph_digest(_load(ctx, "mixed")) == before
    for edge in _load(ctx, "mixed").edges:
        assert edge.valid_to is None and edge.activity_id == 1
    active = _api(ctx, "/v1/graph/edges/active", at=T3)
    assert {edge["relationship"] for edge in active} >= {"accessed", "has_permission"}
