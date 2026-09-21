"""Account-local Snowflake identifiers must not cross-link source lanes."""

from copy import deepcopy

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.correlation import CorrelationSnapshot, correlation_graph_digest, merge_graph_snapshots
from agent_bom.graph.correlation_workspace import CorrelationMergeWorkspace


def _object_lane(account):
    return {
        "status": "ok",
        "account": account,
        "objects": [{"fqn": "DB.PUBLIC.ORDERS", "object_type": "table"}],
        "grants": [{"role": "ANALYST", "privilege": "SELECT", "object_fqn": "DB.PUBLIC.ORDERS", "object_type": "table"}],
        "role_memberships": [{"user": "ALICE", "role": "ANALYST"}],
    }


def _report(account):
    return {"snowflake_object_graph": _object_lane(account)}


def _governance_lane(account):
    return {
        "status": "ok",
        "account": account,
        "access_records": [
            {
                "query_id": "q-observed",
                "user_name": "ALICE",
                "role_name": "ANALYST",
                "object_name": "DB.PUBLIC.ORDERS",
                "object_type": "table",
                "operation": "READ",
                "is_write": False,
            }
        ],
    }


def _services_lane(account):
    return {"status": "ok", "account": account, "databases": [{"name": "DB"}], "schemas": [{"fqn": "DB.PUBLIC", "database_name": "DB"}]}


def _build(report, scan="scan", tenant="tenant-a"):
    return build_unified_graph_from_report(report, scan_id=scan, tenant_id=tenant)


def _nodes(graph, kind):
    return [node for node in graph.nodes.values() if node.entity_type.value == kind]


@pytest.mark.parametrize(
    ("accounts", "expected"), [(("ACCT1", "ACCT1"), 1), (("ACCT1", "ACCT2"), 2), (("", ""), 2), (("ACCT1", ""), 2), (("acct1", "ACCT1"), 2)]
)
@pytest.mark.parametrize("engine", ["memory", "disk"])
def test_snapshot_correlation_requires_exact_account_and_local_identity(accounts, expected, engine):
    inputs = [_build(_report(account), scan=f"scan-{i}") for i, account in enumerate(accounts)]
    before = [correlation_graph_digest(graph) for graph in inputs]
    snapshots = [CorrelationSnapshot.from_graph(graph) for graph in inputs]
    if engine == "memory":
        result = merge_graph_snapshots(correlation_id="corr", tenant_id="tenant-a", snapshots=snapshots)
    else:
        with CorrelationMergeWorkspace(
            correlation_id="corr", tenant_id="tenant-a", created_at=inputs[-1].created_at, max_output_nodes=100, max_output_edges=100
        ) as workspace:
            for snapshot in snapshots:
                workspace.add_snapshot(snapshot)
            result = workspace.finish()
    for kind in ("user", "role", "data_store"):
        assert len(_nodes(result.graph, kind)) == expected
    assert [correlation_graph_digest(graph) for graph in inputs] == before
    for edge in result.graph.edges:
        if edge.relationship.value in {"has_permission", "assumes"}:
            source = result.graph.nodes[edge.source]
            target = result.graph.nodes[edge.target]
            assert source.attributes.get("account_id") == target.attributes.get("account_id")


def test_mixed_account_lanes_preserve_distinct_user_object_and_schema_context():
    graph = _build({**_report("ACCT1"), "snowflake_governance": _governance_lane("ACCT2"), "snowflake_services": _services_lane("ACCT2")})
    users = _nodes(graph, "user")
    tables = [node for node in _nodes(graph, "data_store") if node.attributes.get("fqn") == "DB.PUBLIC.ORDERS"]
    assert len(users) == len(tables) == 2
    assert {node.attributes["account_id"] for node in users} == {"ACCT1", "ACCT2"}
    for edge in graph.edges:
        source, target = graph.nodes[edge.source], graph.nodes[edge.target]
        assert source.attributes.get("account_id") == target.attributes.get("account_id")
    accessed = next(edge for edge in graph.edges if edge.relationship.value == "accessed")
    grant = next(edge for edge in graph.edges if edge.relationship.value == "has_permission")
    assert accessed.target != grant.target


@pytest.mark.parametrize("object_account", ["ACCT1", ""])
def test_missing_account_lane_is_not_stitched_to_another_source(object_account):
    graph = _build({**_report(object_account), "snowflake_governance": _governance_lane("")})
    assert len(_nodes(graph, "user")) == 2
    assert len(_nodes(graph, "data_store")) == 2
    access = next(edge for edge in graph.edges if edge.relationship.value == "accessed")
    grant = next(edge for edge in graph.edges if edge.relationship.value == "has_permission")
    assert access.target != grant.target


def test_same_account_lanes_keep_existing_ids_and_context():
    graph = _build({**_report("ACCT1"), "snowflake_governance": _governance_lane("ACCT1"), "snowflake_services": _services_lane("ACCT1")})
    assert len(_nodes(graph, "user")) == 1
    assert "user:snowflake:ALICE" in graph.nodes
    assert "role:snowflake:ANALYST" in graph.nodes
    assert "data_store:snowflake:DB.PUBLIC.ORDERS" in graph.nodes
    assert graph.nodes["user:snowflake:ALICE"].attributes["account_id"] == "ACCT1"
    assert graph.nodes["role:snowflake:ANALYST"].attributes["account_id"] == "ACCT1"
    schema = graph.nodes["data_store:snowflake:schema:DB.PUBLIC"]
    assert schema.attributes["account_id"] == "ACCT1"
    assert any(edge.source == schema.id and edge.target == "data_store:snowflake:DB.PUBLIC.ORDERS" for edge in graph.edges)


def test_cross_tenant_correlation_remains_rejected():
    left = _build(_report("ACCT1"), scan="left")
    right = _build(_report("ACCT1"), scan="right", tenant="tenant-b")
    with pytest.raises(ValueError, match="same tenant"):
        merge_graph_snapshots(
            correlation_id="corr", tenant_id="tenant-a", snapshots=[CorrelationSnapshot.from_graph(g) for g in (left, right)]
        )


def test_build_does_not_rewrite_source_payload():
    report = {**_report("ACCT1"), "snowflake_governance": _governance_lane("ACCT2")}
    before = deepcopy(report)
    _build(report)
    assert report == before


@pytest.mark.parametrize("pipeline_account", ["ACCT2", "", "acct1"])
def test_mixed_account_task_cannot_inherit_same_name_role_grants(pipeline_account):
    report = _report("ACCT1")
    lane = report["snowflake_object_graph"]
    lane["grants"][0]["role"] = "PARENT"
    lane["role_memberships"].append({"role": "ANALYST", "parent": "PARENT", "member_type": "role"})
    report["snowflake_pipeline"] = {
        "status": "ok",
        "account": pipeline_account,
        "tasks": [{"fqn": "DB.PUBLIC.TASK", "owner": "ANALYST"}],
    }
    graph = _build(report)
    task = next(node for node in graph.nodes.values() if node.attributes.get("resource_type") == "task")
    table = next(node for node in graph.nodes.values() if node.attributes.get("fqn") == "DB.PUBLIC.ORDERS")
    assert len(_nodes(graph, "role")) == 3
    assert table.id not in graph.reachable_from(task.id)
    alice = next(node for node in _nodes(graph, "user") if node.attributes.get("account_id") == "ACCT1")
    assert table.id in graph.reachable_from(alice.id)


def test_mixed_lane_mapping_is_independent_of_input_key_order():
    report = {**_report("ACCT1"), "snowflake_governance": _governance_lane("ACCT2"), "snowflake_services": _services_lane("ACCT2")}
    graphs = [_build(report), _build(dict(reversed(list(report.items()))))]
    assert set(graphs[0].nodes) == set(graphs[1].nodes)
    assert {edge.id for edge in graphs[0].edges} == {edge.id for edge in graphs[1].edges}


def test_external_bucket_is_not_given_a_snowflake_owning_account():
    report = {
        **_report("ACCT1"),
        "snowflake_exfil_graph": {
            "status": "ok",
            "account": "ACCT2",
            "external_stages": [
                {"stage_name": "EXPORT", "cloud_provider": "aws", "bucket": "external-bucket", "url": "s3://external-bucket"}
            ],
        },
    }
    graph = _build(report)
    bucket = graph.nodes["cloud_resource:aws:s3:bucket:external-bucket"]
    assert "account_id" not in bucket.attributes
    assert "snowflake_local_id" not in bucket.attributes
    assert any(edge.target == bucket.id and edge.relationship.value == "exposed_to" for edge in graph.edges)


def test_legacy_snapshot_ids_remain_loadable_after_new_correlation(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    old = _build(_report("ACCT1"), scan="legacy")
    for node in old.nodes.values():
        node.attributes.pop("snowflake_local_id", None)
        node.attributes.pop("snowflake_scope_version", None)
        if node.entity_type.value in {"user", "role"}:
            node.attributes.pop("account_id", None)
    store = SQLiteGraphStore(tmp_path / "legacy.db")
    store.save_graph(old)
    before = correlation_graph_digest(store.load_graph(scan_id="legacy", tenant_id="tenant-a"))
    current = _build(_report("ACCT1"), scan="current")
    merged = merge_graph_snapshots(
        correlation_id="new-correlation", tenant_id="tenant-a", snapshots=[CorrelationSnapshot.from_graph(g) for g in (old, current)]
    )
    store.save_graph_streaming(
        scan_id=merged.graph.scan_id,
        tenant_id=merged.graph.tenant_id,
        nodes=merged.graph.nodes.values(),
        edges=merged.graph.edges,
        created_at=merged.graph.created_at,
        snapshot_kind="correlation",
        correlation_id=merged.graph.scan_id,
    )
    restored = store.load_graph(scan_id="legacy", tenant_id="tenant-a")
    assert correlation_graph_digest(restored) == before
    assert "user:snowflake:ALICE" in restored.nodes
    assert "role:snowflake:ANALYST" in restored.nodes
    assert "data_store:snowflake:DB.PUBLIC.ORDERS" in restored.nodes
    # Exact account + existing table FQN can join. Scope-free legacy identities
    # remain separate until rebuilt from original source evidence.
    assert len(_nodes(merged.graph, "data_store")) == 1
    assert len(_nodes(merged.graph, "user")) == 2


def test_scoped_and_original_local_ids_join_only_with_matching_account():
    single = _build(_report("ACCT1"), scan="single")
    mixed = _build({**_report("ACCT1"), "snowflake_governance": _governance_lane("ACCT2")}, scan="mixed")
    inputs = [CorrelationSnapshot.from_graph(graph) for graph in (single, mixed)]
    merged = merge_graph_snapshots(correlation_id="corr", tenant_id="tenant-a", snapshots=inputs).graph
    for account in ("ACCT1", "ACCT2"):
        for kind in ("user", "data_store"):
            assert len([node for node in _nodes(merged, kind) if node.attributes.get("account_id") == account]) == 1
    assert len(_nodes(merged, "role")) == 1
    for edge in merged.edges:
        assert merged.nodes[edge.source].attributes.get("account_id") == merged.nodes[edge.target].attributes.get("account_id")


def test_quoted_object_identifiers_preserve_case_in_scoped_mapping():
    report = _report("ACCT1")
    report["snowflake_object_graph"]["objects"] = [
        {"fqn": 'DB.PUBLIC."Orders"', "object_type": "table"},
        {"fqn": 'DB.PUBLIC."ORDERS"', "object_type": "table"},
    ]
    report["snowflake_governance"] = _governance_lane("ACCT2")
    graph = _build(report)
    objects = {node.attributes["fqn"]: node.id for node in _nodes(graph, "data_store")}
    assert objects['DB.PUBLIC."Orders"'] != objects['DB.PUBLIC."ORDERS"']


def test_account_scope_survives_restart_http_and_mcp_node_drilldown(tmp_path):
    import asyncio
    import json

    from starlette.testclient import TestClient

    from agent_bom.api import stores as api_stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.server import app
    from agent_bom.api.stores import set_graph_store
    from agent_bom.mcp_tools.inventory import inventory_asset_impl

    graph = _build({**_report("ACCT1"), "snowflake_governance": _governance_lane("ACCT2")}, tenant="default")
    db = tmp_path / "scope.db"
    SQLiteGraphStore(db).save_graph(graph)
    store = SQLiteGraphStore(db)
    restored = store.load_graph(tenant_id="default", scan_id=graph.scan_id)
    original = api_stores._graph_store
    try:
        set_graph_store(store)
        client = TestClient(app)
        for user in _nodes(restored, "user"):
            response = client.get("/v1/graph/node-context", params={"node_id": user.id, "scan_id": graph.scan_id})
            assert response.status_code == 200
            context = response.json()
            assert context["node"]["attributes"] == user.attributes
            mcp = json.loads(asyncio.run(inventory_asset_impl(asset_id=user.id, scan_id=graph.scan_id, _get_graph_store=lambda: store)))
            assert mcp["node"] == context["node"]
            assert mcp["edges_out"] == context["edges_out"]
            expected_relationship = "assumes" if user.attributes["account_id"] == "ACCT1" else "accessed"
            relationships = {edge["relationship"] for edge in mcp["edges_out"]}
            assert expected_relationship in relationships
            assert relationships <= {expected_relationship, "member_of"}
            for edge in mcp["edges_out"]:
                assert restored.nodes[edge["target"]].attributes["account_id"] == user.attributes["account_id"]
    finally:
        set_graph_store(original)


def test_independent_organization_evidence_survives_unavailable_service_inventory():
    graph = _build(
        {
            "snowflake_services": {
                "status": "unavailable",
                "organization": {"status": "ok", "org_name": "ACME", "accounts": [{"locator": "ACCT1"}, {"locator": "ACCT2"}]},
            }
        }
    )
    assert "org:snowflake:ACME" in graph.nodes
    assert {node.attributes["account_id"] for node in _nodes(graph, "account")} == {"ACCT1", "ACCT2"}
    assert {edge.target for edge in graph.edges if edge.source == "org:snowflake:ACME"} == {
        "account:snowflake:ACCT1",
        "account:snowflake:ACCT2",
    }
