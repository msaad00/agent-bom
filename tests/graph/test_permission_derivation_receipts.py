"""Derived permissions retain ordered source witnesses without inventing grants."""

import os
from datetime import datetime, timezone

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.effective_permissions import apply_effective_permissions
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.store_backed import open_store_backed_unified_graph
from agent_bom.graph.types import EntityType, RelationshipType


def _edge(graph, source, target, relationship, **kwargs):
    edge = UnifiedEdge(source=source, target=target, relationship=relationship, **kwargs)
    graph.add_edge(edge)
    return edge


def _permission(graph, principal, resource):
    return next(
        e for e in graph.edges if e.source == principal and e.target == resource and e.relationship == RelationshipType.HAS_PERMISSION
    )


@pytest.mark.parametrize("backend", ["memory", "sqlite", "postgres"])
def test_direct_group_and_assume_permissions_retain_distinct_source_paths(tmp_path, backend):
    if backend == "postgres" and not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("AGENT_BOM_POSTGRES_URL not set")
    graph = (
        UnifiedGraph(scan_id="proof", tenant_id="tenant-a")
        if backend == "memory"
        else open_store_backed_unified_graph(backend=backend, scan_id="proof", tenant_id="tenant-a")
    )
    try:
        for node_id, kind in [
            ("user:a", EntityType.USER),
            ("group:g", EntityType.GROUP),
            ("role:r", EntityType.ROLE),
            ("data:x", EntityType.DATA_STORE),
        ]:
            graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
        membership = _edge(graph, "user:a", "group:g", RelationshipType.MEMBER_OF)
        assume = _edge(graph, "user:a", "role:r", RelationshipType.ASSUMES)
        group_grant = _edge(graph, "group:g", "data:x", RelationshipType.CAN_ACCESS)
        role_grant = _edge(graph, "role:r", "data:x", RelationshipType.CAN_ACCESS)
        direct = _edge(graph, "user:a", "data:x", RelationshipType.CAN_ACCESS)
        apply_effective_permissions(graph)
        proof = _permission(graph, "user:a", "data:x").evidence["permission_derivation"]
        assert proof["basis"] == "recorded_graph_connections"
        assert proof["path_selection"] == "one_shortest_path_per_grant_and_access"
        assert proof["source_scan_id"] == "proof"
        assert not proof["truncated"]
        paths = {row["access"]: row["source_edge_ids"] for row in proof["paths"]}
        assert paths == {"direct": [direct.id], "group": [membership.id, group_grant.id], "assume_chain": [assume.id, role_grant.id]}
        # A graph witness is not a claim that the user's own provider grant was evaluated.
        assert {row["grant_principal_id"] for row in proof["paths"]} == {"user:a", "group:g", "role:r"}
        store = SQLiteGraphStore(tmp_path / "proof.db")
        store.save_graph(graph)
        restored = SQLiteGraphStore(tmp_path / "proof.db").load_graph(scan_id="proof", tenant_id="tenant-a")
        assert _permission(restored, "user:a", "data:x").evidence["permission_derivation"] == proof
        if backend == "postgres":
            from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
            from agent_bom.api.postgres_graph import PostgresGraphStore

            token = set_current_tenant("tenant-a")
            try:
                PostgresGraphStore().save_graph(graph)
                restored = PostgresGraphStore().load_graph(scan_id="proof", tenant_id="tenant-a")
                assert _permission(restored, "user:a", "data:x").evidence["permission_derivation"] == proof
                assert not PostgresGraphStore().load_graph(scan_id="proof", tenant_id="tenant-b").edges
            finally:
                reset_current_tenant(token)
    finally:
        if backend != "memory":
            graph.close()


def test_depth_limited_permission_walk_is_not_reported_complete(monkeypatch):
    import agent_bom.graph.effective_permissions as module

    monkeypatch.setattr(module, "_MAX_DEPTH", 2)
    graph = UnifiedGraph(scan_id="depth")
    for i in range(4):
        graph.add_node(UnifiedNode(id=f"role:{i}", entity_type=EntityType.ROLE, label=str(i)))
    graph.add_node(UnifiedNode(id="data:x", entity_type=EntityType.DATA_STORE, label="Data"))
    for i in range(3):
        _edge(graph, f"role:{i}", f"role:{i + 1}", RelationshipType.ASSUMES)
    _edge(graph, "role:3", "data:x", RelationshipType.CAN_ACCESS)
    apply_effective_permissions(graph)
    status = graph.analysis_status["effective_permissions"]
    assert status.status.value == "limited"
    assert "permission_depth_limit" in status.reason_codes
    assert not any(e.source == "role:0" and e.target == "data:x" for e in graph.edges)


def test_cycle_does_not_falsely_mark_depth_limit(monkeypatch):
    import agent_bom.graph.effective_permissions as module

    monkeypatch.setattr(module, "_MAX_DEPTH", 2)
    graph = UnifiedGraph(scan_id="cycle")
    for i in range(2):
        graph.add_node(UnifiedNode(id=f"role:{i}", entity_type=EntityType.ROLE, label=str(i)))
    _edge(graph, "role:0", "role:1", RelationshipType.ASSUMES)
    _edge(graph, "role:1", "role:0", RelationshipType.ASSUMES)
    apply_effective_permissions(graph)
    assert graph.analysis_status["effective_permissions"].status.value == "complete"


@pytest.mark.parametrize("empty", [False, True])
def test_incomplete_source_graph_cannot_report_complete_permissions(empty):
    graph = UnifiedGraph(scan_id="partial")
    graph.completeness.truncated = True
    if not empty:
        graph.add_node(UnifiedNode(id="user:a", entity_type=EntityType.USER, label="User"))
    apply_effective_permissions(graph)
    status = graph.analysis_status["effective_permissions"]
    assert status.status.value == "limited"
    assert "incomplete_source_graph" in status.reason_codes


def test_witness_budget_preserves_permission_but_declares_missing_witnesses(monkeypatch):
    import agent_bom.graph.effective_permissions as module

    monkeypatch.setattr(module, "_MAX_PERMISSION_WITNESSES", 2)
    graph = UnifiedGraph(scan_id="witness-limit")
    graph.add_node(UnifiedNode(id="user:a", entity_type=EntityType.USER, label="User"))
    graph.add_node(UnifiedNode(id="data:x", entity_type=EntityType.DATA_STORE, label="Data"))
    for index in range(4):
        role = f"role:{index}"
        graph.add_node(UnifiedNode(id=role, entity_type=EntityType.ROLE, label=role))
        _edge(graph, "user:a", role, RelationshipType.ASSUMES)
        _edge(graph, role, "data:x", RelationshipType.CAN_ACCESS)
    apply_effective_permissions(graph)
    proof = _permission(graph, "user:a", "data:x").evidence["permission_derivation"]
    assert proof["truncated"] is True
    assert len(proof["paths"]) == 2
    assert "permission_witness_limit" in graph.analysis_status["effective_permissions"].reason_codes


@pytest.mark.parametrize("reverse", [False, True])
def test_source_grants_and_overlapping_transfer_types_are_not_reassigned(reverse):
    graph = UnifiedGraph(scan_id="source-identity")
    for node_id, kind in [("user:a", EntityType.USER), ("group:g", EntityType.GROUP), ("data:x", EntityType.DATA_STORE)]:
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    kinds = [RelationshipType.MEMBER_OF, RelationshipType.ASSUMES]
    for kind in kinds[::-1] if reverse else kinds:
        _edge(graph, "user:a", "group:g", kind)
    receipt = {"source": "authorization-evidence", "action": "storage.objects.get", "principal_id": "group:g", "binding_ids": ["read-only"]}
    grant = _edge(graph, "group:g", "data:x", RelationshipType.CAN_ACCESS, evidence={"authorization_decisions": [receipt]})
    apply_effective_permissions(graph)
    proof = _permission(graph, "user:a", "data:x").evidence["permission_derivation"]
    by_access = {p["access"]: p for p in proof["paths"]}
    assert by_access["group"]["source_edge_ids"] == ["member_of:user:a:group:g", grant.id]
    assert by_access["assume_chain"]["source_edge_ids"] == ["assumes:user:a:group:g", grant.id]
    # Follow the stored grant reference: the receipt still belongs to the group.
    for row in proof["paths"]:
        source = next(e for e in graph.edges if e.id == row["grant_edge_id"])
        assert source.evidence["authorization_decisions"] == [receipt]
        assert row["grant_principal_id"] == "group:g"


@pytest.mark.parametrize("relation", [RelationshipType.CAN_ACCESS, RelationshipType.ASSUMES, RelationshipType.MEMBER_OF])
@pytest.mark.parametrize("start,end", [("2026-01-01T00:00:00Z", "2026-09-01T00:00:00Z"), ("2026-10-01T00:00:00Z", None), ("invalid", None)])
def test_inactive_source_authority_never_yields_current_permission(relation, start, end):
    g = UnifiedGraph(scan_id="time-qualified")
    for node_id, kind in [("user:a", EntityType.USER), ("group:g", EntityType.GROUP), ("data:x", EntityType.DATA_STORE)]:
        g.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    if relation is RelationshipType.CAN_ACCESS:
        _edge(g, "user:a", "data:x", relation, valid_from=start, valid_to=end)
    else:
        _edge(g, "user:a", "group:g", relation, valid_from=start, valid_to=end)
        _edge(g, "group:g", "data:x", RelationshipType.CAN_ACCESS, valid_from="2026-01-01T00:00:00Z")
    apply_effective_permissions(g, at=datetime(2026, 9, 20, tzinfo=timezone.utc))
    assert not any(e.source == "user:a" and e.relationship is RelationshipType.HAS_PERMISSION for e in g.edges)
    if start == "invalid":
        assert "invalid_permission_validity" in g.analysis_status["effective_permissions"].reason_codes


def test_derived_permission_preserves_intersection_of_witness_validity(tmp_path):
    g = UnifiedGraph(scan_id="time-window", tenant_id="tenant-a")
    for node_id, kind in [("user:a", EntityType.USER), ("group:g", EntityType.GROUP), ("data:x", EntityType.DATA_STORE)]:
        g.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    _edge(g, "user:a", "group:g", RelationshipType.MEMBER_OF, valid_from="2026-09-01T00:00:00Z", valid_to="2026-10-01T00:00:00Z")
    _edge(g, "group:g", "data:x", RelationshipType.CAN_ACCESS, valid_from="2026-09-10T00:00:00Z", valid_to="2026-11-01T00:00:00Z")
    apply_effective_permissions(g, at=datetime(2026, 9, 20, tzinfo=timezone.utc))
    edge = _permission(g, "user:a", "data:x")
    assert edge.valid_from == "2026-09-10T00:00:00+00:00"
    assert edge.valid_to == "2026-10-01T00:00:00+00:00"
    store = SQLiteGraphStore(tmp_path / "window.db")
    store.save_graph(g)
    restored = SQLiteGraphStore(tmp_path / "window.db").load_graph(scan_id="time-window", tenant_id="tenant-a")
    assert _permission(restored, "user:a", "data:x").valid_to == edge.valid_to


@pytest.mark.parametrize(
    "at,activity_id,expected",
    [
        (datetime(2026, 8, 15, tzinfo=timezone.utc), 1, True),
        (datetime(2026, 9, 1, tzinfo=timezone.utc), 1, False),
        (datetime(2026, 9, 20, tzinfo=timezone.utc), 1, False),
        (datetime(2026, 8, 15, tzinfo=timezone.utc), 3, False),
    ],
)
def test_permission_evaluation_uses_requested_time_and_excludes_deleted_source(at, activity_id, expected):
    graph = UnifiedGraph(scan_id="historical")
    graph.add_node(UnifiedNode(id="user:a", entity_type=EntityType.USER, label="User"))
    graph.add_node(UnifiedNode(id="data:x", entity_type=EntityType.DATA_STORE, label="Data"))
    _edge(
        graph,
        "user:a",
        "data:x",
        RelationshipType.CAN_ACCESS,
        valid_from="2026-08-01T00:00:00Z",
        valid_to="2026-09-01T00:00:00Z",
        activity_id=activity_id,
    )
    apply_effective_permissions(graph, at=at)
    assert any(e.relationship is RelationshipType.HAS_PERMISSION for e in graph.edges) is expected


def test_alternate_permission_witnesses_preserve_union_of_overlapping_windows():
    graph = UnifiedGraph(scan_id="alternate-window")
    for node_id, kind in [("user:a", EntityType.USER), ("role:r", EntityType.ROLE), ("data:x", EntityType.DATA_STORE)]:
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    _edge(graph, "user:a", "data:x", RelationshipType.CAN_ACCESS, valid_from="2026-09-01T00:00:00Z", valid_to="2026-10-01T00:00:00Z")
    _edge(graph, "user:a", "role:r", RelationshipType.ASSUMES, valid_from="2026-09-10T00:00:00Z", valid_to="2026-11-01T00:00:00Z")
    _edge(graph, "role:r", "data:x", RelationshipType.CAN_ACCESS, valid_from="2026-09-05T00:00:00Z", valid_to="2026-12-01T00:00:00Z")
    apply_effective_permissions(graph, at=datetime(2026, 9, 20, tzinfo=timezone.utc))
    permission = _permission(graph, "user:a", "data:x")
    assert permission.valid_from == "2026-09-01T00:00:00+00:00"
    assert permission.valid_to == "2026-11-01T00:00:00+00:00"
    assert len(permission.evidence["permission_derivation"]["paths"]) == 2
