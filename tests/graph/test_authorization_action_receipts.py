"""Action-specific authorization evidence must survive edge aggregation."""

from __future__ import annotations

import copy
import os

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.store_backed import open_store_backed_unified_graph
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_graph_authorization_evidence_integration import _gcp_inventory


@pytest.mark.parametrize("backend", ["memory", "sqlite", "postgres"])
@pytest.mark.parametrize("reverse", [False, True])
def test_same_resource_actions_keep_their_own_binding_receipts(tmp_path, backend, reverse):
    if backend == "postgres" and not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("AGENT_BOM_POSTGRES_URL not set")
    store_backed = backend != "memory"
    graph = (
        open_store_backed_unified_graph(backend=backend, tenant_id="tenant-a", scan_id="actions")
        if store_backed
        else UnifiedGraph(tenant_id="tenant-a", scan_id="actions")
    )
    graph.add_node(UnifiedNode(id="principal:a", entity_type=EntityType.SERVICE_ACCOUNT, label="Reader"))
    graph.add_node(UnifiedNode(id="bucket:a", entity_type=EntityType.DATA_STORE, label="Data"))
    records = [
        {
            "source": "authorization-evidence",
            "provider": "gcp",
            "principal_id": "principal:a",
            "action": "storage.objects.get",
            "resource": "bucket:a",
            "decision": "allow",
            "binding_ids": ["read-binding"],
            "observed_at": "2026-09-20T12:00:00Z",
        },
        {
            "source": "authorization-evidence",
            "provider": "gcp",
            "principal_id": "principal:a",
            "action": "storage.objects.create",
            "resource": "bucket:a",
            "decision": "allow",
            "binding_ids": ["write-binding"],
            "observed_at": "2026-09-20T12:00:00Z",
        },
    ]
    try:
        for record in records[:: -1 if reverse else 1] * 2:
            graph.add_edge(
                UnifiedEdge(
                    source="principal:a",
                    target="bucket:a",
                    relationship=RelationshipType.CAN_ACCESS,
                    evidence={**copy.deepcopy(record), "authorization_decisions": [copy.deepcopy(record)]},
                )
            )
        edges = list(graph.edges)
        assert len(edges) == 1
        evidence = edges[0].evidence
        assert evidence["authorization_decisions"] == sorted(records, key=lambda row: row["action"])
        assert "action" not in evidence  # No arbitrary single action on an aggregate.
        assert evidence["binding_ids"] == ["read-binding", "write-binding"]
        store = SQLiteGraphStore(tmp_path / "graph.db")
        store.save_graph(graph)
        restored = SQLiteGraphStore(tmp_path / "graph.db").load_graph(scan_id="actions", tenant_id="tenant-a")
        assert restored.edges[0].evidence == evidence
        assert not SQLiteGraphStore(tmp_path / "graph.db").load_graph(scan_id="actions", tenant_id="tenant-b").edges
        if backend == "postgres":
            from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
            from agent_bom.api.postgres_graph import PostgresGraphStore

            token = set_current_tenant("tenant-a")
            try:
                persisted = PostgresGraphStore()
                persisted.save_graph(graph)
                assert PostgresGraphStore().load_graph(scan_id="actions", tenant_id="tenant-a").edges[0].evidence == evidence
                assert not PostgresGraphStore().load_graph(scan_id="actions", tenant_id="tenant-b").edges
            finally:
                reset_current_tenant(token)
    finally:
        if store_backed:
            graph.close()


def test_provider_builder_retains_every_evaluated_allowed_action():
    inventory = _gcp_inventory()
    inventory["role_definitions"][0]["permissions"] = ["storage.objects.get", "storage.objects.create"]
    graph = build_unified_graph_from_report({"scan_id": "multi-action", "cloud_inventory": inventory})
    edges = [
        e for e in graph.edges if e.relationship == RelationshipType.CAN_ACCESS and e.evidence.get("source") == "authorization-evidence"
    ]
    assert len(edges) == 1
    records = edges[0].evidence["authorization_decisions"]
    assert {r["action"] for r in records} == {"storage.objects.get", "storage.objects.create"}
    assert all(r["principal_id"] == "serviceAccount:reader@proj-1.iam.gserviceaccount.com" for r in records)
    assert all(r["decision"] == "allow" and r["binding_ids"] for r in records)


def test_legacy_scalar_receipt_is_not_lost_or_reassigned_to_a_new_binding():
    from agent_bom.graph.edge import merge_edge_evidence

    old = {
        "source": "authorization-evidence",
        "provider": "gcp",
        "action": "read",
        "resource": "bucket:a",
        "decision": "allow",
        "binding_ids": ["read-binding"],
        "observed_at": None,
    }
    new = {**old, "action": "write", "binding_ids": ["write-binding"], "observed_at": "2026-09-20T12:00:00Z", "principal_id": "principal:a"}
    stored = copy.deepcopy(old)
    merge_edge_evidence(stored, {**new, "authorization_decisions": [new]})
    assert stored["authorization_decisions"] == [old, new]
    assert "action" not in stored and "observed_at" not in stored and "principal_id" not in stored
    assert old["binding_ids"] == ["read-binding"]
    assert not merge_edge_evidence(stored, {"authorization_decisions": [new]})


def test_malformed_optional_binding_ids_do_not_crash_evidence_merge():
    from agent_bom.graph.edge import merge_edge_evidence

    stored = {"authorization_decisions": [{"action": "read", "binding_ids": None}]}
    merge_edge_evidence(stored, {"authorization_decisions": [{"action": "write", "binding_ids": ["write-binding"]}]})
    assert len(stored["authorization_decisions"]) == 2


def test_provider_batches_actions_for_one_resource_without_rewriting_each_receipt(monkeypatch):
    inventory = _gcp_inventory()
    inventory["role_definitions"][0]["permissions"] = [f"storage.objects.synthetic{i}" for i in range(100)]
    writes = []
    original = UnifiedGraph.add_edge

    def record_write(graph, edge):
        if edge.evidence.get("source") == "authorization-evidence":
            writes.append(edge)
        return original(graph, edge)

    monkeypatch.setattr(UnifiedGraph, "add_edge", record_write)
    graph = build_unified_graph_from_report({"scan_id": "batched-actions", "cloud_inventory": inventory})
    assert len(writes) == 1
    assert len(writes[0].evidence["authorization_decisions"]) == 100
    assert graph.analysis_status["authorization_evidence:gcp"].observed["evaluated_requests"] == 100
