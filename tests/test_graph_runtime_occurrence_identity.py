"""Runtime graph joins preserve deployment identity independently of image reuse."""

from copy import deepcopy

import pytest

from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph
from agent_bom.graph.attack_path_fusion import compute_fused_attack_paths
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots
from agent_bom.graph.correlation_workspace import CorrelationMergeWorkspace
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _snapshots(kind):
    prod = UnifiedGraph(scan_id="prod", tenant_id="tenant")
    dev = UnifiedGraph(scan_id="dev", tenant_id="tenant")
    attrs = {
        "image_digest": "sha256:" + "a" * 64,
        "runtime_uid": "prod-uid",
        "cloud_provider": "aws",
        "cloud_account_id": "account",
        "cluster_id": "cluster",
    }
    other = deepcopy(attrs)
    if kind == "different_uid":
        other["runtime_uid"] = "dev-uid"
    elif kind == "different_cluster":
        other["cluster_id"] = "other-cluster"
    elif kind == "different_environment":
        attrs["environment"] = "production"
        other["environment"] = "development"
    elif kind == "different_account":
        other["cloud_account_id"] = "other-account"
    elif kind == "missing_provider":
        attrs.pop("cloud_provider")
        other.pop("cloud_provider")
    elif kind in {"same_kubernetes_container", "different_kubernetes_container", "kubernetes_without_name"}:
        for obj in (attrs, other):
            obj.pop("runtime_uid")
            obj["kubernetes_uid"] = "pod-uid"
            if kind != "kubernetes_without_name":
                obj["container_name"] = "api"
        if kind == "different_kubernetes_container":
            other["container_name"] = "sidecar"
    elif kind == "missing_uid":
        attrs.pop("runtime_uid")
        other.pop("runtime_uid")
    elif kind == "missing_scope":
        for obj in (attrs, other):
            obj.pop("cloud_account_id")
            obj.pop("cluster_id")
    prod.add_node(UnifiedNode(id="entry", entity_type=EntityType.CLOUD_RESOURCE, label="entry", attributes={"internet_exposed": True}))
    prod.add_node(UnifiedNode(id="prod:container", entity_type=EntityType.CONTAINER, label="container", attributes=attrs))
    dev.add_node(UnifiedNode(id="dev:container", entity_type=EntityType.CONTAINER, label="container", attributes=other))
    dev.add_node(UnifiedNode(id="role", entity_type=EntityType.ROLE, label="role"))
    dev.add_node(UnifiedNode(id="data", entity_type=EntityType.DATA_STORE, label="data", attributes={"data_sensitivity": "restricted"}))
    for graph, source, target, rel in [
        (prod, "entry", "prod:container", RelationshipType.CONTAINS),
        (dev, "dev:container", "role", RelationshipType.AUTHENTICATES_AS),
        (dev, "role", "data", RelationshipType.HAS_PERMISSION),
    ]:
        graph.add_edge(
            UnifiedEdge(source=source, target=target, relationship=rel, source_scan_id=graph.scan_id, provenance={"collector": "fixture"})
        )
    return [CorrelationSnapshot.from_graph(graph) for graph in (prod, dev)]


@pytest.mark.parametrize(
    "kind",
    [
        "different_uid",
        "different_cluster",
        "different_account",
        "different_environment",
        "missing_uid",
        "missing_scope",
        "missing_provider",
        "same_occurrence",
        "same_kubernetes_container",
        "different_kubernetes_container",
        "kubernetes_without_name",
    ],
)
@pytest.mark.parametrize("engine", ["memory", "disk"])
def test_runtime_occurrence_joins_never_follow_shared_image_digest(tmp_path, kind, engine):
    snapshots = _snapshots(kind)
    if engine == "memory":
        result = merge_graph_snapshots(correlation_id="correlated", tenant_id="tenant", snapshots=snapshots)
    else:
        with CorrelationMergeWorkspace(
            correlation_id="correlated", tenant_id="tenant", created_at="2026-09-04T00:00:00Z", max_output_nodes=100, max_output_edges=100
        ) as workspace:
            for snapshot in snapshots:
                workspace.add_snapshot(snapshot)
            result = workspace.finish()
    expected = kind in {"same_occurrence", "same_kubernetes_container"}
    assert bool(compute_fused_attack_paths(result.graph)) is expected
    assert result.manifest["identity_version"] == "runtime-occurrence.v2"
    with open_graph_db(tmp_path / "graph.db") as connection:
        save_graph(connection, result.graph)
        restored = load_graph(connection, tenant_id="tenant", scan_id="correlated")
        assert bool(compute_fused_attack_paths(restored)) is expected
        assert len(load_graph(connection, tenant_id="foreign", scan_id="correlated").nodes) == 0


def test_legacy_correlated_receipts_require_recomputation():
    from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
    from agent_bom.graph.path_evidence import annotate_attack_path_evidence

    result = merge_graph_snapshots(correlation_id="correlated", tenant_id="tenant", snapshots=_snapshots("same_occurrence"))
    graph = result.graph
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE)
    for edge in graph.edges:
        edge.provenance["correlation"]["freshness"] = "fresh"
        edge.provenance["correlation"].pop("identity_version", None)
    original_edges = deepcopy([edge.to_dict() for edge in graph.edges])
    path = compute_fused_attack_paths(graph)[0]
    annotate_attack_path_evidence(path, graph)
    assert path.reachability != "confirmed"
    assert "correlation_recomputation_required" in path.reachability_basis
    assert original_edges == [edge.to_dict() for edge in graph.edges]


def test_recorrelating_legacy_output_does_not_upgrade_its_receipts():
    from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
    from agent_bom.graph.path_evidence import annotate_attack_path_evidence

    original = merge_graph_snapshots(correlation_id="legacy", tenant_id="tenant", snapshots=_snapshots("same_occurrence")).graph
    for edge in original.edges:
        edge.provenance["correlation"].pop("identity_version")
    another = deepcopy(original)
    another.scan_id = "copy"
    graph = merge_graph_snapshots(
        correlation_id="rerun",
        tenant_id="tenant",
        snapshots=[CorrelationSnapshot.from_graph(original), CorrelationSnapshot.from_graph(another)],
    ).graph
    graph.analysis_status["attack_path_fusion"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE)
    for edge in graph.edges:
        edge.provenance["correlation"]["freshness"] = "fresh"
    for path in compute_fused_attack_paths(graph):
        annotate_attack_path_evidence(path, graph)
        assert path.reachability != "confirmed"
        assert "correlation_recomputation_required" in path.reachability_basis


@pytest.mark.parametrize("engine", ["memory", "disk"])
def test_runtime_scope_dimensions_and_attributes_have_the_same_identity(engine):
    snapshots = _snapshots("same_occurrence")
    right = snapshots[1].graph.nodes["dev:container"]
    right.dimensions.cloud_provider = right.attributes.pop("cloud_provider")
    if engine == "memory":
        result = merge_graph_snapshots(correlation_id="correlated", tenant_id="tenant", snapshots=snapshots)
    else:
        with CorrelationMergeWorkspace(
            correlation_id="correlated", tenant_id="tenant", created_at="2026-09-04T00:00:00Z", max_output_nodes=100, max_output_edges=100
        ) as workspace:
            for snapshot in snapshots:
                workspace.add_snapshot(snapshot)
            result = workspace.finish()
    assert compute_fused_attack_paths(result.graph)


@pytest.mark.parametrize("kind", ["same_occurrence", "different_uid", "missing_uid"])
@pytest.mark.parametrize("engine", ["memory", "disk"])
def test_runtime_occurrences_survive_live_postgres_roundtrip(kind, engine):
    import os
    import uuid

    dsn = os.environ.get("AGENT_BOM_POSTGRES_URL")
    if not dsn:
        pytest.skip("AGENT_BOM_POSTGRES_URL not set")
    from psycopg_pool import ConnectionPool

    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    correlation_id = f"runtime-identity-{uuid.uuid4().hex}"
    snapshots = _snapshots(kind)
    if engine == "memory":
        result = merge_graph_snapshots(correlation_id=correlation_id, tenant_id="tenant", snapshots=snapshots)
    else:
        with CorrelationMergeWorkspace(
            correlation_id=correlation_id, tenant_id="tenant", created_at="2026-09-04T00:00:00Z", max_output_nodes=100, max_output_edges=100
        ) as workspace:
            for snapshot in snapshots:
                workspace.add_snapshot(snapshot)
            result = workspace.finish()
    with ConnectionPool(dsn, min_size=1, max_size=2) as pool:
        store = PostgresGraphStore(pool=pool)
        token = set_current_tenant("tenant")
        try:
            store.save_graph(result.graph)
            restored = store.load_graph(tenant_id="tenant", scan_id=correlation_id)
            assert bool(compute_fused_attack_paths(restored)) is (kind == "same_occurrence")
            assert all(edge.provenance["correlation"]["identity_version"] == "runtime-occurrence.v2" for edge in restored.edges)
            foreign = set_current_tenant("foreign")
            try:
                assert not store.load_graph(tenant_id="tenant", scan_id=correlation_id).nodes
            finally:
                reset_current_tenant(foreign)
        finally:
            store.delete_snapshot(tenant_id="tenant", scan_id=correlation_id)
            reset_current_tenant(token)
