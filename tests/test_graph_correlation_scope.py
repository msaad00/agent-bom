"""Correlation must not create paths by joining differently located identities."""

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.correlation import CorrelationSnapshot, correlation_identity, merge_graph_snapshots
from agent_bom.graph.correlation_workspace import CorrelationMergeWorkspace
from agent_bom.graph.node import NodeDimensions


def _node(kind, attributes, dimensions=None):
    return UnifiedNode(
        id="shared", entity_type=kind, label="same local identifier", attributes=attributes, dimensions=NodeDimensions(**(dimensions or {}))
    )


@pytest.mark.parametrize(
    "kind,key",
    [(EntityType.CLOUD_RESOURCE, "resource_id"), (EntityType.SERVICE_PRINCIPAL, "principal_id"), (EntityType.AGENT, "runtime_id")],
)
def test_provider_dimension_is_an_identity_boundary(kind, key):
    aws = _node(kind, {key: "local-42"}, {"cloud_provider": "aws"})
    azure = _node(kind, {key: "local-42"}, {"cloud_provider": "azure"})
    assert correlation_identity(aws, scan_id="one") != correlation_identity(azure, scan_id="two")


@pytest.mark.parametrize("scope", ["cluster_id", "runtime_host_id", "environment"])
@pytest.mark.parametrize("kind", [EntityType.AGENT, EntityType.SERVER, EntityType.TOOL])
def test_runtime_local_identifiers_keep_deployment_scope(scope, kind):
    left = _node(kind, {"runtime_id": "same", scope: "left"})
    right = _node(kind, {"runtime_id": "same", scope: "right"})
    assert correlation_identity(left, scan_id="one") != correlation_identity(right, scan_id="two")


def test_provider_attribute_and_dimension_agree_but_conflicts_do_not_merge():
    attrs = _node(EntityType.CLOUD_RESOURCE, {"resource_id": "same", "cloud_provider": "aws"})
    dims = _node(EntityType.CLOUD_RESOURCE, {"resource_id": "same"}, {"cloud_provider": "aws"})
    conflict = _node(EntityType.CLOUD_RESOURCE, {"resource_id": "same", "cloud_provider": "aws"}, {"cloud_provider": "azure"})
    assert correlation_identity(attrs, scan_id="one") == correlation_identity(dims, scan_id="two")
    assert correlation_identity(attrs, scan_id="one") != correlation_identity(conflict, scan_id="three")


@pytest.mark.parametrize("disk_backed", [False, True])
def test_provider_collision_cannot_fabricate_an_investigation_path(disk_backed):
    snapshots = []
    for scan, provider in (("one", "aws"), ("two", "azure")):
        g = UnifiedGraph(tenant_id="tenant-a", scan_id=scan, created_at="2026-10-01T00:00:00Z")
        g.add_node(_node(EntityType.CLOUD_RESOURCE, {"resource_id": "shared-name"}, {"cloud_provider": provider}))
        g.add_node(UnifiedNode(id=scan, entity_type=EntityType.AGENT if scan == "one" else EntityType.CREDENTIAL, label=scan))
        g.add_edge(
            UnifiedEdge(
                source=scan if scan == "one" else "shared",
                target="shared" if scan == "one" else scan,
                relationship=RelationshipType.CAN_ACCESS,
            )
        )
        snapshots.append(CorrelationSnapshot.from_graph(g))
    if disk_backed:
        with CorrelationMergeWorkspace(
            correlation_id="corr", tenant_id="tenant-a", created_at="2026-10-01T01:00:00Z", max_output_nodes=10, max_output_edges=10
        ) as workspace:
            for snapshot in snapshots:
                workspace.add_snapshot(snapshot)
            result = workspace.finish()
    else:
        result = merge_graph_snapshots(correlation_id="corr", tenant_id="tenant-a", snapshots=snapshots)
    assert len(result.graph.nodes) == 4
    edges = result.graph.edges
    assert len(edges) == 2 and edges[0].target != edges[1].source
    assert all(len(node.attributes["correlation"]["source_scan_ids"]) == 1 for node in result.graph.nodes.values())


@pytest.mark.parametrize(
    "kind,left_key,right_key",
    [
        (EntityType.CLOUD_RESOURCE, "kubernetes_uid", "resource_id"),
        (EntityType.SERVICE_PRINCIPAL, "object_id", "client_id"),
        (EntityType.AGENT, "runtime_id", "canonical_id"),
    ],
)
def test_distinct_identifier_namespaces_never_join(kind, left_key, right_key):
    left = _node(kind, {left_key: "same", "cloud_provider": "azure", "account_id": "account"})
    right = _node(kind, {right_key: "same", "cloud_provider": "azure", "account_id": "account"})
    assert correlation_identity(left, scan_id="one") != correlation_identity(right, scan_id="two")


@pytest.mark.parametrize("scope", ["cluster_id", "region", "namespace"])
def test_provider_local_resource_ids_preserve_recorded_location(scope):
    left = _node(EntityType.CLOUD_RESOURCE, {"resource_id": "same", scope: "left"})
    right = _node(EntityType.CLOUD_RESOURCE, {"resource_id": "same", scope: "right"})
    assert correlation_identity(left, scan_id="one") != correlation_identity(right, scan_id="two")


def test_explicit_arn_aliases_preserve_exact_join():
    left = _node(EntityType.CLOUD_RESOURCE, {"arn": "arn:aws:s3:::same", "cloud_provider": "aws"})
    right = _node(EntityType.CLOUD_RESOURCE, {"resource_arn": "arn:aws:s3:::same"}, {"cloud_provider": "aws"})
    assert correlation_identity(left, scan_id="one") == correlation_identity(right, scan_id="two")
