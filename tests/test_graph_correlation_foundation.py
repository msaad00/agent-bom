"""Deterministic, provenance-preserving graph correlation contracts."""

from __future__ import annotations

from copy import deepcopy

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots


def _graph(scan_id: str, tenant_id: str = "acme") -> UnifiedGraph:
    return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id, created_at=f"2026-08-{10 + int(scan_id[-1])}T12:00:00+00:00")


def _package(graph: UnifiedGraph, *, node_id: str, owner: str, severity: str, risk: float, source: str) -> None:
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.PACKAGE,
            label="pillow@9.0.0",
            severity=severity,
            risk_score=risk,
            attributes={
                "canonical_id": "pkg:pypi/pillow@9.0.0",
                "purl": "pkg:pypi/pillow@9.0.0",
                "owner": owner,
                "retained_when_newer_blank": "keep-me",
            },
            data_sources=[source],
        )
    )


def test_merge_is_order_independent_and_preserves_observations_and_conflicts() -> None:
    older = _graph("scan-1")
    newer = _graph("scan-2")
    _package(older, node_id="pkg:older", owner="platform", severity="critical", risk=9.8, source="repo")
    _package(newer, node_id="pkg:newer", owner="runtime", severity="medium", risk=5.0, source="image")
    newer.nodes["pkg:newer"].attributes["retained_when_newer_blank"] = ""

    first = merge_graph_snapshots(
        correlation_id="corr-1",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(older), CorrelationSnapshot.from_graph(newer)],
        created_at="2026-08-30T00:00:00+00:00",
    )
    second = merge_graph_snapshots(
        correlation_id="corr-1",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(deepcopy(newer)), CorrelationSnapshot.from_graph(deepcopy(older))],
        created_at="2026-08-30T00:00:00+00:00",
    )

    assert first.graph.to_dict() == second.graph.to_dict()
    assert len(first.graph.nodes) == 1
    node = next(iter(first.graph.nodes.values()))
    assert node.id == "pkg:newer"
    assert node.severity == "critical"
    assert node.risk_score == 9.8
    assert node.attributes["owner"] == "runtime"
    assert node.attributes["retained_when_newer_blank"] == "keep-me"
    correlation = node.attributes["correlation"]
    assert correlation["observation_count"] == 2
    assert correlation["source_scan_ids"] == ["scan-1", "scan-2"]
    assert correlation["conflict_fields"] == ["owner"]
    assert [item["scan_id"] for item in correlation["observations"]] == ["scan-1", "scan-2"]
    assert node.data_sources == ["image", "repo"]


def test_container_images_merge_only_on_exact_oci_digest() -> None:
    left = _graph("scan-1")
    right = _graph("scan-2")
    for graph, node_id in ((left, "container:app:latest"), (right, "container:registry/app:latest")):
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CONTAINER,
                label="app:latest",
                attributes={"container_image": "app:latest"},
            )
        )

    unpinned = merge_graph_snapshots(
        correlation_id="corr-unpinned",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(left), CorrelationSnapshot.from_graph(right)],
    )
    assert len(unpinned.graph.nodes) == 2

    digest = "sha256:" + "a" * 64
    left.nodes["container:app:latest"].attributes["image_digest"] = digest
    right.nodes["container:registry/app:latest"].attributes["repo_digest"] = f"registry/app@{digest}"
    pinned = merge_graph_snapshots(
        correlation_id="corr-pinned",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(left), CorrelationSnapshot.from_graph(right)],
    )
    assert len(pinned.graph.nodes) == 1
    node = next(iter(pinned.graph.nodes.values()))
    assert node.attributes["correlation"]["identity_basis"] == "oci_digest"


def test_packages_without_exact_purl_remain_snapshot_scoped() -> None:
    left = _graph("scan-1")
    right = _graph("scan-2")
    for graph in (left, right):
        graph.add_node(
            UnifiedNode(
                id="package:pillow:9.0.0",
                entity_type=EntityType.PACKAGE,
                label="pillow@9.0.0",
                attributes={"name": "pillow", "version": "9.0.0"},
            )
        )

    merged = merge_graph_snapshots(
        correlation_id="corr-no-purl",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(left), CorrelationSnapshot.from_graph(right)],
    )

    assert len(merged.graph.nodes) == 2


def test_repository_nodes_require_exact_commit_and_path_identity() -> None:
    left = _graph("scan-1")
    right = _graph("scan-2")
    for graph in (left, right):
        graph.add_node(
            UnifiedNode(
                id="source_file:app/main.py",
                entity_type=EntityType.SOURCE_FILE,
                label="main.py",
                attributes={"path": "app/main.py"},
            )
        )

    unpinned = merge_graph_snapshots(
        correlation_id="corr-unpinned-repo",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(left), CorrelationSnapshot.from_graph(right)],
    )
    assert len(unpinned.graph.nodes) == 2

    for graph in (left, right):
        graph.nodes["source_file:app/main.py"].attributes["repository_commit"] = "a" * 40
    pinned = merge_graph_snapshots(
        correlation_id="corr-pinned-repo",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(left), CorrelationSnapshot.from_graph(right)],
    )
    assert len(pinned.graph.nodes) == 1
    assert next(iter(pinned.graph.nodes.values())).attributes["correlation"]["identity_basis"] == "repository_commit_path"


def test_snapshot_scoped_mutable_images_with_same_node_id_remain_distinct() -> None:
    left = _graph("scan-1")
    right = _graph("scan-2")
    left.add_node(
        UnifiedNode(
            id="container:app",
            entity_type=EntityType.CONTAINER,
            label="app:latest",
            attributes={"container_image": "registry.example/app:latest"},
        )
    )
    right.add_node(
        UnifiedNode(
            id="container:app",
            entity_type=EntityType.CONTAINER,
            label="app:stable",
            attributes={"container_image": "registry.example/app:stable"},
        )
    )

    merged = merge_graph_snapshots(
        correlation_id="corr-same-id",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(left), CorrelationSnapshot.from_graph(right)],
    )

    assert len(merged.graph.nodes) == 2
    assert len(set(merged.graph.nodes)) == 2
    assert {node.label for node in merged.graph.nodes.values()} == {"app:latest", "app:stable"}


def test_same_label_without_shared_identity_does_not_merge_or_fabricate_edges() -> None:
    left = _graph("scan-1")
    right = _graph("scan-2")
    left.add_node(UnifiedNode(id="resource:left", entity_type=EntityType.CLOUD_RESOURCE, label="production"))
    right.add_node(UnifiedNode(id="resource:right", entity_type=EntityType.CLOUD_RESOURCE, label="production"))
    right.add_node(UnifiedNode(id="data:right", entity_type=EntityType.DATA_STORE, label="customer-data"))
    right.add_edge(UnifiedEdge(source="resource:right", target="data:right", relationship=RelationshipType.STORES))

    merged = merge_graph_snapshots(
        correlation_id="corr-labels",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(left), CorrelationSnapshot.from_graph(right)],
    )

    assert len(merged.graph.nodes) == 3
    assert len(merged.graph.edges) == 1
    edge = merged.graph.edges[0]
    assert (edge.source, edge.target) == ("resource:right", "data:right")


def test_edge_observations_are_union_preserved_after_endpoint_remap() -> None:
    left = _graph("scan-1")
    right = _graph("scan-2")
    for graph, suffix, source in ((left, "old", "repo"), (right, "new", "image")):
        graph.add_node(
            UnifiedNode(
                id=f"pkg:{suffix}",
                entity_type=EntityType.PACKAGE,
                label="pillow@9.0.0",
                attributes={"canonical_id": "pkg:pypi/pillow@9.0.0", "purl": "pkg:pypi/pillow@9.0.0"},
            )
        )
        graph.add_node(
            UnifiedNode(
                id=f"vuln:{suffix}",
                entity_type=EntityType.VULNERABILITY,
                label="CVE-2023-4863",
                attributes={"canonical_id": "CVE-2023-4863"},
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=f"pkg:{suffix}",
                target=f"vuln:{suffix}",
                relationship=RelationshipType.VULNERABLE_TO,
                evidence={"source": source},
                confidence=0.8 if source == "repo" else 1.0,
            )
        )

    merged = merge_graph_snapshots(
        correlation_id="corr-edges",
        tenant_id="acme",
        snapshots=[CorrelationSnapshot.from_graph(left), CorrelationSnapshot.from_graph(right)],
    )
    assert len(merged.graph.edges) == 1
    edge = merged.graph.edges[0]
    assert edge.source == "pkg:new"
    assert edge.target == "vuln:new"
    assert edge.confidence == 1.0
    assert edge.provenance["correlation"]["source_scan_ids"] == ["scan-1", "scan-2"]
    assert [item["scan_id"] for item in edge.provenance["correlation"]["observations"]] == ["scan-1", "scan-2"]


def test_merge_rejects_invalid_snapshot_sets() -> None:
    one = _graph("scan-1")
    with pytest.raises(ValueError, match="at least 2"):
        merge_graph_snapshots(correlation_id="corr", tenant_id="acme", snapshots=[CorrelationSnapshot.from_graph(one)])

    other_tenant = _graph("scan-2", tenant_id="other")
    with pytest.raises(ValueError, match="same tenant"):
        merge_graph_snapshots(
            correlation_id="corr",
            tenant_id="acme",
            snapshots=[CorrelationSnapshot.from_graph(one), CorrelationSnapshot.from_graph(other_tenant)],
        )
