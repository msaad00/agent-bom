"""Bounded correlation workspace parity and cleanup contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.correlation import CorrelationSnapshot, merge_graph_snapshots
from agent_bom.graph.correlation_workspace import CorrelationMergeBudgetError, CorrelationMergeWorkspace


def _snapshot(scan_id: str, created_at: str, owner: str, *, extra: bool = False) -> CorrelationSnapshot:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id="tenant-a", created_at=created_at)
    graph.add_node(
        UnifiedNode(
            id=f"package:{scan_id}",
            entity_type=EntityType.PACKAGE,
            label="pillow@9.0.0",
            severity="critical" if scan_id == "repo" else "medium",
            risk_score=9.8 if scan_id == "repo" else 5.0,
            attributes={"purl": "pkg:pypi/pillow@9.0.0", "owner": owner},
            data_sources=[scan_id],
        )
    )
    graph.add_node(
        UnifiedNode(
            id=f"vulnerability:{scan_id}",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2023-4863",
            attributes={"canonical_id": "CVE-2023-4863"},
        )
    )
    graph.add_edge(
        UnifiedEdge(
            source=f"package:{scan_id}",
            target=f"vulnerability:{scan_id}",
            relationship=RelationshipType.VULNERABLE_TO,
            confidence=0.8 if scan_id == "repo" else 1.0,
            evidence={"source": scan_id},
        )
    )
    if extra:
        graph.add_node(
            UnifiedNode(
                id="agent:runtime",
                entity_type=EntityType.AGENT,
                label="runtime",
                attributes={"runtime_id": "runtime-1"},
            )
        )
    return CorrelationSnapshot.from_graph(graph)


def _workspace_merge(snapshots: list[CorrelationSnapshot], tmp_path: Path):
    workspace = CorrelationMergeWorkspace(
        correlation_id="corr-parity",
        tenant_id="tenant-a",
        created_at="2026-08-30T12:00:00+00:00",
        max_output_nodes=100,
        max_output_edges=100,
    )
    workspace_path = workspace._path
    with workspace:
        for snapshot in snapshots:
            workspace.add_snapshot(snapshot)
        merged = workspace.finish()
    assert not workspace_path.exists()
    return merged


def test_disk_backed_merge_is_byte_identical_to_in_memory_contract(tmp_path: Path) -> None:
    older = _snapshot("repo", "2026-08-30T10:00:00+00:00", "platform")
    newer = _snapshot("image", "2026-08-30T11:00:00+00:00", "runtime", extra=True)

    expected = merge_graph_snapshots(
        correlation_id="corr-parity",
        tenant_id="tenant-a",
        snapshots=[older, newer],
        created_at="2026-08-30T12:00:00+00:00",
    )
    actual = _workspace_merge([newer, older], tmp_path)

    assert actual.graph.to_dict() == expected.graph.to_dict()
    assert actual.manifest == expected.manifest
    assert actual.manifest_sha256 == expected.manifest_sha256


def test_disk_backed_merge_applies_exact_output_budget_progressively() -> None:
    older = _snapshot("repo", "2026-08-30T10:00:00+00:00", "platform")
    newer = _snapshot("image", "2026-08-30T11:00:00+00:00", "runtime", extra=True)

    with CorrelationMergeWorkspace(
        correlation_id="corr-bounded",
        tenant_id="tenant-a",
        created_at="2026-08-30T12:00:00+00:00",
        max_output_nodes=2,
        max_output_edges=100,
    ) as workspace:
        workspace.add_snapshot(older)
        with pytest.raises(CorrelationMergeBudgetError, match="node_limit"):
            workspace.add_snapshot(newer)
