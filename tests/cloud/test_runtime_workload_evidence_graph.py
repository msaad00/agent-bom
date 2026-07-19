"""Graph-join enrichment for CWPP runtime workload evidence (#4158 stage 3).

The enrichment annotates a workload node's attributes with additive runtime
evidence. It must NEVER add an edge (reachability stays edge-derived) and must
refuse to cross the tenant boundary in the graph join.
"""

from __future__ import annotations

from agent_bom.cloud.runtime_workload_evidence import (
    STATE_HAS_IOC,
    RuntimeWorkloadEvidenceIndex,
    RuntimeWorkloadSignal,
    enrich_graph_workload_runtime_evidence,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType


def _signal(tenant: str = "tenant-a") -> RuntimeWorkloadSignal:
    return RuntimeWorkloadSignal(
        tenant_id=tenant,
        provider="aws",
        account_id="123456789012",
        workload_ref="i-0abc",
        signal_type="ioc_detection",  # type: ignore[arg-type]
        severity="high",
        observed_at="2026-07-18T12:00:00Z",
        source_id="edr-1",
        source_kind="edr",
        dedup_key="evt-1",
        title="known C2",
        evidence={"ioc_type": "domain"},
    )


def _workload_graph(tenant: str = "tenant-a") -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant)
    # Mirrors the builder's CWPP side-scan target node (builder.py ~4445).
    graph.add_node(
        UnifiedNode(
            id="cloud_resource:aws:cwpp:managed_disk:i-0abc",
            entity_type=EntityType.CLOUD_RESOURCE,
            label="managed_disk: i-0abc",
            attributes={
                "resource_id": "i-0abc",
                "resource_type": "workload_disk",
                "resource_kind": "managed_disk",
                "cloud_provider": "aws",
                "cloud_service": "cwpp-side-scan",
                "account_id": "123456789012",
            },
            dimensions=NodeDimensions(cloud_provider="aws", surface="cwpp"),
        )
    )
    return graph


def test_graph_enrichment_annotates_workload_node_without_new_edges():
    graph = _workload_graph()
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", [_signal()])
    edges_before = len(graph.edges)
    count = enrich_graph_workload_runtime_evidence(graph, index)
    assert count == 1
    node = graph.nodes["cloud_resource:aws:cwpp:managed_disk:i-0abc"]
    ev = node.attributes["runtime_evidence"]
    assert ev["state"] == STATE_HAS_IOC
    assert ev["clean_workload_assertion"] is False
    # reachability is never fabricated: no edges added
    assert len(graph.edges) == edges_before


def test_graph_enrichment_refuses_cross_tenant_join():
    graph = _workload_graph(tenant="tenant-b")
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", [_signal(tenant="tenant-a")])
    count = enrich_graph_workload_runtime_evidence(graph, index)
    assert count == 0
    node = graph.nodes["cloud_resource:aws:cwpp:managed_disk:i-0abc"]
    assert "runtime_evidence" not in node.attributes


def test_graph_enrichment_marks_unmatched_workload_no_signal_not_clean():
    graph = _workload_graph()
    index = RuntimeWorkloadEvidenceIndex.from_signals("tenant-a", [])  # no signals
    count = enrich_graph_workload_runtime_evidence(graph, index)
    assert count == 1
    node = graph.nodes["cloud_resource:aws:cwpp:managed_disk:i-0abc"]
    assert node.attributes["runtime_evidence"]["state"] == "no_runtime_signal"
    assert node.attributes["runtime_evidence"]["clean_workload_assertion"] is False
