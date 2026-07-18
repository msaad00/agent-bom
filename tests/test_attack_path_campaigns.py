"""Bounded partitioned attack-path campaign engine for large estates.

These tests pin the #4156 contract: graphs above the node cap must no longer
produce an all-or-nothing fusion skip. Instead they yield bounded, partitioned
campaigns + top attack paths with an *honest* completeness status, deterministic
campaign identity, cross-partition reconciliation from authoritative edges, and a
bounded working set (no full-estate path enumeration).
"""

from __future__ import annotations

from agent_bom.graph.analysis import GraphAnalysisState
from agent_bom.graph.attack_path_campaigns import (
    _MAX_PARTITION_NODES,
    compute_partitioned_campaigns,
)
from agent_bom.graph.attack_path_fusion import _MAX_NODES, apply_attack_path_fusion
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _entry(node_id: str, account: str, *, risk: float = 5.0) -> UnifiedNode:
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.CLOUD_RESOURCE,
        label=node_id,
        risk_score=risk,
        attributes={"internet_exposed": True, "account_id": account},
    )


def _jewel(node_id: str, account: str) -> UnifiedNode:
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.DATA_STORE,
        label=node_id,
        attributes={
            "account_id": account,
            "data_sensitivity": "sensitive",
            "data_regulatory_frameworks": ["PCI-DSS"],
            "owner": f"team-{account}",
        },
    )


def _plain(node_id: str, account: str) -> UnifiedNode:
    return UnifiedNode(
        id=node_id,
        entity_type=EntityType.CLOUD_RESOURCE,
        label=node_id,
        attributes={"account_id": account},
    )


def _pad(graph: UnifiedGraph, count: int, account: str = "acct-pad") -> None:
    """Inflate the graph past the node cap with inert isolated nodes."""
    for i in range(count):
        graph.add_node(
            UnifiedNode(id=f"pad-{account}-{i}", entity_type=EntityType.PACKAGE, label=f"p{i}", attributes={"account_id": account})
        )


def _large_single_partition_graph() -> UnifiedGraph:
    g = UnifiedGraph(scan_id="s", tenant_id="tenant-alpha")
    g.add_node(_entry("entry", "acct-a", risk=9.0))
    g.add_node(_jewel("ds:crown", "acct-a"))
    g.add_edge(UnifiedEdge(source="entry", target="ds:crown", relationship=RelationshipType.STORES))
    _pad(g, _MAX_NODES + 10, account="acct-a")
    return g


def test_large_graph_produces_campaigns_instead_of_skip() -> None:
    g = _large_single_partition_graph()
    result = compute_partitioned_campaigns(g)
    assert result.paths, "large estate must now yield bounded fused paths, not a blanket skip"
    assert result.campaigns, "paths must be clustered into at least one campaign"
    assert result.status.status is GraphAnalysisState.LIMITED
    assert "partitioned" in result.status.reason_codes


def test_large_graph_status_is_never_complete_and_never_skipped() -> None:
    g = _large_single_partition_graph()
    result = compute_partitioned_campaigns(g)
    # A bounded/partitioned run must never over-claim completeness, and must never
    # regress to the old all-or-nothing SKIPPED.
    assert result.status.status is not GraphAnalysisState.COMPLETE
    assert result.status.status is not GraphAnalysisState.SKIPPED


def test_empty_estate_stays_empty_no_fabrication() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="tenant-alpha")
    # No entries and no jewels — just inert padding past the cap.
    _pad(g, _MAX_NODES + 10)
    result = compute_partitioned_campaigns(g)
    assert result.paths == []
    assert result.campaigns == []
    # Honest: 0 paths, but still a bounded partitioned scan (not falsely COMPLETE).
    assert result.status.status is GraphAnalysisState.LIMITED
    assert result.status.observed["result_count"] == 0


def test_no_jewel_yields_no_campaigns() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="tenant-alpha")
    g.add_node(_entry("entry", "acct-a"))
    g.add_node(_plain("mid", "acct-a"))
    g.add_edge(UnifiedEdge(source="entry", target="mid", relationship=RelationshipType.CAN_ACCESS))
    _pad(g, _MAX_NODES + 10)
    result = compute_partitioned_campaigns(g)
    assert result.paths == []
    assert result.campaigns == []


def test_cross_partition_path_is_reconciled() -> None:
    """Entry in account A -> (cross-account ASSUMES) -> crown jewel in account B.

    The reconciliation must stitch the authoritative cross-partition edge; a purely
    intra-partition engine would miss this chain entirely.
    """
    g = UnifiedGraph(scan_id="s", tenant_id="tenant-alpha")
    g.add_node(_entry("entry", "acct-a", risk=9.0))
    g.add_node(_plain("role-b", "acct-b"))
    g.add_node(_jewel("ds:crown", "acct-b"))
    # entry(A) --ASSUMES--> role-b(B) --CAN_ACCESS--> jewel(B)
    g.add_edge(UnifiedEdge(source="entry", target="role-b", relationship=RelationshipType.ASSUMES))
    g.add_edge(UnifiedEdge(source="role-b", target="ds:crown", relationship=RelationshipType.CAN_ACCESS))
    _pad(g, _MAX_NODES + 10)
    result = compute_partitioned_campaigns(g)
    cross = [p for p in result.paths if p.source == "entry" and p.target == "ds:crown"]
    assert cross, "cross-partition entry->jewel chain must be found by reconciliation"
    assert "role-b" in cross[0].hops
    assert "cross_partition" in result.status.reason_codes
    assert result.status.observed["cross_partition_paths"] >= 1
    campaign = next(c for c in result.campaigns if c.crown_jewel == "ds:crown")
    assert campaign.cross_partition is True


def test_campaign_ids_are_deterministic_across_runs() -> None:
    g1 = _large_single_partition_graph()
    g2 = _large_single_partition_graph()
    ids1 = [c.campaign_id for c in compute_partitioned_campaigns(g1).campaigns]
    ids2 = [c.campaign_id for c in compute_partitioned_campaigns(g2).campaigns]
    assert ids1 == ids2
    assert all(cid for cid in ids1)


def test_campaign_id_isolated_per_tenant() -> None:
    g_a = _large_single_partition_graph()
    g_b = _large_single_partition_graph()
    g_b.tenant_id = "tenant-beta"
    id_a = compute_partitioned_campaigns(g_a).campaigns[0].campaign_id
    id_b = compute_partitioned_campaigns(g_b).campaigns[0].campaign_id
    assert id_a != id_b, "same jewel under a different tenant must not collide"


def test_working_set_is_bounded_not_full_estate() -> None:
    g = _large_single_partition_graph()
    result = compute_partitioned_campaigns(g)
    peak = result.status.observed["peak_working_set"]
    assert peak <= _MAX_PARTITION_NODES
    assert peak < len(g.nodes), "the analysis must never materialize the whole estate at once"


def test_campaign_carries_decision_fields() -> None:
    g = _large_single_partition_graph()
    campaign = compute_partitioned_campaigns(g).campaigns[0]
    assert campaign.crown_jewel == "ds:crown"
    assert campaign.owner == "team-acct-a"
    assert "PCI-DSS" in campaign.business_impact
    assert campaign.exploitability > 0
    assert campaign.expected_risk_reduction > 0
    assert campaign.path_count >= 1
    assert campaign.top_path_summary


def test_apply_materialises_campaigns_on_large_graph() -> None:
    g = _large_single_partition_graph()
    stats = apply_attack_path_fusion(g)
    assert stats["fused_attack_paths"] >= 1
    assert stats.get("bounded") is True
    assert stats.get("partitioned") is True
    assert stats["campaign_count"] >= 1
    assert "skipped" not in stats
    assert g.attack_campaigns, "campaigns must be attached to the graph for the product surface"
    assert g.analysis_status["attack_path_fusion"].status is GraphAnalysisState.LIMITED
    # Materialised member paths surface via the existing attack_paths API with no new plumbing.
    assert any(p.target == "ds:crown" for p in g.attack_paths)


def test_apply_is_idempotent_on_large_graph() -> None:
    g = _large_single_partition_graph()
    apply_attack_path_fusion(g)
    first_paths = len(g.attack_paths)
    first_campaigns = [c.campaign_id for c in g.attack_campaigns]
    apply_attack_path_fusion(g)
    assert len(g.attack_paths) == first_paths
    assert [c.campaign_id for c in g.attack_campaigns] == first_campaigns
