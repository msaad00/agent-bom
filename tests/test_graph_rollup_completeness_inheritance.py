"""A roll-up of a truncated snapshot is still truncated.

``rollup_view`` computed completeness purely from its OWN orphan-limit cut and
ignored ``graph.completeness``. Budget-truncate a 61-node estate down to 15 and
``filtered_view`` correctly said "truncated" while the roll-up answered
``{"status": "complete", "complete": true}`` next to ``summary.total_nodes: 15``
— a complete-looking read of a quarter of the estate.

The roll-up cannot know what the 46 dropped nodes contained; the only honest
answer says so, keeps the estate total the SOURCE had, and names both reasons
when both cuts applied.
"""

from __future__ import annotations

import pytest

from agent_bom.graph.container import UnifiedGraph, apply_node_budget
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.rollup import attack_path_view, drill_down, rollup_view
from agent_bom.graph.types import EntityType, RelationshipType

ESTATE_NODES = 61
NODE_BUDGET = 15


def _estate() -> UnifiedGraph:
    """One account containing 60 resources — 61 nodes with a CONTAINS tree."""
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="account:1", entity_type=EntityType.ACCOUNT, label="prod", risk_score=99.0))
    for index in range(ESTATE_NODES - 1):
        node_id = f"res:{index:03d}"
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=node_id,
                severity="high",
                risk_score=float(index),
            )
        )
        graph.add_edge(UnifiedEdge(source="account:1", target=node_id, relationship=RelationshipType.CONTAINS))
    return graph


def _truncated_estate() -> UnifiedGraph:
    graph = apply_node_budget(_estate(), NODE_BUDGET)
    assert graph.completeness.truncated is True
    assert len(graph.nodes) == NODE_BUDGET
    return graph


def test_rollup_of_a_truncated_snapshot_reports_truncated():
    payload = rollup_view(_truncated_estate())
    completeness = payload["completeness"]
    assert completeness["truncated"] is True, "the roll-up claimed a complete read of a bounded snapshot"
    assert completeness["complete"] is False
    assert completeness["status"] == "truncated"
    assert "node_budget" in completeness["reason"]


def test_rollup_summary_carries_the_pre_truncation_estate_total():
    """``summary.total_nodes: 15`` is what this roll-up saw; 61 is the estate."""
    summary = rollup_view(_truncated_estate())["summary"]
    assert summary["total_nodes"] == NODE_BUDGET
    assert summary["total_nodes_source"] == ESTATE_NODES


def test_rollup_of_a_complete_snapshot_stays_complete():
    payload = rollup_view(_estate())
    assert payload["completeness"]["complete"] is True
    assert payload["completeness"].get("reason", "") == ""
    assert payload["summary"]["total_nodes_source"] == ESTATE_NODES


def test_orphan_limit_truncation_still_reported_on_its_own():
    """The roll-up's own cut must survive the change — no regression."""
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    for index in range(260):  # > _MAX_TOP_LEVEL_ORPHANS, no CONTAINS tree
        graph.add_node(UnifiedNode(id=f"orphan:{index:03d}", entity_type=EntityType.PACKAGE, label=str(index)))

    completeness = rollup_view(graph)["completeness"]
    assert completeness["truncated"] is True
    assert completeness["reason"] == "orphan_limit"


def test_both_cuts_are_named_when_both_applied():
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    for index in range(400):
        graph.add_node(UnifiedNode(id=f"orphan:{index:03d}", entity_type=EntityType.PACKAGE, label=str(index), risk_score=float(index)))
    apply_node_budget(graph, 300)

    reason = rollup_view(graph)["completeness"]["reason"]
    assert "node_budget" in reason
    assert "orphan_limit" in reason


def test_drill_down_of_a_truncated_snapshot_reports_truncated():
    payload = drill_down(_truncated_estate(), "account:1")
    assert payload["completeness"]["truncated"] is True
    assert "node_budget" in payload["completeness"]["reason"]


def test_drill_down_of_a_complete_snapshot_stays_complete():
    payload = drill_down(_estate(), "account:1")
    assert payload["completeness"]["complete"] is True


def test_drill_down_of_a_missing_node_still_declares_source_truncation():
    """A missing node over a bounded snapshot may only mean "never loaded"."""
    payload = drill_down(_truncated_estate(), "res:999")
    assert payload["node"] is None
    assert payload["completeness"]["truncated"] is True


def test_attack_path_rollup_view_inherits_source_truncation():
    payload = attack_path_view(_truncated_estate(), [])
    assert payload["completeness"]["truncated"] is True
    assert "node_budget" in payload["completeness"]["reason"]
    assert payload["summary"]["total_nodes_source"] == ESTATE_NODES


@pytest.mark.parametrize("builder", [rollup_view, lambda g: attack_path_view(g, [])])
def test_returned_never_exceeds_total(builder):
    payload = builder(_truncated_estate())
    completeness = payload["completeness"]
    assert completeness["returned"] <= completeness["total"]
