"""Cost (FinOps) overlay: attach spend, roll up CONTAINS, fuse cost × risk."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.api.cost_store import LLMCostRecord
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.cost_overlay import apply_cost_overlay
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

_NOW = datetime(2026, 6, 25, 12, 0, 0, tzinfo=timezone.utc)


def _record(agent: str, cost: float, *, observed: str = "2026-06-20T00:00:00+00:00", cost_center: str = "") -> LLMCostRecord:
    return LLMCostRecord(
        tenant_id="t",
        call_id=f"{agent}-{cost}-{observed}",
        agent=agent,
        session_id="s",
        provider="openai",
        model="gpt-4o",
        input_tokens=1000,
        output_tokens=500,
        cost_usd=cost,
        priced=True,
        observed_at=observed,
        cost_center=cost_center,
    )


def _org_account_agent_graph() -> UnifiedGraph:
    """org CONTAINS account CONTAINS agent — the canonical roll-up chain."""
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="org:acme", entity_type=EntityType.ORG, label="acme"))
    graph.add_node(UnifiedNode(id="account:prod", entity_type=EntityType.ACCOUNT, label="prod-account"))
    graph.add_node(UnifiedNode(id="agent:billing-bot", entity_type=EntityType.AGENT, label="billing-bot"))
    graph.add_node(UnifiedNode(id="agent:support-bot", entity_type=EntityType.AGENT, label="support-bot"))
    graph.add_edge(UnifiedEdge(source="org:acme", target="account:prod", relationship=RelationshipType.CONTAINS))
    graph.add_edge(UnifiedEdge(source="account:prod", target="agent:billing-bot", relationship=RelationshipType.CONTAINS))
    graph.add_edge(UnifiedEdge(source="account:prod", target="agent:support-bot", relationship=RelationshipType.CONTAINS))
    return graph


def test_cost_attaches_to_named_agent_node():
    graph = _org_account_agent_graph()
    stats = apply_cost_overlay(graph, [_record("billing-bot", 42.0)], _NOW)

    bot = graph.nodes["agent:billing-bot"]
    assert bot.attributes["cost_usd"] == 42.0
    assert bot.attributes["cost_usd_30d"] == 42.0
    assert bot.attributes["cost_calls"] == 1
    assert "cost-overlay" in bot.data_sources
    # unrelated agent gets nothing
    assert "cost_usd" not in graph.nodes["agent:support-bot"].attributes
    assert stats["cost_nodes"] == 1


def test_subtree_rollup_sums_up_a_contains_chain():
    graph = _org_account_agent_graph()
    apply_cost_overlay(
        graph,
        [_record("billing-bot", 100.0), _record("support-bot", 25.0)],
        _NOW,
    )

    # leaf carries own spend; parents carry SUM of subtree.
    assert graph.nodes["agent:billing-bot"].attributes["subtree_cost_usd"] == 100.0
    assert graph.nodes["agent:support-bot"].attributes["subtree_cost_usd"] == 25.0
    assert graph.nodes["account:prod"].attributes["subtree_cost_usd"] == 125.0
    assert graph.nodes["org:acme"].attributes["subtree_cost_usd"] == 125.0


def test_window_split_30d_vs_all_time():
    graph = _org_account_agent_graph()
    apply_cost_overlay(
        graph,
        [
            _record("billing-bot", 10.0, observed="2026-06-24T00:00:00+00:00"),  # in window
            _record("billing-bot", 90.0, observed="2026-01-01T00:00:00+00:00"),  # out of window
        ],
        _NOW,
    )
    bot = graph.nodes["agent:billing-bot"]
    assert bot.attributes["cost_usd"] == 100.0
    assert bot.attributes["cost_usd_30d"] == 10.0


def test_expensive_and_exposed_gets_fused_signal():
    graph = _org_account_agent_graph()
    # mark the billing bot internet-exposed (as the CNAPP overlay would)
    graph.nodes["agent:billing-bot"].attributes["internet_exposed"] = True
    stats = apply_cost_overlay(graph, [_record("billing-bot", 500.0)], _NOW)

    bot = graph.nodes["agent:billing-bot"]
    assert bot.attributes["cost_risk_priority"] == "expensive_and_exposed"
    assert bot.attributes["cost_risk_spend_usd"] == 500.0
    assert stats["fused_signals"] == 1
    assert any(r.pattern == "expensive_and_exposed" and "billing-bot" in r.agents for r in graph.interaction_risks)


def test_expensive_but_not_risky_is_not_fused():
    graph = _org_account_agent_graph()
    stats = apply_cost_overlay(graph, [_record("billing-bot", 9999.0)], _NOW)
    assert "cost_risk_priority" not in graph.nodes["agent:billing-bot"].attributes
    assert stats["fused_signals"] == 0


def test_risky_but_cheap_is_not_fused():
    graph = _org_account_agent_graph()
    graph.nodes["agent:billing-bot"].attributes["internet_exposed"] = True
    stats = apply_cost_overlay(graph, [_record("billing-bot", 1.0)], _NOW)
    assert "cost_risk_priority" not in graph.nodes["agent:billing-bot"].attributes
    assert stats["fused_signals"] == 0


def test_empty_cost_records_is_total_noop():
    graph = _org_account_agent_graph()
    before = graph.to_dict()
    stats = apply_cost_overlay(graph, [], _NOW)
    after = graph.to_dict()
    assert before == after
    assert stats == {"cost_nodes": 0, "rollup_nodes": 0, "fused_signals": 0}


def test_apply_twice_is_idempotent():
    graph = _org_account_agent_graph()
    graph.nodes["agent:billing-bot"].attributes["internet_exposed"] = True
    records = [_record("billing-bot", 500.0), _record("support-bot", 25.0)]

    apply_cost_overlay(graph, records, _NOW)
    snapshot = graph.to_dict()
    risk_count = len(graph.interaction_risks)

    apply_cost_overlay(graph, records, _NOW)
    assert graph.to_dict() == snapshot
    # the advisory interaction-risk is de-duplicated, not re-appended.
    assert len(graph.interaction_risks) == risk_count


def test_cost_center_allocation_tag_matches_node():
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    # node carries a cost_center attribute; record names that cost_center.
    graph.add_node(
        UnifiedNode(
            id="agent:fleet",
            entity_type=EntityType.AGENT,
            label="fleet-agent",
            attributes={"cost_center": "platform-team"},
        )
    )
    apply_cost_overlay(graph, [_record("other-name", 30.0, cost_center="platform-team")], _NOW)
    assert graph.nodes["agent:fleet"].attributes["cost_usd"] == 30.0


def test_rollup_is_cycle_safe():
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
    graph.add_node(UnifiedNode(id="agent:b", entity_type=EntityType.AGENT, label="b"))
    # a CONTAINS b, b CONTAINS a (pathological cycle) — must terminate.
    graph.add_edge(UnifiedEdge(source="agent:a", target="agent:b", relationship=RelationshipType.CONTAINS))
    graph.add_edge(UnifiedEdge(source="agent:b", target="agent:a", relationship=RelationshipType.CONTAINS))
    stats = apply_cost_overlay(graph, [_record("a", 10.0), _record("b", 20.0)], _NOW)
    # Terminates and each node's own cost is counted exactly once per subtree —
    # the cycle does NOT inflate the sum beyond total spend (10 + 20 = 30).
    assert graph.nodes["agent:a"].attributes["subtree_cost_usd"] == 30.0
    assert graph.nodes["agent:b"].attributes["subtree_cost_usd"] == 30.0
    assert stats["cost_nodes"] == 2


def test_builder_wires_cost_overlay_from_report():
    from agent_bom.graph.builder import build_unified_graph_from_report

    report = {
        "scan_id": "scan-1",
        "agents": [{"name": "billing-bot", "type": "custom", "source": "local"}],
        "llm_cost_records": [
            {
                "tenant_id": "t",
                "call_id": "c1",
                "agent": "billing-bot",
                "session_id": "s",
                "provider": "openai",
                "model": "gpt-4o",
                "input_tokens": 1,
                "output_tokens": 1,
                "cost_usd": 12.5,
                "priced": True,
                "observed_at": "2026-06-24T00:00:00+00:00",
            }
        ],
    }
    graph = build_unified_graph_from_report(report)
    agent_nodes = [n for n in graph.nodes.values() if n.entity_type == EntityType.AGENT]
    assert len(agent_nodes) == 1
    assert agent_nodes[0].attributes["cost_usd"] == 12.5


def test_builder_without_cost_records_leaves_no_cost_attrs():
    from agent_bom.graph.builder import build_unified_graph_from_report

    report = {
        "scan_id": "scan-1",
        "agents": [{"name": "billing-bot", "type": "custom", "source": "local"}],
    }
    graph = build_unified_graph_from_report(report)
    for node in graph.nodes.values():
        assert "cost_usd" not in node.attributes
        assert "subtree_cost_usd" not in node.attributes
