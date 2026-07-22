"""Environment / capability weighting for fix-first path ranking."""

from __future__ import annotations

from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.path_ranking import (
    criticality_rank_meta,
    environment_weight,
    path_rank_tuple,
    tool_capability_boost,
)
from agent_bom.graph.types import EntityType


def test_environment_weight_prefers_production_and_criticality() -> None:
    prod = UnifiedNode(
        id="a",
        entity_type=EntityType.AGENT,
        label="a",
        attributes={"environment": "production"},
        dimensions=NodeDimensions(environment="production"),
    )
    critical = UnifiedNode(
        id="b",
        entity_type=EntityType.DATA_STORE,
        label="b",
        attributes={"asset_criticality": "critical"},
    )
    assert environment_weight(prod) == 1.15
    assert environment_weight(critical) == 1.25


def test_tool_capability_boost_from_execute_tags() -> None:
    tool = UnifiedNode(
        id="t",
        entity_type=EntityType.TOOL,
        label="shell",
        attributes={"capabilities": ["read", "execute"]},
    )
    assert tool_capability_boost(tool) > 0
    assert tool_capability_boost(
        UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a")
    ) == 0.0


def test_path_rank_tuple_raises_prod_paths_above_dev() -> None:
    graph = UnifiedGraph(scan_id="s", tenant_id="default", created_at="2026-07-01T00:00:00Z")
    graph.add_node(
        UnifiedNode(
            id="vuln",
            entity_type=EntityType.VULNERABILITY,
            label="CVE",
            attributes={"environment": "dev"},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="tool",
            entity_type=EntityType.TOOL,
            label="exec",
            attributes={"environment": "production", "capabilities": ["execute"]},
        )
    )
    low = AttackPath(
        source="vuln",
        target="vuln",
        hops=["vuln"],
        edges=[],
        composite_risk=8.0,
        summary="dev",
        credential_exposure=[],
        tool_exposure=[],
        vuln_ids=["CVE"],
    )
    high = AttackPath(
        source="vuln",
        target="tool",
        hops=["vuln", "tool"],
        edges=[],
        composite_risk=8.0,
        summary="prod",
        credential_exposure=[],
        tool_exposure=["exec"],
        vuln_ids=["CVE"],
    )
    assert path_rank_tuple(graph, high) > path_rank_tuple(graph, low)
    meta = criticality_rank_meta(graph, high)
    assert "production" in meta["environments"]
    assert "execute" in meta["tool_capabilities"]
