"""CODE/CI graph overlays — emit reserved kinds only when evidence exists."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_bom.graph.ci_graph_overlay import apply_ci_graph_overlay
from agent_bom.graph.code_graph_overlay import apply_code_graph_overlay
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def test_code_graph_overlay_emits_modules_from_source_files() -> None:
    graph = UnifiedGraph(scan_id="s1", tenant_id="default", created_at="2026-07-01T00:00:00Z")
    graph.add_node(
        UnifiedNode(
            id="directory:src",
            entity_type=EntityType.DIRECTORY,
            label="src",
            attributes={"path": "src"},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="source_file:src/main.py",
            entity_type=EntityType.SOURCE_FILE,
            label="main.py",
            attributes={"path": "src/main.py"},
        )
    )

    counts = apply_code_graph_overlay(graph, {}, datetime(2026, 7, 1, tzinfo=timezone.utc))
    assert counts["code_modules"] == 1
    assert "code_module:src" in graph.nodes
    assert any(edge.relationship == RelationshipType.DEFINES for edge in graph.edges)


def test_code_graph_overlay_noop_without_source_files() -> None:
    graph = UnifiedGraph(scan_id="s1", tenant_id="default", created_at="2026-07-01T00:00:00Z")
    counts = apply_code_graph_overlay(graph, {}, datetime(2026, 7, 1, tzinfo=timezone.utc))
    assert counts == {"code_modules": 0, "defines_edges": 0, "contains_edges": 0}
    assert graph.nodes == {}


def test_ci_graph_overlay_emits_jobs_from_github_actions_agents() -> None:
    graph = UnifiedGraph(scan_id="s1", tenant_id="default", created_at="2026-07-01T00:00:00Z")
    graph.add_node(
        UnifiedNode(
            id="tool:checkout",
            entity_type=EntityType.TOOL,
            label="actions/checkout",
        )
    )
    report = {
        "agents": [
            {
                "name": "gha:ci",
                "source": "github-actions",
                "config_path": ".github/workflows/ci.yml",
                "mcp_servers": [
                    {
                        "name": "gha:ci",
                        "tools": [{"name": "actions/checkout"}],
                    }
                ],
            }
        ]
    }

    counts = apply_ci_graph_overlay(graph, report, datetime(2026, 7, 1, tzinfo=timezone.utc))
    assert counts["ci_jobs"] == 1
    assert counts["runs_edges"] == 1
    assert "ci_job:ci" in graph.nodes
    assert graph.nodes["ci_job:ci"].entity_type == EntityType.CI_JOB
    assert any(edge.relationship == RelationshipType.RUNS for edge in graph.edges)


def test_ci_graph_overlay_noop_without_github_actions() -> None:
    graph = UnifiedGraph(scan_id="s1", tenant_id="default", created_at="2026-07-01T00:00:00Z")
    counts = apply_ci_graph_overlay(
        graph,
        {"agents": [{"name": "cursor", "source": "cursor"}]},
        datetime(2026, 7, 1, tzinfo=timezone.utc),
    )
    assert counts == {"ci_jobs": 0, "runs_edges": 0, "configures_edges": 0}
