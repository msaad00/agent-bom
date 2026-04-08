"""Tests for graph query API endpoints and scan pipeline wiring."""

from __future__ import annotations

import sqlite3

import pytest

from agent_bom.db.graph_store import _init_db, load_graph, save_graph
from agent_bom.graph import (
    AttackPath,
    EntityType,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)


def _build_persisted_graph(db, scan_id="test-scan-001"):
    """Build and persist a test graph."""
    g = UnifiedGraph(scan_id=scan_id)
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    g.add_node(UnifiedNode(id="agent:b", entity_type=EntityType.AGENT, label="agent-b"))
    g.add_node(UnifiedNode(id="server:a:fs", entity_type=EntityType.SERVER, label="mcp-fs"))
    g.add_node(
        UnifiedNode(
            id="vuln:CVE-2024-1",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2024-1",
            severity="critical",
            risk_score=9.0,
        )
    )
    g.add_edge(UnifiedEdge(source="agent:a", target="server:a:fs", relationship=RelationshipType.USES))
    g.add_edge(
        UnifiedEdge(
            source="server:a:fs",
            target="vuln:CVE-2024-1",
            relationship=RelationshipType.VULNERABLE_TO,
            weight=8.0,
        )
    )
    g.add_edge(
        UnifiedEdge(
            source="agent:a",
            target="agent:b",
            relationship=RelationshipType.SHARES_SERVER,
            direction="bidirectional",
            weight=3.0,
        )
    )
    g.attack_paths.append(
        AttackPath(
            source="agent:a",
            target="vuln:CVE-2024-1",
            hops=["agent:a", "server:a:fs", "vuln:CVE-2024-1"],
            edges=["uses", "vulnerable_to"],
            composite_risk=9.0,
            summary="agent-a → mcp-fs → CVE-2024-1",
        )
    )
    save_graph(db, g)
    return g


@pytest.fixture
def graph_db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    yield conn
    conn.close()


class TestScanPipelineWiring:
    """Test that scan pipeline correctly produces and persists unified graphs."""

    def test_context_graph_to_unified_round_trip(self, graph_db):
        """Build context graph → bridge → persist → load → verify."""
        from agent_bom.context_graph import build_context_graph, find_lateral_paths, to_unified_graph

        agents = [
            {
                "name": "claude-desktop",
                "type": "claude-desktop",
                "status": "configured",
                "mcp_servers": [
                    {
                        "name": "mcp-fs",
                        "command": "npx",
                        "transport": "stdio",
                        "packages": [{"name": "express", "version": "4.18.0"}],
                        "tools": [],
                        "env": {"GITHUB_TOKEN": "xxx"},
                    }
                ],
            }
        ]
        blast = [
            {
                "vulnerability_id": "CVE-2024-1234",
                "severity": "high",
                "package": "express",
                "affected_agents": ["claude-desktop"],
                "affected_servers": ["mcp-fs"],
            }
        ]

        cg = build_context_graph(agents, blast)
        paths = find_lateral_paths(cg, "agent:claude-desktop")
        ug = to_unified_graph(cg, paths, scan_id="pipeline-test")

        # Persist
        save_graph(graph_db, ug)

        # Load back
        loaded = load_graph(graph_db, scan_id="pipeline-test")
        assert len(loaded.nodes) == len(ug.nodes)
        assert len(loaded.edges) == len(ug.edges)

        # Verify OCSF fields survived round-trip
        vuln = loaded.nodes.get("vuln:CVE-2024-1234")
        assert vuln is not None
        assert vuln.category_uid == 2
        assert vuln.class_uid == 2001

    def test_multi_scan_persistence(self, graph_db):
        """Two scans persisted — each loadable independently."""
        _build_persisted_graph(graph_db, scan_id="s1")

        g2 = UnifiedGraph(scan_id="s2")
        g2.add_node(UnifiedNode(id="agent:c", entity_type=EntityType.AGENT, label="agent-c"))
        save_graph(graph_db, g2)

        s1 = load_graph(graph_db, scan_id="s1")
        s2 = load_graph(graph_db, scan_id="s2")

        assert "agent:a" in s1.nodes
        assert "agent:c" not in s1.nodes
        assert "agent:c" in s2.nodes
        assert "agent:a" not in s2.nodes


class TestGraphEndpointLogic:
    """Test the endpoint logic directly (no HTTP, just function calls)."""

    def test_load_with_entity_type_filter(self, graph_db):
        _build_persisted_graph(graph_db)
        loaded = load_graph(graph_db, scan_id="test-scan-001", entity_types={"agent"})
        assert all(n.entity_type == EntityType.AGENT for n in loaded.nodes.values())

    def test_load_with_severity_filter(self, graph_db):
        _build_persisted_graph(graph_db)
        loaded = load_graph(graph_db, scan_id="test-scan-001", min_severity_rank=5)
        # Only critical vuln passes
        assert len(loaded.nodes) == 1
        assert "vuln:CVE-2024-1" in loaded.nodes

    def test_diff_between_scans(self, graph_db):
        from agent_bom.db.graph_store import diff_snapshots

        _build_persisted_graph(graph_db, scan_id="s1")

        g2 = UnifiedGraph(scan_id="s2")
        g2.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        g2.add_node(UnifiedNode(id="agent:new", entity_type=EntityType.AGENT, label="new-agent"))
        save_graph(graph_db, g2)

        diff = diff_snapshots(graph_db, "s1", "s2")
        assert "agent:new" in diff["nodes_added"]
        assert "agent:b" in diff["nodes_removed"]

    def test_bfs_from_persisted_graph(self, graph_db):
        _build_persisted_graph(graph_db)
        loaded = load_graph(graph_db, scan_id="test-scan-001")

        paths = loaded.bfs("agent:a", max_depth=3)
        reachable = {p[-1] for p in paths}
        assert "server:a:fs" in reachable
        assert "vuln:CVE-2024-1" in reachable

    def test_attack_paths_queryable(self, graph_db):
        _build_persisted_graph(graph_db)
        loaded = load_graph(graph_db, scan_id="test-scan-001")

        agent_paths = [ap for ap in loaded.attack_paths if ap.source == "agent:a"]
        assert len(agent_paths) == 1
        assert agent_paths[0].composite_risk == 9.0

    def test_snapshots_listed(self, graph_db):
        from agent_bom.db.graph_store import list_snapshots

        _build_persisted_graph(graph_db)
        snaps = list_snapshots(graph_db)
        assert len(snaps) == 1
        assert snaps[0]["scan_id"] == "test-scan-001"
        assert snaps[0]["node_count"] == 4


class TestBackendDirectionality:
    """Regression: graph_backend must respect edge direction from unified graph."""

    def test_directed_edge_no_reverse_in_backend(self):
        from agent_bom.graph_backend import from_unified_graph

        g = UnifiedGraph()
        g.add_node(UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a"))
        g.add_node(UnifiedNode(id="s", entity_type=EntityType.SERVER, label="s"))
        g.add_edge(UnifiedEdge(source="a", target="s", relationship=RelationshipType.USES, direction="directed"))

        backend = from_unified_graph(g, backend="memory")
        # Forward: a has neighbor s
        assert "s" in backend.neighbors("a")
        # Reverse: s should NOT have neighbor a (directed edge)
        assert "a" not in backend.neighbors("s")

    def test_bidirectional_edge_has_reverse_in_backend(self):
        from agent_bom.graph_backend import from_unified_graph

        g = UnifiedGraph()
        g.add_node(UnifiedNode(id="a1", entity_type=EntityType.AGENT, label="a1"))
        g.add_node(UnifiedNode(id="a2", entity_type=EntityType.AGENT, label="a2"))
        g.add_edge(
            UnifiedEdge(
                source="a1",
                target="a2",
                relationship=RelationshipType.SHARES_SERVER,
                direction="bidirectional",
            )
        )

        backend = from_unified_graph(g, backend="memory")
        assert "a2" in backend.neighbors("a1")
        assert "a1" in backend.neighbors("a2")
