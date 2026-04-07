"""Tests for the unified graph schema, persistence, and builder bridge.

Covers:
- Schema types (enums, dataclasses, serialisation round-trips)
- OCSF mapping correctness (category/class/type UIDs, severity)
- Unified severity system (no duplicates, consistent across surfaces)
- Node ID stability (deterministic UUIDs)
- UnifiedGraph operations (add, query, filter, BFS, centrality, views)
- SQL persistence (save/load round-trip, diff, snapshots)
- Context graph bridge (to_unified_graph)
"""

from __future__ import annotations

import sqlite3

import pytest

# ═══════════════════════════════════════════════════════════════════════════
# Schema types & enums
# ═══════════════════════════════════════════════════════════════════════════


class TestEntityType:
    def test_all_entity_types_have_ocsf_mapping(self):
        from agent_bom.graph_schema import ENTITY_OCSF_MAP, EntityType

        for et in EntityType:
            assert et.value in ENTITY_OCSF_MAP, f"Missing OCSF mapping for {et}"

    def test_inventory_entities_are_category_5(self):
        from agent_bom.graph_schema import ENTITY_OCSF_MAP, EntityType

        inventory = [
            EntityType.AGENT,
            EntityType.SERVER,
            EntityType.PACKAGE,
            EntityType.TOOL,
            EntityType.MODEL,
            EntityType.DATASET,
            EntityType.CONTAINER,
            EntityType.CLOUD_RESOURCE,
        ]
        for et in inventory:
            assert ENTITY_OCSF_MAP[et.value]["category_uid"] == 5

    def test_finding_entities_are_category_2(self):
        from agent_bom.graph_schema import ENTITY_OCSF_MAP, EntityType

        findings = [EntityType.VULNERABILITY, EntityType.CREDENTIAL, EntityType.MISCONFIGURATION]
        for et in findings:
            assert ENTITY_OCSF_MAP[et.value]["category_uid"] == 2

    def test_vulnerability_is_security_finding_2001(self):
        from agent_bom.graph_schema import ENTITY_OCSF_MAP, EntityType

        assert ENTITY_OCSF_MAP[EntityType.VULNERABILITY.value]["class_uid"] == 2001

    def test_misconfiguration_is_compliance_finding_2003(self):
        from agent_bom.graph_schema import ENTITY_OCSF_MAP, EntityType

        assert ENTITY_OCSF_MAP[EntityType.MISCONFIGURATION.value]["class_uid"] == 2003


class TestRelationshipType:
    def test_all_relationships_are_strings(self):
        from agent_bom.graph_schema import RelationshipType

        for rt in RelationshipType:
            assert isinstance(rt.value, str)
            assert rt.value == rt.value.lower()

    def test_static_relationships_exist(self):
        from agent_bom.graph_schema import RelationshipType

        static = ["hosts", "uses", "depends_on", "provides_tool", "exposes_cred"]
        for name in static:
            assert name in [r.value for r in RelationshipType]

    def test_runtime_relationships_exist(self):
        from agent_bom.graph_schema import RelationshipType

        runtime = ["invoked", "accessed", "delegated_to"]
        for name in runtime:
            assert name in [r.value for r in RelationshipType]


# ═══════════════════════════════════════════════════════════════════════════
# Severity system (single source of truth)
# ═══════════════════════════════════════════════════════════════════════════


class TestUnifiedSeverity:
    def test_severity_to_ocsf_covers_all_levels(self):
        from agent_bom.graph_schema import SEVERITY_TO_OCSF

        assert SEVERITY_TO_OCSF["critical"] == 5
        assert SEVERITY_TO_OCSF["high"] == 4
        assert SEVERITY_TO_OCSF["medium"] == 3
        assert SEVERITY_TO_OCSF["low"] == 2
        assert SEVERITY_TO_OCSF["info"] == 1
        assert SEVERITY_TO_OCSF["unknown"] == 0

    def test_severity_rank_ordering(self):
        from agent_bom.graph_schema import SEVERITY_RANK

        assert SEVERITY_RANK["critical"] > SEVERITY_RANK["high"]
        assert SEVERITY_RANK["high"] > SEVERITY_RANK["medium"]
        assert SEVERITY_RANK["medium"] > SEVERITY_RANK["low"]
        assert SEVERITY_RANK["low"] > SEVERITY_RANK["unknown"]

    def test_severity_risk_score_ordering(self):
        from agent_bom.graph_schema import SEVERITY_RISK_SCORE

        assert SEVERITY_RISK_SCORE["critical"] > SEVERITY_RISK_SCORE["high"]
        assert SEVERITY_RISK_SCORE["high"] > SEVERITY_RISK_SCORE["medium"]
        assert SEVERITY_RISK_SCORE["medium"] > SEVERITY_RISK_SCORE["low"]

    def test_ocsf_to_syslog_mapping(self):
        from agent_bom.graph_schema import OCSF_TO_SYSLOG, OCSFSeverity

        # Critical OCSF → syslog 2 (Critical)
        assert OCSF_TO_SYSLOG[OCSFSeverity.CRITICAL] == 2
        # Info OCSF → syslog 6 (Informational)
        assert OCSF_TO_SYSLOG[OCSFSeverity.INFORMATIONAL] == 6

    def test_severity_badge_keys(self):
        from agent_bom.graph_schema import SEVERITY_BADGE

        assert "critical" in SEVERITY_BADGE
        assert "high" in SEVERITY_BADGE
        assert "medium" in SEVERITY_BADGE
        assert "low" in SEVERITY_BADGE

    def test_ocsf_severity_names(self):
        from agent_bom.graph_schema import OCSF_SEVERITY_NAMES

        assert OCSF_SEVERITY_NAMES[5] == "Critical"
        assert OCSF_SEVERITY_NAMES[1] == "Informational"

    def test_helper_functions(self):
        from agent_bom.graph_schema import ocsf_to_severity, severity_rank, severity_to_ocsf

        assert severity_rank("critical") == 5
        assert severity_rank("unknown") == 0
        assert severity_rank("") == 0
        assert severity_to_ocsf("high") == 4
        assert severity_to_ocsf("bogus") == 0
        assert ocsf_to_severity(5) == "critical"
        assert ocsf_to_severity(1) == "informational"

    def test_context_graph_uses_unified_severity(self):
        """Verify context_graph.py no longer has its own severity dict."""
        from agent_bom.context_graph import _SEVERITY_SCORES
        from agent_bom.graph_schema import SEVERITY_RISK_SCORE

        # _SEVERITY_SCORES in context_graph IS the same object as SEVERITY_RISK_SCORE
        assert _SEVERITY_SCORES is SEVERITY_RISK_SCORE

    def test_output_graph_uses_unified_severity(self):
        """Verify output/graph.py uses graph_schema severity constants."""
        from agent_bom.graph_schema import SEVERITY_BADGE, SEVERITY_RANK
        from agent_bom.output.graph import _SEVERITY_BADGE, _SEVERITY_RANK

        assert _SEVERITY_RANK is SEVERITY_RANK
        assert _SEVERITY_BADGE is SEVERITY_BADGE

    def test_output_ocsf_uses_unified_severity(self):
        """Verify output/ocsf.py uses graph_schema severity mapping."""
        from agent_bom.graph_schema import SEVERITY_TO_OCSF
        from agent_bom.output.ocsf import _SEVERITY_MAP

        assert _SEVERITY_MAP is SEVERITY_TO_OCSF

    def test_siem_ocsf_uses_unified_severity(self):
        """Verify siem/ocsf.py uses graph_schema severity mapping."""
        from agent_bom.graph_schema import OCSF_SEVERITY_NAMES, SEVERITY_TO_OCSF
        from agent_bom.siem.ocsf import _SEVERITY_MAP, _SEVERITY_NAMES

        assert _SEVERITY_MAP is SEVERITY_TO_OCSF
        assert _SEVERITY_NAMES is OCSF_SEVERITY_NAMES


# ═══════════════════════════════════════════════════════════════════════════
# Node ID stability
# ═══════════════════════════════════════════════════════════════════════════


class TestNodeID:
    def test_stable_node_id_deterministic(self):
        from agent_bom.graph_schema import stable_node_id

        id1 = stable_node_id("agent", "ns", "claude-desktop")
        id2 = stable_node_id("agent", "ns", "claude-desktop")
        assert id1 == id2

    def test_stable_node_id_differs_for_different_inputs(self):
        from agent_bom.graph_schema import stable_node_id

        id1 = stable_node_id("agent", "ns", "claude-desktop")
        id2 = stable_node_id("agent", "ns", "cursor")
        assert id1 != id2

    def test_stable_node_id_case_insensitive(self):
        from agent_bom.graph_schema import stable_node_id

        id1 = stable_node_id("Agent", "NS", "Claude-Desktop")
        id2 = stable_node_id("agent", "ns", "claude-desktop")
        assert id1 == id2


# ═══════════════════════════════════════════════════════════════════════════
# UnifiedNode
# ═══════════════════════════════════════════════════════════════════════════


class TestUnifiedNode:
    def test_auto_populates_ocsf_fields(self):
        from agent_bom.graph_schema import EntityType, UnifiedNode

        node = UnifiedNode(id="agent:test", entity_type=EntityType.AGENT, label="test")
        assert node.category_uid == 5
        assert node.class_uid == 4001
        assert node.type_uid == 400101

    def test_auto_populates_severity_id(self):
        from agent_bom.graph_schema import EntityType, UnifiedNode

        node = UnifiedNode(
            id="vuln:CVE-2024-1234",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2024-1234",
            severity="critical",
        )
        assert node.severity_id == 5
        assert node.category_uid == 2
        assert node.class_uid == 2001

    def test_auto_populates_timestamps(self):
        from agent_bom.graph_schema import EntityType, UnifiedNode

        node = UnifiedNode(id="test", entity_type=EntityType.AGENT, label="test")
        assert node.first_seen
        assert node.last_seen
        assert node.first_seen == node.last_seen

    def test_serialisation_round_trip(self):
        from agent_bom.graph_schema import EntityType, NodeDimensions, UnifiedNode

        original = UnifiedNode(
            id="server:agent1:mcp-fs",
            entity_type=EntityType.SERVER,
            label="mcp-fs",
            severity="high",
            risk_score=6.5,
            attributes={"command": "npx", "transport": "stdio"},
            compliance_tags=["OWASP-A01"],
            data_sources=["mcp-scan"],
            dimensions=NodeDimensions(ecosystem="npm", surface="mcp-server"),
        )
        d = original.to_dict()
        restored = UnifiedNode.from_dict(d)
        assert restored.id == original.id
        assert restored.entity_type == original.entity_type
        assert restored.severity == "high"
        assert restored.severity_id == 4
        assert restored.dimensions.ecosystem == "npm"
        assert restored.compliance_tags == ["OWASP-A01"]

    def test_to_ocsf_event(self):
        from agent_bom.graph_schema import EntityType, UnifiedNode

        node = UnifiedNode(
            id="vuln:CVE-2024-1234",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2024-1234",
            severity="critical",
            attributes={"cvss_score": 9.8},
        )
        event = node.to_ocsf_event("0.75.13")
        assert event["class_uid"] == 2001
        assert event["severity_id"] == 5
        assert event["finding_info"]["title"] == "CVE-2024-1234"
        assert event["metadata"]["product"]["version"] == "0.75.13"


# ═══════════════════════════════════════════════════════════════════════════
# UnifiedEdge
# ═══════════════════════════════════════════════════════════════════════════


class TestUnifiedEdge:
    def test_id_generation(self):
        from agent_bom.graph_schema import RelationshipType, UnifiedEdge

        edge = UnifiedEdge(source="a", target="b", relationship=RelationshipType.USES)
        assert edge.id == "uses:a:b"

    def test_serialisation_round_trip(self):
        from agent_bom.graph_schema import RelationshipType, UnifiedEdge

        original = UnifiedEdge(
            source="agent:x",
            target="server:x:y",
            relationship=RelationshipType.USES,
            weight=2.5,
            evidence={"config": "/path"},
        )
        d = original.to_dict()
        restored = UnifiedEdge.from_dict(d)
        assert restored.source == original.source
        assert restored.relationship == RelationshipType.USES
        assert restored.weight == 2.5


# ═══════════════════════════════════════════════════════════════════════════
# UnifiedGraph
# ═══════════════════════════════════════════════════════════════════════════


def _build_test_graph():
    """Build a small test graph: 2 agents, 1 shared server, 1 vuln."""
    from agent_bom.graph_schema import (
        EntityType,
        RelationshipType,
        UnifiedEdge,
        UnifiedGraph,
        UnifiedNode,
    )

    g = UnifiedGraph(scan_id="test-001")
    g.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    g.add_node(UnifiedNode(id="agent:b", entity_type=EntityType.AGENT, label="agent-b"))
    g.add_node(UnifiedNode(id="server:a:fs", entity_type=EntityType.SERVER, label="mcp-fs"))
    g.add_node(UnifiedNode(id="server:b:fs", entity_type=EntityType.SERVER, label="mcp-fs"))
    g.add_node(
        UnifiedNode(
            id="vuln:CVE-2024-1",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2024-1",
            severity="critical",
            risk_score=9.0,
        )
    )
    g.add_node(
        UnifiedNode(
            id="cred:API_KEY",
            entity_type=EntityType.CREDENTIAL,
            label="API_KEY",
        )
    )
    g.add_edge(UnifiedEdge(source="agent:a", target="server:a:fs", relationship=RelationshipType.USES))
    g.add_edge(UnifiedEdge(source="agent:b", target="server:b:fs", relationship=RelationshipType.USES))
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
            source="server:a:fs",
            target="cred:API_KEY",
            relationship=RelationshipType.EXPOSES_CRED,
            weight=2.0,
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
    return g


class TestUnifiedGraph:
    def test_add_node_dedup(self):
        from agent_bom.graph_schema import EntityType, UnifiedGraph, UnifiedNode

        g = UnifiedGraph()
        g.add_node(UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a", risk_score=1.0))
        g.add_node(UnifiedNode(id="a", entity_type=EntityType.AGENT, label="a", risk_score=5.0))
        assert len(g.nodes) == 1
        assert g.nodes["a"].risk_score == 5.0  # Higher risk_score wins

    def test_add_edge_dedup(self):
        from agent_bom.graph_schema import RelationshipType, UnifiedEdge, UnifiedGraph

        g = UnifiedGraph()
        e = UnifiedEdge(source="a", target="b", relationship=RelationshipType.USES)
        g.add_edge(e)
        g.add_edge(e)  # Duplicate
        assert len(g.edges) == 1

    def test_bfs(self):
        g = _build_test_graph()
        paths = g.bfs("agent:a", max_depth=3)
        reachable_ids = {p[-1] for p in paths}
        assert "server:a:fs" in reachable_ids
        assert "vuln:CVE-2024-1" in reachable_ids
        assert "cred:API_KEY" in reachable_ids

    def test_shortest_path(self):
        g = _build_test_graph()
        path = g.shortest_path("agent:a", "vuln:CVE-2024-1")
        assert path == ["agent:a", "server:a:fs", "vuln:CVE-2024-1"]

    def test_shortest_path_no_path(self):
        g = _build_test_graph()
        # vuln has no edge to cred directly
        path = g.shortest_path("vuln:CVE-2024-1", "cred:API_KEY")
        # They're both connected to server:a:fs so path exists via bidirectional adjacency
        assert path is not None

    def test_reachable_from(self):
        g = _build_test_graph()
        reachable = g.reachable_from("agent:a", max_depth=2)
        assert "agent:a" in reachable
        assert "server:a:fs" in reachable
        assert "agent:b" in reachable  # via SHARES_SERVER

    def test_filter_nodes_by_type(self):
        from agent_bom.graph_schema import EntityType

        g = _build_test_graph()
        agents = g.filter_nodes(entity_types={EntityType.AGENT})
        assert len(agents) == 2

    def test_filter_nodes_by_severity(self):
        g = _build_test_graph()
        critical = g.filter_nodes(min_severity="critical")
        assert len(critical) == 1
        assert critical[0].id == "vuln:CVE-2024-1"

    def test_filter_edges_traversable(self):
        g = _build_test_graph()
        traversable = g.filter_edges(traversable_only=True)
        assert len(traversable) == len(g.edges)

    def test_stats(self):
        g = _build_test_graph()
        s = g.stats()
        assert s["total_nodes"] == 6
        assert s["total_edges"] == 5
        assert "agent" in s["node_types"]
        assert s["node_types"]["agent"] == 2

    def test_degree_centrality(self):
        g = _build_test_graph()
        scores = g.degree_centrality()
        # server:a:fs has the most connections (agent:a, vuln, cred + bidirectional adjacency)
        assert scores["server:a:fs"] > 0

    def test_bottleneck_nodes(self):
        g = _build_test_graph()
        bottlenecks = g.bottleneck_nodes(top_n=3)
        assert len(bottlenecks) <= 3
        # Should include server:a:fs as a critical node
        ids = [b[0] for b in bottlenecks]
        assert "server:a:fs" in ids

    def test_serialisation_round_trip(self):
        from agent_bom.graph_schema import UnifiedGraph

        g = _build_test_graph()
        d = g.to_dict()
        restored = UnifiedGraph.from_dict(d)
        assert len(restored.nodes) == len(g.nodes)
        assert len(restored.edges) == len(g.edges)
        assert restored.scan_id == "test-001"

    def test_ocsf_events_export(self):
        g = _build_test_graph()
        events = g.to_ocsf_events("0.75.13")
        # Only finding-type nodes (vuln + credential)
        assert len(events) == 2
        for ev in events:
            assert ev["class_uid"] in (2001, 2003)
            assert ev["metadata"]["product"]["version"] == "0.75.13"

    def test_inventory_view(self):
        from agent_bom.graph_schema import EntityType

        g = _build_test_graph()
        inv = g.inventory_view()
        for node in inv.nodes.values():
            assert node.entity_type not in (EntityType.VULNERABILITY, EntityType.MISCONFIGURATION)

    def test_attack_path_view(self):
        g = _build_test_graph()
        ap = g.attack_path_view()
        assert len(ap.edges) == len(g.edges)  # All edges are traversable by default

    def test_lateral_movement_view(self):
        g = _build_test_graph()
        lm = g.lateral_movement_view()
        # Should include SHARES_SERVER edge
        rels = {e.relationship.value for e in lm.edges}
        assert "shares_server" in rels


# ═══════════════════════════════════════════════════════════════════════════
# SQL persistence (graph_store)
# ═══════════════════════════════════════════════════════════════════════════


class TestGraphStore:
    @pytest.fixture
    def db(self):
        """In-memory SQLite DB with graph schema."""
        from agent_bom.db.graph_store import _init_db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        _init_db(conn)
        yield conn
        conn.close()

    def test_save_and_load_round_trip(self, db):
        from agent_bom.db.graph_store import load_graph, save_graph

        g = _build_test_graph()
        save_graph(db, g)

        loaded = load_graph(db, scan_id="test-001")
        assert len(loaded.nodes) == len(g.nodes)
        assert len(loaded.edges) == len(g.edges)

        # Verify node fields preserved
        vuln = loaded.nodes.get("vuln:CVE-2024-1")
        assert vuln is not None
        assert vuln.severity == "critical"
        assert vuln.risk_score == 9.0
        assert vuln.category_uid == 2
        assert vuln.class_uid == 2001

    def test_upsert_bumps_last_seen(self, db):
        from agent_bom.db.graph_store import load_graph, save_graph
        from agent_bom.graph_schema import EntityType, UnifiedGraph, UnifiedNode

        # First save
        g1 = UnifiedGraph(scan_id="s1")
        g1.add_node(
            UnifiedNode(
                id="agent:x",
                entity_type=EntityType.AGENT,
                label="x",
                first_seen="2024-01-01T00:00:00+00:00",
                last_seen="2024-01-01T00:00:00+00:00",
            )
        )
        save_graph(db, g1)

        # Second save (same node, new scan)
        g2 = UnifiedGraph(scan_id="s2")
        g2.add_node(
            UnifiedNode(
                id="agent:x",
                entity_type=EntityType.AGENT,
                label="x",
                first_seen="2024-02-01T00:00:00+00:00",
                last_seen="2024-02-01T00:00:00+00:00",
            )
        )
        save_graph(db, g2)

        # Load latest — should have bumped last_seen
        loaded = load_graph(db, scan_id="s2")
        node = loaded.nodes.get("agent:x")
        assert node is not None
        assert "2024-02" in node.last_seen

    def test_diff_snapshots(self, db):
        from agent_bom.db.graph_store import diff_snapshots, save_graph
        from agent_bom.graph_schema import (
            EntityType,
            RelationshipType,
            UnifiedEdge,
            UnifiedGraph,
            UnifiedNode,
        )

        # Scan 1: agent:a + server:a
        g1 = UnifiedGraph(scan_id="s1")
        g1.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
        g1.add_node(UnifiedNode(id="server:a", entity_type=EntityType.SERVER, label="s"))
        g1.add_edge(UnifiedEdge(source="agent:a", target="server:a", relationship=RelationshipType.USES))
        save_graph(db, g1)

        # Scan 2: agent:a + agent:b (server:a removed, agent:b added)
        g2 = UnifiedGraph(scan_id="s2")
        g2.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
        g2.add_node(UnifiedNode(id="agent:b", entity_type=EntityType.AGENT, label="b"))
        g2.add_edge(UnifiedEdge(source="agent:a", target="agent:b", relationship=RelationshipType.SHARES_SERVER))
        save_graph(db, g2)

        diff = diff_snapshots(db, "s1", "s2")
        assert "agent:b" in diff["nodes_added"]
        assert "server:a" in diff["nodes_removed"]
        assert len(diff["edges_added"]) >= 1
        assert len(diff["edges_removed"]) >= 1

    def test_list_snapshots(self, db):
        from agent_bom.db.graph_store import list_snapshots, save_graph

        g = _build_test_graph()
        save_graph(db, g)

        snaps = list_snapshots(db)
        assert len(snaps) == 1
        assert snaps[0]["scan_id"] == "test-001"
        assert snaps[0]["node_count"] == 6

    def test_attack_paths_persisted(self, db):
        from agent_bom.db.graph_store import load_graph, save_graph
        from agent_bom.graph_schema import AttackPath

        g = _build_test_graph()
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

        loaded = load_graph(db, scan_id="test-001")
        assert len(loaded.attack_paths) == 1
        assert loaded.attack_paths[0].composite_risk == 9.0

    def test_interaction_risks_persisted(self, db):
        from agent_bom.db.graph_store import load_graph, save_graph
        from agent_bom.graph_schema import InteractionRisk

        g = _build_test_graph()
        g.interaction_risks.append(
            InteractionRisk(
                pattern="shared_credential",
                agents=["agent-a", "agent-b"],
                risk_score=8.0,
                description="API_KEY shared",
                owasp_agentic_tag="ASI07",
            )
        )
        save_graph(db, g)

        loaded = load_graph(db, scan_id="test-001")
        assert len(loaded.interaction_risks) == 1
        assert loaded.interaction_risks[0].owasp_agentic_tag == "ASI07"


# ═══════════════════════════════════════════════════════════════════════════
# Context graph bridge
# ═══════════════════════════════════════════════════════════════════════════


class TestContextGraphBridge:
    def test_to_unified_graph_basic(self):
        from agent_bom.context_graph import (
            build_context_graph,
            to_unified_graph,
        )
        from agent_bom.graph_schema import EntityType

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
        ug = to_unified_graph(cg, scan_id="bridge-test")

        assert len(ug.nodes) == len(cg.nodes)
        assert len(ug.edges) == len(cg.edges)
        assert ug.scan_id == "bridge-test"

        # Verify OCSF fields populated
        agent_node = ug.nodes.get("agent:claude-desktop")
        assert agent_node is not None
        assert agent_node.entity_type == EntityType.AGENT
        assert agent_node.category_uid == 5
        assert agent_node.class_uid == 4001

        vuln_node = ug.nodes.get("vuln:CVE-2024-1234")
        assert vuln_node is not None
        assert vuln_node.entity_type == EntityType.VULNERABILITY
        assert vuln_node.category_uid == 2
        assert vuln_node.class_uid == 2001

    def test_to_unified_graph_with_lateral_paths(self):
        from agent_bom.context_graph import (
            EdgeKind,
            LateralPath,
            build_context_graph,
            to_unified_graph,
        )

        agents = [
            {
                "name": "agent-a",
                "type": "claude-desktop",
                "status": "configured",
                "mcp_servers": [
                    {"name": "shared-srv", "command": "npx", "transport": "stdio", "packages": [], "tools": [], "env": {"API_KEY": "x"}},
                ],
            },
            {
                "name": "agent-b",
                "type": "cursor",
                "status": "configured",
                "mcp_servers": [
                    {"name": "shared-srv", "command": "npx", "transport": "stdio", "packages": [], "tools": [], "env": {"API_KEY": "x"}},
                ],
            },
        ]

        cg = build_context_graph(agents, [])
        lp = LateralPath(
            source="agent:agent-a",
            target="agent:agent-b",
            hops=["agent:agent-a", "agent:agent-b"],
            edges=[EdgeKind.SHARES_SERVER],
            composite_risk=5.0,
            summary="agent-a → agent-b",
            credential_exposure=["API_KEY"],
            tool_exposure=[],
            vuln_ids=[],
        )

        ug = to_unified_graph(cg, lateral_paths=[lp])
        assert len(ug.attack_paths) == 1
        assert ug.attack_paths[0].composite_risk == 5.0
        assert ug.attack_paths[0].credential_exposure == ["API_KEY"]


# ═══════════════════════════════════════════════════════════════════════════
# graph_backend bridge
# ═══════════════════════════════════════════════════════════════════════════


class TestGraphBackendBridge:
    def test_from_unified_graph(self):
        from agent_bom.graph_backend import from_unified_graph

        g = _build_test_graph()
        backend = from_unified_graph(g, backend="memory")
        assert backend.node_count() == 6
        assert backend.edge_count() >= 5
        # Centrality should work
        scores = backend.centrality_scores()
        assert len(scores) == 6

    def test_bottleneck_analysis(self):
        from agent_bom.graph_backend import from_unified_graph

        g = _build_test_graph()
        backend = from_unified_graph(g, backend="memory")
        bottlenecks = backend.bottleneck_nodes(top_n=3)
        assert len(bottlenecks) <= 3


# ═══════════════════════════════════════════════════════════════════════════
# Backward compatibility
# ═══════════════════════════════════════════════════════════════════════════


class TestBackwardCompat:
    def test_mapping_dicts_exist(self):
        from agent_bom.graph_schema import (
            _EDGE_KIND_TO_RELATIONSHIP,
            _NODE_KIND_TO_ENTITY,
            EntityType,
            RelationshipType,
        )

        assert _NODE_KIND_TO_ENTITY["agent"] == EntityType.AGENT
        assert _NODE_KIND_TO_ENTITY["vulnerability"] == EntityType.VULNERABILITY
        assert _EDGE_KIND_TO_RELATIONSHIP["uses"] == RelationshipType.USES
        assert _EDGE_KIND_TO_RELATIONSHIP["exposes"] == RelationshipType.EXPOSES_CRED
        assert _EDGE_KIND_TO_RELATIONSHIP["shares_credential"] == RelationshipType.SHARES_CRED

    def test_context_graph_still_exports_old_types(self):
        """Existing consumers that import NodeKind etc. from context_graph still work."""
        from agent_bom.context_graph import (
            EdgeKind,
            NodeKind,
        )

        assert NodeKind.AGENT.value == "agent"
        assert EdgeKind.USES.value == "uses"

    def test_ocsf_type_uid_computation(self):
        from agent_bom.graph_schema import EntityType, ocsf_type_uid

        # Security Finding Create: 2001 * 100 + 1 = 200101
        assert ocsf_type_uid(EntityType.VULNERABILITY) == 200101
        # Device Inventory Create: 4001 * 100 + 1 = 400101
        assert ocsf_type_uid(EntityType.AGENT) == 400101
