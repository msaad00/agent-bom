"""Tests for graph query API endpoints and scan pipeline wiring."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.routes import graph as graph_routes
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
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

    def test_load_without_scan_id_returns_latest_snapshot(self, graph_db):
        _build_persisted_graph(graph_db, scan_id="s1")

        g2 = UnifiedGraph(scan_id="s2")
        g2.add_node(UnifiedNode(id="agent:latest", entity_type=EntityType.AGENT, label="latest-agent"))
        save_graph(graph_db, g2)

        latest = load_graph(graph_db)
        assert latest.scan_id == "s2"
        assert "agent:latest" in latest.nodes
        assert "agent:a" not in latest.nodes


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

    def test_sqlite_graph_store_search_is_server_side(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="search-scan", tenant_id="default")
        graph.add_node(
            UnifiedNode(
                id="server:acme:vector",
                entity_type=EntityType.SERVER,
                label="Acme Vector Server",
                severity="high",
                risk_score=8.4,
                compliance_tags=["OWASP-A01"],
                data_sources=["runtime-proxy"],
                attributes={"description": "Vector retrieval service"},
            )
        )
        graph.add_node(
            UnifiedNode(
                id="dataset:kb",
                entity_type=EntityType.DATASET,
                label="Knowledge Base",
                data_sources=["mcp-scan"],
            )
        )
        store.save_graph(graph)

        results, total, next_cursor = store.search_nodes(tenant_id="default", query="vector", offset=0, limit=10)

        assert total == 1
        assert [node.id for node in results] == ["server:acme:vector"]
        assert next_cursor is None

    def test_sqlite_graph_store_search_applies_slice_filters(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="search-scan", tenant_id="default")
        graph.add_node(
            UnifiedNode(
                id="server:prod:vector",
                entity_type=EntityType.SERVER,
                label="Prod Vector Server",
                severity="high",
                compliance_tags=["CIS-5.4.1"],
                data_sources=["runtime-proxy"],
            )
        )
        graph.add_node(
            UnifiedNode(
                id="server:dev:vector",
                entity_type=EntityType.SERVER,
                label="Dev Vector Server",
                severity="low",
                compliance_tags=["SOC2-CC6"],
                data_sources=["fleet-sync"],
            )
        )
        store.save_graph(graph)

        results, total, next_cursor = store.search_nodes(
            tenant_id="default",
            query="vector",
            entity_types={"server"},
            min_severity_rank=4,
            compliance_prefixes={"CIS"},
            data_sources={"runtime-proxy"},
            offset=0,
            limit=10,
        )

        assert total == 1
        assert [node.id for node in results] == ["server:prod:vector"]
        assert next_cursor is None

    def test_graph_agents_endpoint_lists_agent_nodes_without_full_graph_load(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="agent-selector-scan", tenant_id="default")
        graph.add_node(UnifiedNode(id="agent:alpha", entity_type=EntityType.AGENT, label="Alpha Agent", risk_score=8.0))
        graph.add_node(UnifiedNode(id="agent:beta", entity_type=EntityType.AGENT, label="Beta Agent", risk_score=2.0))
        graph.add_node(UnifiedNode(id="server:alpha:fs", entity_type=EntityType.SERVER, label="Filesystem Server"))
        store.save_graph(graph)
        original_store = api_stores._graph_store
        try:
            set_graph_store(store)
            client = TestClient(app)

            response = client.get("/v1/graph/agents?scan_id=agent-selector-scan&limit=1")

            assert response.status_code == 200
            body = response.json()
            assert body["pagination"]["total"] == 2
            assert body["pagination"]["has_more"] is True
            assert len(body["agents"]) == 1
            assert body["agents"][0]["id"].startswith("agent:")
        finally:
            set_graph_store(original_store)

    def test_sqlite_graph_store_search_escapes_like_wildcards(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="search-scan", tenant_id="default")
        graph.add_node(UnifiedNode(id="server:percent", entity_type=EntityType.SERVER, label="100% Secure Server"))
        graph.add_node(UnifiedNode(id="dataset:underscore", entity_type=EntityType.DATASET, label="data_set"))
        graph.add_node(UnifiedNode(id="agent:plain", entity_type=EntityType.AGENT, label="plain agent"))
        store.save_graph(graph)

        percent_results, percent_total, _ = store.search_nodes(tenant_id="default", query="%", offset=0, limit=10)
        underscore_results, underscore_total, _ = store.search_nodes(tenant_id="default", query="_", offset=0, limit=10)

        assert percent_total == 1
        assert [node.id for node in percent_results] == ["server:percent"]
        assert underscore_total == 1
        assert [node.id for node in underscore_results] == ["dataset:underscore"]

    def test_sqlite_graph_store_search_falls_back_when_fts_match_errors(self, tmp_path, monkeypatch):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="search-scan", tenant_id="default")
        graph.add_node(UnifiedNode(id="server:vector", entity_type=EntityType.SERVER, label="Vector Service"))
        store.save_graph(graph)

        monkeypatch.setattr(SQLiteGraphStore, "_search_query_expression", staticmethod(lambda query: '"'))

        results, total, _ = store.search_nodes(tenant_id="default", query="vector", offset=0, limit=10)

        assert total == 1
        assert [node.id for node in results] == ["server:vector"]

    def test_sqlite_graph_store_bfs_paths_uses_persisted_edges(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="traversal-scan", tenant_id="default")
        graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s"))
        graph.add_node(UnifiedNode(id="vuln:cve", entity_type=EntityType.VULNERABILITY, label="CVE-2026-1"))
        graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES, traversable=True))
        graph.add_edge(UnifiedEdge(source="server:s", target="vuln:cve", relationship=RelationshipType.VULNERABLE_TO, traversable=True))
        store.save_graph(graph)

        paths, reachable = store.bfs_paths(tenant_id="default", scan_id="traversal-scan", source="agent:a", max_depth=3)

        assert reachable == {"server:s", "vuln:cve"}
        assert paths == [["agent:a", "server:s"], ["agent:a", "server:s", "vuln:cve"]]

    def test_sqlite_graph_store_impact_of_uses_reverse_edges(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="impact-scan", tenant_id="default")
        graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s"))
        graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
        store.save_graph(graph)

        impact = store.impact_of(tenant_id="default", scan_id="impact-scan", node_id="server:s", max_depth=3)

        assert impact is not None
        assert impact["affected_nodes"] == ["agent:a"]
        assert impact["affected_by_type"] == {"agent": 1}

    def test_sqlite_graph_store_attack_paths_for_sources_returns_persisted_paths(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="attack-path-scan", tenant_id="default")
        graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s"))
        graph.add_node(UnifiedNode(id="vuln:cve", entity_type=EntityType.VULNERABILITY, label="CVE-2026-1"))
        graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
        graph.add_edge(UnifiedEdge(source="server:s", target="vuln:cve", relationship=RelationshipType.VULNERABLE_TO))
        graph.attack_paths.append(
            AttackPath(
                source="agent:a",
                target="vuln:cve",
                hops=["agent:a", "server:s", "vuln:cve"],
                edges=["uses", "vulnerable_to"],
                composite_risk=9.8,
            )
        )
        store.save_graph(graph)

        attack_paths = store.attack_paths_for_sources(tenant_id="default", scan_id="attack-path-scan", source_ids={"agent:a"})

        assert len(attack_paths) == 1
        assert attack_paths[0].target == "vuln:cve"

    def test_sqlite_graph_store_node_context_preserves_bidirectional_neighbors(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="node-context-scan", tenant_id="default")
        graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        graph.add_node(UnifiedNode(id="agent:b", entity_type=EntityType.AGENT, label="agent-b"))
        graph.add_edge(
            UnifiedEdge(
                source="agent:a",
                target="agent:b",
                relationship=RelationshipType.SHARES_SERVER,
                direction="bidirectional",
            )
        )
        store.save_graph(graph)

        node_context = store.node_context(tenant_id="default", scan_id="node-context-scan", node_id="agent:b")

        assert node_context is not None
        assert node_context["neighbors"] == ["agent:a"]
        assert node_context["sources"] == ["agent:a"]
        assert node_context["edges_out"][0].target == "agent:a"
        assert node_context["edges_in"][0].source == "agent:a"

    def test_sqlite_graph_store_compliance_summary_aggregates_frameworks_without_loading_graph(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="compliance-scan", tenant_id="default")
        graph.add_node(
            UnifiedNode(
                id="vuln:cve",
                entity_type=EntityType.VULNERABILITY,
                label="CVE-2026-1",
                severity="critical",
                severity_id=5,
                compliance_tags=["CIS-5.4.1", "OWASP-A01"],
            )
        )
        graph.add_node(
            UnifiedNode(
                id="agent:a",
                entity_type=EntityType.AGENT,
                label="agent-a",
                severity="high",
                severity_id=4,
                compliance_tags=["CIS-6.2"],
            )
        )
        store.save_graph(graph)

        summary = store.compliance_summary(tenant_id="default", scan_id="compliance-scan")

        assert summary["framework_count"] == 2
        assert summary["total_tagged_findings"] == 3
        assert summary["frameworks"]["CIS"]["total_findings"] == 2
        assert summary["frameworks"]["CIS"]["node_count"] == 2
        assert summary["frameworks"]["OWASP"]["total_findings"] == 1


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


class _RecordingGraphStore:
    def __init__(self):
        self.calls: list[tuple] = []
        self.graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
        self.graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        self.presets: dict[str, dict] = {}

    def latest_snapshot_id(self, *, tenant_id: str = "") -> str:
        self.calls.append(("latest_snapshot_id", tenant_id))
        return self.graph.scan_id

    def previous_snapshot_id(self, *, tenant_id: str = "", before_scan_id: str = "") -> str:
        self.calls.append(("previous_snapshot_id", tenant_id, before_scan_id))
        return ""

    def save_graph(self, graph: UnifiedGraph) -> None:
        self.calls.append(("save_graph", graph.scan_id, graph.tenant_id))
        self.graph = graph

    def load_graph(self, *, tenant_id: str = "", scan_id: str = "", entity_types=None, min_severity_rank: int = 0) -> UnifiedGraph:
        self.calls.append(("load_graph", tenant_id, scan_id, entity_types, min_severity_rank))
        return self.graph

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict:
        self.calls.append(("diff_snapshots", tenant_id, scan_id_old, scan_id_new))
        return {"nodes_added": [], "nodes_removed": [], "nodes_changed": [], "edges_added": [], "edges_removed": []}

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50) -> list[dict]:
        self.calls.append(("list_snapshots", tenant_id, limit))
        return [{"scan_id": self.graph.scan_id, "created_at": self.graph.created_at, "node_count": 1, "edge_count": 0, "risk_summary": {}}]

    def snapshot_stats(self, *, tenant_id: str = "", scan_id: str = "", entity_types=None, min_severity_rank: int = 0) -> dict:
        self.calls.append(("snapshot_stats", tenant_id, scan_id, entity_types, min_severity_rank))
        return self.graph.stats()

    def page_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types=None,
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ):
        self.calls.append(("page_nodes", tenant_id, scan_id, entity_types, min_severity_rank, cursor, offset, limit))
        nodes = sorted(
            self.graph.nodes.values(),
            key=lambda node: (-node.severity_id, -(node.risk_score or 0.0), node.label, node.id),
        )
        if entity_types:
            nodes = [node for node in nodes if node.entity_type.value in entity_types]
        if min_severity_rank:
            nodes = [node for node in nodes if node.severity_id >= min_severity_rank]
        full_total = len(nodes)
        if cursor:
            from agent_bom.api.graph_store import decode_graph_cursor, encode_graph_cursor

            severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
            nodes = [
                node
                for node in nodes
                if (
                    node.severity_id < severity_id
                    or (node.severity_id == severity_id and (node.risk_score or 0.0) < risk_score)
                    or (node.severity_id == severity_id and (node.risk_score or 0.0) == risk_score and node.label > label)
                    or (
                        node.severity_id == severity_id
                        and (node.risk_score or 0.0) == risk_score
                        and node.label == label
                        and node.id > node_id
                    )
                )
            ]
            page = nodes[:limit]
            next_cursor = encode_graph_cursor(page[-1]) if len(nodes) > limit and page else None
            return self.graph.scan_id, self.graph.created_at, page, full_total, next_cursor
        page = nodes[offset : offset + limit]
        next_cursor = None
        if offset + limit < full_total and page:
            from agent_bom.api.graph_store import encode_graph_cursor

            next_cursor = encode_graph_cursor(page[-1])
        return self.graph.scan_id, self.graph.created_at, page, full_total, next_cursor

    def edges_for_node_ids(self, *, tenant_id: str = "", scan_id: str = "", node_ids: set[str]):
        self.calls.append(("edges_for_node_ids", tenant_id, scan_id, tuple(sorted(node_ids))))
        return [edge for edge in self.graph.edges if edge.source in node_ids and edge.target in node_ids]

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
        entity_types=None,
        min_severity_rank: int = 0,
        compliance_prefixes=None,
        data_sources=None,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ):
        self.calls.append(
            (
                "search_nodes",
                tenant_id,
                scan_id,
                query,
                entity_types,
                min_severity_rank,
                compliance_prefixes,
                data_sources,
                cursor,
                offset,
                limit,
            )
        )
        matches = [node for node in self.graph.nodes.values() if query.lower() in node.label.lower()]
        if entity_types:
            matches = [node for node in matches if node.entity_type.value in entity_types]
        if min_severity_rank:
            matches = [node for node in matches if node.severity_id >= min_severity_rank]
        if compliance_prefixes:
            matches = [
                node
                for node in matches
                if {tag.split("-")[0].upper() if "-" in tag else tag.upper() for tag in node.compliance_tags}.intersection(
                    compliance_prefixes
                )
            ]
        if data_sources:
            matches = [node for node in matches if set(node.data_sources).intersection(data_sources)]
        matches = sorted(matches, key=lambda node: (-node.severity_id, -(node.risk_score or 0.0), node.label, node.id))
        full_total = len(matches)
        if cursor:
            from agent_bom.api.graph_store import decode_graph_cursor, encode_graph_cursor

            severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
            matches = [
                node
                for node in matches
                if (
                    node.severity_id < severity_id
                    or (node.severity_id == severity_id and (node.risk_score or 0.0) < risk_score)
                    or (node.severity_id == severity_id and (node.risk_score or 0.0) == risk_score and node.label > label)
                    or (
                        node.severity_id == severity_id
                        and (node.risk_score or 0.0) == risk_score
                        and node.label == label
                        and node.id > node_id
                    )
                )
            ]
            page = matches[:limit]
            next_cursor = encode_graph_cursor(page[-1]) if len(matches) > limit and page else None
            return page, full_total, next_cursor
        page = matches[offset : offset + limit]
        next_cursor = None
        if offset + limit < full_total and page:
            from agent_bom.api.graph_store import encode_graph_cursor

            next_cursor = encode_graph_cursor(page[-1])
        return page, full_total, next_cursor

    def nodes_by_ids(self, *, tenant_id: str = "", scan_id: str = "", node_ids: set[str]):
        self.calls.append(("nodes_by_ids", tenant_id, scan_id, tuple(sorted(node_ids))))
        return [node for node_id, node in self.graph.nodes.items() if node_id in node_ids]

    def bfs_paths(self, *, tenant_id: str = "", scan_id: str = "", source: str, max_depth: int = 4, traversable_only: bool = True):
        self.calls.append(("bfs_paths", tenant_id, scan_id, source, max_depth, traversable_only))
        paths = self.graph.bfs(source, max_depth=max_depth, traversable_only=traversable_only)
        reachable = self.graph.reachable_from(source, max_depth=max_depth, traversable_only=traversable_only, include_source=False)
        return paths, reachable

    def impact_of(self, *, tenant_id: str = "", scan_id: str = "", node_id: str, max_depth: int = 4):
        self.calls.append(("impact_of", tenant_id, scan_id, node_id, max_depth))
        if not self.graph.has_node(node_id):
            return None
        return self.graph.impact_of(node_id, max_depth=max_depth)

    def traverse_subgraph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        roots: list[str],
        direction: str = "forward",
        max_depth: int = 4,
        max_nodes: int = 500,
        traversable_only: bool = False,
        relationship_types=None,
        static_only: bool = False,
        dynamic_only: bool = False,
        include_roots: bool = True,
    ):
        self.calls.append(
            (
                "traverse_subgraph",
                tenant_id,
                scan_id,
                tuple(roots),
                direction,
                max_depth,
                max_nodes,
                traversable_only,
                relationship_types,
                static_only,
                dynamic_only,
                include_roots,
            )
        )
        return self.graph.traverse_subgraph(
            roots,
            direction=direction,
            max_depth=max_depth,
            max_nodes=max_nodes,
            traversable_only=traversable_only,
            relationship_types=relationship_types,
            static_only=static_only,
            dynamic_only=dynamic_only,
            include_roots=include_roots,
        )

    def attack_paths_for_sources(self, *, tenant_id: str = "", scan_id: str = "", source_ids: set[str]):
        self.calls.append(("attack_paths_for_sources", tenant_id, scan_id, tuple(sorted(source_ids))))
        return [ap for ap in self.graph.attack_paths if ap.source in source_ids]

    def node_context(self, *, tenant_id: str = "", scan_id: str = "", node_id: str):
        self.calls.append(("node_context", tenant_id, scan_id, node_id))
        node = self.graph.get_node(node_id)
        if not node:
            return None
        return {
            "node": node,
            "edges_out": self.graph.edges_from(node_id),
            "edges_in": self.graph.edges_to(node_id),
            "neighbors": self.graph.neighbors(node_id),
            "sources": self.graph.sources_of(node_id),
            "impact": self.graph.impact_of(node_id),
        }

    def compliance_summary(self, *, tenant_id: str = "", scan_id: str = "", framework: str = ""):
        self.calls.append(("compliance_summary", tenant_id, scan_id, framework))
        frameworks: dict[str, dict] = {}
        for node in self.graph.nodes.values():
            for tag in node.compliance_tags:
                prefix = tag.split("-")[0].upper() if "-" in tag else tag.upper()
                if framework and framework.upper() != prefix:
                    continue
                stats = frameworks.setdefault(
                    prefix,
                    {
                        "total_findings": 0,
                        "by_severity": {},
                        "by_entity_type": {},
                        "tags": set(),
                        "node_ids": [],
                    },
                )
                stats["total_findings"] += 1
                stats["by_severity"][node.severity or "unknown"] = stats["by_severity"].get(node.severity or "unknown", 0) + 1
                entity_type = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
                stats["by_entity_type"][entity_type] = stats["by_entity_type"].get(entity_type, 0) + 1
                stats["tags"].add(tag)
                if node.id not in stats["node_ids"]:
                    stats["node_ids"].append(node.id)
        return {
            "scan_id": self.graph.scan_id,
            "framework_count": len(frameworks),
            "total_tagged_findings": sum(stats["total_findings"] for stats in frameworks.values()),
            "frameworks": {
                name: {
                    "total_findings": stats["total_findings"],
                    "by_severity": stats["by_severity"],
                    "by_entity_type": stats["by_entity_type"],
                    "tags": sorted(stats["tags"]),
                    "node_count": len(stats["node_ids"]),
                    "node_ids": stats["node_ids"][:100],
                }
                for name, stats in sorted(frameworks.items())
            },
        }

    def save_preset(self, *, tenant_id: str, name: str, description: str, filters: dict, created_at: str) -> None:
        self.calls.append(("save_preset", tenant_id, name))
        self.presets[name] = {"name": name, "description": description, "filters": filters, "created_at": created_at}

    def list_presets(self, *, tenant_id: str) -> list[dict]:
        self.calls.append(("list_presets", tenant_id))
        return list(self.presets.values())

    def delete_preset(self, *, tenant_id: str, name: str) -> bool:
        self.calls.append(("delete_preset", tenant_id, name))
        return self.presets.pop(name, None) is not None


@pytest.fixture
def recording_graph_store():
    original = api_stores._graph_store
    store = _RecordingGraphStore()
    set_graph_store(store)
    try:
        yield store
    finally:
        set_graph_store(original)


class TestGraphStoreBackendSelection:
    def test_graph_routes_use_pluggable_store(self, recording_graph_store):
        client = TestClient(app)

        response = client.get("/v1/graph")
        assert response.status_code == 200
        assert response.json()["scan_id"] == "store-scan"
        assert any(call[0] == "latest_snapshot_id" for call in recording_graph_store.calls)
        assert any(call[0] == "page_nodes" for call in recording_graph_store.calls)
        assert not any(call[0] == "load_graph" for call in recording_graph_store.calls)

    def test_graph_overview_filtered_page_stays_store_backed(self, recording_graph_store):
        recording_graph_store.graph.add_node(
            UnifiedNode(
                id="server:prod",
                entity_type=EntityType.SERVER,
                label="prod-server",
                severity="high",
                severity_id=4,
            )
        )
        client = TestClient(app)

        response = client.get(
            "/v1/graph",
            params={"entity_types": "agent,server", "min_severity": "high", "offset": 0, "limit": 1},
        )

        assert response.status_code == 200
        helper_calls = [call[0] for call in recording_graph_store.calls]
        assert helper_calls.count("page_nodes") == 1
        assert helper_calls.count("edges_for_node_ids") == 1
        assert helper_calls.count("snapshot_stats") == 1
        assert "load_graph" not in helper_calls

    def test_graph_presets_use_pluggable_store(self, recording_graph_store):
        client = TestClient(app)

        create = client.post(
            "/v1/graph/presets",
            json={"name": "critical", "description": "Critical only", "filters": {"severity": "critical"}},
        )
        assert create.status_code == 200
        listed = client.get("/v1/graph/presets")
        assert listed.status_code == 200
        assert listed.json()[0]["name"] == "critical"
        deleted = client.delete("/v1/graph/presets/critical")
        assert deleted.status_code == 200
        assert any(call[0] == "save_preset" for call in recording_graph_store.calls)
        assert any(call[0] == "list_presets" for call in recording_graph_store.calls)
        assert any(call[0] == "delete_preset" for call in recording_graph_store.calls)

    def test_scan_pipeline_persists_via_graph_store(self, monkeypatch, recording_graph_store):
        from agent_bom.api.pipeline import _persist_graph_snapshot

        persisted = UnifiedGraph(scan_id="job-123", tenant_id="default")
        persisted.add_node(UnifiedNode(id="agent:scan", entity_type=EntityType.AGENT, label="scan-agent"))

        monkeypatch.setattr("agent_bom.api.pipeline._get_graph_store", lambda: recording_graph_store)
        monkeypatch.setattr("agent_bom.graph.builder.build_unified_graph_from_report", lambda report_json, scan_id, tenant_id: persisted)
        monkeypatch.setattr("agent_bom.graph.webhooks.compute_delta_alerts", lambda previous, current: [])

        job = SimpleNamespace(job_id="job-123", tenant_id="default", progress=[])
        _persist_graph_snapshot(job, {"scan_id": "job-123"})

        assert ("save_graph", "job-123", "default") in recording_graph_store.calls

    def test_graph_search_uses_store_native_query(self, recording_graph_store):
        recording_graph_store.graph.add_node(UnifiedNode(id="server:a", entity_type=EntityType.SERVER, label="agent-a server"))
        client = TestClient(app)

        response = client.get("/v1/graph/search", params={"q": "server"})

        assert response.status_code == 200
        assert response.json()["pagination"]["total"] == 1
        assert response.json()["results"][0]["id"] == "server:a"
        assert any(call[0] == "search_nodes" for call in recording_graph_store.calls)
        assert not any(call[0] == "load_graph" for call in recording_graph_store.calls)

    def test_graph_routes_offload_store_calls_to_thread(self, recording_graph_store, monkeypatch):
        client = TestClient(app)
        helper_calls: list[str] = []

        async def _fake_graph_store_call(fn, /, *args, **kwargs):
            helper_calls.append(fn.__name__)
            return fn(*args, **kwargs)

        monkeypatch.setattr(graph_routes, "_graph_store_call", _fake_graph_store_call)

        graph_response = client.get("/v1/graph")
        search_response = client.get("/v1/graph/search", params={"q": "agent"})

        assert graph_response.status_code == 200
        assert search_response.status_code == 200
        assert "latest_snapshot_id" in helper_calls
        assert "page_nodes" in helper_calls
        assert "search_nodes" in helper_calls

    def test_graph_search_forwards_slice_filters(self, recording_graph_store):
        recording_graph_store.graph.add_node(
            UnifiedNode(
                id="server:prod",
                entity_type=EntityType.SERVER,
                label="prod server",
                severity="high",
                severity_id=4,
                compliance_tags=["CIS-5.4.1"],
                data_sources=["runtime-proxy"],
            )
        )
        client = TestClient(app)

        response = client.get(
            "/v1/graph/search",
            params={
                "q": "server",
                "entity_types": "server",
                "min_severity": "high",
                "compliance_prefixes": "CIS",
                "data_sources": "runtime-proxy",
            },
        )

        assert response.status_code == 200
        assert response.json()["pagination"]["total"] == 1
        assert response.json()["results"][0]["id"] == "server:prod"
        assert (
            "search_nodes",
            "default",
            "",
            "server",
            {"server"},
            4,
            {"CIS"},
            {"runtime-proxy"},
            None,
            0,
            50,
        ) in recording_graph_store.calls

    def test_graph_overview_supports_cursor_pagination(self, recording_graph_store):
        recording_graph_store.graph.add_node(
            UnifiedNode(id="server:b", entity_type=EntityType.SERVER, label="server-b", severity="high", severity_id=4)
        )
        recording_graph_store.graph.add_node(
            UnifiedNode(id="server:c", entity_type=EntityType.SERVER, label="server-c", severity="high", severity_id=4)
        )
        client = TestClient(app)

        first = client.get("/v1/graph", params={"entity_types": "agent,server", "limit": 2})
        assert first.status_code == 200
        next_cursor = first.json()["pagination"]["next_cursor"]
        assert next_cursor

        second = client.get("/v1/graph", params={"entity_types": "agent,server", "limit": 2, "cursor": next_cursor})
        assert second.status_code == 200
        assert second.json()["pagination"]["cursor"] == next_cursor
        assert second.json()["pagination"]["offset"] == 0

    def test_graph_search_supports_cursor_pagination(self, recording_graph_store):
        recording_graph_store.graph.add_node(UnifiedNode(id="server:b", entity_type=EntityType.SERVER, label="agent-b server"))
        recording_graph_store.graph.add_node(UnifiedNode(id="server:c", entity_type=EntityType.SERVER, label="agent-c server"))
        recording_graph_store.graph.add_node(UnifiedNode(id="server:d", entity_type=EntityType.SERVER, label="agent-d server"))
        client = TestClient(app)

        first = client.get("/v1/graph/search", params={"q": "server", "limit": 2})
        assert first.status_code == 200
        next_cursor = first.json()["pagination"]["next_cursor"]
        assert next_cursor

        second = client.get("/v1/graph/search", params={"q": "server", "limit": 2, "cursor": next_cursor})
        assert second.status_code == 200
        assert second.json()["pagination"]["cursor"] == next_cursor

    def test_graph_cursor_rejects_invalid_values(self, recording_graph_store):
        client = TestClient(app)
        response = client.get("/v1/graph", params={"cursor": "not-a-real-cursor"})
        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid graph cursor"

    def test_graph_paths_reachable_nodes_follow_traversable_edges_only(self, recording_graph_store):
        recording_graph_store.graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
        recording_graph_store.graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        recording_graph_store.graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s"))
        recording_graph_store.graph.add_node(UnifiedNode(id="tool:t", entity_type=EntityType.TOOL, label="tool-t"))
        recording_graph_store.graph.add_edge(
            UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES, traversable=True)
        )
        recording_graph_store.graph.add_edge(
            UnifiedEdge(source="server:s", target="tool:t", relationship=RelationshipType.PROVIDES_TOOL, traversable=False)
        )
        client = TestClient(app)

        response = client.get("/v1/graph/paths", params={"source": "agent:a", "max_depth": 4})

        assert response.status_code == 200
        body = response.json()
        assert body["reachable_count"] == 1
        assert body["reachable_nodes"] == ["server:s"]
        assert [path["target"] for path in body["paths"]] == ["server:s"]
        assert any(call[0] == "bfs_paths" for call in recording_graph_store.calls)
        assert not any(call[0] == "load_graph" for call in recording_graph_store.calls)

    def test_graph_impact_uses_store_native_traversal(self, recording_graph_store):
        recording_graph_store.graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
        recording_graph_store.graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        recording_graph_store.graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s"))
        recording_graph_store.graph.add_edge(
            UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES, traversable=True)
        )
        client = TestClient(app)

        response = client.get("/v1/graph/impact", params={"node": "server:s", "max_depth": 4})

        assert response.status_code == 200
        body = response.json()
        assert body["node_id"] == "server:s"
        assert body["affected_nodes"] == ["agent:a"]
        assert any(call[0] == "impact_of" for call in recording_graph_store.calls)
        assert not any(call[0] == "load_graph" for call in recording_graph_store.calls)

    def test_graph_query_returns_bounded_directional_subgraph(self, recording_graph_store):
        recording_graph_store.graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
        recording_graph_store.graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        recording_graph_store.graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s"))
        recording_graph_store.graph.add_node(
            UnifiedNode(
                id="vuln:CVE-2026-1",
                entity_type=EntityType.VULNERABILITY,
                label="CVE-2026-1",
                severity="critical",
                risk_score=9.8,
                data_sources=["osv"],
            )
        )
        recording_graph_store.graph.add_edge(
            UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES, traversable=True)
        )
        recording_graph_store.graph.add_edge(
            UnifiedEdge(
                source="server:s",
                target="vuln:CVE-2026-1",
                relationship=RelationshipType.VULNERABLE_TO,
                traversable=True,
            )
        )
        recording_graph_store.graph.attack_paths.append(
            AttackPath(
                source="agent:a",
                target="vuln:CVE-2026-1",
                hops=["agent:a", "server:s", "vuln:CVE-2026-1"],
                edges=["uses", "vulnerable_to"],
                composite_risk=9.8,
                summary="agent-a -> server-s -> CVE-2026-1",
            )
        )
        client = TestClient(app)

        response = client.post(
            "/v1/graph/query",
            json={
                "roots": ["agent:a"],
                "direction": "forward",
                "max_depth": 2,
                "relationship_types": ["uses", "vulnerable_to"],
                "include_attack_paths": True,
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["roots"] == ["agent:a"]
        assert body["truncated"] is False
        assert set(body["depth_by_node"]) == {"agent:a", "server:s", "vuln:CVE-2026-1"}
        assert {node["id"] for node in body["nodes"]} == {"agent:a", "server:s", "vuln:CVE-2026-1"}
        assert {(edge["source"], edge["target"]) for edge in body["edges"]} == {
            ("agent:a", "server:s"),
            ("server:s", "vuln:CVE-2026-1"),
        }
        assert body["attack_paths"][0]["target"] == "vuln:CVE-2026-1"
        assert any(call[0] == "traverse_subgraph" for call in recording_graph_store.calls)
        assert not any(call[0] == "load_graph" for call in recording_graph_store.calls)

    def test_graph_node_uses_store_native_context(self, recording_graph_store):
        recording_graph_store.graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
        recording_graph_store.graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        recording_graph_store.graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server-s"))
        recording_graph_store.graph.add_edge(
            UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES, traversable=True)
        )
        client = TestClient(app)

        response = client.get("/v1/graph/node/server:s")

        assert response.status_code == 200
        body = response.json()
        assert body["node"]["id"] == "server:s"
        assert body["sources"] == ["agent:a"]
        assert any(call[0] == "node_context" for call in recording_graph_store.calls)
        assert not any(call[0] == "load_graph" for call in recording_graph_store.calls)

    def test_graph_compliance_uses_store_native_summary(self, recording_graph_store):
        recording_graph_store.graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
        recording_graph_store.graph.add_node(
            UnifiedNode(
                id="vuln:cve",
                entity_type=EntityType.VULNERABILITY,
                label="CVE-2026-1",
                severity="critical",
                severity_id=5,
                compliance_tags=["CIS-5.4.1", "OWASP-A01"],
            )
        )
        client = TestClient(app)

        response = client.get("/v1/graph/compliance", params={"framework": "CIS"})

        assert response.status_code == 200
        body = response.json()
        assert body["framework_count"] == 1
        assert body["frameworks"]["CIS"]["total_findings"] == 1
        assert any(call[0] == "compliance_summary" for call in recording_graph_store.calls)
        assert not any(call[0] == "load_graph" for call in recording_graph_store.calls)

    def test_graph_query_filters_by_compliance_and_source(self, recording_graph_store):
        recording_graph_store.graph = UnifiedGraph(scan_id="store-scan", tenant_id="default")
        recording_graph_store.graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
        recording_graph_store.graph.add_node(
            UnifiedNode(
                id="misconfig:iac:K8S-007:file.yaml:12",
                entity_type=EntityType.MISCONFIGURATION,
                label="Secrets in env",
                severity="high",
                compliance_tags=["CIS-5.4.1", "T1552.001"],
                data_sources=["iac", "kubernetes"],
            )
        )
        recording_graph_store.graph.add_node(
            UnifiedNode(
                id="cloud_resource:k8s:file.yaml",
                entity_type=EntityType.CLOUD_RESOURCE,
                label="deploy/k8s/file.yaml",
                data_sources=["iac", "kubernetes"],
            )
        )
        recording_graph_store.graph.add_edge(
            UnifiedEdge(
                source="misconfig:iac:K8S-007:file.yaml:12",
                target="cloud_resource:k8s:file.yaml",
                relationship=RelationshipType.AFFECTS,
            )
        )
        client = TestClient(app)

        response = client.post(
            "/v1/graph/query",
            json={
                "roots": ["misconfig:iac:K8S-007:file.yaml:12"],
                "direction": "forward",
                "max_depth": 1,
                "compliance_prefixes": ["CIS"],
                "data_sources": ["iac"],
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert [node["id"] for node in body["nodes"]] == ["misconfig:iac:K8S-007:file.yaml:12"]
        assert body["edges"] == []

    def test_graph_query_returns_404_for_missing_roots(self, recording_graph_store):
        client = TestClient(app)

        response = client.post("/v1/graph/query", json={"roots": ["agent:missing"]})

        assert response.status_code == 404
        assert response.json()["detail"]["missing_roots"] == ["agent:missing"]
