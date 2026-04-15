"""Tests for graph query API endpoints and scan pipeline wiring."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
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

        results, total = store.search_nodes(tenant_id="default", query="vector", offset=0, limit=10)

        assert total == 1
        assert [node.id for node in results] == ["server:acme:vector"]

    def test_sqlite_graph_store_search_escapes_like_wildcards(self, tmp_path):
        store = SQLiteGraphStore(tmp_path / "graph.db")
        graph = UnifiedGraph(scan_id="search-scan", tenant_id="default")
        graph.add_node(UnifiedNode(id="server:percent", entity_type=EntityType.SERVER, label="100% Secure Server"))
        graph.add_node(UnifiedNode(id="dataset:underscore", entity_type=EntityType.DATASET, label="data_set"))
        graph.add_node(UnifiedNode(id="agent:plain", entity_type=EntityType.AGENT, label="plain agent"))
        store.save_graph(graph)

        percent_results, percent_total = store.search_nodes(tenant_id="default", query="%", offset=0, limit=10)
        underscore_results, underscore_total = store.search_nodes(tenant_id="default", query="_", offset=0, limit=10)

        assert percent_total == 1
        assert [node.id for node in percent_results] == ["server:percent"]
        assert underscore_total == 1
        assert [node.id for node in underscore_results] == ["dataset:underscore"]


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

    def search_nodes(self, *, tenant_id: str = "", scan_id: str = "", query: str, offset: int = 0, limit: int = 50):
        self.calls.append(("search_nodes", tenant_id, scan_id, query, offset, limit))
        matches = [node for node in self.graph.nodes.values() if query.lower() in node.label.lower()]
        return matches[offset : offset + limit], len(matches)

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
        assert any(call[0] == "load_graph" for call in recording_graph_store.calls)

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
