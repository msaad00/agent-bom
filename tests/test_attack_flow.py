"""Tests for attack flow graph builder."""

from __future__ import annotations

from agent_bom.output.attack_flow import build_attack_flow

# ── Test data fixtures ──────────────────────────────────────────────────────


def _make_blast_radius():
    return [
        {
            "vulnerability_id": "CVE-2024-1234",
            "severity": "critical",
            "cvss_score": 9.8,
            "epss_score": 0.72,
            "is_kev": True,
            "risk_score": 9.2,
            "package": "express@4.18.2",
            "ecosystem": "npm",
            "affected_agents": ["claude-desktop"],
            "affected_servers": ["filesystem"],
            "exposed_credentials": ["DB_PASSWORD"],
            "exposed_tools": ["read_file", "write_file"],
            "fixed_version": "4.19.0",
            "owasp_tags": ["LLM05", "LLM06"],
            "atlas_tags": ["AML.T0010"],
            "nist_ai_rmf_tags": ["MAP-3.5"],
            "ai_risk_context": "MCP server with filesystem access",
        },
        {
            "vulnerability_id": "CVE-2024-5678",
            "severity": "high",
            "cvss_score": 7.5,
            "epss_score": 0.15,
            "is_kev": False,
            "risk_score": 6.8,
            "package": "lodash@4.17.20",
            "ecosystem": "npm",
            "affected_agents": ["claude-desktop", "cursor"],
            "affected_servers": ["github"],
            "exposed_credentials": [],
            "exposed_tools": ["create_issue"],
            "fixed_version": "4.17.21",
            "owasp_tags": ["LLM05"],
            "atlas_tags": [],
            "nist_ai_rmf_tags": [],
            "ai_risk_context": None,
        },
    ]


def _make_agents():
    return [
        {"name": "claude-desktop", "agent_type": "claude-desktop", "status": "configured"},
        {"name": "cursor", "agent_type": "cursor", "status": "configured"},
    ]


# ── Node/edge generation tests ─────────────────────────────────────────────


def test_build_attack_flow_basic():
    """build_attack_flow returns nodes, edges, and stats."""
    result = build_attack_flow(_make_blast_radius(), _make_agents())
    assert "nodes" in result
    assert "edges" in result
    assert "stats" in result
    assert len(result["nodes"]) > 0
    assert len(result["edges"]) > 0


def test_attack_flow_node_types():
    """All expected node types are present."""
    result = build_attack_flow(_make_blast_radius(), _make_agents())
    node_types = {n["data"]["nodeType"] for n in result["nodes"]}
    assert "cve" in node_types
    assert "package" in node_types
    assert "agent" in node_types


def test_attack_flow_package_nodes_preserve_version_provenance():
    blast_radius = _make_blast_radius()
    blast_radius[0]["package_version_provenance"] = {
        "version_source": "lockfile",
        "confidence": "exact",
        "resolved_version": "4.18.2",
    }

    result = build_attack_flow(blast_radius, _make_agents())
    package = next(node for node in result["nodes"] if node["data"]["nodeType"] == "package" and node["data"]["label"] == "express")

    assert package["data"]["version_source"] == "lockfile"
    assert package["data"]["version_confidence"] == "exact"
    assert package["data"]["version_provenance"]["resolved_version"] == "4.18.2"


def test_attack_flow_stats():
    """Stats reflect the input data."""
    result = build_attack_flow(_make_blast_radius(), _make_agents())
    stats = result["stats"]
    assert stats["total_cves"] == 2
    assert stats["total_packages"] == 2
    assert stats["severity_counts"]["critical"] == 1
    assert stats["severity_counts"]["high"] == 1


# ── Filter tests ────────────────────────────────────────────────────────────


def test_filter_by_cve():
    """Filtering by CVE shows only that CVE's blast radius."""
    result = build_attack_flow(_make_blast_radius(), _make_agents(), cve="CVE-2024-1234")
    cve_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "cve"]
    assert len(cve_nodes) == 1
    assert cve_nodes[0]["data"]["label"] == "CVE-2024-1234"


def test_filter_by_severity():
    """Filtering by severity returns only matching findings."""
    result = build_attack_flow(_make_blast_radius(), _make_agents(), severity="critical")
    cve_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "cve"]
    assert len(cve_nodes) == 1
    assert all(n["data"]["severity"] == "critical" for n in cve_nodes)


def test_filter_by_framework():
    """Filtering by framework tag works."""
    result = build_attack_flow(_make_blast_radius(), _make_agents(), framework="AML.T0010")
    cve_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "cve"]
    assert len(cve_nodes) == 1
    assert cve_nodes[0]["data"]["label"] == "CVE-2024-1234"


def test_filter_by_agent():
    """Filtering by agent name works."""
    result = build_attack_flow(_make_blast_radius(), _make_agents(), agent_name="cursor")
    cve_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "cve"]
    assert len(cve_nodes) == 1
    assert cve_nodes[0]["data"]["label"] == "CVE-2024-5678"


def test_empty_blast_radius():
    """Empty blast radius returns empty graph."""
    result = build_attack_flow([], [])
    assert result["nodes"] == []
    assert result["edges"] == []
    assert result["stats"]["total_cves"] == 0


def test_credential_nodes_present():
    """Credential nodes are created for exposed credentials."""
    result = build_attack_flow(_make_blast_radius(), _make_agents())
    cred_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "credential"]
    assert len(cred_nodes) >= 1
    assert any(n["data"]["label"] == "DB_PASSWORD" for n in cred_nodes)


def test_tool_nodes_present():
    """Tool nodes are created for exposed tools."""
    result = build_attack_flow(_make_blast_radius(), _make_agents())
    tool_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "tool"]
    assert len(tool_nodes) >= 1
    labels = {n["data"]["label"] for n in tool_nodes}
    assert "read_file" in labels
    assert "write_file" in labels


# ── Lateral movement flow tests ───────────────────────────────────────────────

from agent_bom.output.attack_flow import build_lateral_movement_flow  # noqa: E402


class TestBuildLateralMovementFlow:
    def _shared_server_ctx(self):
        return {
            "shared_servers": [
                {
                    "name": "shared-memory-mcp",
                    "agents": ["agent-a", "agent-b"],
                    "tools": ["store_memory", "similarity_search"],
                }
            ],
            "lateral_paths": [],
        }

    def test_returns_nodes_and_edges(self):
        result = build_lateral_movement_flow(self._shared_server_ctx())
        assert "nodes" in result
        assert "edges" in result
        assert "stats" in result

    def test_agent_nodes_created(self):
        result = build_lateral_movement_flow(self._shared_server_ctx())
        agent_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "agent"]
        labels = {n["data"]["label"] for n in agent_nodes}
        assert "agent-a" in labels
        assert "agent-b" in labels

    def test_server_node_created(self):
        result = build_lateral_movement_flow(self._shared_server_ctx())
        server_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "server"]
        assert len(server_nodes) == 1
        assert server_nodes[0]["data"]["label"] == "shared-memory-mcp"

    def test_cross_poison_server_flagged(self):
        result = build_lateral_movement_flow(self._shared_server_ctx())
        server_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "server"]
        assert server_nodes[0]["data"]["is_cross_poison"] is True

    def test_cross_poison_edges_are_animated_and_red(self):
        result = build_lateral_movement_flow(self._shared_server_ctx())
        cross_edges = [e for e in result["edges"] if e.get("data", {}).get("edgeType") == "cross_poison"]
        assert len(cross_edges) >= 1
        for e in cross_edges:
            assert e.get("animated") is True
            assert "#dc2626" in e["style"]["stroke"]

    def test_readonly_server_not_cross_poison(self):
        ctx = {
            "shared_servers": [
                {
                    "name": "readonly-mcp",
                    "agents": ["agent-a", "agent-b"],
                    "tools": ["similarity_search", "retrieve_docs"],
                }
            ],
            "lateral_paths": [],
        }
        result = build_lateral_movement_flow(ctx)
        server_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "server"]
        assert server_nodes[0]["data"]["is_cross_poison"] is False

    def test_empty_context_returns_empty(self):
        result = build_lateral_movement_flow({})
        assert result["nodes"] == []
        assert result["edges"] == []

    def test_stats_cross_poison_count(self):
        result = build_lateral_movement_flow(self._shared_server_ctx())
        assert result["stats"]["cross_poison_servers"] == 1
        assert result["stats"]["total_agents"] == 2
        assert result["stats"]["total_servers"] == 1

    def test_lateral_paths_add_edges(self):
        ctx = {
            "shared_servers": [],
            "lateral_paths": [["agent-x", "agent-y"]],
        }
        result = build_lateral_movement_flow(ctx)
        assert len(result["edges"]) >= 1
        edge = result["edges"][0]
        assert edge.get("data", {}).get("edgeType") == "lateral"

    def test_build_attack_flow_overlays_lateral_edges(self):
        """build_attack_flow with context_graph_data includes lateral edges."""
        br = _make_blast_radius()
        ctx = {
            "shared_servers": [
                {
                    "name": "filesystem",
                    "agents": ["claude-desktop", "cursor"],
                    "tools": ["write_file", "read_file"],
                }
            ],
            "lateral_paths": [],
        }
        result = build_attack_flow(br, _make_agents(), context_graph_data=ctx)
        lateral = [e for e in result["edges"] if e.get("data", {}).get("edgeType") in ("lateral", "cross_poison")]
        assert len(lateral) >= 1
        assert result["stats"].get("cross_poison_servers", 0) >= 1
