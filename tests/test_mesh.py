"""Tests for agent mesh graph builder."""

from __future__ import annotations

from agent_bom.output.agent_mesh import _vuln_color, build_agent_mesh


def _agent(name: str, servers: list[dict] | None = None) -> dict:
    return {
        "name": name,
        "agent_type": "test",
        "mcp_servers": servers or [],
    }


def _server(name: str, pkgs: list[dict] | None = None, tools: list[dict] | None = None, env: dict | None = None) -> dict:
    return {
        "name": name,
        "packages": pkgs or [],
        "tools": tools or [],
        "env": env or {},
    }


def _pkg(name: str, vulns: list[dict] | None = None) -> dict:
    return {
        "name": name,
        "version": "1.0.0",
        "ecosystem": "pypi",
        "vulnerabilities": vulns or [],
    }


def _vuln(vid: str = "CVE-2024-0001", severity: str = "high") -> dict:
    return {"id": vid, "severity": severity}


class TestBuildAgentMesh:
    def test_empty_agents(self):
        result = build_agent_mesh([])
        assert result["nodes"] == []
        assert result["edges"] == []
        assert result["stats"]["total_agents"] == 0

    def test_single_agent_no_servers(self):
        result = build_agent_mesh([_agent("a1")])
        assert result["stats"]["total_agents"] == 1
        assert result["stats"]["total_servers"] == 0
        assert len(result["nodes"]) == 1
        assert result["nodes"][0]["data"]["nodeType"] == "agent"

    def test_agent_with_server(self):
        agents = [_agent("a1", [_server("srv1")])]
        result = build_agent_mesh(agents)
        assert result["stats"]["total_agents"] == 1
        assert result["stats"]["total_servers"] == 1
        node_types = {n["data"]["nodeType"] for n in result["nodes"]}
        assert "agent" in node_types
        assert "server" in node_types
        assert len(result["edges"]) == 1

    def test_shared_server_detection(self):
        shared = _server("shared-srv")
        agents = [
            _agent("a1", [shared]),
            _agent("a2", [_server("shared-srv")]),
        ]
        result = build_agent_mesh(agents)
        # Server node created once, edges from both agents
        server_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "server"]
        assert len(server_nodes) == 1
        # Two agent→server edges (one normal, one shared)
        agent_to_server = [e for e in result["edges"] if e["source"].startswith("agent:")]
        assert len(agent_to_server) == 2

    def test_vulnerability_counting(self):
        pkg = _pkg("vuln-pkg", [_vuln("CVE-1"), _vuln("CVE-2")])
        agents = [_agent("a1", [_server("srv1", pkgs=[pkg])])]
        result = build_agent_mesh(agents)
        assert result["stats"]["total_vulnerabilities"] == 2
        agent_node = result["nodes"][0]
        assert agent_node["data"]["vuln_count"] == 2

    def test_credential_counting(self):
        env = {"API_KEY": "xxx", "DB_PASSWORD": "yyy", "NORMAL_VAR": "zzz"}
        agents = [_agent("a1", [_server("srv1", env=env)])]
        result = build_agent_mesh(agents)
        assert result["stats"]["total_credentials"] == 2

    def test_tool_nodes(self):
        tools = [{"name": "t1"}, {"name": "t2"}]
        agents = [_agent("a1", [_server("srv1", tools=tools)])]
        result = build_agent_mesh(agents)
        assert result["stats"]["total_tools"] == 2
        tool_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "tool"]
        assert len(tool_nodes) == 2

    def test_tool_limit_8(self):
        tools = [{"name": f"t{i}"} for i in range(15)]
        agents = [_agent("a1", [_server("srv1", tools=tools)])]
        result = build_agent_mesh(agents)
        tool_nodes = [n for n in result["nodes"] if n["data"]["nodeType"] == "tool"]
        assert len(tool_nodes) == 8

    def test_blast_radius_overlay(self):
        blast = [
            {"package": "pkg1"},
            {"package": "pkg1"},
            {"package": "pkg2"},
        ]
        result = build_agent_mesh([_agent("a1", [_server("srv1")])], blast_radius=blast)
        # Stats still work even without vulns in packages
        assert result["stats"]["total_agents"] == 1

    def test_multiple_agents_stats(self):
        agents = [
            _agent("a1", [_server("srv1", pkgs=[_pkg("p1")])]),
            _agent("a2", [_server("srv2", pkgs=[_pkg("p2"), _pkg("p3")])]),
        ]
        result = build_agent_mesh(agents)
        assert result["stats"]["total_agents"] == 2
        assert result["stats"]["total_servers"] == 2
        assert result["stats"]["total_packages"] == 3


class TestVulnColor:
    def test_zero(self):
        assert _vuln_color(0) == "#10b981"

    def test_low(self):
        assert _vuln_color(2) == "#eab308"

    def test_medium(self):
        assert _vuln_color(5) == "#f97316"

    def test_high(self):
        assert _vuln_color(10) == "#ef4444"
