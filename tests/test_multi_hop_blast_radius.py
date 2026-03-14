"""Tests for multi-hop blast radius delegation chain tracking.

Covers:
- 1-hop default behavior (unchanged)
- 2-hop delegation chain discovery
- Cycle detection (agent A → server B → agent C → server B)
- Risk amplification decreases with hops
- Depth limit enforcement
"""

from __future__ import annotations

from agent_bom.models import (
    Agent,
    AgentStatus,
    AgentType,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.scanners import expand_blast_radius_hops


def _make_agent(name: str, servers: list[MCPServer]) -> Agent:
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path="/tmp/test",
        source="test",
        status=AgentStatus.CONFIGURED,
        mcp_servers=servers,
    )


def _make_server(name: str, packages: list[Package] | None = None, cred_names: list[str] | None = None) -> MCPServer:
    srv = MCPServer(
        name=name,
        command="node",
        args=[f"{name}.js"],
        transport=TransportType.STDIO,
        packages=packages or [],
    )
    # Set credential env vars via env dict for credential_names property
    if cred_names:
        srv.env = {k: "***" for k in cred_names}
    return srv


def _make_vuln(vuln_id: str = "CVE-2025-0001", severity: Severity = Severity.HIGH) -> Vulnerability:
    return Vulnerability(id=vuln_id, summary="Test vuln", severity=severity)


def _make_pkg(name: str = "test-pkg", version: str = "1.0.0") -> Package:
    return Package(name=name, version=version, ecosystem="npm")


def _make_blast_radius(
    vuln: Vulnerability,
    pkg: Package,
    servers: list[MCPServer],
    agents: list[Agent],
) -> BlastRadius:
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=servers,
        affected_agents=agents,
        exposed_credentials=[],
        exposed_tools=[MCPTool(name="read_file", description="Read a file")],
    )
    br.risk_score = 6.0
    return br


class TestDefaultOneHop:
    """When depth=1 (default), no multi-hop expansion happens."""

    def test_no_op_at_depth_1(self):
        srv = _make_server("srv1")
        agent1 = _make_agent("agent1", [srv])
        pkg = _make_pkg()
        vuln = _make_vuln()
        br = _make_blast_radius(vuln, pkg, [srv], [agent1])

        expand_blast_radius_hops([br], [agent1], max_depth=1)

        assert br.hop_depth == 1
        assert br.delegation_chain == []
        assert br.transitive_agents == []
        assert br.transitive_risk_score == 0.0

    def test_no_op_at_depth_0(self):
        """Depth < 1 is clamped to 1."""
        srv = _make_server("srv1")
        agent1 = _make_agent("agent1", [srv])
        br = _make_blast_radius(_make_vuln(), _make_pkg(), [srv], [agent1])

        expand_blast_radius_hops([br], [agent1], max_depth=0)

        assert br.hop_depth == 1
        assert br.transitive_agents == []


class TestTwoHopDelegation:
    """Two-hop: vuln → pkg → server1 → agent1 → server2 → agent2."""

    def test_finds_transitive_agent(self):
        shared_srv = _make_server("shared-server")
        other_srv = _make_server("other-server")

        agent1 = _make_agent("agent1", [shared_srv, other_srv])
        agent2 = _make_agent("agent2", [other_srv])

        pkg = _make_pkg()
        vuln = _make_vuln()
        br = _make_blast_radius(vuln, pkg, [shared_srv], [agent1])

        expand_blast_radius_hops([br], [agent1, agent2], max_depth=2)

        assert br.hop_depth == 2
        assert len(br.transitive_agents) == 1
        assert br.transitive_agents[0]["name"] == "agent2"
        assert br.transitive_agents[0]["hop"] == 2
        assert len(br.delegation_chain) == 1

    def test_transitive_credentials_collected(self):
        shared_srv = _make_server("shared-server")
        secret_srv = _make_server("secret-server", cred_names=["AWS_SECRET_KEY"])

        agent1 = _make_agent("agent1", [shared_srv, secret_srv])
        agent2 = _make_agent("agent2", [secret_srv])

        br = _make_blast_radius(_make_vuln(), _make_pkg(), [shared_srv], [agent1])

        expand_blast_radius_hops([br], [agent1, agent2], max_depth=2)

        assert "AWS_SECRET_KEY" in br.transitive_credentials


class TestCycleDetection:
    """BFS should not loop when agents share servers cyclically."""

    def test_no_infinite_loop(self):
        srv_a = _make_server("srv-a")
        srv_b = _make_server("srv-b")

        agent1 = _make_agent("agent1", [srv_a, srv_b])
        agent2 = _make_agent("agent2", [srv_b, srv_a])

        br = _make_blast_radius(_make_vuln(), _make_pkg(), [srv_a], [agent1])

        # Should complete without hanging
        expand_blast_radius_hops([br], [agent1, agent2], max_depth=3)

        # agent2 found once via srv_b
        assert len(br.transitive_agents) == 1
        assert br.transitive_agents[0]["name"] == "agent2"


class TestRiskAmplification:
    """Risk score decreases with hop distance."""

    def test_hop2_factor(self):
        srv1 = _make_server("srv1")
        srv2 = _make_server("srv2")
        agent1 = _make_agent("agent1", [srv1, srv2])
        agent2 = _make_agent("agent2", [srv2])

        br = _make_blast_radius(_make_vuln(), _make_pkg(), [srv1], [agent1])
        br.risk_score = 8.0

        expand_blast_radius_hops([br], [agent1, agent2], max_depth=2)

        assert br.transitive_risk_score == 8.0 * 0.7  # hop 2 factor

    def test_hop3_factor(self):
        srv1 = _make_server("srv1")
        srv2 = _make_server("srv2")
        srv3 = _make_server("srv3")

        agent1 = _make_agent("agent1", [srv1, srv2])
        agent2 = _make_agent("agent2", [srv2, srv3])
        agent3 = _make_agent("agent3", [srv3])

        br = _make_blast_radius(_make_vuln(), _make_pkg(), [srv1], [agent1])
        br.risk_score = 10.0

        expand_blast_radius_hops([br], [agent1, agent2, agent3], max_depth=3)

        assert br.hop_depth == 3
        assert br.transitive_risk_score == 10.0 * 0.5  # hop 3 factor
        assert len(br.transitive_agents) == 2

    def test_risk_decreases_with_depth(self):
        """Higher hop depth = lower transitive risk factor."""
        from agent_bom.scanners import _HOP_RISK_FACTORS

        prev = 1.1
        for hop in range(1, 6):
            factor = _HOP_RISK_FACTORS[hop]
            assert factor < prev, f"Factor at hop {hop} ({factor}) should be less than {prev}"
            prev = factor


class TestDepthLimit:
    """Max depth is clamped to [1, 5]."""

    def test_depth_clamped_to_5(self):
        srv1 = _make_server("srv1")
        srv2 = _make_server("srv2")
        agent1 = _make_agent("agent1", [srv1, srv2])
        agent2 = _make_agent("agent2", [srv2])

        br = _make_blast_radius(_make_vuln(), _make_pkg(), [srv1], [agent1])

        # max_depth=10 should clamp to 5
        expand_blast_radius_hops([br], [agent1, agent2], max_depth=10)

        assert br.hop_depth <= 5

    def test_no_transitive_at_depth_1(self):
        """Even with shared servers, depth=1 returns no transitive agents."""
        srv = _make_server("shared")
        agent1 = _make_agent("a1", [srv])
        agent2 = _make_agent("a2", [srv])

        br = _make_blast_radius(_make_vuln(), _make_pkg(), [srv], [agent1])

        expand_blast_radius_hops([br], [agent1, agent2], max_depth=1)

        assert br.transitive_agents == []


class TestMultipleBlastRadii:
    """expand_blast_radius_hops handles multiple blast radius entries."""

    def test_multiple_brs_expanded(self):
        srv1 = _make_server("srv1")
        srv2 = _make_server("srv2")
        agent1 = _make_agent("agent1", [srv1, srv2])
        agent2 = _make_agent("agent2", [srv2])

        br1 = _make_blast_radius(_make_vuln("CVE-1"), _make_pkg("pkg1"), [srv1], [agent1])
        br2 = _make_blast_radius(_make_vuln("CVE-2"), _make_pkg("pkg2"), [srv1], [agent1])

        expand_blast_radius_hops([br1, br2], [agent1, agent2], max_depth=2)

        assert len(br1.transitive_agents) == 1
        assert len(br2.transitive_agents) == 1
