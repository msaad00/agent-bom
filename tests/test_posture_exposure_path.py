"""Posture card surfaces the top agent → MCP → CVE → tool exposure path."""

from __future__ import annotations

from agent_bom.cli.agents._posture import render_posture_summary
from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)


def _chain_blast_radius() -> tuple[list[Agent], list[BlastRadius]]:
    vuln = Vulnerability(
        id="GHSA-8vj2-vxx3-667w",
        summary="Code execution in pillow",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="9.0.1",
    )
    pkg = Package(
        name="pillow",
        version="9.0.0",
        ecosystem="pypi",
        vulnerabilities=[vuln],
        is_direct=True,
    )
    server = MCPServer(
        name="database-server",
        tools=[MCPTool(name="run_query", description="Run a SQL query")],
        packages=[pkg],
    )
    agent = Agent(
        name="cursor",
        agent_type=AgentType.CURSOR,
        config_path="/tmp/cursor.json",
        mcp_servers=[server],
        version="1.0",
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["DATABASE_URL", "ANTHROPIC_API_KEY"],
        exposed_tools=[MCPTool(name="run_query", description="Run a SQL query")],
    )
    br.calculate_risk_score()
    return [agent], [br]


def test_posture_renders_top_exposure_chain(capsys) -> None:
    agents, blast_radii = _chain_blast_radius()
    render_posture_summary(agents, blast_radii)
    out = capsys.readouterr().out
    # Rich wraps the panel, so normalise whitespace before asserting the chain.
    flat = " ".join(out.split())
    assert "Path:" in flat
    assert "cursor → database-server → pillow@9.0.0 → GHSA-8vj2-vxx3-667w → run_query" in flat
    assert "2 cred(s), 1 tool(s) reachable" in flat


def test_posture_omits_exposure_chain_when_no_findings(capsys) -> None:
    agent = Agent(
        name="cursor",
        agent_type=AgentType.CURSOR,
        config_path="/tmp/cursor.json",
        mcp_servers=[],
        version="1.0",
    )
    render_posture_summary([agent], [])
    flat = " ".join(capsys.readouterr().out.split())
    assert "Path:" not in flat
    assert "No vulnerabilities found" in flat
