from __future__ import annotations

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Agent, AgentType, MCPServer


def test_doctor_groups_output_and_shows_next_steps():
    result = CliRunner().invoke(main, ["doctor"])

    assert result.exit_code == 0
    assert "Core readiness" in result.output
    assert "Runtime surfaces" in result.output
    assert "Platform integrations" in result.output
    assert "Next commands" in result.output
    assert "agent-bom agents --demo --offline" in result.output


def test_doctor_suppresses_raw_discovery_output(monkeypatch):
    def noisy_discovery(*, quiet: bool = False):
        assert quiet is True
        print("raw discovery line before banner")
        return [
            Agent(
                name="Claude Desktop",
                agent_type=AgentType.CLAUDE_DESKTOP,
                config_path="/tmp/claude.json",
                mcp_servers=[MCPServer(name="filesystem"), MCPServer(name="git")],
            )
        ]

    monkeypatch.setattr("agent_bom.discovery.discover_global_configs", noisy_discovery)

    result = CliRunner().invoke(main, ["doctor"])

    assert result.exit_code == 0
    assert "raw discovery line before banner" not in result.output
    assert "agent-bom doctor" in result.output
    assert "MCP discovery" in result.output
    assert "1 client config(s), 2 MCP server(s) (Claude Desktop)" in result.output


def test_doctor_reports_mcp_discovery_error_without_raw_parser_line(monkeypatch):
    def failing_discovery(*, quiet: bool = False):
        assert quiet is True
        print("raw parser warning")
        raise RuntimeError("boom")

    monkeypatch.setattr("agent_bom.discovery.discover_global_configs", failing_discovery)

    result = CliRunner().invoke(main, ["doctor"])

    assert result.exit_code == 0
    assert "raw parser warning" not in result.output
    assert "MCP discovery" in result.output
    assert "discovery error" in result.output
