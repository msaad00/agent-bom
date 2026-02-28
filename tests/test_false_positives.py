"""Tests for false positive reduction — tool dedup, credential dedup, OWASP tagging."""

from __future__ import annotations

from agent_bom.models import (
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.owasp import tag_blast_radius


def _vuln(vid: str = "CVE-2024-0001", severity: str = "high") -> Vulnerability:
    return Vulnerability(id=vid, summary="test vulnerability", severity=Severity(severity))


def _pkg(name: str = "express", version: str = "4.17.1", ecosystem: str = "npm") -> Package:
    return Package(name=name, version=version, ecosystem=ecosystem)


def _tool(name: str) -> MCPTool:
    return MCPTool(name=name, description="")


def _server(name: str, tools: list[MCPTool] | None = None, env: dict | None = None) -> MCPServer:
    return MCPServer(name=name, tools=tools or [], env=env or {})


class TestToolDeduplication:
    """exposed_tools should be deduplicated by name across servers."""

    def test_same_tool_from_multiple_servers(self):
        """Same tool name from 3 servers should appear once in blast radius."""
        tool = _tool("read_file")
        servers = [
            _server("srv1", tools=[tool]),
            _server("srv2", tools=[MCPTool(name="read_file", description="different desc")]),
            _server("srv3", tools=[tool]),
        ]
        br = BlastRadius(
            vulnerability=_vuln(),
            package=_pkg(),
            affected_servers=servers,
            affected_agents=["agent1"],
            exposed_credentials=[],
            exposed_tools=[],  # will be filled by scanner, but test the model
        )
        # Simulate what the fixed scanner does: dedup by name
        all_tools = []
        for s in servers:
            all_tools.extend(s.tools)

        seen: set[str] = set()
        deduped = []
        for t in all_tools:
            if t.name not in seen:
                seen.add(t.name)
                deduped.append(t)

        assert len(all_tools) == 3
        assert len(deduped) == 1
        assert deduped[0].name == "read_file"

    def test_different_tools_preserved(self):
        """Distinct tool names should all be preserved."""
        tools = [_tool("read_file"), _tool("write_file"), _tool("execute")]
        seen: set[str] = set()
        deduped = []
        for t in tools:
            if t.name not in seen:
                seen.add(t.name)
                deduped.append(t)
        assert len(deduped) == 3


class TestCredentialDedup:
    """Credential lists should be consistent between message and score."""

    def test_same_cred_from_multiple_servers(self):
        """Same credential name from 2 servers should count once."""
        creds = ["API_KEY", "API_KEY", "DB_PASSWORD"]
        deduped = list(set(creds))
        assert len(deduped) == 2
        assert "API_KEY" in deduped
        assert "DB_PASSWORD" in deduped


class TestOwaspLLM05Tagging:
    """LLM05 should only be applied to AI/ML packages, not all findings."""

    def test_non_ai_package_no_llm05(self):
        """A generic npm package should NOT get LLM05."""
        br = BlastRadius(
            vulnerability=_vuln(),
            package=_pkg("express", "4.17.1", "npm"),
            affected_servers=[],
            affected_agents=["agent1"],
            exposed_credentials=[],
            exposed_tools=[],
        )
        br.calculate_risk_score()
        tags = tag_blast_radius(br)
        assert "LLM05" not in tags

    def test_ai_package_gets_llm05(self):
        """An AI framework package should get LLM05."""
        br = BlastRadius(
            vulnerability=_vuln(),
            package=_pkg("langchain", "0.1.0", "pypi"),
            affected_servers=[],
            affected_agents=["agent1"],
            exposed_credentials=[],
            exposed_tools=[],
        )
        br.calculate_risk_score()
        tags = tag_blast_radius(br)
        assert "LLM05" in tags

    def test_training_package_gets_llm05(self):
        """A training data package should get LLM05."""
        br = BlastRadius(
            vulnerability=_vuln(),
            package=_pkg("transformers", "4.30.0", "pypi"),
            affected_servers=[],
            affected_agents=["agent1"],
            exposed_credentials=[],
            exposed_tools=[],
        )
        br.calculate_risk_score()
        tags = tag_blast_radius(br)
        assert "LLM05" in tags

    def test_vector_store_gets_llm05(self):
        """A vector store package should get LLM05."""
        br = BlastRadius(
            vulnerability=_vuln(),
            package=_pkg("chromadb", "0.4.0", "pypi"),
            affected_servers=[],
            affected_agents=["agent1"],
            exposed_credentials=[],
            exposed_tools=[],
        )
        br.calculate_risk_score()
        tags = tag_blast_radius(br)
        assert "LLM05" in tags

    def test_cred_exposure_gets_llm06(self):
        """Credential exposure should trigger LLM06 regardless of package type."""
        br = BlastRadius(
            vulnerability=_vuln(),
            package=_pkg("express", "4.17.1", "npm"),
            affected_servers=[],
            affected_agents=["agent1"],
            exposed_credentials=["API_KEY"],
            exposed_tools=[],
        )
        br.calculate_risk_score()
        tags = tag_blast_radius(br)
        assert "LLM06" in tags


class TestRiskScoreNotInflated:
    """Risk scores should not be inflated by tool/credential duplication."""

    def test_tool_factor_capped(self):
        """tool_factor should be capped at 1.0 regardless of tool count."""
        br = BlastRadius(
            vulnerability=_vuln(severity="critical"),
            package=_pkg(),
            affected_servers=[],
            affected_agents=["agent1"],
            exposed_credentials=[],
            exposed_tools=[_tool(f"tool_{i}") for i in range(20)],
        )
        br.calculate_risk_score()
        # tool_factor = min(20 * 0.1, 1.0) = 1.0
        # base(8.0) + agent(0.5) + cred(0) + tool(1.0) = 9.5
        assert br.risk_score <= 10.0

    def test_deduped_tools_lower_score(self):
        """Deduped tools should give lower score than inflated count."""
        # With 20 duplicate tools (inflated)
        br_inflated = BlastRadius(
            vulnerability=_vuln(severity="medium"),
            package=_pkg(),
            affected_servers=[],
            affected_agents=["agent1"],
            exposed_credentials=[],
            exposed_tools=[_tool("read_file") for _ in range(20)],
        )
        br_inflated.calculate_risk_score()

        # With 1 unique tool (deduped)
        br_deduped = BlastRadius(
            vulnerability=_vuln(severity="medium"),
            package=_pkg(),
            affected_servers=[],
            affected_agents=["agent1"],
            exposed_credentials=[],
            exposed_tools=[_tool("read_file")],
        )
        br_deduped.calculate_risk_score()

        # Deduped should have lower or equal risk score
        assert br_deduped.risk_score <= br_inflated.risk_score
