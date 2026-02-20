"""Tests for AI-powered enrichment via litellm."""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)


def _make_blast_radius() -> BlastRadius:
    """Create a test BlastRadius with realistic data based on real OpenClaw CVEs."""
    vuln = Vulnerability(
        id="CVE-2026-27001",
        summary="Unsanitized CWD path injection into LLM prompts in OpenClaw",
        severity=Severity.HIGH,
        cvss_score=8.1,
        fixed_version="2026.1.30",
    )
    pkg = Package(name="openclaw", version="2026.1.15", ecosystem="npm")
    tool = MCPTool(name="exec", description="Execute shell commands")
    server = MCPServer(
        name="openclaw-gateway",
        command="openclaw",
        args=["daemon"],
        env={"OPENAI_API_KEY": "***REDACTED***"},
        tools=[tool],
    )
    agent = Agent(
        name="openclaw",
        agent_type=AgentType.OPENCLAW,
        config_path="~/.openclaw/openclaw.json",
        mcp_servers=[server],
    )
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["OPENAI_API_KEY"],
        exposed_tools=[tool],
        risk_score=9.5,
    )


def _make_report(blast_radii=None) -> AIBOMReport:
    """Create a test AIBOMReport."""
    br = blast_radii or [_make_blast_radius()]
    seen = set()
    agents = []
    for br_item in br:
        for a in br_item.affected_agents:
            if a.name not in seen:
                seen.add(a.name)
                agents.append(a)
    return AIBOMReport(agents=agents, blast_radii=br)


# ── Empty Input Tests ──────────────────────────────────────────────────────


def test_enrich_empty_blast_radii():
    """Should return 0 for empty blast radii list."""
    from agent_bom.ai_enrich import enrich_blast_radii
    result = asyncio.run(enrich_blast_radii([]))
    assert result == 0


def test_executive_summary_empty_report():
    """Should return None for report with no blast radii."""
    from agent_bom.ai_enrich import generate_executive_summary
    report = AIBOMReport(agents=[], blast_radii=[])
    result = asyncio.run(generate_executive_summary(report))
    assert result is None


def test_threat_chains_empty_report():
    """Should return empty list for report with no blast radii."""
    from agent_bom.ai_enrich import generate_threat_chains
    report = AIBOMReport(agents=[], blast_radii=[])
    result = asyncio.run(generate_threat_chains(report))
    assert result == []


# ── Prompt Building Tests ──────────────────────────────────────────────────


def test_build_blast_radius_prompt():
    """Prompt should include CVE ID, package, credentials, tools."""
    from agent_bom.ai_enrich import _build_blast_radius_prompt
    br = _make_blast_radius()
    prompt = _build_blast_radius_prompt(br)
    assert "CVE-2026-27001" in prompt
    assert "openclaw" in prompt
    assert "OPENAI_API_KEY" in prompt
    assert "exec" in prompt
    assert "8.1" in prompt


def test_build_executive_summary_prompt():
    """Prompt should include scan statistics."""
    from agent_bom.ai_enrich import _build_executive_summary_prompt
    report = _make_report()
    prompt = _build_executive_summary_prompt(report)
    assert "agent(s)" in prompt
    assert "MCP server(s)" in prompt


def test_build_threat_chain_prompt():
    """Prompt should include top findings with tools and creds."""
    from agent_bom.ai_enrich import _build_threat_chain_prompt
    report = _make_report()
    prompt = _build_threat_chain_prompt(report)
    assert "CVE-2026-27001" in prompt
    assert "exec" in prompt
    assert "OPENAI_API_KEY" in prompt


# ── LLM Call Mocking Tests ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enrich_blast_radii_with_mock_llm():
    """Should enrich findings when LLM returns a response."""
    from agent_bom.ai_enrich import enrich_blast_radii
    br = _make_blast_radius()

    with patch("agent_bom.ai_enrich._check_litellm", return_value=True), \
         patch("agent_bom.ai_enrich._call_llm", new_callable=AsyncMock, return_value="This CVE allows RCE through the OpenClaw agent."):
        result = await enrich_blast_radii([br])
        assert result == 1
        assert br.ai_summary == "This CVE allows RCE through the OpenClaw agent."


@pytest.mark.asyncio
async def test_executive_summary_with_mock_llm():
    """Should generate executive summary from LLM response."""
    from agent_bom.ai_enrich import generate_executive_summary
    report = _make_report()

    with patch("agent_bom.ai_enrich._check_litellm", return_value=True), \
         patch("agent_bom.ai_enrich._call_llm", new_callable=AsyncMock, return_value="Critical risk: 1 RCE vulnerability found."):
        result = await generate_executive_summary(report)
        assert result == "Critical risk: 1 RCE vulnerability found."


@pytest.mark.asyncio
async def test_threat_chains_with_mock_llm():
    """Should generate threat chain analysis."""
    from agent_bom.ai_enrich import generate_threat_chains
    report = _make_report()

    with patch("agent_bom.ai_enrich._check_litellm", return_value=True), \
         patch("agent_bom.ai_enrich._call_llm", new_callable=AsyncMock, return_value="1. Exploit CVE-2026-27001\n2. Access exec\n3. Exfiltrate OPENAI_API_KEY"):
        result = await generate_threat_chains(report)
        assert len(result) == 1
        assert "CVE-2026-27001" in result[0]


@pytest.mark.asyncio
async def test_llm_failure_returns_none():
    """When LLM call fails, should fall back gracefully."""
    from agent_bom.ai_enrich import enrich_blast_radii
    br = _make_blast_radius()

    with patch("agent_bom.ai_enrich._check_litellm", return_value=True), \
         patch("agent_bom.ai_enrich._call_llm", new_callable=AsyncMock, return_value=None):
        result = await enrich_blast_radii([br])
        assert result == 0
        assert br.ai_summary is None


@pytest.mark.asyncio
async def test_caching_avoids_duplicate_calls():
    """Same package should reuse cached LLM response."""
    from agent_bom.ai_enrich import enrich_blast_radii

    br1 = _make_blast_radius()
    br2 = _make_blast_radius()
    br2.vulnerability = Vulnerability(
        id="CVE-2026-24764", summary="SSRF", severity=Severity.HIGH,
    )

    call_count = 0

    async def mock_call(prompt, model, max_tokens=500):
        nonlocal call_count
        call_count += 1
        return "Mocked analysis"

    with patch("agent_bom.ai_enrich._check_litellm", return_value=True), \
         patch("agent_bom.ai_enrich._call_llm", side_effect=mock_call):
        result = await enrich_blast_radii([br1, br2])
        assert result == 2
        assert call_count == 1  # Only one LLM call, second reused from cache


# ── Model Field Tests ──────────────────────────────────────────────────────


def test_blast_radius_has_ai_summary_field():
    """BlastRadius should have ai_summary field."""
    br = _make_blast_radius()
    assert hasattr(br, "ai_summary")
    assert br.ai_summary is None


def test_report_has_executive_summary_field():
    """AIBOMReport should have executive_summary field."""
    report = _make_report()
    assert hasattr(report, "executive_summary")
    assert report.executive_summary is None


def test_report_has_ai_threat_chains_field():
    """AIBOMReport should have ai_threat_chains field."""
    report = _make_report()
    assert hasattr(report, "ai_threat_chains")
    assert report.ai_threat_chains == []


# ── JSON Output Tests ──────────────────────────────────────────────────────


def test_json_output_includes_ai_summary():
    """JSON output should include ai_summary field in blast_radius."""
    from agent_bom.output import to_json
    br = _make_blast_radius()
    br.ai_summary = "AI-generated analysis of CVE-2026-27001"
    report = _make_report([br])
    data = to_json(report)
    assert data["blast_radius"][0]["ai_summary"] == "AI-generated analysis of CVE-2026-27001"


def test_json_output_includes_executive_summary():
    """JSON output should include executive_summary when present."""
    from agent_bom.output import to_json
    report = _make_report()
    report.executive_summary = "Critical risk assessment summary"
    data = to_json(report)
    assert data["executive_summary"] == "Critical risk assessment summary"


def test_json_output_includes_threat_chains():
    """JSON output should include ai_threat_chains when present."""
    from agent_bom.output import to_json
    report = _make_report()
    report.ai_threat_chains = ["Chain 1: exploit -> lateral -> exfiltrate"]
    data = to_json(report)
    assert data["ai_threat_chains"] == ["Chain 1: exploit -> lateral -> exfiltrate"]


def test_json_output_omits_ai_fields_when_not_enriched():
    """JSON output should not include AI fields when not enriched."""
    from agent_bom.output import to_json
    report = _make_report()
    data = to_json(report)
    assert "executive_summary" not in data
    assert "ai_threat_chains" not in data


# ── CLI Flag Tests ─────────────────────────────────────────────────────────


def test_cli_has_ai_enrich_flag():
    """CLI should accept --ai-enrich flag."""
    from click.testing import CliRunner

    from agent_bom.cli import main
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--ai-enrich" in result.output


def test_cli_has_ai_model_option():
    """CLI should accept --ai-model option."""
    from click.testing import CliRunner

    from agent_bom.cli import main
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "--ai-model" in result.output
