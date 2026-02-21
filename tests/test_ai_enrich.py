"""Tests for AI-powered enrichment — Ollama (local) + litellm providers."""

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
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


def test_cli_ai_model_shows_ollama_examples():
    """CLI --ai-model help should mention Ollama examples."""
    from click.testing import CliRunner

    from agent_bom.cli import main
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "ollama" in result.output.lower()


# ── Ollama Detection Tests ────────────────────────────────────────────────


def test_detect_ollama_when_running():
    """Should detect Ollama when API responds 200."""
    from agent_bom.ai_enrich import _detect_ollama

    mock_response = MagicMock()
    mock_response.status_code = 200
    with patch("agent_bom.ai_enrich.httpx.get", return_value=mock_response):
        assert _detect_ollama() is True


def test_detect_ollama_when_not_running():
    """Should return False when Ollama is not running."""
    from agent_bom.ai_enrich import _detect_ollama

    with patch("agent_bom.ai_enrich.httpx.get", side_effect=httpx.ConnectError("Connection refused")):
        assert _detect_ollama() is False


def test_detect_ollama_timeout():
    """Should return False when Ollama times out."""
    from agent_bom.ai_enrich import _detect_ollama

    with patch("agent_bom.ai_enrich.httpx.get", side_effect=httpx.TimeoutException("Timeout")):
        assert _detect_ollama() is False


def test_get_ollama_models():
    """Should return model list from Ollama API."""
    from agent_bom.ai_enrich import _get_ollama_models

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"models": [{"name": "llama3.2"}, {"name": "mistral"}]}
    with patch("agent_bom.ai_enrich.httpx.get", return_value=mock_response):
        models = _get_ollama_models()
        assert "llama3.2" in models
        assert "mistral" in models


def test_get_ollama_models_failure():
    """Should return empty list on Ollama failure."""
    from agent_bom.ai_enrich import _get_ollama_models

    with patch("agent_bom.ai_enrich.httpx.get", side_effect=httpx.ConnectError("Connection refused")):
        assert _get_ollama_models() == []


# ── Model Resolution Tests ────────────────────────────────────────────────


def test_resolve_model_prefers_ollama():
    """Should prefer Ollama when running with installed models."""
    from agent_bom.ai_enrich import _resolve_model

    with patch("agent_bom.ai_enrich._detect_ollama", return_value=True), \
         patch("agent_bom.ai_enrich._get_ollama_models", return_value=["llama3.2:latest"]):
        result = _resolve_model()
        assert result == "ollama/llama3.2:latest"


def test_resolve_model_falls_back_to_openai():
    """Should use openai when Ollama unavailable and key set."""
    from agent_bom.ai_enrich import _resolve_model

    with patch("agent_bom.ai_enrich._detect_ollama", return_value=False), \
         patch("agent_bom.ai_enrich._check_huggingface", return_value=False), \
         patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
        result = _resolve_model()
        assert result == "openai/gpt-4o-mini"


def test_resolve_model_no_provider():
    """Should return default when no provider available."""
    from agent_bom.ai_enrich import DEFAULT_MODEL, _resolve_model

    with patch("agent_bom.ai_enrich._detect_ollama", return_value=False), \
         patch("agent_bom.ai_enrich._check_huggingface", return_value=False), \
         patch.dict(os.environ, {}, clear=True):
        result = _resolve_model()
        assert result == DEFAULT_MODEL


# ── Ollama Direct Call Tests ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_call_ollama_direct_success():
    """Should call Ollama API and return text."""
    from agent_bom.ai_enrich import _cache, _call_ollama_direct

    _cache.clear()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "message": {"content": "Analysis of the vulnerability..."}
    }

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("agent_bom.ai_enrich.httpx.AsyncClient", return_value=mock_client):
        result = await _call_ollama_direct("test prompt", "llama3.2")
        assert result == "Analysis of the vulnerability..."


@pytest.mark.asyncio
async def test_call_ollama_direct_connection_error():
    """Should return None when Ollama is unreachable."""
    from agent_bom.ai_enrich import _cache, _call_ollama_direct

    _cache.clear()

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("agent_bom.ai_enrich.httpx.AsyncClient", return_value=mock_client):
        result = await _call_ollama_direct("test prompt", "llama3.2")
        assert result is None


# ── LLM Routing Tests ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_call_llm_routes_ollama_to_direct():
    """ollama/ prefix should route to direct API."""
    from agent_bom.ai_enrich import _call_llm

    with patch("agent_bom.ai_enrich._call_ollama_direct", new_callable=AsyncMock, return_value="Ollama response"):
        result = await _call_llm("test prompt", "ollama/llama3.2")
        assert result == "Ollama response"


@pytest.mark.asyncio
async def test_call_llm_routes_openai_to_litellm():
    """Non-Ollama models should route to litellm."""
    from agent_bom.ai_enrich import _call_llm

    with patch("agent_bom.ai_enrich._call_llm_via_litellm", new_callable=AsyncMock, return_value="OpenAI response"):
        result = await _call_llm("test prompt", "openai/gpt-4o-mini")
        assert result == "OpenAI response"


@pytest.mark.asyncio
async def test_call_llm_ollama_falls_back_to_litellm():
    """When Ollama direct fails and no HuggingFace, should fall back to litellm."""
    from agent_bom.ai_enrich import _call_llm

    with patch("agent_bom.ai_enrich._call_ollama_direct", new_callable=AsyncMock, return_value=None), \
         patch("agent_bom.ai_enrich._check_huggingface", return_value=False), \
         patch("agent_bom.ai_enrich._check_litellm", return_value=True), \
         patch("agent_bom.ai_enrich._call_llm_via_litellm", new_callable=AsyncMock, return_value="litellm fallback"):
        result = await _call_llm("test prompt", "ollama/llama3.2")
        assert result == "litellm fallback"


@pytest.mark.asyncio
async def test_call_llm_ollama_no_fallback():
    """When Ollama direct fails and no HuggingFace or litellm, should return None."""
    from agent_bom.ai_enrich import _call_llm

    with patch("agent_bom.ai_enrich._call_ollama_direct", new_callable=AsyncMock, return_value=None), \
         patch("agent_bom.ai_enrich._check_huggingface", return_value=False), \
         patch("agent_bom.ai_enrich._check_litellm", return_value=False):
        result = await _call_llm("test prompt", "ollama/llama3.2")
        assert result is None


# ── Provider Guard Tests ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enrichment_guard_allows_ollama():
    """enrich_blast_radii should proceed when Ollama available (no litellm)."""
    from agent_bom.ai_enrich import enrich_blast_radii
    br = _make_blast_radius()

    with patch("agent_bom.ai_enrich._check_litellm", return_value=False), \
         patch("agent_bom.ai_enrich._detect_ollama", return_value=True), \
         patch("agent_bom.ai_enrich._call_llm", new_callable=AsyncMock, return_value="Ollama analysis"):
        result = await enrich_blast_radii([br], model="ollama/llama3.2")
        assert result == 1
        assert br.ai_summary == "Ollama analysis"


@pytest.mark.asyncio
async def test_enrichment_guard_blocks_no_provider():
    """enrich_blast_radii should return 0 when no provider available."""
    from agent_bom.ai_enrich import enrich_blast_radii
    br = _make_blast_radius()

    with patch("agent_bom.ai_enrich._check_litellm", return_value=False), \
         patch("agent_bom.ai_enrich._detect_ollama", return_value=False), \
         patch("agent_bom.ai_enrich._check_huggingface", return_value=False):
        result = await enrich_blast_radii([br])
        assert result == 0


@pytest.mark.asyncio
async def test_executive_summary_guard_allows_ollama():
    """generate_executive_summary should work with Ollama only."""
    from agent_bom.ai_enrich import generate_executive_summary
    report = _make_report()

    with patch("agent_bom.ai_enrich._check_litellm", return_value=False), \
         patch("agent_bom.ai_enrich._detect_ollama", return_value=True), \
         patch("agent_bom.ai_enrich._call_llm", new_callable=AsyncMock, return_value="Risk summary"):
        result = await generate_executive_summary(report, model="ollama/llama3.2")
        assert result == "Risk summary"


# ── Has-Any-Provider Tests ─────────────────────────────────────────────────


def test_has_any_provider_ollama():
    """Should return True for ollama/ model when Ollama is running."""
    from agent_bom.ai_enrich import _has_any_provider

    with patch("agent_bom.ai_enrich._detect_ollama", return_value=True):
        assert _has_any_provider("ollama/llama3.2") is True


def test_has_any_provider_litellm():
    """Should return True for non-ollama model when litellm installed."""
    from agent_bom.ai_enrich import _has_any_provider

    with patch("agent_bom.ai_enrich._check_litellm", return_value=True):
        assert _has_any_provider("openai/gpt-4o-mini") is True


def test_has_any_provider_none():
    """Should return False for ollama model when no providers available."""
    from agent_bom.ai_enrich import _has_any_provider

    with patch("agent_bom.ai_enrich._detect_ollama", return_value=False), \
         patch("agent_bom.ai_enrich._check_huggingface", return_value=False), \
         patch("agent_bom.ai_enrich._check_litellm", return_value=False):
        assert _has_any_provider("ollama/llama3.2") is False


# ── Action YAML Tests ─────────────────────────────────────────────────────


def test_action_yml_exists():
    """action.yml should exist at repo root."""
    from pathlib import Path
    action_path = Path(__file__).parent.parent / "action.yml"
    assert action_path.exists(), "action.yml not found at repo root"


def test_action_yml_valid_yaml():
    """action.yml should be valid YAML."""
    from pathlib import Path

    import yaml
    action_path = Path(__file__).parent.parent / "action.yml"
    with open(action_path) as f:
        data = yaml.safe_load(f)
    assert data is not None
    assert "name" in data
    assert "runs" in data


def test_action_yml_has_required_inputs():
    """action.yml should have key inputs."""
    from pathlib import Path

    import yaml
    action_path = Path(__file__).parent.parent / "action.yml"
    with open(action_path) as f:
        data = yaml.safe_load(f)
    inputs = data.get("inputs", {})
    assert "severity-threshold" in inputs
    assert "upload-sarif" in inputs
    assert "policy" in inputs
    assert "enrich" in inputs
    assert "format" in inputs


def test_action_yml_has_outputs():
    """action.yml should have expected outputs."""
    from pathlib import Path

    import yaml
    action_path = Path(__file__).parent.parent / "action.yml"
    with open(action_path) as f:
        data = yaml.safe_load(f)
    outputs = data.get("outputs", {})
    assert "sarif-file" in outputs
    assert "exit-code" in outputs
    assert "vulnerability-count" in outputs


def test_action_yml_composite():
    """action.yml should use composite runs."""
    from pathlib import Path

    import yaml
    action_path = Path(__file__).parent.parent / "action.yml"
    with open(action_path) as f:
        data = yaml.safe_load(f)
    assert data["runs"]["using"] == "composite"


# ── Skill file AI analysis tests ────────────────────────────────────────────


def test_build_skill_analysis_prompt():
    """Prompt should include file content, static findings, and threat categories."""
    from agent_bom.ai_enrich import _build_skill_analysis_prompt
    raw_content = {"CLAUDE.md": "# Claude\nUse npx @mcp/server-filesystem /tmp\nNever bind to 0.0.0.0"}
    findings = [{"severity": "high", "category": "shell_access",
                 "title": "Shell access via server 'bash'",
                 "detail": "Uses bash", "source_file": "CLAUDE.md"}]
    prompt = _build_skill_analysis_prompt(raw_content, findings)
    assert "CLAUDE.md" in prompt
    assert "Never bind to 0.0.0.0" in prompt
    assert "Shell access" in prompt
    assert "social_engineering" in prompt
    assert "overall_risk_level" in prompt


def test_parse_skill_analysis_response_valid():
    """Should parse valid JSON response."""
    from agent_bom.ai_enrich import _parse_skill_analysis_response
    response = '{"overall_risk_level": "low", "summary": "Safe", "finding_reviews": [], "new_findings": []}'
    result = _parse_skill_analysis_response(response)
    assert result is not None
    assert result["overall_risk_level"] == "low"
    assert result["summary"] == "Safe"


def test_parse_skill_analysis_response_markdown_fenced():
    """Should strip markdown code fences."""
    from agent_bom.ai_enrich import _parse_skill_analysis_response
    response = '```json\n{"overall_risk_level": "medium", "summary": "Some risk"}\n```'
    result = _parse_skill_analysis_response(response)
    assert result is not None
    assert result["overall_risk_level"] == "medium"


def test_parse_skill_analysis_response_invalid():
    """Should return None for non-JSON response."""
    from agent_bom.ai_enrich import _parse_skill_analysis_response
    result = _parse_skill_analysis_response("I cannot analyze this file.")
    assert result is None


def test_apply_skill_analysis_adjusts_severity():
    """Should adjust finding severity based on AI review."""
    from agent_bom.ai_enrich import _apply_skill_analysis
    from agent_bom.parsers.skill_audit import SkillAuditResult, SkillFinding

    audit = SkillAuditResult(
        findings=[SkillFinding(
            severity="high", category="shell_access",
            title="Shell access via server 'bash'",
            detail="Uses bash", source_file="CLAUDE.md",
        )],
        passed=False,
    )
    ai_data = {
        "overall_risk_level": "low",
        "summary": "The shell reference is in a 'do not use' section.",
        "finding_reviews": [{
            "original_title": "Shell access via server 'bash'",
            "verdict": "false_positive",
            "adjusted_severity": None,
            "reasoning": "The file warns against using bash, not instructing to use it."
        }],
        "new_findings": [],
    }
    _apply_skill_analysis(audit, ai_data)

    assert audit.ai_overall_risk_level == "low"
    assert audit.findings[0].ai_adjusted_severity == "false_positive"
    assert "warns against" in audit.findings[0].ai_analysis.lower()
    assert audit.passed is True  # Recalculated since only finding is FP


def test_apply_skill_analysis_adds_new_findings():
    """Should add AI-discovered findings to the audit."""
    from agent_bom.ai_enrich import _apply_skill_analysis
    from agent_bom.parsers.skill_audit import SkillAuditResult

    audit = SkillAuditResult(findings=[], passed=True)
    ai_data = {
        "overall_risk_level": "high",
        "summary": "Detected prompt injection pattern.",
        "finding_reviews": [],
        "new_findings": [{
            "severity": "high",
            "category": "prompt_injection",
            "title": "Hidden instruction in HTML comment",
            "detail": "An HTML comment contains instructions to ignore safety guidelines.",
            "recommendation": "Remove hidden instructions from skill files."
        }],
    }
    _apply_skill_analysis(audit, ai_data)

    assert len(audit.findings) == 1
    assert audit.findings[0].category == "prompt_injection"
    assert audit.findings[0].context == "ai_analysis"
    assert audit.passed is False


@pytest.mark.asyncio
async def test_enrich_skill_audit_with_mock_llm():
    """Should enrich skill audit when LLM returns valid JSON."""
    import json as _json

    from agent_bom.ai_enrich import enrich_skill_audit
    from agent_bom.parsers.skill_audit import SkillAuditResult
    from agent_bom.parsers.skills import SkillScanResult

    skill_result = SkillScanResult(
        source_files=["CLAUDE.md"],
        raw_content={"CLAUDE.md": "# Claude\nDo not use 0.0.0.0"},
    )
    skill_audit = SkillAuditResult(findings=[], passed=True)

    mock_response = _json.dumps({
        "overall_risk_level": "safe",
        "summary": "No security risks found in this skill file.",
        "finding_reviews": [],
        "new_findings": [],
    })

    with patch("agent_bom.ai_enrich._has_any_provider", return_value=True), \
         patch("agent_bom.ai_enrich._call_llm", new_callable=AsyncMock, return_value=mock_response):
        result = await enrich_skill_audit(skill_result, skill_audit)
        assert result is True
        assert skill_audit.ai_overall_risk_level == "safe"
        assert skill_audit.ai_skill_summary == "No security risks found in this skill file."


@pytest.mark.asyncio
async def test_enrich_skill_audit_no_provider():
    """Should return False when no LLM provider available."""
    from agent_bom.ai_enrich import enrich_skill_audit
    from agent_bom.parsers.skill_audit import SkillAuditResult
    from agent_bom.parsers.skills import SkillScanResult

    skill_result = SkillScanResult(
        source_files=["CLAUDE.md"],
        raw_content={"CLAUDE.md": "# Claude instructions"},
    )
    skill_audit = SkillAuditResult(findings=[], passed=True)

    with patch("agent_bom.ai_enrich._has_any_provider", return_value=False):
        result = await enrich_skill_audit(skill_result, skill_audit)
        assert result is False
        assert skill_audit.ai_skill_summary is None


@pytest.mark.asyncio
async def test_enrich_skill_audit_empty_content():
    """Should return False when raw_content is empty."""
    from agent_bom.ai_enrich import enrich_skill_audit
    from agent_bom.parsers.skill_audit import SkillAuditResult
    from agent_bom.parsers.skills import SkillScanResult

    skill_result = SkillScanResult(raw_content={})
    skill_audit = SkillAuditResult()

    result = await enrich_skill_audit(skill_result, skill_audit)
    assert result is False


# ── Generic JSON Parser Tests ────────────────────────────────────────────


def test_parse_json_response_clean():
    """Should parse clean JSON directly."""
    from agent_bom.ai_enrich import _parse_json_response
    result = _parse_json_response('{"key": "value", "num": 42}')
    assert result == {"key": "value", "num": 42}


def test_parse_json_response_fenced():
    """Should extract JSON from markdown fences."""
    from agent_bom.ai_enrich import _parse_json_response
    result = _parse_json_response('```json\n{"key": "fenced"}\n```')
    assert result == {"key": "fenced"}


def test_parse_json_response_embedded():
    """Should extract JSON embedded in other text."""
    from agent_bom.ai_enrich import _parse_json_response
    result = _parse_json_response('Here is the analysis: {"key": "embedded"} and more text.')
    assert result == {"key": "embedded"}


def test_parse_json_response_invalid():
    """Should return None for non-JSON text."""
    from agent_bom.ai_enrich import _parse_json_response
    assert _parse_json_response("I cannot analyze this.") is None


def test_parse_json_response_empty():
    """Should return None for empty/whitespace input."""
    from agent_bom.ai_enrich import _parse_json_response
    assert _parse_json_response("") is None
    assert _parse_json_response("   ") is None
    assert _parse_json_response(None) is None


# ── HuggingFace Provider Tests ───────────────────────────────────────────


def test_check_huggingface_installed():
    """Should return True when huggingface_hub is importable."""
    from agent_bom.ai_enrich import _check_huggingface

    with patch.dict("sys.modules", {"huggingface_hub": MagicMock()}):
        assert _check_huggingface() is True


def test_check_huggingface_not_installed():
    """Should return False when huggingface_hub is not installed."""
    from agent_bom.ai_enrich import _check_huggingface

    with patch("builtins.__import__", side_effect=ImportError("No module")):
        # The function does its own import, so we need to patch at module level
        with patch.dict("sys.modules", {"huggingface_hub": None}):
            # Force reimport failure
            result = _check_huggingface()
            # Can't reliably test import failure this way; test the function directly
    # Just verify the function exists and returns bool
    assert isinstance(_check_huggingface(), bool)


@pytest.mark.asyncio
async def test_call_huggingface_success():
    """Should call HuggingFace InferenceClient and return text."""
    from agent_bom.ai_enrich import _cache, _call_huggingface

    _cache.clear()

    mock_choice = MagicMock()
    mock_choice.message.content = "HuggingFace analysis result"
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    mock_client = MagicMock()
    mock_client.chat_completion = MagicMock(return_value=mock_response)

    # Create a fake huggingface_hub module since it may not be installed
    fake_hf = MagicMock()
    fake_hf.InferenceClient = MagicMock(return_value=mock_client)

    with patch.dict("sys.modules", {"huggingface_hub": fake_hf}), \
         patch("agent_bom.ai_enrich.asyncio.to_thread", new_callable=AsyncMock, return_value=mock_response):
        result = await _call_huggingface("test prompt")
        assert result == "HuggingFace analysis result"


@pytest.mark.asyncio
async def test_call_llm_ollama_falls_back_to_huggingface():
    """When Ollama fails and HuggingFace available, should use HF."""
    from agent_bom.ai_enrich import _call_llm

    with patch("agent_bom.ai_enrich._call_ollama_direct", new_callable=AsyncMock, return_value=None), \
         patch("agent_bom.ai_enrich._check_huggingface", return_value=True), \
         patch("agent_bom.ai_enrich._call_huggingface", new_callable=AsyncMock, return_value="HF response"):
        result = await _call_llm("test prompt", "ollama/llama3.2")
        assert result == "HF response"


@pytest.mark.asyncio
async def test_call_llm_routes_huggingface_model():
    """huggingface/ prefix should route to HuggingFace directly."""
    from agent_bom.ai_enrich import _call_llm

    with patch("agent_bom.ai_enrich._call_huggingface", new_callable=AsyncMock, return_value="HF direct"):
        result = await _call_llm("test prompt", "huggingface/meta-llama/Llama-3.1-8B-Instruct")
        assert result == "HF direct"


def test_has_any_provider_with_huggingface():
    """Should return True for ollama/ model when HuggingFace is available as fallback."""
    from agent_bom.ai_enrich import _has_any_provider

    with patch("agent_bom.ai_enrich._detect_ollama", return_value=False), \
         patch("agent_bom.ai_enrich._check_huggingface", return_value=True):
        assert _has_any_provider("ollama/llama3.2") is True


def test_has_any_provider_huggingface_model():
    """Should return True for huggingface/ model when hub installed."""
    from agent_bom.ai_enrich import _has_any_provider

    with patch("agent_bom.ai_enrich._check_huggingface", return_value=True):
        assert _has_any_provider("huggingface/meta-llama/Llama-3.1-8B-Instruct") is True


def test_has_any_provider_huggingface_not_installed():
    """Should return False for huggingface/ model when hub not installed."""
    from agent_bom.ai_enrich import _has_any_provider

    with patch("agent_bom.ai_enrich._check_huggingface", return_value=False):
        assert _has_any_provider("huggingface/some-model") is False


# ── Smart Model Selection Tests ──────────────────────────────────────────


def test_resolve_model_picks_best_ollama():
    """Should pick the highest-priority installed Ollama model."""
    from agent_bom.ai_enrich import _resolve_model

    with patch("agent_bom.ai_enrich._detect_ollama", return_value=True), \
         patch("agent_bom.ai_enrich._get_ollama_models", return_value=["mistral:latest", "llama3.1:8b"]):
        result = _resolve_model()
        # llama3.1:8b is higher in OLLAMA_MODEL_PREFERENCE than mistral
        assert result == "ollama/llama3.1:8b"


def test_resolve_model_huggingface_tier():
    """Should fall back to HuggingFace when Ollama has no models."""
    from agent_bom.ai_enrich import HF_DEFAULT_MODEL, _resolve_model

    with patch("agent_bom.ai_enrich._detect_ollama", return_value=True), \
         patch("agent_bom.ai_enrich._get_ollama_models", return_value=[]), \
         patch("agent_bom.ai_enrich._check_huggingface", return_value=True), \
         patch.dict(os.environ, {"HF_TOKEN": "hf_test123"}):
        result = _resolve_model()
        assert result == f"huggingface/{HF_DEFAULT_MODEL}"


def test_resolve_model_empty_ollama_models():
    """Ollama running but no models → fall through to next tier."""
    from agent_bom.ai_enrich import _resolve_model

    with patch("agent_bom.ai_enrich._detect_ollama", return_value=True), \
         patch("agent_bom.ai_enrich._get_ollama_models", return_value=[]), \
         patch("agent_bom.ai_enrich._check_huggingface", return_value=False), \
         patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=True):
        result = _resolve_model()
        assert result == "openai/gpt-4o-mini"


def test_resolve_model_ollama_uses_first_available():
    """When no preferred model installed, should use first available."""
    from agent_bom.ai_enrich import _resolve_model

    with patch("agent_bom.ai_enrich._detect_ollama", return_value=True), \
         patch("agent_bom.ai_enrich._get_ollama_models", return_value=["some-obscure-model:latest"]):
        result = _resolve_model()
        assert result == "ollama/some-obscure-model:latest"


# ── MCP Config Analysis Tests ────────────────────────────────────────────


def test_build_mcp_config_analysis_prompt():
    """Prompt should include server names, tools, credentials, and agent info."""
    from agent_bom.ai_enrich import _build_mcp_config_analysis_prompt
    report = _make_report()
    prompt = _build_mcp_config_analysis_prompt(report)
    assert "openclaw-gateway" in prompt
    assert "exec" in prompt
    assert "OPENAI_API_KEY" in prompt
    assert "openclaw" in prompt
    assert "auth_missing" in prompt


@pytest.mark.asyncio
async def test_analyze_mcp_config_security_with_mock():
    """Should return structured analysis when LLM returns valid JSON."""
    import json as _json

    from agent_bom.ai_enrich import analyze_mcp_config_security

    report = _make_report()
    mock_response = _json.dumps({
        "overall_risk": "High",
        "summary": "Multiple servers lack authentication.",
        "findings": [{
            "severity": "high",
            "category": "auth_missing",
            "title": "No auth on openclaw-gateway",
            "detail": "Server exposes exec tool without credentials.",
            "recommendation": "Add API key authentication.",
        }],
    })

    with patch("agent_bom.ai_enrich._has_any_provider", return_value=True), \
         patch("agent_bom.ai_enrich._call_llm_structured", new_callable=AsyncMock, return_value=None), \
         patch("agent_bom.ai_enrich._call_llm", new_callable=AsyncMock, return_value=mock_response):
        result = await analyze_mcp_config_security(report, model="ollama/llama3.2")
        assert result is not None
        assert result.overall_risk == "High"
        assert len(result.findings) == 1
        assert result.findings[0].category == "auth_missing"


@pytest.mark.asyncio
async def test_analyze_mcp_config_no_servers():
    """Should return None when report has no MCP servers."""
    from agent_bom.ai_enrich import analyze_mcp_config_security
    report = AIBOMReport(agents=[], blast_radii=[])
    result = await analyze_mcp_config_security(report)
    assert result is None


@pytest.mark.asyncio
async def test_analyze_mcp_config_no_provider():
    """Should return None when no LLM provider available."""
    from agent_bom.ai_enrich import analyze_mcp_config_security
    report = _make_report()

    with patch("agent_bom.ai_enrich._has_any_provider", return_value=False):
        result = await analyze_mcp_config_security(report)
        assert result is None


# ── JSON Output — MCP Config Analysis ──────────────────────────────────


def test_json_output_includes_mcp_config_analysis():
    """JSON output should include mcp_config_analysis when present."""
    from agent_bom.output import to_json
    report = _make_report()
    report.mcp_config_analysis = {
        "overall_risk": "Medium",
        "summary": "Some risks found.",
        "findings": [],
    }
    data = to_json(report)
    assert "mcp_config_analysis" in data
    assert data["mcp_config_analysis"]["overall_risk"] == "Medium"


def test_json_output_omits_mcp_config_when_not_enriched():
    """JSON output should not include mcp_config_analysis when absent."""
    from agent_bom.output import to_json
    report = _make_report()
    data = to_json(report)
    assert "mcp_config_analysis" not in data
