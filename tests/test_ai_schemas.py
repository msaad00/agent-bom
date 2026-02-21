"""Tests for Pydantic structured output schemas used by AI enrichment."""

import json

from agent_bom.ai_schemas import (
    BlastRadiusAnalysis,
    ExecutiveSummary,
    MCPConfigFinding,
    MCPConfigSecurityAnalysis,
    SkillAnalysisResult,
    ThreatChain,
    ThreatChainAnalysis,
)


def test_blast_radius_analysis_valid():
    """BlastRadiusAnalysis should validate correct data."""
    obj = BlastRadiusAnalysis(
        agent_context="This CVE in an MCP server exposes the agent's credential store.",
        attack_path="Attacker exploits SSRF to reach internal endpoints via the filesystem tool.",
        business_impact="API keys for production services could be exfiltrated.",
    )
    assert obj.agent_context.startswith("This CVE")
    assert obj.attack_path.startswith("Attacker")
    assert obj.business_impact.startswith("API keys")


def test_blast_radius_analysis_narrative():
    """BlastRadiusAnalysis.narrative should combine all three fields."""
    obj = BlastRadiusAnalysis(
        agent_context="Context.",
        attack_path="Path.",
        business_impact="Impact.",
    )
    assert obj.narrative == "Context. Path. Impact."


def test_executive_summary_valid():
    """ExecutiveSummary should validate and include recommended_actions list."""
    obj = ExecutiveSummary(
        risk_rating="High",
        summary="Critical vulnerabilities found in 3 MCP servers exposing API keys.",
        recommended_actions=["Upgrade fastapi-mcp to 0.5.0", "Rotate exposed API keys"],
    )
    assert obj.risk_rating == "High"
    assert len(obj.recommended_actions) == 2


def test_threat_chain_analysis_valid():
    """ThreatChainAnalysis should validate nested chains."""
    obj = ThreatChainAnalysis(
        chains=[
            ThreatChain(
                name="SSRF to credential exfiltration",
                steps=["Exploit SSRF in server-fetch", "Access internal APIs", "Exfiltrate secrets"],
            ),
        ]
    )
    assert len(obj.chains) == 1
    assert len(obj.chains[0].steps) == 3


def test_skill_analysis_result_defaults():
    """SkillAnalysisResult should have empty defaults for lists."""
    obj = SkillAnalysisResult(
        overall_risk_level="safe",
        summary="No issues found.",
    )
    assert obj.finding_reviews == []
    assert obj.new_findings == []


def test_mcp_config_security_analysis_valid():
    """MCPConfigSecurityAnalysis should validate with findings list."""
    obj = MCPConfigSecurityAnalysis(
        overall_risk="High",
        summary="Multiple servers lack authentication.",
        findings=[
            MCPConfigFinding(
                severity="high",
                category="auth_missing",
                title="No auth on filesystem server",
                detail="The server exposes write tools without credentials.",
                recommendation="Add authentication via API key env var.",
            ),
        ],
    )
    assert obj.overall_risk == "High"
    assert len(obj.findings) == 1
    assert obj.findings[0].category == "auth_missing"


def test_schemas_produce_json_schema():
    """All schemas should produce valid JSON schema for Ollama's format parameter."""
    for cls in [
        BlastRadiusAnalysis,
        ExecutiveSummary,
        ThreatChainAnalysis,
        SkillAnalysisResult,
        MCPConfigSecurityAnalysis,
    ]:
        schema = cls.model_json_schema()
        assert isinstance(schema, dict)
        assert "properties" in schema
        # Should be serializable to JSON (for Ollama's format param)
        json_str = json.dumps(schema)
        assert len(json_str) > 10


def test_round_trip_blast_radius_analysis():
    """BlastRadiusAnalysis should survive model_dump_json → model_validate_json round-trip."""
    original = BlastRadiusAnalysis(
        agent_context="Agent context here.",
        attack_path="Attack path here.",
        business_impact="Business impact here.",
    )
    json_str = original.model_dump_json()
    restored = BlastRadiusAnalysis.model_validate_json(json_str)
    assert restored.agent_context == original.agent_context
    assert restored.narrative == original.narrative


def test_round_trip_mcp_config_analysis():
    """MCPConfigSecurityAnalysis should survive JSON round-trip."""
    original = MCPConfigSecurityAnalysis(
        overall_risk="Medium",
        summary="Some risks detected.",
        findings=[
            MCPConfigFinding(
                severity="medium",
                category="overpermissive",
                title="Too many tools exposed",
                detail="Server has 20+ tools.",
                recommendation="Limit tool scope.",
            ),
        ],
    )
    json_str = original.model_dump_json()
    restored = MCPConfigSecurityAnalysis.model_validate_json(json_str)
    assert restored.overall_risk == "Medium"
    assert len(restored.findings) == 1
    assert restored.findings[0].title == "Too many tools exposed"
