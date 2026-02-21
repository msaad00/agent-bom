"""Pydantic schemas for structured LLM output.

Used to:
1. Generate JSON schema for Ollama's ``format`` parameter (guaranteed JSON)
2. Validate and parse LLM responses reliably
3. Replace fragile regex-based JSON extraction
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class BlastRadiusAnalysis(BaseModel):
    """Structured output for blast radius risk narrative."""

    agent_context: str = Field(description="Why this vulnerability matters in an AI agent context")
    attack_path: str = Field(description="How an attacker could exploit via the MCP tool chain")
    business_impact: str = Field(description="Specific business impact given exposed credentials/tools")

    @property
    def narrative(self) -> str:
        """Combine fields into a single risk narrative."""
        return f"{self.agent_context} {self.attack_path} {self.business_impact}"


class ExecutiveSummary(BaseModel):
    """Structured output for executive summary."""

    risk_rating: str = Field(description="Critical, High, Medium, or Low")
    summary: str = Field(description="4-6 sentence executive summary for leadership")
    recommended_actions: list[str] = Field(description="Top 1-3 recommended actions")


class ThreatChain(BaseModel):
    """A single attack chain."""

    name: str = Field(description="Short name for the attack chain")
    steps: list[str] = Field(description="3-5 step attack chain from initial access to impact")


class ThreatChainAnalysis(BaseModel):
    """Structured output for threat chain analysis."""

    chains: list[ThreatChain] = Field(description="1-2 realistic attack chains")


class SkillAnalysisResult(BaseModel):
    """Structured output for skill file analysis."""

    overall_risk_level: str = Field(description="critical, high, medium, low, or safe")
    summary: str = Field(description="2-3 sentence summary of skill file security")
    finding_reviews: list[dict] = Field(default_factory=list, description="Verdicts on static findings")
    new_findings: list[dict] = Field(default_factory=list, description="New threats detected by AI")


class MCPConfigFinding(BaseModel):
    """A single finding from MCP config security analysis."""

    severity: str = Field(description="critical, high, medium, or low")
    category: str = Field(description="e.g. auth_missing, overpermissive, credential_exposure, awm_pattern, transport_risk")
    title: str = Field(description="Short finding title")
    detail: str = Field(description="Explanation of the risk")
    recommendation: str = Field(description="How to fix or mitigate")


class MCPConfigSecurityAnalysis(BaseModel):
    """Structured output for MCP config security analysis."""

    overall_risk: str = Field(description="Critical, High, Medium, or Low")
    summary: str = Field(description="2-3 sentence overall assessment")
    findings: list[MCPConfigFinding] = Field(default_factory=list, description="Individual security findings")
