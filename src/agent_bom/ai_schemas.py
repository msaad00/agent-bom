"""Pydantic schemas for structured LLM output.

Used to:
1. Generate JSON schema for Ollama's ``format`` parameter (guaranteed JSON)
2. Validate and parse LLM responses reliably
3. Replace fragile regex-based JSON extraction
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

AIConfidence = Literal["high", "medium", "low"]


class AIProvenance(BaseModel):
    """Immutable provenance for one model-derived assessment."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: Literal["ai.provenance.v1"] = "ai.provenance.v1"
    run_id: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=64)
    model: str = Field(min_length=1, max_length=256)
    model_revision: str = Field(default="", max_length=256)
    prompt_version: str = Field(default="ai-enrichment.v2", min_length=1, max_length=64)
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generated_at: datetime
    deterministic: bool
    redaction_applied: bool


class AIFindingAssessment(BaseModel):
    """Versioned advisory classification tied to a deterministic finding."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: Literal["ai.finding-assessment.v1"] = "ai.finding-assessment.v1"
    finding_id: str = Field(min_length=1, max_length=128)
    task: Literal["triage"] = "triage"
    classification: str = Field(default="needs_review", min_length=1, max_length=64)
    confidence: AIConfidence = "low"
    false_positive_likelihood: AIConfidence = "low"
    rationale: str = Field(default="", max_length=1000)
    suggested_controls: list[str] = Field(default_factory=list, max_length=10)
    advisory: Literal[True] = True
    ai_detected: Literal[False] = False
    provenance: AIProvenance


class AIFindingAssessmentCandidate(BaseModel):
    """Bounded untrusted model output before known-ID filtering."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    finding_id: str = Field(min_length=1, max_length=128)
    classification: str = Field(default="needs_review", min_length=1, max_length=64)
    confidence: AIConfidence = "low"
    false_positive_likelihood: AIConfidence = "low"
    rationale: str = Field(default="", max_length=1000)
    suggested_controls: list[str] = Field(default_factory=list, max_length=10)


class AIFindingAssessmentResponse(BaseModel):
    """Bounded provider response for one triage batch."""

    model_config = ConfigDict(extra="ignore")

    assessments: list[AIFindingAssessmentCandidate] = Field(default_factory=list, max_length=50)


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


class SkillFindingReview(BaseModel):
    """Bounded review of one deterministic skill finding."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    title: str = Field(default="", max_length=240)
    original_title: str = Field(default="", max_length=240)
    verdict: Literal["confirmed", "false_positive", "severity_adjusted"] = "confirmed"
    adjusted_severity: Literal["critical", "high", "medium", "low"] | None = None
    reasoning: str = Field(default="", max_length=1000)
    confidence: AIConfidence | None = None


class SkillNewFinding(BaseModel):
    """Bounded novel finding proposed from local skill-file analysis."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    severity: Literal["critical", "high", "medium", "low"] = "medium"
    category: str = Field(default="ai_detected", min_length=1, max_length=80)
    title: str = Field(default="AI-detected finding", min_length=1, max_length=240)
    detail: str = Field(default="", max_length=2000)
    recommendation: str = Field(default="", max_length=1000)
    confidence: AIConfidence = "medium"


class SkillAnalysisResult(BaseModel):
    """Structured output for skill file analysis."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    overall_risk_level: Literal["critical", "high", "medium", "low", "safe"]
    summary: str = Field(default="", max_length=2000, description="2-3 sentence summary of skill file security")
    finding_reviews: list[SkillFindingReview] = Field(default_factory=list, max_length=100)
    new_findings: list[SkillNewFinding] = Field(default_factory=list, max_length=100)


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
