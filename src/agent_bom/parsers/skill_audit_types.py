"""Shared result types for skill security audits."""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Result models ────────────────────────────────────────────────────────────


@dataclass
class SkillFinding:
    """A single security finding from the skill audit."""

    severity: str  # "critical" | "high" | "medium" | "low"
    category: str  # typosquat | unverified_server | excessive_permissions | shell_access | unknown_package | dangerous_tool | external_url
    title: str
    detail: str
    source_file: str
    package: str | None = None
    server: str | None = None
    recommendation: str = ""
    context: str = "config_block"  # "config_block" | "code_block" | "env_reference" — where the data was extracted from
    ai_analysis: str | None = None  # LLM-generated context-aware explanation
    ai_adjusted_severity: str | None = None  # LLM may adjust severity or mark "false_positive"
    ai_source: str | None = None  # Provider that generated ai_analysis / AI-detected finding
    ai_model: str | None = None  # Model identifier that generated ai_analysis / AI-detected finding
    ai_confidence: str | None = None  # high | medium | low, as reported or assigned by AI review
    evidence_source: str = "static_config"  # static_text | static_config | ast_python | ast_js | external_registry
    confidence: str = "medium"  # high | medium | low
    source_line: int | None = None
    source_column: int | None = None


@dataclass
class SkillAuditResult:
    """Aggregated result of the skill security audit."""

    findings: list[SkillFinding] = field(default_factory=list)
    packages_checked: int = 0
    servers_checked: int = 0
    credentials_checked: int = 0
    passed: bool = True  # no critical/high findings
    deterministic_passed: bool | None = None  # pass/fail before optional AI advice is applied
    ai_gate_enabled: bool = False  # true only for explicit deterministic-mode opt-in
    behavioral_summary: dict[str, object] = field(default_factory=dict)
    ai_skill_summary: str | None = None  # LLM-generated overall narrative
    ai_overall_risk_level: str | None = None  # "critical"|"high"|"medium"|"low"|"safe"
