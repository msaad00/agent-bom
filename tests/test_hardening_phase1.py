"""Phase 1 hardening tests — edge cases, boundary conditions, and regression guards.

Covers:
- AI package list consolidation (single source of truth)
- Risk scoring boundaries with configurable constants
- EPSS threshold consistency
- Word-boundary tool classification
- Config env var overrides
"""

from __future__ import annotations

import importlib

import pytest

from agent_bom.models import BlastRadius, MCPTool, Package, Severity, Vulnerability
from agent_bom.risk_analyzer import ToolCapability, classify_tool, score_server_risk

# ── AI Package Consolidation ─────────────────────────────────────────────────


class TestAIPackageConsolidation:
    """Ensure a single source of truth for AI package lists."""

    def test_scanners_uses_constants_ai_packages(self):
        """scanners/__init__.py imports AI_PACKAGES from constants, not its own."""
        from agent_bom.constants import AI_PACKAGES
        from agent_bom.scanners import _AI_FRAMEWORK_PACKAGES

        assert _AI_FRAMEWORK_PACKAGES is AI_PACKAGES

    def test_nvidia_packages_in_ai_packages(self):
        """All NVIDIA CUDA packages should be in the unified AI_PACKAGES."""
        from agent_bom.constants import AI_PACKAGES

        nvidia_pkgs = [
            "nvidia-cublas-cu12",
            "nvidia-cudnn-cu12",
            "nvidia-nccl-cu12",
            "tensorrt",
            "cuda-python",
        ]
        for pkg in nvidia_pkgs:
            assert pkg in AI_PACKAGES, f"{pkg} missing from AI_PACKAGES"

    def test_mcp_infrastructure_in_ai_packages(self):
        """MCP, FastMCP, modelcontextprotocol should be in AI_PACKAGES."""
        from agent_bom.constants import AI_PACKAGES

        for pkg in ("mcp", "fastmcp", "modelcontextprotocol"):
            assert pkg in AI_PACKAGES, f"{pkg} missing from AI_PACKAGES"

    def test_mlops_packages_in_ai_packages(self):
        """MLOps packages should be in AI_PACKAGES."""
        from agent_bom.constants import AI_PACKAGES

        for pkg in ("mlflow", "wandb", "ray", "clearml"):
            assert pkg in AI_PACKAGES, f"{pkg} missing from AI_PACKAGES"

    def test_training_data_packages_overlap(self):
        """Most TRAINING_DATA_PACKAGES should also be in AI_PACKAGES."""
        from agent_bom.constants import AI_PACKAGES, TRAINING_DATA_PACKAGES

        # datasets is generic enough to not require overlap
        overlap = TRAINING_DATA_PACKAGES - {"datasets"} - AI_PACKAGES
        assert not overlap, f"These training data packages are missing from AI_PACKAGES: {overlap}"


# ── EPSS Threshold Consistency ───────────────────────────────────────────────


class TestEPSSThresholds:
    """Ensure EPSS thresholds are consistent across the codebase."""

    def test_active_exploitation_threshold_default(self):
        from agent_bom.config import EPSS_ACTIVE_EXPLOITATION_THRESHOLD

        assert EPSS_ACTIVE_EXPLOITATION_THRESHOLD == 0.5

    def test_critical_threshold_default(self):
        from agent_bom.config import EPSS_CRITICAL_THRESHOLD

        assert EPSS_CRITICAL_THRESHOLD == 0.7

    def test_high_likely_threshold_default(self):
        from agent_bom.config import EPSS_HIGH_LIKELY_THRESHOLD

        assert EPSS_HIGH_LIKELY_THRESHOLD == 0.3

    def test_is_actively_exploited_at_boundary(self):
        """EPSS exactly at 0.5 should NOT trigger (uses >)."""
        v = Vulnerability(id="CVE-TEST", summary="test", severity=Severity.HIGH, epss_score=0.5)
        assert not v.is_actively_exploited

    def test_is_actively_exploited_just_above(self):
        """EPSS at 0.501 should trigger."""
        v = Vulnerability(id="CVE-TEST", summary="test", severity=Severity.HIGH, epss_score=0.501)
        assert v.is_actively_exploited

    def test_risk_level_epss_critical_boundary(self):
        """EPSS exactly 0.7 should NOT trigger CRITICAL (uses >)."""
        v = Vulnerability(id="CVE-TEST", summary="test", severity=Severity.LOW, epss_score=0.7)
        assert "CRITICAL" not in v.risk_level

    def test_risk_level_epss_above_critical(self):
        """EPSS 0.71 should trigger CRITICAL."""
        v = Vulnerability(id="CVE-TEST", summary="test", severity=Severity.LOW, epss_score=0.71)
        assert "CRITICAL" in v.risk_level

    def test_enrichment_exploitability_uses_config_thresholds(self):
        """calculate_exploitability should use config thresholds."""
        from agent_bom.enrichment import calculate_exploitability

        assert calculate_exploitability(0.8) == "HIGH"
        assert calculate_exploitability(0.5) == "MEDIUM"
        assert calculate_exploitability(0.1) == "LOW"
        assert calculate_exploitability(None) is None


# ── Config Env Var Overrides ─────────────────────────────────────────────────


class TestConfigOverrides:
    """Verify env var overrides work correctly."""

    def test_default_values_without_env(self):
        import agent_bom.config as cfg

        assert cfg.RISK_BASE_CRITICAL == 8.0
        assert cfg.RISK_AGENT_WEIGHT == 0.5
        assert cfg.SERVER_RISK_BASE_CEILING == 7.0

    def test_float_override(self, monkeypatch):
        monkeypatch.setenv("AGENT_BOM_EPSS_CRITICAL_THRESHOLD", "0.9")
        import agent_bom.config as cfg

        importlib.reload(cfg)
        assert cfg.EPSS_CRITICAL_THRESHOLD == 0.9
        # Restore
        monkeypatch.delenv("AGENT_BOM_EPSS_CRITICAL_THRESHOLD")
        importlib.reload(cfg)

    def test_invalid_env_var_falls_back(self, monkeypatch):
        monkeypatch.setenv("AGENT_BOM_RISK_BASE_CRITICAL", "not_a_number")
        import agent_bom.config as cfg

        importlib.reload(cfg)
        assert cfg.RISK_BASE_CRITICAL == 8.0  # default
        monkeypatch.delenv("AGENT_BOM_RISK_BASE_CRITICAL")
        importlib.reload(cfg)

    def test_int_helper(self):
        from agent_bom.config import _int

        assert _int("NONEXISTENT_VAR_12345", 42) == 42

    def test_float_helper(self):
        from agent_bom.config import _float

        assert _float("NONEXISTENT_VAR_12345", 3.14) == 3.14


# ── Word-Boundary Tool Classification ────────────────────────────────────────


class TestToolClassificationWordBoundary:
    """Ensure token-based matching eliminates false positives."""

    def test_preset_does_not_match_delete(self):
        """'preset_config' should NOT match DELETE (via 'reset' substring)."""
        caps = classify_tool("preset_config")
        assert ToolCapability.DELETE not in caps
        assert ToolCapability.ADMIN in caps  # "config" → ADMIN

    def test_create_matches_write(self):
        caps = classify_tool("create_directory")
        assert ToolCapability.WRITE in caps

    def test_reader_matches_read(self):
        """'spreadsheet_reader' should match READ (reader starts with read)."""
        caps = classify_tool("spreadsheet_reader")
        assert ToolCapability.READ in caps

    def test_authenticate_matches_auth_not_read(self):
        caps = classify_tool("authenticate_user")
        assert ToolCapability.AUTH in caps
        assert ToolCapability.READ not in caps

    def test_camel_case_split(self):
        """'readFile' (camelCase) should match READ."""
        caps = classify_tool("readFile")
        assert ToolCapability.READ in caps

    def test_kebab_case_split(self):
        """'delete-record' (kebab-case) should match DELETE."""
        caps = classify_tool("delete-record")
        assert ToolCapability.DELETE in caps

    def test_description_word_boundary(self):
        """Description 'execute shell command' should match EXECUTE."""
        caps = classify_tool("foo", description="execute shell command")
        assert ToolCapability.EXECUTE in caps

    def test_empty_name_no_crash(self):
        caps = classify_tool("")
        assert caps == []

    def test_unicode_name_no_crash(self):
        """Non-English tool name should not crash."""
        caps = classify_tool("lecture_fichier")  # French
        assert isinstance(caps, list)

    def test_run_command_matches_execute(self):
        """Verify standard tool names still work."""
        caps = classify_tool("run_command")
        assert ToolCapability.EXECUTE in caps


# ── Risk Score Boundaries ────────────────────────────────────────────────────


def _make_blast_radius(
    severity: Severity = Severity.CRITICAL,
    agents: int = 0,
    creds: int = 0,
    tools: int = 0,
    is_kev: bool = False,
    epss: float | None = None,
    scorecard: float | None = None,
    ai_context: str | None = None,
) -> BlastRadius:
    """Helper to build BlastRadius with controllable dimensions."""
    return BlastRadius(
        vulnerability=Vulnerability(
            id="CVE-TEST-0001",
            summary="test",
            severity=severity,
            is_kev=is_kev,
            epss_score=epss,
        ),
        package=Package(
            name="test-pkg",
            version="1.0.0",
            ecosystem="pypi",
            scorecard_score=scorecard,
        ),
        affected_servers=[],
        affected_agents=[object() for _ in range(agents)],  # type: ignore[list-item]
        exposed_credentials=[f"KEY_{i}" for i in range(creds)],
        exposed_tools=[MCPTool(name=f"tool_{i}", description="") for i in range(tools)],
        ai_risk_context=ai_context,
    )


class TestRiskScoreBoundaries:
    """Verify risk scoring edge cases and caps."""

    def test_score_never_exceeds_10(self):
        """Maximum amplifiers should still cap at 10.0."""
        br = _make_blast_radius(
            severity=Severity.CRITICAL,
            agents=100,
            creds=100,
            tools=100,
            is_kev=True,
            epss=0.99,
            scorecard=1.0,
            ai_context="AI framework with full surface",
        )
        br.calculate_risk_score()
        assert br.risk_score <= 10.0

    def test_minimum_is_base(self):
        """No amplifiers → score equals severity base."""
        br = _make_blast_radius(severity=Severity.MEDIUM)
        br.calculate_risk_score()
        assert br.risk_score == 4.0  # RISK_BASE_MEDIUM default

    def test_agent_factor_caps(self):
        """100 agents should produce same factor as 4."""
        br4 = _make_blast_radius(severity=Severity.LOW, agents=4)
        br100 = _make_blast_radius(severity=Severity.LOW, agents=100)
        br4.calculate_risk_score()
        br100.calculate_risk_score()
        assert br4.risk_score == br100.risk_score

    def test_cred_factor_caps(self):
        """100 creds should produce same factor as 5."""
        br5 = _make_blast_radius(severity=Severity.LOW, creds=5)
        br100 = _make_blast_radius(severity=Severity.LOW, creds=100)
        br5.calculate_risk_score()
        br100.calculate_risk_score()
        assert br5.risk_score == br100.risk_score

    def test_tool_factor_caps(self):
        """100 tools should produce same factor as 10."""
        br10 = _make_blast_radius(severity=Severity.LOW, tools=10)
        br100 = _make_blast_radius(severity=Severity.LOW, tools=100)
        br10.calculate_risk_score()
        br100.calculate_risk_score()
        assert br10.risk_score == br100.risk_score

    def test_scorecard_tier_boundary(self):
        """Scorecard score == 3.0 should NOT get tier 1 boost (< 3.0)."""
        br = _make_blast_radius(severity=Severity.LOW, scorecard=3.0)
        br.calculate_risk_score()
        # Should get tier 2 boost (0.5), not tier 1 (0.75)
        assert br.risk_score == 2.0 + 0.5  # base + tier2

    def test_kev_boost_applied(self):
        """KEV=True adds exactly RISK_KEV_BOOST (1.0) to score."""
        br_no_kev = _make_blast_radius(severity=Severity.HIGH)
        br_kev = _make_blast_radius(severity=Severity.HIGH, is_kev=True)
        br_no_kev.calculate_risk_score()
        br_kev.calculate_risk_score()
        assert br_kev.risk_score - br_no_kev.risk_score == pytest.approx(1.0)

    def test_server_risk_with_registry_floor(self):
        """Registry 'high' floor ensures minimum 6.0."""
        tools = [MCPTool(name="read_file", description="reads")]
        profile = score_server_risk(tools, registry_entry={"risk_level": "high"})
        assert profile.risk_score >= 6.0


# ── Self-Scan Dogfooding ─────────────────────────────────────────────────────


class TestSelfScan:
    def test_agent_bom_can_parse_own_deps(self):
        """agent-bom's own dependencies can be structured as Package objects."""
        import importlib.metadata

        dist = importlib.metadata.distribution("agent-bom")
        requires = dist.requires or []
        assert len(requires) > 0
        packages = []
        for req_str in requires[:5]:
            name = req_str.split()[0].split(";")[0].split("[")[0]
            packages.append(Package(name=name, version="0.0.0", ecosystem="pypi"))
        assert len(packages) > 0
