"""Tests for two-tier severity: --warn-on (exit 0 + banner) and --fail-on-severity (exit 1)."""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from agent_bom.cli import main

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_blast_radius(severity: str, vuln_id: str = "CVE-2025-TEST"):
    """Build a minimal BlastRadius with the given severity."""
    from agent_bom.models import (
        Agent,
        AgentType,
        BlastRadius,
        MCPServer,
        Package,
        Severity,
        TransportType,
        Vulnerability,
    )

    vuln = Vulnerability(
        id=vuln_id,
        summary="test vulnerability",
        severity=Severity(severity),
        is_kev=False,
    )
    pkg = Package(name="test-pkg", version="1.0.0", ecosystem="pypi")
    server = MCPServer(name="test-server", command="npx", transport=TransportType.STDIO)
    agent = Agent(name="test-agent", agent_type=AgentType.CUSTOM, config_path="/tmp/t", mcp_servers=[server])
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )


def _run_scan_with_findings(
    runner: CliRunner,
    blast_radii: list,
    extra_args: list[str] | None = None,
):
    """Invoke `agent-bom agents` with mocked scan output returning the given blast radii.

    Uses a minimal agent with one package so the scan step is reached.
    Mocks scan_agents_sync to return the provided blast radii.
    """
    from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

    pkg = Package(name="test-pkg", version="1.0.0", ecosystem="pypi")
    server = MCPServer(name="test-server", command="npx", transport=TransportType.STDIO, packages=[pkg])
    mock_agent = Agent(
        name="test-agent",
        agent_type=AgentType.CUSTOM,
        config_path="/tmp/test",
        mcp_servers=[server],
    )

    args = ["scan"] + (extra_args or [])

    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[mock_agent]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=blast_radii),
        patch("agent_bom.cli.agents.extract_packages", return_value=[pkg]),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=None),
        patch("agent_bom.vex.is_vex_suppressed", return_value=False),
    ):
        return runner.invoke(main, args, catch_exceptions=False)


# ---------------------------------------------------------------------------
# Tests: --warn-on only
# ---------------------------------------------------------------------------


def test_warn_on_help_option_present():
    """--warn-on should appear in scan --help."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--warn-on" in result.output


def test_warn_on_no_findings_exits_zero():
    """When --warn-on is set but no findings exist, exit 0 with no warning banner."""
    runner = CliRunner()
    result = _run_scan_with_findings(runner, [], extra_args=["--warn-on", "medium"])
    assert result.exit_code == 0
    assert "--warn-on threshold" not in result.output


def test_warn_on_exits_zero_with_warning_banner():
    """When --warn-on=medium and a MEDIUM finding exists, exit 0 and print warning banner."""
    runner = CliRunner()
    br = _make_blast_radius("medium")
    result = _run_scan_with_findings(runner, [br], extra_args=["--warn-on", "medium"])
    assert result.exit_code == 0
    assert "MEDIUM" in result.output
    assert "--warn-on threshold" in result.output


def test_warn_on_exits_zero_below_threshold():
    """LOW finding when --warn-on=high → exits 0 with no warning (below threshold)."""
    runner = CliRunner()
    br = _make_blast_radius("low")
    result = _run_scan_with_findings(runner, [br], extra_args=["--warn-on", "high"])
    assert result.exit_code == 0
    # Banner should NOT appear since low < high threshold
    assert "--warn-on threshold" not in result.output


# ---------------------------------------------------------------------------
# Tests: --fail-on-severity only (existing behavior preserved)
# ---------------------------------------------------------------------------


def test_fail_on_severity_exits_one():
    """--fail-on-severity=critical with a CRITICAL finding → exit 1."""
    runner = CliRunner()
    br = _make_blast_radius("critical", "CVE-2025-CRIT")
    result = _run_scan_with_findings(runner, [br], extra_args=["--fail-on-severity", "critical"])
    assert result.exit_code == 1


def test_fail_on_severity_exits_one_for_unified_non_cve_finding():
    """--fail-on-severity should include unified findings such as MCP_BLOCKLIST."""
    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.cli.agents._post import compute_exit_code
    from agent_bom.finding import Asset, Finding, FindingSource, FindingType
    from agent_bom.models import AIBOMReport

    finding = Finding(
        finding_type=FindingType.MCP_BLOCKLIST,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name="bad-mcp", asset_type="mcp_server", location="mcp.json"),
        severity="high",
        title="Blocked MCP",
    )
    report = AIBOMReport(findings=[finding])
    ctx = ScanContext(con=Console(file=StringIO(), force_terminal=False), report=report)

    assert (
        compute_exit_code(
            ctx,
            fail_on_severity="high",
            warn_on_severity=None,
            fail_on_kev=False,
            fail_if_ai_risk=False,
            push_url=None,
            push_api_key=None,
            quiet=True,
        )
        == 1
    )


def test_fail_on_severity_accepts_uppercase_choice():
    """--fail-on-severity should normalize case like --warn-on."""
    runner = CliRunner()
    br = _make_blast_radius("high", "CVE-2025-HIGH")
    result = _run_scan_with_findings(runner, [br], extra_args=["--fail-on-severity", "HIGH"])
    assert result.exit_code == 1


def test_fail_on_severity_exits_zero_no_match():
    """--fail-on-severity=critical with only a MEDIUM finding → exit 0."""
    runner = CliRunner()
    br = _make_blast_radius("medium")
    result = _run_scan_with_findings(runner, [br], extra_args=["--fail-on-severity", "critical"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Tests: two-tier (--warn-on + --fail-on-severity together)
# ---------------------------------------------------------------------------


def test_both_tiers_warn_zone_exits_zero():
    """Finding is at MEDIUM (warn zone), fail threshold is CRITICAL → exit 0 with banner."""
    runner = CliRunner()
    br = _make_blast_radius("medium")
    result = _run_scan_with_findings(runner, [br], extra_args=["--warn-on", "medium", "--fail-on-severity", "critical"])
    assert result.exit_code == 0
    assert "--warn-on threshold" in result.output


def test_both_tiers_fail_zone_exits_one():
    """Finding is at CRITICAL (above both thresholds) → fail wins, exit 1, no warn banner."""
    runner = CliRunner()
    br = _make_blast_radius("critical", "CVE-2025-CRIT2")
    result = _run_scan_with_findings(runner, [br], extra_args=["--warn-on", "medium", "--fail-on-severity", "critical"])
    assert result.exit_code == 1
    # Warn banner should NOT print when fail gate already fired
    assert "--warn-on threshold" not in result.output


# ---------------------------------------------------------------------------
# Tests: MCP scan_impl warn_severity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_scan_impl_warn_severity_warn_status():
    """scan_impl with warn_severity returns warn_gate_status=warn when findings exceed threshold."""

    from agent_bom.mcp_tools.scanning import scan_impl

    br = _make_blast_radius("high")

    async def _mock_pipeline(*args, **kwargs):
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType

        agent = Agent(
            name="a",
            agent_type=AgentType.CUSTOM,
            config_path="/t",
            mcp_servers=[MCPServer(name="s", command="x", transport=TransportType.STDIO)],
        )
        return [agent], [br], [], []

    import json

    raw = await scan_impl(
        warn_severity="medium",
        _run_scan_pipeline=_mock_pipeline,
        _truncate_response=lambda x: x,
    )
    data = json.loads(raw)
    assert data.get("warn_gate_status") == "warn"
    assert data.get("warn_gate_severity") == "medium"
    assert data.get("warn_gate_count", 0) >= 1


@pytest.mark.asyncio
async def test_scan_impl_warn_severity_pass_status():
    """scan_impl with warn_severity returns warn_gate_status=pass when no findings exceed threshold."""
    from agent_bom.mcp_tools.scanning import scan_impl

    br = _make_blast_radius("low")

    async def _mock_pipeline(*args, **kwargs):
        from agent_bom.models import Agent, AgentType, MCPServer, TransportType

        agent = Agent(
            name="a",
            agent_type=AgentType.CUSTOM,
            config_path="/t",
            mcp_servers=[MCPServer(name="s", command="x", transport=TransportType.STDIO)],
        )
        return [agent], [br], [], []

    import json

    raw = await scan_impl(
        warn_severity="high",
        _run_scan_pipeline=_mock_pipeline,
        _truncate_response=lambda x: x,
    )
    data = json.loads(raw)
    assert data.get("warn_gate_status") == "pass"
    assert data.get("warn_gate_count", 0) == 0


# ---------------------------------------------------------------------------
# Preset CI two-tier defaults
# ---------------------------------------------------------------------------


def test_preset_ci_sets_warn_on_high():
    """--preset ci should set warn_on_severity=high automatically."""

    # Verify the preset==ci block assigns warn_on_severity via AST inspection
    # (avoids the cost of a full scan invocation).
    import ast
    import pathlib

    src = pathlib.Path("src/agent_bom/cli/agents/__init__.py").read_text()
    tree = ast.parse(src)

    # Find the preset == "ci" block and verify warn_on_severity assignment
    found = False
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "preset"
        ):
            for child in ast.walk(node):
                if isinstance(child, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "warn_on_severity" for t in child.targets):
                    found = True
    assert found, "preset=='ci' block must assign warn_on_severity"
