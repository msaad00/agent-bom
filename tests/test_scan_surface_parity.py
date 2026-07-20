"""Scan-surface parity: the same graph-derived finding CATEGORIES surface on
every scan surface (CLI default, MCP, API) for one seeded estate.

Regression for the 2026-07-19 audit: graph-derived categories
(``COMBINATION`` / ``CIEM_OVER_PRIVILEGE`` / ``NHI``) were only surfaced on the
CLI ``--context-graph`` path and the API. The MCP scan path and the default CLI
path dropped them, so ``scan_impl(config_path=<estate>)`` and a default demo run
emitted ``{CVE}`` while ``/v1/findings`` carried ``COMBINATION``.

The estate below (an agent whose credentialed MCP server carries a vulnerable
package) yields a COMBINATION toxic-combination finding when built into the
unified graph — the same category the API surfaces.
"""

from __future__ import annotations

import json

import pytest

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)


def _trunc(s: str) -> str:
    return s


def _seeded_estate() -> tuple[list[Agent], list[BlastRadius]]:
    """An agent + credentialed MCP server + a critical CVE that the unified graph
    turns into a COMBINATION (agentic credential-harvest) toxic chain."""
    pkg = Package(name="requests", version="2.0.0", ecosystem="pypi")
    vuln = Vulnerability(
        id="CVE-2024-9999",
        summary="RCE",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="2.32.0",
    )
    pkg.vulnerabilities = [vuln]
    server = MCPServer(
        name="gh",
        command="npx",
        transport=TransportType.STDIO,
        env={"GITHUB_TOKEN": "x", "AWS_SECRET_ACCESS_KEY": "y"},
        packages=[pkg],
    )
    agent = Agent(
        name="assistant",
        agent_type=AgentType.CUSTOM,
        config_path="/tmp/cfg.json",
        mcp_servers=[server],
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=["GITHUB_TOKEN"],
        exposed_tools=[],
        risk_score=9.0,
    )
    return [agent], [br]


def _categories_from_report(report: AIBOMReport) -> set[str]:
    return {f.finding_type.value for f in report.to_findings()}


def _categories_from_json(payload: dict) -> set[str]:
    return {str(f.get("finding_type")) for f in payload.get("findings", [])}


# ── The shared build+attach helper produces the graph-derived category ────────


def test_shared_helper_surfaces_combination_from_estate():
    from agent_bom.graph.scan_findings import surface_graph_derived_findings

    agents, brs = _seeded_estate()
    report = AIBOMReport(agents=agents, blast_radii=brs)
    # Before surfacing: only the raw CVE.
    assert _categories_from_report(report) == {"CVE"}

    surface_graph_derived_findings(report, scan_id="s1", tenant_id="default")

    cats = _categories_from_report(report)
    assert "COMBINATION" in cats
    assert "CVE" in cats


# ── MCP scan path emits the same categories (leg 1) ───────────────────────────


@pytest.mark.asyncio
async def test_mcp_scan_emits_graph_derived_categories():
    from agent_bom.mcp_tools.scanning import scan_impl

    agents, brs = _seeded_estate()

    async def _pipeline(*_args, **_kwargs):
        return agents, brs, [], []

    result = await scan_impl(
        config_path="/tmp/estate",
        offline=True,
        _run_scan_pipeline=_pipeline,
        _truncate_response=_trunc,
    )
    payload = json.loads(result)
    cats = _categories_from_json(payload)
    assert "COMBINATION" in cats, f"MCP dropped graph-derived category; got {cats}"
    assert "CVE" in cats


# ── MCP == API category parity on the same estate ─────────────────────────────


@pytest.mark.asyncio
async def test_mcp_matches_api_categories():
    from agent_bom.graph.scan_findings import surface_graph_derived_findings
    from agent_bom.mcp_tools.scanning import scan_impl

    agents, brs = _seeded_estate()

    async def _pipeline(*_args, **_kwargs):
        return agents, brs, [], []

    mcp_payload = json.loads(
        await scan_impl(
            config_path="/tmp/estate",
            offline=True,
            _run_scan_pipeline=_pipeline,
            _truncate_response=_trunc,
        )
    )
    mcp_cats = _categories_from_json(mcp_payload)

    # API path: same shared build+attach helper.
    api_report = AIBOMReport(agents=agents, blast_radii=brs)
    surface_graph_derived_findings(api_report, scan_id="s1", tenant_id="default")
    api_cats = _categories_from_report(api_report)

    assert mcp_cats == api_cats


# ── Default CLI path (no --context-graph) surfaces the same categories (leg 2) ─


def test_default_cli_scan_surfaces_combination():
    from unittest.mock import patch

    from click.testing import CliRunner

    from agent_bom.cli import main

    agents, brs = _seeded_estate()
    pkg = agents[0].mcp_servers[0].packages[0]

    runner = CliRunner()
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=agents),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=brs),
        patch("agent_bom.cli.agents.extract_packages", return_value=[pkg]),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=None),
        patch("agent_bom.vex.is_vex_suppressed", return_value=False),
    ):
        # No --context-graph flag — the default surface.
        result = runner.invoke(
            main,
            ["scan", "--no-auto-update-db", "--format", "json"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0, result.output
    # The console prints a status banner before the JSON document.
    payload = json.loads(result.output[result.output.index("{") :])
    cats = _categories_from_json(payload)
    assert "COMBINATION" in cats, f"default CLI dropped graph-derived category; got {cats}"


def test_default_cli_toxic_count_is_single_honest_number():
    """The console must not print a legacy toxic count that contradicts the
    unified stream (never 11 vs 5 vs 0). Only the unified graph count shows."""
    from unittest.mock import patch

    from click.testing import CliRunner

    from agent_bom.cli import main

    agents, brs = _seeded_estate()
    pkg = agents[0].mcp_servers[0].packages[0]

    runner = CliRunner()
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=agents),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=brs),
        patch("agent_bom.cli.agents.extract_packages", return_value=[pkg]),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=None),
        patch("agent_bom.vex.is_vex_suppressed", return_value=False),
    ):
        result = runner.invoke(
            main,
            ["scan", "--no-auto-update-db", "--enrich", "--offline"],
            catch_exceptions=False,
        )
    assert result.exit_code == 0, result.output
    # The legacy "N detected (…critical, …high)" wording must not appear; the
    # single reconciled toxic line uses "finding(s)".
    assert "detected (" not in result.output
