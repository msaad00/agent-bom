"""Regression: scan_agents_with_enrichment threads offline_mode into enrich_vulnerabilities.

Without this wiring the offline-cache EPSS/KEV joins added by #2514 are dead code
because the production call site never sets ``offline=True`` even when ``--offline``
is passed on the CLI.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom import scanners
from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)


@pytest.mark.asyncio
async def test_scan_agents_with_enrichment_passes_offline_mode(monkeypatch):
    captured: dict[str, Any] = {}

    async def _fake_enrich(vulns, **kwargs):
        captured.update(kwargs)
        captured["vuln_count"] = len(vulns)
        return len(vulns)

    async def _fake_scan_agents(agents, **kwargs):
        return [
            BlastRadius(
                vulnerability=v,
                package=pkg,
                affected_servers=[server],
                affected_agents=[agent],
                exposed_credentials=[],
                exposed_tools=[],
            )
            for agent in agents
            for server in agent.mcp_servers
            for pkg in server.packages
            for v in pkg.vulnerabilities
        ]

    monkeypatch.setattr(scanners, "scan_agents", _fake_scan_agents)
    monkeypatch.setattr("agent_bom.enrichment.enrich_vulnerabilities", _fake_enrich)
    monkeypatch.setattr(
        "agent_bom.resolver.enrich_supply_chain_metadata",
        lambda *args, **kwargs: None,
    )

    vuln = Vulnerability(id="CVE-2026-0001", summary="x", severity=Severity.HIGH)
    pkg = Package(name="demo", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    server = MCPServer(name="demo-server", command="demo", packages=[pkg])
    agent = Agent(name="demo-agent", agent_type=AgentType.CUSTOM, config_path="/tmp/x", mcp_servers=[server])

    scanners.set_offline_mode(True)
    try:
        await scanners.scan_agents_with_enrichment([agent])
    finally:
        scanners.set_offline_mode(False)

    assert captured.get("offline") is True, (
        "scan_agents_with_enrichment must pass offline=offline_mode through to "
        "enrich_vulnerabilities so the offline EPSS/KEV cache joins fire"
    )
    assert captured.get("vuln_count") == 1


@pytest.mark.asyncio
async def test_scan_agents_with_enrichment_passes_online_mode(monkeypatch):
    captured: dict[str, Any] = {}

    async def _fake_enrich(vulns, **kwargs):
        captured.update(kwargs)
        return len(vulns)

    async def _fake_scan_agents(agents, **kwargs):
        return [
            BlastRadius(
                vulnerability=v,
                package=pkg,
                affected_servers=[server],
                affected_agents=[agent],
                exposed_credentials=[],
                exposed_tools=[],
            )
            for agent in agents
            for server in agent.mcp_servers
            for pkg in server.packages
            for v in pkg.vulnerabilities
        ]

    monkeypatch.setattr(scanners, "scan_agents", _fake_scan_agents)
    monkeypatch.setattr("agent_bom.enrichment.enrich_vulnerabilities", _fake_enrich)
    monkeypatch.setattr(
        "agent_bom.resolver.enrich_supply_chain_metadata",
        lambda *args, **kwargs: None,
    )

    vuln = Vulnerability(id="CVE-2026-0002", summary="y", severity=Severity.HIGH)
    pkg = Package(name="demo", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    server = MCPServer(name="demo-server", command="demo", packages=[pkg])
    agent = Agent(name="demo-agent", agent_type=AgentType.CUSTOM, config_path="/tmp/x", mcp_servers=[server])

    scanners.set_offline_mode(False)
    await scanners.scan_agents_with_enrichment([agent])

    assert captured.get("offline") is False
