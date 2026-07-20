"""Regression tests for scan-time registry enrichment caching."""

from __future__ import annotations

import asyncio

from agent_bom.models import Agent, AgentType, MCPServer, Package, Severity, Vulnerability


def test_scan_agents_reuses_registry_match_for_each_server(monkeypatch) -> None:
    """A server with many vulnerable packages should be matched once per scan."""
    import agent_bom.parsers
    import agent_bom.scanners

    server = MCPServer(name="shared-server", command="npx", args=["shared-server"])
    server.packages = [
        Package(name=f"pkg-{index}", version="1.0.0", ecosystem="npm")
        for index in range(12)
    ]
    agent = Agent(
        name="test-agent",
        agent_type=AgentType.CUSTOM,
        config_path="/tmp/agent.json",
        mcp_servers=[server],
    )

    async def _fake_scan_packages(packages, **_kwargs):
        for package in packages:
            package.vulnerabilities.append(
                Vulnerability(
                    id=f"CVE-2026-{package.name}",
                    summary="synthetic test vulnerability",
                    severity=Severity.HIGH,
                )
            )
        return len(packages)

    lookups: list[str] = []

    def _fake_registry_entry(candidate):
        lookups.append(candidate.name)
        return {"tools": ["read_file"], "credential_env_vars": ["TEST_TOKEN"]}

    monkeypatch.setattr(agent_bom.scanners, "scan_packages", _fake_scan_packages)
    monkeypatch.setattr(agent_bom.parsers, "get_registry_entry", _fake_registry_entry)

    findings = asyncio.run(agent_bom.scanners.scan_agents([agent], show_scan_banner=False))

    assert len(findings) == len(server.packages)
    assert lookups == ["shared-server"]

