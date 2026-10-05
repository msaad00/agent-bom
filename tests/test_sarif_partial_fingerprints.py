"""Regression: SARIF exports include GitHub partialFingerprints for dedup."""

from __future__ import annotations

from agent_bom.models import Agent, AIBOMReport, MCPServer, Package
from agent_bom.output.sarif import to_sarif


def _malicious_report() -> AIBOMReport:
    pkg = Package(
        name="evil-requests",
        version="9.9.9",
        ecosystem="pypi",
        is_malicious=True,
        malicious_reason="Typosquat of requests",
    )
    server = MCPServer(name="tools", command="npx", packages=[pkg])
    agent = Agent(name="dev-agent", agent_type="cli", config_path="/tmp/agent", mcp_servers=[server])
    return AIBOMReport(agents=[agent], blast_radii=[])


def test_locationless_sarif_has_stable_identity_without_a_source_line_hash() -> None:
    sarif = to_sarif(_malicious_report())
    results = sarif["runs"][0]["results"]
    assert results
    assert "partialFingerprints" not in results[0]
    assert results[0]["locations"][0]["logicalLocations"]
    assert results[0]["fingerprints"]["agent-bom/v1"]
