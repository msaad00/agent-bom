"""Project vulnerability observations already supplied by inventory or SBOM input."""

from __future__ import annotations

from agent_bom.models import Agent, BlastRadius


def build_supplied_findings(agents: list[Agent]) -> list[BlastRadius]:
    """Retain input evidence without querying a feed or inferring runtime access."""
    observations: dict[tuple[str, str], BlastRadius] = {}
    for agent in agents:
        for server in agent.mcp_servers:
            for package in server.packages:
                for vulnerability in package.vulnerabilities:
                    key = (package.stable_id, vulnerability.id)
                    if key not in observations:
                        observations[key] = BlastRadius(
                            vulnerability=vulnerability,
                            package=package,
                            affected_agents=[],
                            affected_servers=[],
                            exposed_credentials=[],
                            exposed_tools=[],
                        )
                    finding = observations[key]
                    if agent not in finding.affected_agents:
                        finding.affected_agents.append(agent)
                    if server not in finding.affected_servers:
                        finding.affected_servers.append(server)
    for finding in observations.values():
        finding.calculate_risk_score()
    return sorted(observations.values(), key=lambda finding: (-finding.risk_score, finding.package.stable_id, finding.vulnerability.id))
