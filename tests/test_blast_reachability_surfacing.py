"""End-to-end test for graph-walk reachability surfacing.

Pins the contract that:
1. ``apply_dependency_reachability_to_blast_radii`` stamps the new
   ``graph_reachable`` / ``graph_min_hop_distance`` / ``graph_reachable_from_agents``
   fields on each BlastRadius row whose vulnerability has a corresponding
   reachability record from the engine.
2. The risk score moves up for reachable findings (boost applied) and
   down for explicitly-unreachable findings (penalty applied), within
   the ``[0, 10]`` clamp.
3. Failures inside the engine downgrade to a no-op — the helper
   returns ``0`` and the BlastRadius rows stay untouched, so a graph
   bug never breaks the scan path.
"""

from __future__ import annotations

import pytest

from agent_bom.graph.blast_reach import (
    apply_dependency_reachability_to_blast_radii,
)
from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)


def _br(
    *,
    vuln_id: str,
    pkg_name: str,
    pkg_version: str,
    affected_agents: list[Agent],
    affected_servers: list[MCPServer],
) -> BlastRadius:
    vuln = Vulnerability(
        id=vuln_id,
        summary="test cve",
        severity=Severity.HIGH,
    )
    pkg = Package(name=pkg_name, version=pkg_version, ecosystem="npm")
    pkg.vulnerabilities = [vuln]
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=affected_servers,
        affected_agents=affected_agents,
        exposed_credentials=[],
        exposed_tools=[],
    )


@pytest.fixture
def reachable_setup() -> tuple[list[BlastRadius], list[Agent]]:
    """Build agents + servers + a single reachable vulnerability."""
    package = Package(name="lodash", version="4.17.20", ecosystem="npm")
    server = MCPServer(
        name="sqlite-mcp",
        command="npx -y mcp-server-sqlite",
        packages=[package],
    )
    agent = Agent(name="cursor", agent_type=AgentType.CURSOR, config_path="/tmp/cursor.json", mcp_servers=[server])
    blast = _br(
        vuln_id="CVE-2099-0001",
        pkg_name="lodash",
        pkg_version="4.17.20",
        affected_agents=[agent],
        affected_servers=[server],
    )
    return [blast], [agent]


def test_stamps_reachable_findings(reachable_setup) -> None:
    blast_radii, agents = reachable_setup
    stamped = apply_dependency_reachability_to_blast_radii(blast_radii, agents, rescore=True)

    assert stamped == 1
    br = blast_radii[0]
    assert br.graph_reachable is True
    assert br.graph_min_hop_distance is not None
    assert br.graph_min_hop_distance >= 1
    # The agent we wired up must appear in the reachable_from list.
    assert any("cursor" in node_id for node_id in br.graph_reachable_from_agents)


def test_no_op_when_no_blast_radii() -> None:
    assert apply_dependency_reachability_to_blast_radii([], [], rescore=True) == 0


def test_no_op_when_no_agents(reachable_setup) -> None:
    blast_radii, _ = reachable_setup
    # Empty agents → engine has no roots to walk from; helper returns 0
    # without touching the rows.
    assert apply_dependency_reachability_to_blast_radii(blast_radii, [], rescore=True) == 0
    assert blast_radii[0].graph_reachable is None


def test_rescore_changes_risk_score_when_reachable(reachable_setup) -> None:
    blast_radii, agents = reachable_setup
    br = blast_radii[0]

    # Score before reachability is applied (engine not run).
    br.calculate_risk_score()
    base_score = br.risk_score
    assert br.graph_reachable is None

    apply_dependency_reachability_to_blast_radii(blast_radii, agents, rescore=True)
    boosted_score = br.risk_score

    assert br.graph_reachable is True
    assert boosted_score > base_score
    # Boost is ~0.5 by default; allow some floor for clamp at 10.0.
    assert boosted_score - base_score == pytest.approx(0.5, abs=0.05) or boosted_score == 10.0


def test_engine_failure_is_a_no_op(monkeypatch, reachable_setup) -> None:
    blast_radii, agents = reachable_setup

    def explode(*args, **kwargs):
        raise RuntimeError("synthetic engine failure")

    monkeypatch.setattr("agent_bom.graph.blast_reach.compute_dependency_reach", explode)
    stamped = apply_dependency_reachability_to_blast_radii(blast_radii, agents, rescore=True)

    assert stamped == 0
    # Untouched.
    assert blast_radii[0].graph_reachable is None
    assert blast_radii[0].graph_reachable_from_agents == []
