"""Regression tests for evidence-bounded MITRE ATLAS mapping."""

from agent_bom.atlas import tag_blast_radius
from agent_bom.models import Agent, AgentType, BlastRadius, Package, Severity, Vulnerability


def _blast_radius(*, package: str, affected_agents: list[Agent] | None = None) -> BlastRadius:
    return BlastRadius(
        vulnerability=Vulnerability(
            id="CVE-2026-1000",
            summary="Generic dependency vulnerability",
            severity=Severity.LOW,
        ),
        package=Package(name=package, version="1.0.0", ecosystem="pypi"),
        affected_servers=[],
        affected_agents=affected_agents or [],
        exposed_credentials=[],
        exposed_tools=[],
    )


def test_generic_dependency_without_ai_path_is_not_ai_supply_chain_compromise():
    tags = tag_blast_radius(_blast_radius(package="flask"))

    assert "AML.T0010" not in tags
    assert "AML.T0010.001" not in tags


def test_generic_dependency_on_confirmed_agent_path_is_ai_supply_chain_relevant():
    agent = Agent(
        name="Claude Desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude.json",
    )

    tags = tag_blast_radius(_blast_radius(package="flask", affected_agents=[agent]))

    assert "AML.T0010" in tags
    assert "AML.T0010.001" in tags


def test_ai_framework_dependency_is_ai_supply_chain_relevant():
    tags = tag_blast_radius(_blast_radius(package="langchain"))

    assert "AML.T0010" in tags
    assert "AML.T0010.001" in tags
