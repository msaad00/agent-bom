"""Display-only agent classification: AI clients vs background agents.

Locks the vocabulary fix that stops "N agents" from implying autonomy when
some records are AI client/host apps (Cursor, Claude Desktop) and others are
framework/service agent definitions. See ``classify_agent_kind``.
"""

from __future__ import annotations

from agent_bom.api.routes.discovery import _agent_count_by_class
from agent_bom.models import Agent, AgentType, AIBOMReport, classify_agent_kind


def _agent(name: str, agent_type: AgentType) -> Agent:
    return Agent(name=name, agent_type=agent_type, config_path="/x")


def test_client_apps_classify_as_client() -> None:
    for t in (AgentType.CURSOR, AgentType.CLAUDE_DESKTOP, AgentType.VSCODE_COPILOT, AgentType.CODEX_CLI):
        assert classify_agent_kind(_agent("app", t)) == "client"


def test_framework_definition_classifies_as_background() -> None:
    assert classify_agent_kind(_agent("langchain:orders", AgentType.CUSTOM)) == "background"
    assert classify_agent_kind(_agent("crewai:support", AgentType.CUSTOM)) == "background"


def test_sbom_and_image_wrappers_are_synthetic_not_agents() -> None:
    assert classify_agent_kind(_agent("sbom:requirements.txt", AgentType.CUSTOM)) == "synthetic"
    assert classify_agent_kind(_agent("image:nginx:1.25", AgentType.CUSTOM)) == "synthetic"


def test_report_counts_split_clients_and_background_excluding_synthetic() -> None:
    report = AIBOMReport(
        agents=[
            _agent("cursor", AgentType.CURSOR),
            _agent("claude-desktop", AgentType.CLAUDE_DESKTOP),
            _agent("langchain:orders", AgentType.CUSTOM),
            _agent("crewai:support", AgentType.CUSTOM),
            _agent("celery:pipeline", AgentType.CUSTOM),
            _agent("sbom:reqs", AgentType.CUSTOM),  # synthetic — not an agent
        ]
    )
    # Mirrors the seeded demo estate: 2 AI clients + 3 background agents.
    assert report.agent_class_counts == {"client": 2, "background": 3}


def test_api_count_by_class_matches_and_ignores_synthetic() -> None:
    agents = [
        _agent("cursor", AgentType.CURSOR),
        _agent("langchain:orders", AgentType.CUSTOM),
        _agent("image:nginx", AgentType.CUSTOM),
    ]
    assert _agent_count_by_class(agents) == {"client": 1, "background": 1}
