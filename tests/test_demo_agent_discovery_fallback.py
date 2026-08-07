"""A single stray binary in the image must not defeat the demo estate.

``_discover_agents_with_demo_fallback`` fell back to the curated demo inventory
only when live discovery found *nothing*:

    agents = discover_all()
    if agents:
        return agents

Its docstring justified that with "on a hosted/anonymous demo server there are
no local agent configs to discover". The hosted image ships the ``mcp`` CLI at
``/app/.venv/bin/mcp``, so discovery returned exactly one agent, the guard
short-circuited, and the fallback never fired.

The result on a 4,101-asset estate: ``/v1/agents/mesh`` served one unlinked node
and the Agent Topology page rendered a "trust mesh" of a single dot.

In demo-estate mode the curated inventory IS the story, so it is used whenever
the mode is on. Real deployments (env unset) still get live discovery only — the
fallback is never injected there.
"""

from __future__ import annotations

import pytest

import agent_bom.api.routes.discovery as discovery


class _FakeAgent:
    def __init__(self, name: str) -> None:
        self.name = name
        self.mcp_servers: list[object] = []


@pytest.fixture()
def demo_mode(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")


def _stub_discovery(monkeypatch: pytest.MonkeyPatch, found: list[object]) -> None:
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda: found)


def test_one_incidental_agent_does_not_suppress_the_demo_estate(monkeypatch: pytest.MonkeyPatch, demo_mode) -> None:
    """The regression: the hosted image's own mcp CLI defeated the fallback."""
    _stub_discovery(monkeypatch, [_FakeAgent("mcp-cli")])

    agents = discovery._discover_agents_with_demo_fallback()

    assert len(agents) > 1, "a single incidental agent must not stand in for the estate"


def test_demo_estate_renders_a_real_mesh(monkeypatch: pytest.MonkeyPatch, demo_mode) -> None:
    """A trust mesh needs more than one node to be a mesh at all."""
    _stub_discovery(monkeypatch, [_FakeAgent("mcp-cli")])

    agents = discovery._discover_agents_with_demo_fallback()
    names = {getattr(agent, "name", "") for agent in agents}

    assert len(names) > 1


def test_empty_discovery_still_falls_back(monkeypatch: pytest.MonkeyPatch, demo_mode) -> None:
    """The original behaviour is preserved, not replaced."""
    _stub_discovery(monkeypatch, [])

    assert discovery._discover_agents_with_demo_fallback()


def test_real_deployments_never_get_demo_agents(monkeypatch: pytest.MonkeyPatch) -> None:
    """Demo rows must never appear in a real tenant's topology.

    This is the guard that makes the fix safe: with the mode off, whatever
    discovery found is exactly what is returned — including nothing.
    """
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    discovered = [_FakeAgent("mcp-cli")]
    _stub_discovery(monkeypatch, discovered)

    assert discovery._discover_agents_with_demo_fallback() == discovered


def test_real_deployment_with_no_agents_stays_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    _stub_discovery(monkeypatch, [])

    assert discovery._discover_agents_with_demo_fallback() == []
