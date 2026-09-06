"""Manifest relationships require an unambiguous identity binding."""

import pytest

from agent_bom.agent_manifest import _graph


def _uses(agents, servers):
    return {(edge["source"], edge["target"]) for edge in _graph(agents, servers)["edges"] if edge["relationship"] == "uses"}


@pytest.mark.parametrize("reverse", [False, True])
def test_same_name_in_different_environments_does_not_invent_binding(reverse):
    agents = [
        {"id": "prod-agent", "name": "assistant", "environment": "prod"},
        {"id": "dev-agent", "name": "assistant", "environment": "dev"},
    ]
    if reverse:
        agents.reverse()
    assert _uses(agents, [{"id": "server", "agent_name": "assistant"}]) == set()


def test_explicit_server_membership_takes_precedence_over_name_hint():
    agents = [
        {"id": "actual", "name": "actual", "mcp_server_ids": ["server"]},
        {"id": "name-only", "name": "assistant"},
    ]
    assert _uses(agents, [{"id": "server", "agent_name": "assistant"}]) == {("actual", "server")}


def test_shared_server_retains_all_explicit_memberships():
    agents = [{"id": key, "name": "assistant", "mcp_server_ids": ["server"]} for key in ("prod", "dev")]
    assert _uses(agents, [{"id": "server", "agent_name": "assistant"}]) == {("prod", "server"), ("dev", "server")}


def test_unambiguous_name_hint_preserves_legacy_observation_link():
    assert _uses([{"id": "agent", "name": "assistant"}], [{"id": "server", "agent_name": "assistant"}]) == {("agent", "server")}
