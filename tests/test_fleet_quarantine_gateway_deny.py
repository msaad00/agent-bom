"""Fleet quarantine → gateway deny one-click containment.

Quarantining a fleet agent must (a) move it to the QUARANTINED lifecycle
state and (b) mint an enforce-mode gateway policy, bound to that agent's
identity, that denies every tool call — fail closed and idempotent.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.policy_store import InMemoryPolicyStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_fleet_store, set_policy_store


@pytest.fixture
def client_with_agent():
    fleet_store = InMemoryFleetStore()
    policy_store = InMemoryPolicyStore()
    set_fleet_store(fleet_store)
    set_policy_store(policy_store)
    agent = FleetAgent(
        agent_id="agent-123",
        name="rogue-agent",
        agent_type="custom",
        lifecycle_state=FleetLifecycleState.APPROVED,
        tenant_id="default",
        updated_at="2026-01-01T00:00:00Z",
    )
    fleet_store.put(agent)
    return TestClient(app, raise_server_exceptions=False), fleet_store, policy_store


def test_quarantine_creates_bound_deny_policy(client_with_agent):
    client, fleet_store, policy_store = client_with_agent

    resp = client.post("/v1/fleet/agent-123/quarantine")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["lifecycle_state"] == "quarantined"
    assert body["gateway_policy"]["created"] is True
    assert body["gateway_policy"]["bound_agents"] == ["rogue-agent"]

    # Fleet agent is quarantined.
    stored = fleet_store.get("agent-123", tenant_id="default")
    assert stored is not None
    assert stored.lifecycle_state == FleetLifecycleState.QUARANTINED

    # A fail-closed enforce-mode deny-all policy exists, scoped to the agent.
    policies = policy_store.list_policies(tenant_id="default")
    assert len(policies) == 1
    policy = policies[0]
    assert policy.enabled is True
    assert policy.mode.value == "enforce"
    assert policy.bound_agents == ["rogue-agent"]
    assert len(policy.rules) == 1
    assert policy.rules[0].block_tools == ["*"]


def test_quarantine_is_idempotent(client_with_agent):
    client, _fleet_store, policy_store = client_with_agent

    first = client.post("/v1/fleet/agent-123/quarantine")
    second = client.post("/v1/fleet/agent-123/quarantine")
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["gateway_policy"]["created"] is False

    # No duplicate policy stacked; the same policy is re-enabled.
    policies = policy_store.list_policies(tenant_id="default")
    assert len(policies) == 1
    assert policies[0].enabled is True
    assert policies[0].mode.value == "enforce"


def test_quarantine_unknown_agent_is_404(client_with_agent):
    client, _fleet_store, policy_store = client_with_agent
    resp = client.post("/v1/fleet/does-not-exist/quarantine")
    assert resp.status_code == 404
    # No policy created for a missing agent.
    assert policy_store.list_policies(tenant_id="default") == []
