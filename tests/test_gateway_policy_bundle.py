"""Public gateway policy-bundle evaluation owns bound_agents scoping.

``agent_bom.gateway.evaluate_gateway_policy_bundle`` is the one public entry
point for evaluating a control-plane GatewayPolicy bundle scoped to an agent.
Both runtime lanes (per-MCP proxy and standalone gateway relay) must call it —
the gateway lane previously reached into a private ``proxy._*`` helper, which
these tests also guard against reintroducing.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.api.policy_store import GatewayPolicy
from agent_bom.gateway import evaluate_gateway_policy_bundle

SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "agent_bom"


def _block_read_policy(*, bound_agents: list[str], mode: str = "enforce") -> GatewayPolicy:
    return GatewayPolicy(
        policy_id="p-block-read",
        name="block-read-file",
        enabled=True,
        mode=mode,
        bound_agents=bound_agents,
        rules=[{"id": "r1", "action": "block", "block_tools": ["read_file"]}],
    )


def test_policy_bound_to_other_agent_does_not_apply():
    policies = [_block_read_policy(bound_agents=["agent-a"])]
    allowed, reason = evaluate_gateway_policy_bundle(policies, "agent-b", "read_file", {"path": "/etc/hosts"})
    assert allowed is True
    assert reason == ""


def test_policy_bound_to_calling_agent_blocks():
    policies = [_block_read_policy(bound_agents=["agent-a"])]
    allowed, reason = evaluate_gateway_policy_bundle(policies, "agent-a", "read_file", {"path": "/etc/hosts"})
    assert allowed is False
    assert reason


def test_unbound_policy_applies_to_all_agents():
    policies = [_block_read_policy(bound_agents=[])]
    for agent in ("agent-a", "agent-b"):
        allowed, reason = evaluate_gateway_policy_bundle(policies, agent, "read_file", {})
        assert allowed is False, agent
        assert reason


def test_empty_bundle_allows():
    allowed, reason = evaluate_gateway_policy_bundle([], "agent-a", "read_file", {})
    assert allowed is True
    assert reason == ""


def test_disabled_policy_does_not_block():
    policy = _block_read_policy(bound_agents=[])
    policy.enabled = False
    allowed, _ = evaluate_gateway_policy_bundle([policy], "agent-a", "read_file", {})
    assert allowed is True


def test_audit_mode_allows_with_audit_reason():
    policies = [_block_read_policy(bound_agents=["agent-a"], mode="audit")]
    allowed, reason = evaluate_gateway_policy_bundle(policies, "agent-a", "read_file", {})
    assert allowed is True
    assert reason.startswith("[audit]")


def test_exported_in_gateway_all():
    import agent_bom.gateway as gateway

    assert "evaluate_gateway_policy_bundle" in gateway.__all__


def test_gateway_server_does_not_import_private_proxy_helper():
    """The gateway lane must use the public gateway API, not proxy privates."""
    source = (SRC_ROOT / "gateway_server.py").read_text(encoding="utf-8")
    assert "_evaluate_gateway_policy_bundle" not in source
    assert "from agent_bom.proxy import _" not in source


def test_private_bundle_helper_removed_from_proxy():
    """The private helper was replaced by the public gateway function."""
    import agent_bom.proxy as proxy

    assert not hasattr(proxy, "_evaluate_gateway_policy_bundle")
