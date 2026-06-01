"""Gateway enforces control-plane GatewayPolicy binding (bound_agents) per call.

The standalone gateway runs on a flattened file policy that is agent-agnostic.
These tests cover the fusion that lets the relay also enforce the control-plane
policy bundle, scoped to the resolved source_agent the way the per-MCP proxy
does — so a policy bound to one agent never affects another.
"""

from __future__ import annotations

from typing import Any

from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _registry() -> UpstreamRegistry:
    return UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")])


def _call(token: str | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"name": "read_file", "arguments": {"path": "/etc/hosts"}}
    if token is not None:
        params["_meta"] = {"agent_identity": token}
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}


async def _ok_caller(upstream, message, extra_headers):
    return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}


def _block_read_policy(*, bound_agents: list[str]) -> dict[str, Any]:
    return {
        "policy_id": "p-block-read",
        "name": "block-read-file",
        "enabled": True,
        "mode": "enforce",
        "bound_agents": bound_agents,
        "rules": [{"id": "r1", "action": "block", "block_tools": ["read_file"]}],
    }


def _settings(control_plane_policies: list[dict[str, Any]]) -> GatewaySettings:
    return GatewaySettings(
        registry=_registry(),
        # File policy allows everything; only the control-plane bundle can block.
        policy={"agent_tokens": {"token-a": "agent-a", "token-b": "agent-b"}},
        upstream_caller=_ok_caller,
        control_plane_policies=control_plane_policies,
    )


def _is_blocked(resp) -> bool:
    body = resp.json()
    return resp.status_code == 200 and isinstance(body.get("error"), dict) and body["error"].get("code") == -32001


def test_bound_policy_blocks_only_the_bound_agent():
    client = TestClient(create_gateway_app(_settings([_block_read_policy(bound_agents=["agent-a"])])))

    # agent-a is bound -> the control-plane policy applies and blocks.
    blocked = client.post("/mcp/filesystem", json=_call("token-a"))
    assert _is_blocked(blocked), blocked.text

    # agent-b is NOT bound -> policy is scoped out, request relays normally.
    allowed = client.post("/mcp/filesystem", json=_call("token-b"))
    assert allowed.status_code == 200
    assert allowed.json()["result"] == {"ok": True}


def test_unbound_policy_applies_to_all_agents():
    client = TestClient(create_gateway_app(_settings([_block_read_policy(bound_agents=[])])))
    for token in ("token-a", "token-b"):
        resp = client.post("/mcp/filesystem", json=_call(token))
        assert _is_blocked(resp), resp.text


def test_no_bundle_leaves_file_policy_behavior_unchanged():
    client = TestClient(create_gateway_app(_settings([])))
    resp = client.post("/mcp/filesystem", json=_call("token-a"))
    assert resp.status_code == 200
    assert resp.json()["result"] == {"ok": True}
