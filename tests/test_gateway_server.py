"""End-to-end tests for the multi-MCP gateway server.

Uses TestClient(create_gateway_app(settings)) with an injected
UpstreamCaller so we exercise:
- the full FastAPI route layer (not just the handler)
- real policy evaluation via check_policy
- audit sink capture
- happy path + blocked-by-policy + unknown-upstream + upstream error

No real network. The injected caller simulates both success + failure
paths a pilot team would actually run into.
"""

from __future__ import annotations

from typing import Any

from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


def _simple_registry() -> UpstreamRegistry:
    return UpstreamRegistry(
        [
            UpstreamConfig(name="filesystem", url="http://fs.local:8100"),
            UpstreamConfig(name="jira", url="http://jira.local:8200"),
        ]
    )


def _json_rpc(method: str, **params: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }


# ─── Happy path: relay returns upstream response verbatim ──────────────────


def test_healthz_lists_configured_upstreams() -> None:
    settings = GatewaySettings(registry=_simple_registry(), policy={})
    client = TestClient(create_gateway_app(settings))
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "upstreams": ["filesystem", "jira"]}


def test_relay_forwards_to_upstream_and_returns_response() -> None:
    upstream_calls: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append({"name": upstream.name, "url": upstream.url, "message": message})
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"content": [{"type": "text", "text": "ok"}]},
        }

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=fake_caller,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/etc/hosts"}),
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["content"][0]["text"] == "ok"
    assert upstream_calls[0]["name"] == "filesystem"
    assert upstream_calls[0]["url"] == "http://fs.local:8100"


# ─── Policy block ─────────────────────────────────────────────────────────


def test_relay_blocks_tool_by_policy() -> None:
    upstream_calls: list[dict[str, Any]] = []
    audit_events: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append(message)
        return {}

    async def audit_sink(event):
        audit_events.append(event)

    # block_tools rule — the exact shape proxy.check_policy understands
    policy = {
        "rules": [
            {
                "id": "no-shell",
                "action": "block",
                "block_tools": ["run_shell"],
            }
        ]
    }
    settings = GatewaySettings(
        registry=_simple_registry(),
        policy=policy,
        upstream_caller=fake_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_json_rpc("tools/call", name="run_shell", arguments={"command": "rm -rf /"}),
    )

    assert resp.status_code == 200
    body = resp.json()
    assert "error" in body
    assert body["error"]["code"] == -32001
    assert "Blocked by agent-bom gateway policy" in body["error"]["message"]
    # Blocked tool must NOT reach the upstream
    assert upstream_calls == []
    # And the audit trail must record the block with the tool name + reason
    assert len(audit_events) == 1
    assert audit_events[0]["action"] == "gateway.tool_call_blocked"
    assert audit_events[0]["tool"] == "run_shell"
    assert "no-shell" in (audit_events[0]["reason"] or "")


def test_relay_allows_tool_not_in_blocklist() -> None:
    async def fake_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    policy = {
        "rules": [
            {"id": "no-shell", "action": "block", "block_tools": ["run_shell"]},
        ]
    }
    settings = GatewaySettings(
        registry=_simple_registry(),
        policy=policy,
        upstream_caller=fake_caller,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/jira",
        json=_json_rpc("tools/call", name="query_issues", arguments={"jql": "project = ACME"}),
    )
    assert resp.status_code == 200
    assert resp.json()["result"]["ok"] is True


# ─── Error cases ──────────────────────────────────────────────────────────


def test_relay_unknown_upstream_returns_404() -> None:
    settings = GatewaySettings(registry=_simple_registry(), policy={})
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/nonexistent",
        json=_json_rpc("tools/call", name="x", arguments={}),
    )
    assert resp.status_code == 404
    assert "unknown upstream 'nonexistent'" in resp.json()["detail"]


def test_relay_non_json_rpc_body_returns_400() -> None:
    settings = GatewaySettings(registry=_simple_registry(), policy={})
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json={"hello": "world"},  # no jsonrpc envelope
    )
    assert resp.status_code == 400


def test_relay_upstream_error_surfaces_as_502_and_is_audited() -> None:
    audit_events: list[dict[str, Any]] = []

    async def failing_caller(upstream, message, extra_headers):
        raise RuntimeError("boom")

    async def audit_sink(event):
        audit_events.append(event)

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={},
        upstream_caller=failing_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post(
        "/mcp/filesystem",
        json=_json_rpc("tools/call", name="read_file", arguments={"path": "/tmp/x"}),
    )
    assert resp.status_code == 502
    assert "boom" in resp.json()["detail"]
    assert any(e["action"] == "gateway.upstream_error" for e in audit_events)


def test_relay_non_tool_message_bypasses_policy_and_forwards() -> None:
    """tools/list and other non-tools/call methods must pass through without a policy check."""
    upstream_calls: list[dict[str, Any]] = []

    async def fake_caller(upstream, message, extra_headers):
        upstream_calls.append(message)
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"tools": []}}

    settings = GatewaySettings(
        registry=_simple_registry(),
        policy={"rules": [{"id": "block-all", "action": "block", "block_tools": ["*"]}]},
        upstream_caller=fake_caller,
    )
    client = TestClient(create_gateway_app(settings))
    resp = client.post("/mcp/filesystem", json=_json_rpc("tools/list"))
    assert resp.status_code == 200
    assert upstream_calls and upstream_calls[0]["method"] == "tools/list"
