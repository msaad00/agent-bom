"""A wrongly-typed JSON-RPC field must be governed, not thrown.

``extract_tool_name`` / ``extract_tool_arguments`` assumed ``params`` was a dict
and ``params.name`` a string. A caller sending ``{"name": {...}}`` or
``"params": [...]`` produced an ``AttributeError`` that escaped the relay: a 500
with no policy decision, no audit event, and no ledger record. An unparseable
call is a call that must still be accounted for.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.proxy import extract_tool_arguments, extract_tool_name, policy_subject_from_message

HOSTILE_PARAMS = [
    pytest.param({"name": {"nested": "dict"}, "arguments": {}}, id="name-is-a-dict"),
    pytest.param({"name": ["read_file"], "arguments": {}}, id="name-is-a-list"),
    pytest.param({"name": 7, "arguments": {}}, id="name-is-an-int"),
    pytest.param({"name": "read_file", "arguments": [1, 2]}, id="arguments-is-a-list"),
    pytest.param({"name": "read_file", "arguments": "path=/etc/passwd"}, id="arguments-is-a-string"),
    pytest.param([1, 2], id="params-is-a-list"),
    pytest.param("params", id="params-is-a-string"),
]


@pytest.mark.parametrize("params", HOSTILE_PARAMS)
def test_extractors_coerce_instead_of_raising(params: Any):
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}

    name = extract_tool_name(message)
    arguments = extract_tool_arguments(message)

    assert name is None or isinstance(name, str)
    assert isinstance(arguments, dict)


@pytest.mark.parametrize("params", HOSTILE_PARAMS)
def test_policy_subject_is_always_a_governable_pair(params: Any):
    """Whatever the caller sends, policy gets a (str, dict) it can evaluate."""
    from agent_bom.proxy_policy import check_policy

    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params}

    subject = policy_subject_from_message(message)

    assert subject is not None
    tool_name, arguments = subject
    assert isinstance(tool_name, str) and tool_name
    assert isinstance(arguments, dict)
    # An unnameable tool is not a free pass: it still runs through policy.
    check_policy({"rules": [{"id": "r", "action": "block", "block_tools": ["delete_file"]}]}, tool_name, arguments)


@pytest.mark.parametrize("params", HOSTILE_PARAMS)
def test_relay_accounts_for_a_wrongly_typed_tool_call(params: Any):
    audit: list[dict[str, Any]] = []

    async def _sink(event: dict[str, Any]) -> None:
        audit.append(event)

    async def _ok_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
        policy={"rules": [{"id": "no-delete", "action": "block", "block_tools": ["delete_file"]}]},
        upstream_caller=_ok_caller,
        audit_sink=_sink,
    )
    client = TestClient(create_gateway_app(settings))

    resp = client.post(
        "/mcp/filesystem",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params},
    )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "error" in body or "result" in body, body
