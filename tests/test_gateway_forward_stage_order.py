"""Durable admission, upstream effects and completion auditing keep their order."""

import asyncio

import pytest
from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewayAuditDeliveryUnavailableError, GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


@pytest.mark.parametrize(
    "method,admission_fails,upstream_fails,completion_fails,status,order",
    [
        ("tools/call", True, False, False, 503, ["admit"]),
        ("tools/call", False, False, False, 200, ["admit", "upstream"]),
        ("tools/call", False, True, True, 502, ["admit", "upstream", "complete"]),
        ("tools/list", False, False, False, 200, ["upstream", "complete"]),
        ("tools/list", False, False, True, 200, ["upstream", "complete"]),
        ("tools/list", False, True, True, 502, ["upstream", "complete"]),
    ],
)
def test_forward_stages_preserve_effect_and_audit_order(method, admission_fails, upstream_fails, completion_fails, status, order, caplog):
    calls = []
    events = []
    forwarded = []

    class Audit:
        async def admit_before_tool_execution(self, event):
            calls.append("admit")
            events.append(event)
            if admission_fails:
                raise GatewayAuditDeliveryUnavailableError("private-admission-details")

        async def __call__(self, event):
            calls.append("complete")
            events.append(event)
            if completion_fails:
                raise RuntimeError("private-completion-details")

    async def upstream(target, message, headers):
        calls.append("upstream")
        forwarded.append((message, headers))
        if upstream_fails:
            raise asyncio.TimeoutError()
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"done": True}}

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="fixture", url="http://fixture.local:8123")]),
        policy={},
        audit_sink=Audit(),
        upstream_caller=upstream,
    )
    message = {"jsonrpc": "2.0", "id": "call-one", "method": method, "params": {"name": "read_file", "arguments": {}}}
    with TestClient(create_gateway_app(settings)) as client:
        response = client.post("/mcp/fixture", json=message)
    assert response.status_code == status
    assert calls == order
    assert "private-admission-details" not in response.text + caplog.text
    assert "private-completion-details" not in response.text + caplog.text
    if completion_fails:
        assert response.headers["x-agent-bom-audit-delivery"] == "degraded"
    if admission_fails:
        assert not forwarded
    elif status == 200:
        assert response.json()["result"] == {"done": True}
        assert response.headers["traceparent"] == forwarded[0][1]["traceparent"]
    if method == "tools/call":
        assert events[0]["action"] == "gateway.tool_call"
        assert events[0]["tenant_id"] == "default"
