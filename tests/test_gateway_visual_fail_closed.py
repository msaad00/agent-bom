"""A completed tool call cannot release images when visual enforcement fails."""

from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry


@pytest.mark.parametrize("stage", ["check", "redact"])
@pytest.mark.parametrize("failure", [TimeoutError, RuntimeError])
@pytest.mark.parametrize("audit_fails", [False, True])
def test_visual_failure_withholds_completed_result_without_retry_or_false_redaction(monkeypatch, stage, failure, audit_fails):
    import agent_bom.gateway_server as gateway
    from agent_bom.runtime import visual_leak_detector as visual

    events = []
    upstream_calls = []
    detector = SimpleNamespace(enabled=True)
    monkeypatch.setattr(gateway, "_get_visual_leak_detector", lambda: detector)

    async def check(*args):
        if stage == "check":
            raise failure("private-OCR-token-path")
        return [SimpleNamespace(details={"leak_type": "fixture"})]

    async def redact(*args):
        raise failure("private-OCR-token-path")

    monkeypatch.setattr(visual, "run_visual_leak_check", check)
    monkeypatch.setattr(visual, "run_visual_leak_redact", redact)

    class Audit:
        async def admit_before_tool_execution(self, event):
            events.append(event)

        async def __call__(self, event):
            if audit_fails:
                raise RuntimeError("private-audit-path")
            events.append(event)

    async def upstream(config, message, headers):
        upstream_calls.append(message)
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"content": [{"type": "image", "data": "sensitive-pixels", "mimeType": "image/png"}]},
        }

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="fixture", url="https://fixture.invalid/mcp")]),
        policy={},
        upstream_caller=upstream,
        audit_sink=Audit(),
        enable_visual_leak_detection=True,
    )
    with TestClient(create_gateway_app(settings), raise_server_exceptions=False) as client:
        response = client.post(
            "/mcp/fixture",
            json={"jsonrpc": "2.0", "id": "completed-call", "method": "tools/call", "params": {"name": "screenshot", "arguments": {}}},
        )
    assert response.status_code == 200
    assert len(upstream_calls) == 1
    assert "sensitive-pixels" not in response.text
    assert "private-" not in response.text
    data = response.json()["error"]["data"]
    assert data["execution_status"] == "upstream_completed"
    assert data["retryable"] is False
    assert data["scan_status"] == "incomplete"
    assert not any(event.get("event_type") == "gateway.visual.redacted" for event in events)
    if audit_fails:
        assert response.headers["x-agent-bom-audit-delivery"] == "degraded"
    else:
        assert events[-1]["event_type"] == "gateway.dlp.result_blocked"
        assert events[-1]["decision"] == "deny"
        assert events[-1]["policy_source"] == "visual_dlp"
