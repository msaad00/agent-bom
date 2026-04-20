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

import time
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


def test_metrics_endpoint_returns_prometheus_text_format() -> None:
    """Guard: /metrics must be plain Prometheus exposition, not a JSON-quoted string.

    Prometheus scrapers fail on a JSON-wrapped body ("# HELP..." — quoted
    string with escaped \\n). Must be raw text starting with `# HELP`.
    """
    settings = GatewaySettings(registry=_simple_registry(), policy={})
    client = TestClient(create_gateway_app(settings))
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    # Raw text — never a JSON-quoted string
    assert not body.startswith('"'), "body is JSON-quoted; Prometheus scrapers will reject"
    assert body.startswith("# HELP"), f"expected Prometheus exposition, got: {body[:80]!r}"
    # Contains the gateway-specific series
    assert "agent_bom_gateway_relays_total" in body


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


# ─── Visual-leak detection wire-up ─────────────────────────────────────────


class _StubVisualDetector:
    """Stand-in for VisualLeakDetector that avoids pulling OCR deps in CI.

    The real detector is exercised in tests/test_visual_leak_detector.py;
    here we only need to prove the gateway calls ``check`` + ``redact`` on
    the response content when the feature flag is on.
    """

    def __init__(self, alert: object | None) -> None:
        self._alert = alert
        self.check_calls: list[tuple[str, list]] = []
        self.redact_calls: list[list] = []
        self.enabled = True

    def check(self, tool_name, content_blocks):
        self.check_calls.append((tool_name, content_blocks))
        return [self._alert] if self._alert is not None else []

    def redact(self, content_blocks):
        self.redact_calls.append(content_blocks)
        return [{"type": "image", "data": "REDACTED", "mimeType": "image/png"}]


def test_visual_leak_detection_off_by_default_no_scan() -> None:
    """Feature flag is opt-in — default deploys must not invoke the detector."""
    import agent_bom.gateway_server as gw

    detector = _StubVisualDetector(alert=None)
    # If the gateway calls _get_visual_leak_detector when the flag is off,
    # the stub gets populated — assert that does not happen.
    gw._visual_detector_singleton = detector

    async def fake_caller(upstream, message, extra_headers):
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"content": [{"type": "image", "data": "AAA", "mimeType": "image/png"}]},
        }

    try:
        settings = GatewaySettings(registry=_simple_registry(), policy={}, upstream_caller=fake_caller)
        client = TestClient(create_gateway_app(settings))
        resp = client.post(
            "/mcp/filesystem",
            json=_json_rpc("tools/call", name="take_screenshot", arguments={}),
        )
        assert resp.status_code == 200
        assert detector.check_calls == []
        assert detector.redact_calls == []
    finally:
        gw._visual_detector_singleton = None


def test_visual_leak_detection_scans_and_redacts_image_content() -> None:
    """With the flag on and alerts found, the response must be redacted + audited."""
    import agent_bom.gateway_server as gw
    from agent_bom.runtime.detectors import Alert, AlertSeverity

    alert = Alert(
        detector="visual_credential_leak",
        severity=AlertSeverity.CRITICAL,
        message="visual AWS key",
        details={"leak_type": "AWS Access Key", "bbox": [0, 0, 10, 10]},
    )
    detector = _StubVisualDetector(alert=alert)
    gw._visual_detector_singleton = detector

    audit_events: list[dict] = []

    async def audit_sink(event):
        audit_events.append(event)

    async def fake_caller(upstream, message, extra_headers):
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [{"type": "image", "data": "ORIGINAL", "mimeType": "image/png"}],
            },
        }

    try:
        settings = GatewaySettings(
            registry=_simple_registry(),
            policy={},
            upstream_caller=fake_caller,
            audit_sink=audit_sink,
            enable_visual_leak_detection=True,
        )
        client = TestClient(create_gateway_app(settings))
        resp = client.post(
            "/mcp/filesystem",
            json=_json_rpc("tools/call", name="take_screenshot", arguments={}),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["result"]["content"][0]["data"] == "REDACTED"
        assert detector.check_calls and detector.check_calls[0][0] == "take_screenshot"
        assert detector.redact_calls, "redact must fire when alerts are present"

        leak_events = [e for e in audit_events if e["action"] == "gateway.visual_leak_blocked"]
        assert leak_events, "audit sink must receive a gateway.visual_leak_blocked event"
        assert leak_events[0]["tool"] == "take_screenshot"
        assert leak_events[0]["alert_count"] == 1
    finally:
        gw._visual_detector_singleton = None


def test_visual_leak_detection_clean_response_passes_through() -> None:
    """Clean scans must not redact the response or emit a leak audit event."""
    import agent_bom.gateway_server as gw

    detector = _StubVisualDetector(alert=None)
    gw._visual_detector_singleton = detector

    audit_events: list[dict] = []

    async def audit_sink(event):
        audit_events.append(event)

    async def fake_caller(upstream, message, extra_headers):
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"content": [{"type": "image", "data": "CLEAN", "mimeType": "image/png"}]},
        }

    try:
        settings = GatewaySettings(
            registry=_simple_registry(),
            policy={},
            upstream_caller=fake_caller,
            audit_sink=audit_sink,
            enable_visual_leak_detection=True,
        )
        client = TestClient(create_gateway_app(settings))
        resp = client.post(
            "/mcp/filesystem",
            json=_json_rpc("tools/call", name="take_screenshot", arguments={}),
        )
        assert resp.status_code == 200
        body = resp.json()
        # Clean content passes through unchanged (no redact call)
        assert body["result"]["content"][0]["data"] == "CLEAN"
        assert detector.check_calls, "check must fire when the flag is on"
        assert detector.redact_calls == [], "redact must not fire without alerts"
        assert not any(e["action"] == "gateway.visual_leak_blocked" for e in audit_events)
    finally:
        gw._visual_detector_singleton = None


def test_visual_leak_detection_timeout_fails_open_without_blocking_response(monkeypatch) -> None:
    import agent_bom.gateway_server as gw

    class _SlowDetector:
        enabled = True

        def check(self, tool_name, content_blocks):
            time.sleep(0.05)
            return []

        def redact(self, content_blocks):
            return content_blocks

    detector = _SlowDetector()
    gw._visual_detector_singleton = detector
    monkeypatch.setenv("AGENT_BOM_VISUAL_LEAK_TIMEOUT_SECONDS", "0.001")

    async def fake_caller(upstream, message, extra_headers):
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {"content": [{"type": "image", "data": "CLEAN", "mimeType": "image/png"}]},
        }

    try:
        settings = GatewaySettings(
            registry=_simple_registry(),
            policy={},
            upstream_caller=fake_caller,
            enable_visual_leak_detection=True,
        )
        client = TestClient(create_gateway_app(settings))
        resp = client.post(
            "/mcp/filesystem",
            json=_json_rpc("tools/call", name="take_screenshot", arguments={}),
        )
        assert resp.status_code == 200
        assert resp.json()["result"]["content"][0]["data"] == "CLEAN"
    finally:
        gw._visual_detector_singleton = None
