"""Real gateway decisions through authenticated ingest, disk receipts and SSE replay.

Only the upstream and OCR detector are fixtures; policy, profile resolution,
DLP text scanning, delivery, ingest, persistence and stream routing execute.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from starlette.testclient import TestClient

from agent_bom import agent_identity, gateway_server
from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, issue_identity, set_agent_identity_store, verify_token
from agent_bom.api.browser_session import SESSION_COOKIE_NAME, create_browser_session_token
from agent_bom.api.gateway_activity_store import SQLiteGatewayActivityStore, set_gateway_activity_store
from agent_bom.api.mcp_config_store import InMemoryMcpConfigStore, McpClientConfigAssignment, set_mcp_config_store
from agent_bom.api.routes import gateway_feed, proxy
from agent_bom.api.server import app, configure_api
from agent_bom.gateway_server import GatewaySettings, build_control_plane_audit_sink, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.runtime.detectors import Alert, AlertSeverity


def _frames(response):
    assert response.status_code == 200, response.text
    frames = []
    for raw in response.text.replace("\r\n", "\n").split("\n\n"):
        fields = dict(line.split(": ", 1) for line in raw.splitlines() if ": " in line and not line.startswith(":"))
        if "data" in fields:
            fields["data"] = json.loads(fields["data"])
            frames.append(fields)
    return frames


@pytest.fixture(autouse=True)
def _reset_managed_profile_state():
    yield
    set_mcp_config_store(None)
    agent_identity.set_local_identity_verifier(None)


@pytest.mark.parametrize("outcome", ["allow", "profile_block", "policy_block", "pii", "secret", "visual"])
def test_gateway_call_survives_ingest_restart_and_authenticated_reconnect(tmp_path, monkeypatch, outcome):
    secret = "runtime-acceptance-proxy-secret-32-bytes"
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", secret)
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "runtime-acceptance-browser-signing-key")
    monkeypatch.setattr(gateway_feed, "_STREAM_MAX_SECONDS", 0.04)
    monkeypatch.setattr(gateway_feed, "_STREAM_POLL_SECONDS", 0.001)
    configure_api(api_key=None)
    database = str(tmp_path / "activity.db")
    ledger = SQLiteGatewayActivityStore(database)
    set_gateway_activity_store(ledger)
    identities = InMemoryAgentIdentityStore()
    identity, identity_token = issue_identity(
        identities, agent_id="finance-agent", tenant_id="default", blueprint_id="finance", allowed_tools=["read_file"]
    )
    set_agent_identity_store(identities)
    agent_identity.set_local_identity_verifier(lambda raw: verify_token(identities, raw))
    profiles = InMemoryMcpConfigStore()
    profiles.put(
        McpClientConfigAssignment(
            config_id="finance-prod",
            name="Finance",
            tenant_id="default",
            profile_id="finance",
            identity_id=identity.identity_id,
            connector_ids=["filesystem"],
            allowed_tools=["read_file"],
            environment="prod",
            issuer="agent-bom",
            revision=3,
            policy_ids=["finance-policy@7"],
            revoked=outcome == "profile_block",
        )
    )
    set_mcp_config_store(profiles)
    delivered = []
    forwarded = []

    async def sender(payload, _headers):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://control") as client:
            response = await client.post(
                "/v1/proxy/audit",
                json=payload,
                headers={"X-Agent-Bom-Proxy-Secret": secret, "X-Agent-Bom-Role": "admin", "X-Agent-Bom-Tenant-ID": "default"},
            )
        assert response.status_code == 200, response.text
        delivered.extend(payload["alerts"])
        return response.json()

    async def upstream(_upstream, message, _headers):
        forwarded.append(message)
        result = {"content": "safe result"}
        if outcome == "pii":
            result = {"content": "owner@example.com"}
        elif outcome == "secret":
            result = {"content": "password=SuperSecretValue12345"}
        elif outcome == "visual":
            result = {"content": [{"type": "image", "data": "PRIVATE_IMAGE_BYTES", "mimeType": "image/png"}]}
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}

    class VisualFixture:
        enabled = True

        def check(self, *_args):
            return [
                Alert(
                    detector="visual_credential_leak",
                    severity=AlertSeverity.CRITICAL,
                    message="Synthetic image credential",
                    details={"leak_type": "credential"},
                )
            ]

        def redact(self, _blocks):
            return [{"type": "image", "data": "REDACTED", "mimeType": "image/png"}]

    monkeypatch.setattr(gateway_server, "_visual_detector_singleton", VisualFixture())
    sink = build_control_plane_audit_sink("http://control", "acceptance-token", tenant_id="default", sender=sender)
    policy = {"rules": [{"id": "block-read", "action": "block", "tool_name": "read_file"}]} if outcome == "policy_block" else {}
    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fixture.invalid")]),
        policy=policy,
        upstream_caller=upstream,
        audit_sink=sink,
        listener_host="0.0.0.0",
        bearer_token="transport-token",
        bearer_token_expires_at=(datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        runtime_profile_enforcement_mode="enforce",
        runtime_profile_environment="prod",
        dlp_enabled=True,
        dlp_mode="enforce",
        dlp_scanners=["pii", "secrets"],
        enable_visual_leak_detection=outcome == "visual",
        require_visual_leak_detection_ready=False,
    )
    reader = TestClient(app)
    cookie, _ = create_browser_session_token(
        subject="operator", role="viewer", tenant_id="default", auth_method="browser_session", max_age_seconds=120
    )
    reader.cookies.set(SESSION_COOKIE_NAME, cookie)
    checkpoint = next(frame["id"] for frame in _frames(reader.get("/v1/gateway/feed/stream")) if frame["event"] == "checkpoint")
    with TestClient(create_gateway_app(settings)) as gateway:
        response = gateway.post(
            "/mcp/filesystem",
            headers={"Authorization": "Bearer transport-token"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    "arguments": {"email": "requester@example.com"} if outcome == "pii" else {},
                    "_meta": {"agent_identity": identity_token},
                },
            },
        )
    assert response.status_code == 200
    assert bool(forwarded) == (outcome not in {"profile_block", "policy_block"})
    expected = {
        "allow": "gateway.tool_call.allowed",
        "profile_block": "gateway.tool_call.blocked",
        "policy_block": "gateway.tool_call.blocked",
        "pii": "gateway.dlp.result_redacted",
        "secret": "gateway.dlp.result_blocked",
        "visual": "gateway.visual.redacted",
    }[outcome]
    assert expected in {event.get("event_type") for event in delivered}
    assert identity_token not in repr(forwarded)
    for sensitive in ["requester@example.com", "owner@example.com", "SuperSecretValue12345", "PRIVATE_IMAGE_BYTES"]:
        assert sensitive not in response.text
        assert sensitive not in repr(forwarded)

    # Discard process state and reopen disk before reading through the API.
    proxy._reset_proxy_runtime_for_tests()
    set_gateway_activity_store(SQLiteGatewayActivityStore(database))
    resumed = _frames(reader.get("/v1/gateway/feed/stream", headers={"Last-Event-ID": checkpoint}))
    batches = [frame for frame in resumed if frame["event"] == "activity"]
    events = [event for batch in batches for event in batch["data"]["events"]]
    assert [event["event_id"] for event in events] == [event["event_id"] for event in delivered if event.get("event_type")]
    assert [event["ingest_ordinal"] for event in events] == list(range(1, len(events) + 1))
    assert all(event["agent_id"] == "finance-agent" and event["tenant_id"] == "default" for event in events)
    if outcome == "profile_block":
        assert all(event["reason_code"] == "profile_revoked" and not event["profile_id"] for event in events)
    else:
        assert all(event["profile_id"] == "finance-prod" and event["profile_revision"] == 3 for event in events)
        assert all(event["blueprint_id"] == "finance" for event in events)
    assert all(event["trace_id"] for event in events)
    serialized = json.dumps(events)
    for sensitive in [
        identity_token,
        "transport-token",
        "requester@example.com",
        "owner@example.com",
        "SuperSecretValue12345",
        "PRIVATE_IMAGE_BYTES",
    ]:
        assert sensitive not in serialized
    again = _frames(reader.get("/v1/gateway/feed/stream", headers={"Last-Event-ID": batches[-1]["id"]}))
    assert not [frame for frame in again if frame["event"] == "activity"]
    foreign, _ = create_browser_session_token(
        subject="other", role="viewer", tenant_id="tenant-b", auth_method="browser_session", max_age_seconds=120
    )
    reader.cookies.set(SESSION_COOKIE_NAME, foreign)
    assert reader.get("/v1/gateway/feed/stream", headers={"Last-Event-ID": batches[-1]["id"]}).status_code == 400
    reader.cookies.clear()
    assert reader.get("/v1/gateway/feed/stream").status_code == 401
