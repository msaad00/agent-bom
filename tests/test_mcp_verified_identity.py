"""Verified MCP HTTP identity reaches authorization, rate limiting and audit."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from starlette.requests import Request
from starlette.testclient import TestClient

from agent_bom.mcp_server import create_mcp_server
from agent_bom.mcp_server_runtime import current_tool_request
from agent_bom.mcp_tools.result_store import scan_result_owner


def _context(token: AccessToken | None, *, claimed_client: str = "claimed-client"):
    scope = {"type": "http"}
    if token is not None:
        scope["user"] = AuthenticatedUser(token)
    return SimpleNamespace(request=Request(scope), meta=SimpleNamespace(client_id=claimed_client), session=object(), request_id="r1")


def test_request_metadata_uses_verified_http_token():
    token = AccessToken(token="fixture-secret", client_id="verified-client", scopes=["admin", "connectors:write"])
    meta = current_tool_request(lambda: _context(token))
    assert meta["caller"] == "token-client:verified-client"
    assert set(meta["auth_scopes"].split(",")) == {"admin", "connectors:write"}
    assert "fixture-secret" not in json.dumps(meta)


def test_unverified_context_attributes_cannot_supply_grants():
    context = _context(None)
    context.access_token = SimpleNamespace(client_id="forged", scopes=["admin", "*"])
    context.experimental = SimpleNamespace(auth=context.access_token)
    meta = current_tool_request(lambda: context)
    assert meta["auth_scopes"] == ""
    assert meta["caller"] != "token-client:forged"


@pytest.mark.parametrize("http_token", [None, "current-token"])
def test_http_identity_never_inherits_ambient_session_token(monkeypatch, http_token):
    ambient = AccessToken(token="old-token", client_id="old-client", scopes=["admin", "*"])
    monkeypatch.setattr("mcp.server.auth.middleware.auth_context.get_access_token", lambda: ambient)
    token = AccessToken(token=http_token, client_id="current-client", scopes=["read"]) if http_token else None
    context = _context(token)
    meta = current_tool_request(lambda: context)
    assert meta["auth_scopes"] == ("read" if token else "")
    if token:
        assert scan_result_owner(lambda: context) == "token:" + hashlib.sha256(http_token.encode()).hexdigest()
    else:
        with pytest.raises(ValueError, match="authenticated"):
            scan_result_owner(lambda: context)


def test_expired_http_identity_cannot_authorize_or_read_saved_results():
    token = AccessToken(token="expired-token", client_id="expired-client", scopes=["admin", "*"], expires_at=1)
    context = _context(token)
    assert current_tool_request(lambda: context)["auth_scopes"] == ""
    with pytest.raises(ValueError, match="authenticated"):
        scan_result_owner(lambda: context)


def test_transport_without_http_request_uses_sdk_authenticated_context(monkeypatch):
    token = AccessToken(token="transport-token", client_id="transport-client", scopes=["read"])
    monkeypatch.setattr("mcp.server.auth.middleware.auth_context.get_access_token", lambda: token)
    context = SimpleNamespace(request=None)
    assert current_tool_request(lambda: context)["caller"] == "token-client:transport-client"
    assert scan_result_owner(lambda: context) == "token:" + hashlib.sha256(token.token.encode()).hexdigest()


def test_sdk_auth_context_is_reset_between_calls():
    from mcp.server.auth.middleware.auth_context import auth_context_var

    context = SimpleNamespace(request=None)
    token = AccessToken(token="context-token", client_id="context-client", scopes=["admin"])
    reset = auth_context_var.set(AuthenticatedUser(token))
    try:
        assert current_tool_request(lambda: context)["auth_scopes"] == "admin"
    finally:
        auth_context_var.reset(reset)
    assert current_tool_request(lambda: context)["auth_scopes"] == ""
    assert scan_result_owner(lambda: context) == "local"


@pytest.mark.asyncio
@pytest.mark.parametrize("sync", [False, True])
async def test_dispatch_propagates_verified_actor_and_role(sync):
    from agent_bom import mcp_server

    token = AccessToken(token="fixture-token", client_id="verified-operator", scopes=["admin", "connectors:write"])
    context_token = mcp_server._mcp_request_ctx.set(_context(token))

    def handle(**kwargs):
        return kwargs

    async def handle_async(**kwargs):
        return kwargs

    try:
        dispatch = mcp_server._execute_tool_sync_async if sync else mcp_server._execute_tool_async
        result = await dispatch(
            "endpoint_sync",
            handle if sync else handle_async,
            destructive=True,
            required_scope="connectors:write",
            operator_role="viewer",
            _authenticated_actor="forged-internal-actor",
        )
    finally:
        mcp_server._mcp_request_ctx.reset(context_token)
    assert result["_authenticated_actor"] == "token-client:verified-operator"
    assert result["operator_role"] == "admin"


def _initialize(client: TestClient, token: str) -> dict[str, str]:
    headers = {"Accept": "application/json, text/event-stream", "Authorization": f"Bearer {token}"}
    response = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "identity-contract", "version": "1"},
            },
        },
    )
    assert response.status_code == 200
    headers.update({"mcp-session-id": response.headers["mcp-session-id"], "mcp-protocol-version": "2025-11-25"})
    response = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert response.status_code == 202
    return headers


@pytest.mark.parametrize("credential,allowed", [("operator-token", True), ("read-token", False)])
def test_real_http_write_uses_verified_grants_and_actor(monkeypatch, tmp_path, credential, allowed):
    expiry = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", expiry)
    monkeypatch.setenv("AGENT_BOM_MCP_OPERATOR_TOKEN", "operator-token")
    monkeypatch.setenv("AGENT_BOM_MCP_OPERATOR_TOKEN_EXPIRES_AT", expiry)
    handler = AsyncMock(return_value=json.dumps({"status": "completed"}))
    scan_handler = AsyncMock(return_value=json.dumps({"status": "completed"}))
    monkeypatch.setattr("agent_bom.mcp_tools.endpoint_connectors.endpoint_sync_impl", handler)
    monkeypatch.setattr("agent_bom.mcp_tools.scanning.scan_impl", scan_handler)
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="read-token", profile="full")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        headers = _initialize(client, credential)
        response = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "endpoint_sync",
                    "arguments": {
                        "connection_id": "fixture",
                        "operator_role": "admin",
                        "operator_scopes": "connectors:write",
                    },
                    "_meta": {"client_id": "forged-audit-actor"},
                },
            },
        )
        assert response.status_code == 200
        scan_response = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "scan",
                    "arguments": {"result_id": "fixture-result"},
                },
            },
        )
        assert scan_response.status_code == 200
    scan_handler.assert_awaited_once()
    assert scan_handler.call_args.kwargs["_result_owner"] == "token:" + hashlib.sha256(credential.encode()).hexdigest()
    if allowed:
        handler.assert_awaited_once()
        assert handler.call_args.kwargs["_authenticated_actor"] == "token-client:agent-bom-operator-token"
    else:
        handler.assert_not_called()
        assert "requires an authenticated operator token" in response.text


def test_http_session_rotation_changes_saved_result_owner(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
    handler = AsyncMock(return_value=json.dumps({"status": "completed"}))
    monkeypatch.setattr("agent_bom.mcp_tools.scanning.scan_impl", handler)
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="first-token", profile="full")

    async def verify(token):
        if token in {"first-token", "second-token"}:
            return AccessToken(token=token, client_id="same-approved-client", scopes=["read"])
        return None

    monkeypatch.setattr(server._token_verifier, "verify_token", verify)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        headers = _initialize(client, "first-token")
        for credential in ("first-token", "second-token"):
            headers["Authorization"] = f"Bearer {credential}"
            response = client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": credential,
                    "method": "tools/call",
                    "params": {"name": "scan", "arguments": {"result_id": "fixture-result"}},
                },
            )
            assert response.status_code == 200
            assert handler.call_args.kwargs["_result_owner"] == "token:" + hashlib.sha256(credential.encode()).hexdigest()
    assert handler.await_count == 2
