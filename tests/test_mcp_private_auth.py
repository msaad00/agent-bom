"""Private MCP reads require operator-provisioned credentials."""

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

from agent_bom.mcp_server import create_mcp_server


@pytest.fixture(autouse=True)
def _bounded_read_credential(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())


def _event(response):
    for line in response.text.splitlines():
        if line.startswith("data: "):
            import json

            return json.loads(line[6:])
    raise AssertionError("Missing MCP response event")


def _read(client, token=None):
    headers = {"Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
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
                "clientInfo": {"name": "auth-contract", "version": "1"},
            },
        },
    )
    if response.status_code != 200:
        return response.status_code, None, None
    headers.update({"mcp-session-id": response.headers["mcp-session-id"], "mcp-protocol-version": "2025-11-25"})
    client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    with patch(
        "agent_bom.api.routes.enterprise.list_audit_entries", new=AsyncMock(return_value={"entries": [{"marker": "private-sentinel"}]})
    ) as reader:
        result = client.post(
            "/mcp",
            headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "audit_query", "arguments": {}}},
        )
        return result.status_code, reader.called, headers


@pytest.mark.parametrize("grant", ["authorization_code", "client_credentials"])
def test_unapproved_oauth_client_cannot_reach_private_reads(monkeypatch, tmp_path, grant):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_PUBLIC_URL", "http://localhost:8000")
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="private-read-token", profile="full")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        assert _read(client)[0] == 401
        registration = client.post("/oauth/register", json={"redirect_uris": ["https://client.example/cb"], "grant_types": [grant]})
        if registration.status_code >= 400:
            return
        registered = registration.json()
        form = {"grant_type": grant, "client_id": registered["client_id"]}
        if grant == "authorization_code":
            verifier = secrets.token_urlsafe(32)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            authorization = client.get(
                "/oauth/authorize",
                params={
                    "response_type": "code",
                    "client_id": registered["client_id"],
                    "redirect_uri": "https://client.example/cb",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
                follow_redirects=False,
            )
            if authorization.status_code >= 400:
                return
            form.update(
                {
                    "code": parse_qs(urlparse(authorization.headers["location"]).query)["code"][0],
                    "code_verifier": verifier,
                    "redirect_uri": "https://client.example/cb",
                }
            )
        else:
            form["client_secret"] = registered["client_secret"]
        issued = client.post("/oauth/token", data=form)
        if issued.status_code >= 400:
            return
        status, reader_called, _ = _read(client, issued.json()["access_token"])
        assert status == 401 and not reader_called, "Unapproved OAuth client reached private audit data"


def test_configured_read_token_reads_but_cannot_write(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="private-read-token", profile="full")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        status, reader_called, headers = _read(client, "private-read-token")
        assert status == 200 and reader_called
        response = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "identity_revoke",
                    "arguments": {
                        "identity_id": "test-identity",
                        "operator_role": "admin",
                        "operator_scopes": "identity:write",
                        "reason": "contract verification",
                    },
                },
            },
        )
        assert "requires an authenticated operator token" in response.text


@pytest.mark.parametrize("credential", ["wrong-token", "expired-read", "replaced-read"])
def test_invalid_configured_read_credentials_fail_before_private_read(monkeypatch, tmp_path, credential):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    server = create_mcp_server(
        host="127.0.0.1", port=8000, bearer_token="expired-read" if credential == "expired-read" else "current-read", profile="full"
    )
    if credential == "expired-read":
        from agent_bom import mcp_server

        clock = Mock(wraps=datetime)
        clock.now.return_value = datetime.now(timezone.utc) + timedelta(hours=1)
        monkeypatch.setattr(mcp_server, "datetime", clock)
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        assert _read(client, credential)[0] == 401


def test_existing_http_session_loses_access_at_token_deadline(monkeypatch, tmp_path):
    from agent_bom import mcp_server

    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="private-read-token", profile="full")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        status, called, headers = _read(client, "private-read-token")
        assert status == 200 and called
        clock = Mock(wraps=datetime)
        clock.now.return_value = datetime.now(timezone.utc) + timedelta(hours=1)
        monkeypatch.setattr(mcp_server, "datetime", clock)
        with patch("agent_bom.api.routes.enterprise.list_audit_entries", new=AsyncMock()) as reader:
            response = client.post(
                "/mcp",
                headers=headers,
                json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "audit_query", "arguments": {}}},
            )
            assert response.status_code == 401
            reader.assert_not_called()


def test_sse_rejects_expired_credential_before_opening_stream(monkeypatch, tmp_path):
    from agent_bom import mcp_server

    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="private-read-token")
    clock = Mock(wraps=datetime)
    clock.now.return_value = datetime.now(timezone.utc) + timedelta(hours=1)
    monkeypatch.setattr(mcp_server, "datetime", clock)
    with TestClient(server.sse_app(), base_url="http://localhost:8000") as client:
        response = client.get("/sse", headers={"Authorization": "Bearer private-read-token"})
        assert response.status_code == 401
