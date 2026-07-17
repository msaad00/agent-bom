"""API + MCP surface tests for the ticketing connector (#4004).

Proves the REST plane enforces auth/RBAC, seals the secret (never returned),
files a ticket through the stored connection with no per-action credential, and
that the MCP tools are registered with no credential/link parameter.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.fernet import Fernet
from starlette.testclient import TestClient

from agent_bom.api import connection_crypto
from agent_bom.ticketing.connection_store import InMemoryTicketingStore, set_ticketing_store
from agent_bom.ticketing.models import PROVIDER_JIRA, TicketRef, TicketStatus

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"
_TEST_KEY = Fernet.generate_key().decode("ascii")


def _headers(role: str = "admin", tenant: str = "tenant-alpha") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


@pytest.fixture(autouse=True)
def _env(monkeypatch) -> Iterator[None]:
    # Keep the route tests hermetic: the endpoint SSRF check does live DNS, which
    # would reject an unresolvable test host. SSRF logic is covered elsewhere.
    monkeypatch.setattr("agent_bom.api.routes.ticketing.validate_url", lambda *a, **k: None)
    prior = {
        k: os.environ.get(k)
        for k in (
            "AGENT_BOM_TRUST_PROXY_AUTH",
            "AGENT_BOM_TRUST_PROXY_AUTH_SECRET",
            connection_crypto.CONNECTIONS_KEY_ENV,
            f"{connection_crypto.CONNECTIONS_KEY_ENV}_FILE",
            connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV,
        )
    }
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET
    os.environ[connection_crypto.CONNECTIONS_KEY_ENV] = _TEST_KEY
    os.environ.pop(f"{connection_crypto.CONNECTIONS_KEY_ENV}_FILE", None)
    os.environ.pop(connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV, None)
    connection_crypto.reset_key_cache()
    set_ticketing_store(InMemoryTicketingStore())
    try:
        yield
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        connection_crypto.reset_key_cache()
        set_ticketing_store(None)


def _app() -> Any:
    from agent_bom.api.server import app

    return app


def _mcp_conn_body() -> dict[str, Any]:
    return {
        "provider": "jira",
        "transport": "mcp",
        "auth_method": "mcp",
        "display_name": "Jira MCP",
        "endpoint": "https://itsm.example.com/mcp",
        "secret": "server-bearer-token",
        "auth_params": {"create_tool": "create_issue", "status_tool": "get_issue", "default_project": "SEC"},
    }


FINDING = {"vulnerability_id": "CVE-2024-1", "package": "acme", "severity": "high", "risk_score": 7.0}


def test_api_requires_authentication() -> None:
    client = TestClient(_app())
    assert client.get("/v1/ticketing/connections").status_code == 401
    assert client.post("/v1/ticketing/connections", json=_mcp_conn_body()).status_code == 401


def test_api_rejects_underprivileged_role() -> None:
    client = TestClient(_app())
    resp = client.post("/v1/ticketing/connections", json=_mcp_conn_body(), headers=_headers(role="viewer"))
    assert resp.status_code == 403


def test_create_connection_seals_secret_and_never_returns_it() -> None:
    client = TestClient(_app())
    resp = client.post("/v1/ticketing/connections", json=_mcp_conn_body(), headers=_headers())
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "secret" not in body and "secret_encrypted" not in body
    assert body["has_secret"] is True
    assert "server-bearer-token" not in resp.text


def test_create_connection_rejects_unknown_body_field() -> None:
    client = TestClient(_app())
    bad = _mcp_conn_body()
    bad["api_token"] = "should-not-be-here"  # per-action/extra credential field forbidden
    resp = client.post("/v1/ticketing/connections", json=bad, headers=_headers())
    assert resp.status_code == 422


def test_create_ticket_body_forbids_credential_fields() -> None:
    client = TestClient(_app())
    resp = client.post(
        "/v1/ticketing/tickets",
        json={"connection_id": "x", "finding": FINDING, "token": "nope"},
        headers=_headers(),
    )
    assert resp.status_code == 422  # extra="forbid" rejects a credential field


def test_create_ticket_without_connection_says_connect_first() -> None:
    client = TestClient(_app())
    resp = client.post("/v1/ticketing/tickets", json={"finding": FINDING}, headers=_headers())
    assert resp.status_code == 409
    assert "Connect" in resp.json()["detail"]


def test_create_ticket_through_stored_connection(monkeypatch) -> None:
    client = TestClient(_app())
    created = client.post("/v1/ticketing/connections", json=_mcp_conn_body(), headers=_headers())
    connection_id = created.json()["id"]

    class _FakeTransport:
        async def create_ticket(self, draft):
            assert draft.project == "SEC"
            return TicketRef(
                provider=PROVIDER_JIRA, external_id="100", key="SEC-100", url="https://itsm/browse/SEC-100", status=TicketStatus.OPEN
            )

        async def get_status(self, ref):
            return TicketStatus.DONE

    monkeypatch.setattr("agent_bom.ticketing.service.build_transport", lambda *a, **k: _FakeTransport())

    resp = client.post(
        "/v1/ticketing/tickets",
        json={"connection_id": connection_id, "finding": FINDING},
        headers=_headers(),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["ticket"]["key"] == "SEC-100"
    assert body["deduplicated"] is False
    assert body["audit_metadata"]["per_action_credential"] is False

    ticket_id = body["ticket"]["id"]
    synced = client.post(f"/v1/ticketing/tickets/{ticket_id}/sync", headers=_headers())
    assert synced.status_code == 200
    assert synced.json()["ticket"]["status"] == "done"


def test_tickets_and_connections_are_tenant_scoped(monkeypatch) -> None:
    client = TestClient(_app())
    client.post("/v1/ticketing/connections", json=_mcp_conn_body(), headers=_headers(tenant="tenant-alpha"))
    # A different tenant sees none of tenant-alpha's connections.
    other = client.get("/v1/ticketing/connections", headers=_headers(tenant="tenant-beta"))
    assert other.status_code == 200
    assert other.json()["count"] == 0


def test_mcp_tools_registered_without_credential_params() -> None:
    import asyncio

    from agent_bom.mcp_server import create_mcp_server
    from agent_bom.mcp_server_metadata import server_card_tool_names

    names = server_card_tool_names()
    assert "create_ticket" in names and "sync_ticket_status" in names

    mcp = create_mcp_server()
    tools = {t.name: t for t in asyncio.run(mcp.list_tools())}
    assert "create_ticket" in tools and "sync_ticket_status" in tools
    props = set(tools["create_ticket"].inputSchema.get("properties", {}))
    forbidden = {
        "token",
        "api_token",
        "password",
        "secret",
        "credential",
        "auth",
        "email",
        "base_url",
        "jira_url",
        "endpoint",
        "site_url",
        "url",
    }
    assert not (props & forbidden), f"MCP create_ticket leaked credential/link params: {props & forbidden}"
