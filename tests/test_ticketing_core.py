"""Ticketing connector core tests (#4004).

Covers the connect-once invariant (no per-action credential/link param), the
transport abstraction (MCP-client primary + Jira REST fallback), claim-first
idempotency, tenant isolation, and OAuth-first connect helpers. No live network:
HTTP is mocked via httpx.MockTransport and the MCP transport via an injected
caller (a mock/generic ITSM MCP server).
"""

from __future__ import annotations

import inspect
import json

import httpx
import pytest
from cryptography.fernet import Fernet

from agent_bom.ticketing.connection_store import (
    InMemoryTicketingStore,
    SQLiteTicketingStore,
    TicketLink,
)
from agent_bom.ticketing.jira_rest import JiraRestTransport
from agent_bom.ticketing.mcp_transport import McpTicketingTransport
from agent_bom.ticketing.models import (
    AUTH_API_TOKEN,
    AUTH_MCP,
    AUTH_OAUTH,
    PROVIDER_JIRA,
    TRANSPORT_MCP,
    TRANSPORT_REST,
    TicketDraft,
    TicketingConnectionRecord,
    TicketStatus,
)
from agent_bom.ticketing.service import TicketingError, create_ticket_for_finding, sync_ticket_status
from agent_bom.ticketing.transport import map_jira_status, map_servicenow_status


@pytest.fixture(autouse=True)
def _connections_key(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_KEY", Fernet.generate_key().decode("ascii"))
    from agent_bom.api import connection_crypto

    connection_crypto.reset_key_cache()
    yield
    connection_crypto.reset_key_cache()


def _seal(plaintext: str) -> str:
    from agent_bom.api.connection_crypto import encrypt_secret

    return encrypt_secret(plaintext) if plaintext else ""


FINDING = {
    "vulnerability_id": "CVE-2024-9999",
    "package": "acme-lib",
    "severity": "high",
    "risk_score": 8.4,
    "fixed_version": "2.1.0",
    "affected_agents": ["agent-a"],
}


def _mock_client_factory(handler):
    def factory(timeout: float = 15.0):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    return factory


# ── Draft / model ─────────────────────────────────────────────────────────────


def test_ticket_draft_from_finding_is_deterministic_and_labelled():
    draft = TicketDraft.from_finding(FINDING, project="SEC")
    assert draft.project == "SEC"
    assert "CVE-2024-9999" in draft.title and "acme-lib" in draft.title
    assert draft.finding_id == "CVE-2024-9999:acme-lib"
    assert "severity-high" in draft.labels
    assert "upgrade to 2.1.0" in draft.description


def test_public_dict_never_exposes_secret():
    record = TicketingConnectionRecord(
        id="c1",
        tenant_id="t1",
        provider=PROVIDER_JIRA,
        transport=TRANSPORT_REST,
        auth_method=AUTH_API_TOKEN,
        display_name="Jira",
        endpoint="https://x.atlassian.net",
        secret_encrypted=_seal("super-secret-token"),
    )
    public = record.to_public_dict()
    assert "secret_encrypted" not in public
    assert public["has_secret"] is True
    assert "super-secret-token" not in json.dumps(public)


# ── Status mapping ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "key,expected",
    [
        ("new", TicketStatus.OPEN),
        ("indeterminate", TicketStatus.IN_PROGRESS),
        ("done", TicketStatus.DONE),
        ("bogus", TicketStatus.UNKNOWN),
    ],
)
def test_map_jira_status(key, expected):
    assert map_jira_status(key) is expected


@pytest.mark.parametrize(
    "label,expected",
    [
        ("New", TicketStatus.OPEN),
        ("In Progress", TicketStatus.IN_PROGRESS),
        ("Resolved", TicketStatus.DONE),
        ("Closed", TicketStatus.DONE),
        ("Cancelled", TicketStatus.DONE),
    ],
)
def test_map_servicenow_status(label, expected):
    assert map_servicenow_status(label) is expected


# ── Jira REST transport (fallback) ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_jira_rest_api_token_create_and_status():
    calls = {}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["last"] = request
        if request.method == "POST":
            assert request.url.path == "/rest/api/3/issue"
            assert request.headers["Authorization"].startswith("Basic ")
            body = json.loads(request.content)
            assert body["fields"]["project"]["key"] == "SEC"
            return httpx.Response(201, json={"id": "10001", "key": "SEC-1"})
        assert request.url.path == "/rest/api/3/issue/SEC-1"
        return httpx.Response(200, json={"fields": {"status": {"statusCategory": {"key": "indeterminate", "name": "In Progress"}}}})

    record = TicketingConnectionRecord(
        id="c1",
        tenant_id="t1",
        provider=PROVIDER_JIRA,
        transport=TRANSPORT_REST,
        auth_method=AUTH_API_TOKEN,
        display_name="Jira",
        endpoint="https://acme.atlassian.net",
        secret_encrypted="",
        auth_params={"email": "sec@acme.io"},
    )
    transport = JiraRestTransport(record, "the-token", client_factory=_mock_client_factory(handler))
    draft = TicketDraft.from_finding(FINDING, project="SEC")
    ref = await transport.create_ticket(draft)
    assert ref.key == "SEC-1"
    assert ref.url == "https://acme.atlassian.net/browse/SEC-1"

    status = await transport.get_status(ref)
    assert status is TicketStatus.IN_PROGRESS


@pytest.mark.asyncio
async def test_jira_rest_oauth_uses_atlassian_gateway_and_bearer():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("Authorization", "")
        return httpx.Response(201, json={"id": "20002", "key": "OPS-2"})

    bundle = json.dumps({"access_token": "at-123", "refresh_token": "rt-123"})
    record = TicketingConnectionRecord(
        id="c2",
        tenant_id="t1",
        provider=PROVIDER_JIRA,
        transport=TRANSPORT_REST,
        auth_method=AUTH_OAUTH,
        display_name="Jira OAuth",
        endpoint="https://acme.atlassian.net",
        secret_encrypted="",
        auth_params={"cloud_id": "cid-9", "site_url": "https://acme.atlassian.net"},
    )
    transport = JiraRestTransport(record, bundle, client_factory=_mock_client_factory(handler))
    ref = await transport.create_ticket(TicketDraft.from_finding(FINDING, project="OPS"))
    assert "https://api.atlassian.com/ex/jira/cid-9/rest/api/3/issue" in seen["url"]
    assert seen["auth"] == "Bearer at-123"
    assert ref.url == "https://acme.atlassian.net/browse/OPS-2"


# ── MCP-client transport (primary) ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mcp_transport_drives_itsm_mcp_server_tools():
    invoked = []

    async def fake_caller(tool_name: str, arguments: dict) -> dict:
        invoked.append((tool_name, arguments))
        if tool_name == "make_issue":
            return {"key": "JIRA-77", "id": "77", "url": "https://itsm/browse/JIRA-77", "status": "open"}
        return {"status": "Done"}

    record = TicketingConnectionRecord(
        id="c3",
        tenant_id="t1",
        provider=PROVIDER_JIRA,
        transport=TRANSPORT_MCP,
        auth_method=AUTH_MCP,
        display_name="Jira MCP",
        endpoint="https://itsm.example/mcp",
        secret_encrypted="",
        auth_params={"create_tool": "make_issue", "status_tool": "read_issue"},
    )
    transport = McpTicketingTransport(record, "", caller=fake_caller)
    ref = await transport.create_ticket(TicketDraft.from_finding(FINDING, project="JIRA"))
    assert invoked[0][0] == "make_issue"
    assert invoked[0][1]["project"] == "JIRA"
    assert ref.key == "JIRA-77"

    status = await transport.get_status(ref)
    assert status is TicketStatus.DONE


# ── Store: parity, tenant isolation, dedupe claim ─────────────────────────────


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryTicketingStore()
    return SQLiteTicketingStore(str(tmp_path / "ticketing.db"))


def _conn(tenant="t1", cid="c1"):
    return TicketingConnectionRecord(
        id=cid,
        tenant_id=tenant,
        provider=PROVIDER_JIRA,
        transport=TRANSPORT_MCP,
        auth_method=AUTH_MCP,
        display_name="Jira",
        endpoint="https://itsm/mcp",
        secret_encrypted="",
        created_at="2026-07-16T00:00:00Z",
        updated_at="2026-07-16T00:00:00Z",
    )


def test_store_connection_is_tenant_scoped(store):
    store.put_connection(_conn(tenant="t1", cid="c1"))
    assert store.get_connection("t1", "c1") is not None
    assert store.get_connection("t2", "c1") is None  # cross-tenant read blocked
    assert store.list_connections("t2") == []
    assert store.delete_connection("t2", "c1") is False  # cross-tenant delete blocked
    assert store.delete_connection("t1", "c1") is True


def _link(tenant="t1", cid="c1", dedupe="CVE-1", lid="l1"):
    return TicketLink(
        id=lid,
        tenant_id=tenant,
        connection_id=cid,
        dedupe_key=dedupe,
        provider=PROVIDER_JIRA,
        created_at="2026-07-16T00:00:00Z",
        updated_at="2026-07-16T00:00:00Z",
    )


def test_claim_ticket_link_dedupes_within_tenant(store):
    won1, link1 = store.claim_ticket_link(_link(lid="l1"))
    assert won1 is True
    won2, link2 = store.claim_ticket_link(_link(lid="l2"))  # same tenant+conn+dedupe
    assert won2 is False
    assert link2.id == link1.id  # the second caller gets the first row, no duplicate


def test_claim_ticket_link_isolated_across_tenants(store):
    # Same logical dedupe key for two tenants must both win (tenant_id in the key).
    won_a, _ = store.claim_ticket_link(_link(tenant="ta", lid="la"))
    won_b, _ = store.claim_ticket_link(_link(tenant="tb", lid="lb"))
    assert won_a is True and won_b is True
    assert store.get_ticket_link("ta", "la") is not None
    assert store.get_ticket_link("tb", "la") is None  # cross-tenant read blocked


# ── Service: connect-once, dedupe, tenant isolation, no-connection guard ───────


def _mcp_connection(store, tenant="t1", cid="c1"):
    record = TicketingConnectionRecord(
        id=cid,
        tenant_id=tenant,
        provider=PROVIDER_JIRA,
        transport=TRANSPORT_MCP,
        auth_method=AUTH_MCP,
        display_name="Jira MCP",
        endpoint="https://itsm/mcp",
        secret_encrypted="",
        auth_params={"create_tool": "create_issue", "status_tool": "get_issue", "default_project": "SEC"},
        created_at="2026-07-16T00:00:00Z",
        updated_at="2026-07-16T00:00:00Z",
    )
    store.put_connection(record)
    return record


@pytest.mark.asyncio
async def test_create_ticket_runs_through_stored_connection():
    store = InMemoryTicketingStore()
    _mcp_connection(store)
    calls = []

    async def caller(tool, args):
        calls.append((tool, args))
        return {"key": "SEC-100", "id": "100", "url": "https://itsm/browse/SEC-100", "status": "open"}

    result = await create_ticket_for_finding(tenant_id="t1", connection_id="c1", finding=FINDING, store=store, mcp_caller=caller)
    assert result["deduplicated"] is False
    assert result["ticket"]["key"] == "SEC-100"
    assert result["audit_metadata"]["per_action_credential"] is False
    # persisted + tenant scoped
    links = store.list_ticket_links("t1")
    assert len(links) == 1 and links[0].status == "open"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_create_ticket_is_idempotent_no_duplicate():
    store = InMemoryTicketingStore()
    _mcp_connection(store)
    calls = []

    async def caller(tool, args):
        calls.append(tool)
        return {"key": "SEC-1", "id": "1", "status": "open"}

    first = await create_ticket_for_finding(tenant_id="t1", connection_id="c1", finding=FINDING, store=store, mcp_caller=caller)
    second = await create_ticket_for_finding(tenant_id="t1", connection_id="c1", finding=FINDING, store=store, mcp_caller=caller)
    assert first["deduplicated"] is False
    assert second["deduplicated"] is True
    assert second["ticket"]["id"] == first["ticket"]["id"]
    assert len(calls) == 1  # provider create invoked exactly once
    assert len(store.list_ticket_links("t1")) == 1


@pytest.mark.asyncio
async def test_create_ticket_tenant_isolation():
    store = InMemoryTicketingStore()
    _mcp_connection(store, tenant="t1", cid="c1")

    async def caller(tool, args):
        return {"key": "X-1", "id": "1", "status": "open"}

    # Tenant t2 cannot use tenant t1's connection id — guided to connect, not a prompt.
    with pytest.raises(TicketingError) as exc:
        await create_ticket_for_finding(tenant_id="t2", connection_id="c1", finding=FINDING, store=store, mcp_caller=caller)
    assert exc.value.code == "no_connection"
    assert "Connect" in str(exc.value)


@pytest.mark.asyncio
async def test_create_ticket_without_connection_says_connect_first():
    store = InMemoryTicketingStore()

    with pytest.raises(TicketingError) as exc:
        await create_ticket_for_finding(tenant_id="t1", finding=FINDING, store=store)
    assert exc.value.code == "no_connection"
    assert "Connect" in str(exc.value)


@pytest.mark.asyncio
async def test_create_ticket_rolls_back_claim_on_provider_failure():
    store = InMemoryTicketingStore()
    _mcp_connection(store)

    async def failing_caller(tool, args):
        raise RuntimeError("itsm down")

    with pytest.raises(TicketingError):
        await create_ticket_for_finding(tenant_id="t1", connection_id="c1", finding=FINDING, store=store, mcp_caller=failing_caller)
    # Claim rolled back so a later retry can re-file.
    assert store.list_ticket_links("t1") == []


@pytest.mark.asyncio
async def test_sync_ticket_status_updates_link():
    store = InMemoryTicketingStore()
    _mcp_connection(store)

    async def create_caller(tool, args):
        return {"key": "SEC-9", "id": "9", "status": "open"}

    created = await create_ticket_for_finding(tenant_id="t1", connection_id="c1", finding=FINDING, store=store, mcp_caller=create_caller)
    ticket_id = created["ticket"]["id"]

    async def status_caller(tool, args):
        return {"status": "Done"}

    synced = await sync_ticket_status(tenant_id="t1", ticket_id=ticket_id, store=store, mcp_caller=status_caller)
    assert synced["ticket"]["status"] == "done"
    assert store.get_ticket_link("t1", ticket_id).status == "done"


@pytest.mark.asyncio
async def test_sync_ticket_status_tenant_isolation():
    store = InMemoryTicketingStore()
    _mcp_connection(store)

    async def create_caller(tool, args):
        return {"key": "SEC-9", "id": "9", "status": "open"}

    created = await create_ticket_for_finding(tenant_id="t1", connection_id="c1", finding=FINDING, store=store, mcp_caller=create_caller)
    with pytest.raises(TicketingError) as exc:
        await sync_ticket_status(tenant_id="t2", ticket_id=created["ticket"]["id"], store=store)
    assert exc.value.code == "not_found"


# ── The connect-once invariant: NO per-action credential/link parameters ──────


def test_create_ticket_signature_has_no_credential_or_link_param():
    params = set(inspect.signature(create_ticket_for_finding).parameters)
    forbidden = {
        "token",
        "api_token",
        "password",
        "secret",
        "credential",
        "credentials",
        "auth",
        "email",
        "url",
        "base_url",
        "jira_url",
        "endpoint",
        "link",
        "site_url",
    }
    leaked = params & forbidden
    assert not leaked, f"create_ticket must resolve auth/base-url from the stored connection only; leaked: {leaked}"
