"""Agent identity lifecycle: issue, rotate, revoke, and verify (incl. proxy tie-in)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom import agent_identity
from agent_bom.api.agent_identity_store import (
    AccessContext,
    InMemoryAgentIdentityStore,
    approve_jit_grant,
    create_conditional_policy,
    deny_jit_grant,
    evaluate_conditional_access,
    hash_token,
    issue_identity,
    issue_jit_grant,
    request_jit_grant,
    revoke_identity,
    revoke_jit_grant,
    rotate_identity,
    set_agent_identity_store,
    set_conditional_policy_status,
    verify_token,
)


@pytest.fixture()
def store():
    s = InMemoryAgentIdentityStore()
    set_agent_identity_store(s)
    # The gateway/proxy resolve abi_ lifecycle tokens through the local identity
    # verifier; production wires it via register_local_identity_verifier(). Wire
    # it here so issued tokens resolve (and revoked ones fail closed) the same way.
    agent_identity.set_local_identity_verifier(lambda tok: verify_token(s, tok))
    try:
        yield s
    finally:
        set_agent_identity_store(None)
        agent_identity.set_local_identity_verifier(None)


# ── core lifecycle ──────────────────────────────────────────────────────────────


def test_issue_then_verify(store):
    identity, raw = issue_identity(store, agent_id="agent-a", tenant_id="t1")
    assert raw.startswith("abi_")
    assert identity.status == "active"
    agent_id, error = verify_token(store, raw)
    assert error is None and agent_id == "agent-a"


def test_token_stored_only_as_hash(store):
    identity, raw = issue_identity(store, agent_id="agent-a", tenant_id="t1")
    assert identity.token_hash == hash_token(raw)
    assert "token_hash" not in identity.to_public_dict()


def test_revoke_fails_closed(store):
    identity, raw = issue_identity(store, agent_id="agent-a", tenant_id="t1")
    revoke_identity(store, identity.identity_id, reason="compromised")
    agent_id, error = verify_token(store, raw)
    assert agent_id == "anonymous" and "revoked" in error


def test_expired_fails_closed(store):
    identity, raw = issue_identity(store, agent_id="agent-a", tenant_id="t1", ttl_seconds=60)
    # Force expiry into the past.
    identity.expires_at = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    store.put(identity)
    agent_id, error = verify_token(store, raw)
    assert agent_id == "anonymous" and "expired" in error


def test_rotate_keeps_old_live_during_overlap_then_new_works(store):
    identity, old_raw = issue_identity(store, agent_id="agent-a", tenant_id="t1")
    new_identity, new_raw = rotate_identity(store, identity.identity_id, overlap_seconds=3600)
    # Both tokens authenticate during the overlap window.
    assert verify_token(store, old_raw) == ("agent-a", None)
    assert verify_token(store, new_raw) == ("agent-a", None)
    old = store.get(identity.identity_id)
    assert old.status == "rotating" and old.rotated_to_id == new_identity.identity_id


def test_unknown_token_is_anonymous(store):
    agent_id, error = verify_token(store, "abi_deadbeef_nope")
    assert agent_id == "anonymous" and error is not None


# ── proxy/gateway tie-in via resolve_agent_id ───────────────────────────────────


def test_resolve_agent_id_honors_lifecycle(store):
    identity, raw = issue_identity(store, agent_id="agent-a", tenant_id="t1")
    agent_identity.set_local_identity_verifier(lambda tok: verify_token(store, tok))
    try:
        assert agent_identity.resolve_agent_id(raw, {}) == ("agent-a", None)
        revoke_identity(store, identity.identity_id)
        resolved, error = agent_identity.resolve_agent_id(raw, {})
        assert resolved == agent_identity.ANONYMOUS and "revoked" in error
    finally:
        agent_identity.set_local_identity_verifier(None)


# ── API surface ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def client(store):
    from agent_bom.api.server import app

    return TestClient(app)


def test_issue_rotate_revoke_via_api(client):
    issued = client.post("/v1/identities", json={"agent_id": "agent-a", "blueprint_id": "developer"})
    assert issued.status_code == 201, issued.text
    payload = issued.json()
    identity_id = payload["identity"]["identity_id"]
    assert payload["token"].startswith("abi_")
    assert "token_hash" not in payload["identity"]

    listed = client.get("/v1/identities").json()
    assert listed["count"] == 1

    rotated = client.post(f"/v1/identities/{identity_id}/rotate", json={})
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["rotated_from"] == identity_id
    assert rotated.json()["token"].startswith("abi_")

    new_id = rotated.json()["identity"]["identity_id"]
    revoked = client.post(f"/v1/identities/{new_id}/revoke", json={"reason": "test"})
    assert revoked.status_code == 200
    assert revoked.json()["identity"]["status"] == "revoked"


def test_issue_requires_agent_id(client):
    assert client.post("/v1/identities", json={}).status_code == 400


def test_get_unknown_identity_404s(client):
    assert client.get("/v1/identities/nope").status_code == 404


def test_double_rotation_is_rejected(store):
    identity, _ = issue_identity(store, agent_id="agent-a", tenant_id="t1")
    first = rotate_identity(store, identity.identity_id)
    assert first is not None
    # The original is now 'rotating'; rotating it again would orphan the chain.
    assert rotate_identity(store, identity.identity_id) is None


def test_jit_grant_is_time_bound_and_revocable(store):
    identity, _ = issue_identity(store, agent_id="agent-a", tenant_id="t1", allowed_tools=["list_files"])
    request = request_jit_grant(
        store,
        identity_id=identity.identity_id,
        agent_id=identity.agent_id,
        tenant_id=identity.tenant_id,
        tool_name="read_file",
        reason="incident response",
        ticket_id="INC-42",
    )
    assert store.active_jit_grant("t1", identity.identity_id, "read_file") is None

    grant = approve_jit_grant(store, request.grant_id, ttl_seconds=300, approved_by="admin")
    assert grant is not None
    assert grant.status == "active"
    assert store.active_jit_grant("t1", identity.identity_id, "read_file").grant_id == grant.grant_id

    grant.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    store.put_jit_grant(grant)
    assert store.active_jit_grant("t1", identity.identity_id, "read_file") is None


def test_jit_deny_and_revoke_remove_live_access(store):
    identity, _ = issue_identity(store, agent_id="agent-a", tenant_id="t1")
    denied = request_jit_grant(
        store,
        identity_id=identity.identity_id,
        agent_id=identity.agent_id,
        tenant_id=identity.tenant_id,
        tool_name="run_shell",
    )
    assert deny_jit_grant(store, denied.grant_id, reason="too broad").status == "denied"
    assert approve_jit_grant(store, denied.grant_id, ttl_seconds=300) is None

    grant = issue_jit_grant(
        store,
        identity_id=identity.identity_id,
        agent_id=identity.agent_id,
        tenant_id=identity.tenant_id,
        tool_name="run_shell",
        ttl_seconds=300,
    )
    assert store.active_jit_grant("t1", identity.identity_id, "run_shell") is not None
    assert revoke_jit_grant(store, grant.grant_id, reason="done").status == "revoked"
    assert store.active_jit_grant("t1", identity.identity_id, "run_shell") is None


def test_lifecycle_writes_audit_chain(client):
    from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log

    audit = InMemoryAuditLog()
    set_audit_log(audit)
    try:
        issued = client.post("/v1/identities", json={"agent_id": "agent-a"})
        iid = issued.json()["identity"]["identity_id"]
        rotated = client.post(f"/v1/identities/{iid}/rotate", json={})
        nid = rotated.json()["identity"]["identity_id"]
        client.post(f"/v1/identities/{nid}/revoke", json={"reason": "test"})

        actions = {e.action for e in audit.list_entries(limit=100)}
        assert "agent_identity.issued" in actions
        assert "agent_identity.rotated" in actions
        assert "agent_identity.revoked" in actions
    finally:
        set_audit_log(InMemoryAuditLog())


def test_jit_grant_api_writes_audit_and_lists_grants(client):
    from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log

    audit = InMemoryAuditLog()
    set_audit_log(audit)
    try:
        issued = client.post("/v1/identities", json={"agent_id": "agent-a", "allowed_tools": ["list_files"]})
        iid = issued.json()["identity"]["identity_id"]

        requested = client.post(
            f"/v1/identities/{iid}/jit-requests",
            json={"tool_name": "read_file", "reason": "break-glass review", "ticket_id": "INC-42"},
        )
        assert requested.status_code == 201, requested.text
        grant_id = requested.json()["grant"]["grant_id"]

        approved = client.post(f"/v1/identity-jit-grants/{grant_id}/approve", json={"ttl_seconds": 300})
        assert approved.status_code == 200, approved.text
        assert approved.json()["grant"]["status"] == "active"

        listed = client.get(f"/v1/identities/{iid}/jit-grants?include_inactive=true")
        assert listed.status_code == 200
        assert listed.json()["count"] == 1

        revoked = client.post(f"/v1/identity-jit-grants/{grant_id}/revoke", json={"reason": "finished"})
        assert revoked.status_code == 200
        assert revoked.json()["grant"]["status"] == "revoked"

        actions = {e.action for e in audit.list_entries(limit=100)}
        assert {
            "agent_identity.jit_requested",
            "agent_identity.jit_approved",
            "agent_identity.jit_revoked",
        } <= actions
    finally:
        set_audit_log(InMemoryAuditLog())


def test_per_tool_scope_blocks_out_of_scope_tool(store):
    from starlette.testclient import TestClient

    from agent_bom.gateway_server import GatewaySettings, create_gateway_app
    from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry

    # Issue an identity scoped to only "list_files".
    identity, token = issue_identity(store, agent_id="agent-a", tenant_id="default", allowed_tools=["list_files"])
    assert identity.tool_allowed("list_files") and not identity.tool_allowed("read_file")

    async def ok_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
        policy={},
        upstream_caller=ok_caller,
    )
    client = TestClient(create_gateway_app(settings))

    def call(tool):
        return {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": {}, "_meta": {"agent_identity": token}},
        }

    blocked = client.post("/mcp/filesystem", json=call("read_file"))
    assert blocked.json().get("error", {}).get("code") == -32001, blocked.text
    allowed = client.post("/mcp/filesystem", json=call("list_files"))
    assert allowed.status_code == 200 and allowed.json()["result"] == {"ok": True}


def test_jit_grant_temporarily_allows_out_of_scope_tool(store):
    from starlette.testclient import TestClient

    from agent_bom.gateway_server import GatewaySettings, create_gateway_app
    from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry

    identity, token = issue_identity(store, agent_id="agent-a", tenant_id="default", allowed_tools=["list_files"])
    grant = issue_jit_grant(
        store,
        identity_id=identity.identity_id,
        agent_id=identity.agent_id,
        tenant_id=identity.tenant_id,
        tool_name="read_file",
        ttl_seconds=300,
        approved_by="admin",
    )
    audit_events = []

    async def ok_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    async def audit_sink(event):
        audit_events.append(event)

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
        policy={},
        upstream_caller=ok_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))

    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {}, "_meta": {"agent_identity": token}},
    }
    allowed = client.post("/mcp/filesystem", json=message)
    assert allowed.status_code == 200 and allowed.json()["result"] == {"ok": True}
    assert any(e.get("action") == "gateway.identity_jit_grant_used" and e.get("grant_id") == grant.grant_id for e in audit_events)

    revoke_jit_grant(store, grant.grant_id)
    blocked = client.post("/mcp/filesystem", json=message)
    assert blocked.json().get("error", {}).get("code") == -32001, blocked.text
    assert blocked.json()["error"]["data"] == {"reason": "Identity scope blocked this tool", "policy_source": "identity_scope"}


# ── conditional / context-aware access ──────────────────────────────────────────


def test_require_policy_denies_when_environment_off():
    policy = create_conditional_policy(
        InMemoryAgentIdentityStore(),
        tenant_id="t1",
        name="prod-only",
        effect="require",
        agent_ids=["agent-a"],
        allowed_environments=["prod"],
    )
    allowed, _, pid = evaluate_conditional_access([policy], AccessContext(agent_id="agent-a", environment="dev"))
    assert not allowed and pid == policy.policy_id
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(agent_id="agent-a", environment="prod"))
    assert allowed
    # A policy out of scope never applies.
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(agent_id="agent-b", environment="dev"))
    assert allowed


def test_require_policy_fails_closed_on_missing_context():
    policy = create_conditional_policy(
        InMemoryAgentIdentityStore(), tenant_id="t1", name="cidr", effect="require", allowed_source_cidrs=["10.0.0.0/8"]
    )
    # No source IP supplied → the require condition cannot be proven → deny.
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(source_ip=""))
    assert not allowed
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(source_ip="10.1.2.3"))
    assert allowed
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(source_ip="192.168.1.1"))
    assert not allowed


def test_deny_policy_wins_over_require():
    require = create_conditional_policy(
        InMemoryAgentIdentityStore(), tenant_id="t1", name="allow-prod", effect="require", allowed_environments=["prod"]
    )
    deny = create_conditional_policy(InMemoryAgentIdentityStore(), tenant_id="t1", name="block-shell", effect="deny", tools=["run_shell"])
    ctx = AccessContext(tool_name="run_shell", environment="prod")
    allowed, _, pid = evaluate_conditional_access([require, deny], ctx)
    assert not allowed and pid == deny.policy_id


def test_disabled_policy_is_ignored():
    store = InMemoryAgentIdentityStore()
    policy = create_conditional_policy(store, tenant_id="t1", name="prod-only", effect="require", allowed_environments=["prod"])
    set_conditional_policy_status(store, policy.policy_id, status="disabled")
    active = store.list_conditional_policies("t1")
    assert active == []
    allowed, _, _ = evaluate_conditional_access(store.list_conditional_policies("t1"), AccessContext(environment="dev"))
    assert allowed


def test_conditional_access_blocks_at_gateway(store):
    from starlette.testclient import TestClient

    from agent_bom.gateway_server import GatewaySettings, create_gateway_app
    from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry

    issue_identity(store, agent_id="agent-a", tenant_id="default")
    create_conditional_policy(store, tenant_id="default", name="prod-only", effect="require", allowed_environments=["prod"])
    audit_events = []

    async def ok_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    async def audit_sink(event):
        audit_events.append(event)

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
        policy={},
        upstream_caller=ok_caller,
        audit_sink=audit_sink,
    )
    client = TestClient(create_gateway_app(settings))
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}}

    blocked = client.post("/mcp/filesystem", json=message, headers={"x-agent-environment": "dev"})
    assert blocked.json().get("error", {}).get("code") == -32001, blocked.text
    assert any(e.get("action") == "gateway.conditional_access_blocked" for e in audit_events)

    allowed = client.post("/mcp/filesystem", json=message, headers={"x-agent-environment": "prod"})
    assert allowed.status_code == 200 and allowed.json()["result"] == {"ok": True}


def test_conditional_access_api_crud(client):
    created = client.post(
        "/v1/conditional-access-policies",
        json={
            "name": "business-hours",
            "effect": "require",
            "allowed_hours_utc": [9, 10, 11, 12, 13, 14, 15, 16, 17],
            "allowed_source_cidrs": ["10.0.0.0/8"],
        },
    )
    assert created.status_code == 201, created.text
    pid = created.json()["policy"]["policy_id"]
    assert created.json()["policy"]["status"] == "active"

    assert client.get("/v1/conditional-access-policies").json()["count"] == 1

    disabled = client.post(f"/v1/conditional-access-policies/{pid}/disable")
    assert disabled.status_code == 200 and disabled.json()["policy"]["status"] == "disabled"
    assert client.get("/v1/conditional-access-policies").json()["count"] == 0
    assert client.get("/v1/conditional-access-policies?include_disabled=true").json()["count"] == 1

    enabled = client.post(f"/v1/conditional-access-policies/{pid}/enable")
    assert enabled.status_code == 200 and enabled.json()["policy"]["status"] == "active"


def test_conditional_access_api_rejects_bad_input(client):
    assert client.post("/v1/conditional-access-policies", json={"effect": "require"}).status_code == 400
    assert client.post("/v1/conditional-access-policies", json={"name": "x", "effect": "maybe"}).status_code == 400
    assert client.post("/v1/conditional-access-policies", json={"name": "x", "allowed_source_cidrs": ["not-a-cidr"]}).status_code == 400
    assert client.post("/v1/conditional-access-policies", json={"name": "x", "allowed_hours_utc": [25]}).status_code == 400


# ── MCP identity write tools (admin/scope/audit gated) ──────────────────────────


def _passthrough(s: str) -> str:
    return s


@pytest.mark.asyncio
async def test_mcp_identity_issue_requires_admin_and_scope(store):
    from agent_bom.mcp_tools.identity import identity_issue_impl

    # Non-admin is blocked before any state change.
    out = json.loads(
        await identity_issue_impl(
            agent_id="agent-a",
            operator_role="viewer",
            operator_scopes="identity:write",
            reason="provision build agent",
            _truncate_response=_passthrough,
        )
    )
    assert out["status"] == "blocked" and "admin role" in out["error"]
    assert store.list("default") == []

    # Admin without the scope is blocked.
    out = json.loads(
        await identity_issue_impl(
            agent_id="agent-a",
            operator_role="admin",
            operator_scopes="",
            reason="provision build agent",
            _truncate_response=_passthrough,
        )
    )
    assert out["status"] == "blocked" and "identity:write" in out["error"]

    # Short audit reason is blocked.
    out = json.loads(
        await identity_issue_impl(
            agent_id="agent-a",
            operator_role="admin",
            operator_scopes="identity:write",
            reason="x",
            _truncate_response=_passthrough,
        )
    )
    assert out["status"] == "blocked"


@pytest.mark.asyncio
async def test_mcp_identity_issue_then_grant_and_revoke_jit(store):
    from agent_bom.mcp_tools.identity import (
        identity_grant_jit_impl,
        identity_issue_impl,
        identity_revoke_jit_impl,
    )

    issued = json.loads(
        await identity_issue_impl(
            agent_id="agent-a",
            allowed_tools="list_files",
            operator_role="admin",
            operator_scopes="identity:write",
            reason="provision build agent",
            _truncate_response=_passthrough,
        )
    )
    assert issued["token"].startswith("abi_")
    assert issued["mcp_write_policy"]["required_scope"] == "identity:write"
    identity_id = issued["identity"]["identity_id"]
    assert store.get(identity_id) is not None

    granted = json.loads(
        await identity_grant_jit_impl(
            identity_id=identity_id,
            tool_name="read_file",
            ttl_seconds=300,
            operator_role="admin",
            operator_scopes="identity:write",
            reason="incident response window",
            _truncate_response=_passthrough,
        )
    )
    grant_id = granted["grant"]["grant_id"]
    assert store.active_jit_grant("default", identity_id, "read_file") is not None

    revoked = json.loads(
        await identity_revoke_jit_impl(
            grant_id=grant_id,
            operator_role="admin",
            operator_scopes="identity:write",
            reason="window closed early",
            _truncate_response=_passthrough,
        )
    )
    assert revoked["grant"]["status"] == "revoked"
    assert store.active_jit_grant("default", identity_id, "read_file") is None


@pytest.mark.asyncio
async def test_mcp_identity_write_emits_lifecycle_audit_chain(store):
    from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log
    from agent_bom.mcp_tools.identity import identity_issue_impl, identity_revoke_impl

    audit = InMemoryAuditLog()
    set_audit_log(audit)
    try:
        issued = json.loads(
            await identity_issue_impl(
                agent_id="agent-a",
                operator_role="admin",
                operator_scopes="identity:write",
                reason="provision build agent",
                _truncate_response=_passthrough,
            )
        )
        await identity_revoke_impl(
            identity_id=issued["identity"]["identity_id"],
            operator_role="admin",
            operator_scopes="identity:write",
            reason="decommission build agent",
            _truncate_response=_passthrough,
        )
        actions = {e.action for e in audit.list_entries(limit=100)}
        assert "agent_identity.issued" in actions
        assert "agent_identity.revoked" in actions
        # operator_role remains authorization/audit metadata; the actor is the
        # authenticated MCP caller, not a self-asserted tool argument.
        assert any(e.actor == "mcp-operator" for e in audit.list_entries(limit=100))
    finally:
        set_audit_log(InMemoryAuditLog())
