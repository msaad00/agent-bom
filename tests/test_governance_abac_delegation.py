"""ABAC device/group/client conditions + scoped delegation tokens (#3906)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom import agent_identity
from agent_bom.api.agent_identity_store import (
    AccessContext,
    InMemoryAgentIdentityStore,
    create_conditional_policy,
    evaluate_conditional_access,
    issue_identity,
    set_agent_identity_store,
    verify_token,
)
from agent_bom.api.delegation_token import (
    DelegationTokenError,
    issue_delegation_token,
    propagate_delegation_token,
    verify_delegation_token,
)
from agent_bom.proxy_policy import context_from_now, evaluate_conditions


@pytest.fixture()
def store():
    s = InMemoryAgentIdentityStore()
    set_agent_identity_store(s)
    agent_identity.set_local_identity_verifier(lambda tok: verify_token(s, tok))
    try:
        yield s
    finally:
        set_agent_identity_store(None)
        agent_identity.set_local_identity_verifier(None)


# ── ABAC: ConditionalAccessPolicy device / group / client (gateway path) ─────────


def test_require_policy_denies_on_wrong_device_fail_closed():
    policy = create_conditional_policy(
        InMemoryAgentIdentityStore(), tenant_id="t1", name="managed-only", effect="require", allowed_devices=["dev-managed-1"]
    )
    # No device supplied → cannot prove the condition → deny (fail-closed).
    allowed, _, pid = evaluate_conditional_access([policy], AccessContext(agent_id="a"))
    assert not allowed and pid == policy.policy_id
    # Wrong device → deny.
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(agent_id="a", device_id="dev-byod-9"))
    assert not allowed
    # Correct device → allow.
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(agent_id="a", device_id="dev-managed-1"))
    assert allowed


def test_require_policy_denies_on_missing_group_membership():
    policy = create_conditional_policy(
        InMemoryAgentIdentityStore(), tenant_id="t1", name="sec-eng-only", effect="require", allowed_groups=["security-eng"]
    )
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(groups=[]))
    assert not allowed
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(groups=["marketing"]))
    assert not allowed
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(groups=["marketing", "security-eng"]))
    assert allowed


def test_require_policy_denies_on_wrong_client():
    policy = create_conditional_policy(
        InMemoryAgentIdentityStore(), tenant_id="t1", name="approved-client", effect="require", allowed_clients=["claude-desktop"]
    )
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(client_id=""))
    assert not allowed
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(client_id="rogue-cli"))
    assert not allowed
    allowed, _, _ = evaluate_conditional_access([policy], AccessContext(client_id="claude-desktop"))
    assert allowed


def test_proxy_declarative_conditions_device_group_client_fail_closed():
    ctx = context_from_now(now=0.0)  # no device/group/client supplied
    ok, reason = evaluate_conditions({"allowed_devices": ["dev-1"]}, ctx)
    assert not ok and "device" in reason
    ok, reason = evaluate_conditions({"allowed_groups": ["sec"]}, ctx)
    assert not ok and "group" in reason
    ok, reason = evaluate_conditions({"allowed_clients": ["claude"]}, ctx)
    assert not ok and "client" in reason

    good = context_from_now(now=0.0, device_id="dev-1", groups=["sec"], client_id="claude")
    assert evaluate_conditions({"allowed_devices": ["dev-1"]}, good) == (True, "")
    assert evaluate_conditions({"allowed_groups": ["sec"]}, good) == (True, "")
    assert evaluate_conditions({"allowed_clients": ["claude"]}, good) == (True, "")


def test_conditional_access_blocks_at_gateway_on_device(store):
    from agent_bom.gateway_server import GatewaySettings, create_gateway_app
    from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry

    issue_identity(store, agent_id="agent-a", tenant_id="default")
    create_conditional_policy(store, tenant_id="default", name="managed-only", effect="require", allowed_devices=["dev-managed"])

    async def ok_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
        policy={},
        upstream_caller=ok_caller,
    )
    client = TestClient(create_gateway_app(settings))
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_files", "arguments": {}}}

    blocked = client.post("/mcp/filesystem", json=message, headers={"x-agent-device-id": "dev-byod"})
    assert blocked.json().get("error", {}).get("code") == -32001, blocked.text

    allowed = client.post("/mcp/filesystem", json=message, headers={"x-agent-device-id": "dev-managed"})
    assert allowed.status_code == 200 and allowed.json()["result"] == {"ok": True}


# ── Scoped delegation tokens ─────────────────────────────────────────────────────


def test_delegation_token_verifies_and_is_scoped():
    token, claims = issue_delegation_token(
        tenant_id="t1", delegator="orchestrator", delegatee="worker", scopes=["read_repo", "list_files"], ttl_seconds=300
    )
    verified = verify_delegation_token(token, tenant_id="t1", required_scope="read_repo")
    assert verified.delegator == "orchestrator" and verified.delegatee == "worker"
    assert set(verified.scopes) == {"read_repo", "list_files"}


def test_delegation_token_rejects_over_scoped_call():
    token, _ = issue_delegation_token(tenant_id="t1", delegator="o", delegatee="w", scopes=["read_repo"], ttl_seconds=300)
    with pytest.raises(DelegationTokenError):
        verify_delegation_token(token, tenant_id="t1", required_scope="delete_repo")


def test_delegation_token_rejects_expired():
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    token, _ = issue_delegation_token(tenant_id="t1", delegator="o", delegatee="w", scopes=["read_repo"], ttl_seconds=60, at=past)
    with pytest.raises(DelegationTokenError):
        verify_delegation_token(token, tenant_id="t1")


def test_delegation_token_rejects_tampered_signature():
    token, _ = issue_delegation_token(tenant_id="t1", delegator="o", delegatee="w", scopes=["read_repo"], ttl_seconds=60)
    payload, _sig = token.split(".", 1)
    tampered = f"{payload}.AAAA"
    with pytest.raises(DelegationTokenError):
        verify_delegation_token(tampered, tenant_id="t1")


def test_delegation_token_rejects_cross_tenant():
    token, _ = issue_delegation_token(tenant_id="t1", delegator="o", delegatee="w", scopes=["read_repo"], ttl_seconds=60)
    with pytest.raises(DelegationTokenError):
        verify_delegation_token(token, tenant_id="t2")


def test_delegation_scopeless_token_refused():
    with pytest.raises(ValueError):
        issue_delegation_token(tenant_id="t1", delegator="o", delegatee="w", scopes=[], ttl_seconds=60)


def test_delegation_propagation_narrows_scope_and_decrements_depth():
    token, parent = issue_delegation_token(
        tenant_id="t1", delegator="o", delegatee="w1", scopes=["read_repo", "list_files"], ttl_seconds=300
    )
    child_token, child = propagate_delegation_token(token, next_delegatee="w2", scopes=["read_repo"], tenant_id="t1")
    assert child.scopes == ["read_repo"]
    assert child.chain[-1] == "w2"
    assert child.remaining_depth == parent.remaining_depth - 1
    assert child.exp == parent.exp  # expiry never extended
    verify_delegation_token(child_token, tenant_id="t1", required_scope="read_repo")


def test_delegation_propagation_cannot_broaden_scope():
    token, _ = issue_delegation_token(tenant_id="t1", delegator="o", delegatee="w1", scopes=["read_repo"], ttl_seconds=300)
    with pytest.raises(DelegationTokenError):
        propagate_delegation_token(token, next_delegatee="w2", scopes=["read_repo", "delete_repo"], tenant_id="t1")


# ── API surface ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def client(store):
    from agent_bom.api.server import app

    return TestClient(app)


def test_delegation_api_issue_verify_propagate(client, store):
    issued = client.post("/v1/identities", json={"agent_id": "orchestrator", "blueprint_id": "developer"})
    assert issued.status_code == 201, issued.text
    identity_id = issued.json()["identity"]["identity_id"]

    resp = client.post(
        f"/v1/identities/{identity_id}/delegations",
        json={"delegatee": "worker", "scopes": ["read_repo", "list_files"], "ttl_seconds": 300},
    )
    assert resp.status_code == 201, resp.text
    token = resp.json()["token"]
    assert resp.json()["delegation"]["scopes"] == ["list_files", "read_repo"]

    verified = client.post("/v1/delegations/verify", json={"token": token, "required_scope": "read_repo"})
    assert verified.status_code == 200 and verified.json()["valid"] is True

    over = client.post("/v1/delegations/verify", json={"token": token, "required_scope": "delete_repo"})
    assert over.json()["valid"] is False

    prop = client.post("/v1/delegations/propagate", json={"token": token, "next_delegatee": "worker-2", "scopes": ["read_repo"]})
    assert prop.status_code == 201, prop.text
    assert prop.json()["delegation"]["scopes"] == ["read_repo"]


def test_delegation_api_requires_scopes(client, store):
    issued = client.post("/v1/identities", json={"agent_id": "o", "blueprint_id": "developer"})
    identity_id = issued.json()["identity"]["identity_id"]
    resp = client.post(f"/v1/identities/{identity_id}/delegations", json={"delegatee": "w", "scopes": []})
    assert resp.status_code == 400


def test_conditional_access_api_accepts_device_group_client(client, store):
    created = client.post(
        "/v1/conditional-access-policies",
        json={
            "name": "managed-sec-eng",
            "effect": "require",
            "allowed_devices": ["dev-managed"],
            "allowed_groups": ["security-eng"],
            "allowed_clients": ["claude-desktop"],
        },
    )
    assert created.status_code == 201, created.text
    policy = created.json()["policy"]
    assert policy["allowed_devices"] == ["dev-managed"]
    assert policy["allowed_groups"] == ["security-eng"]
    assert policy["allowed_clients"] == ["claude-desktop"]
