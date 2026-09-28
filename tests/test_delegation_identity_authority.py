"""Delegations cannot outlive or broaden their source identity authority."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    SQLiteAgentIdentityStore,
    issue_identity,
    revoke_identity,
    set_agent_identity_store,
)
from agent_bom.api.delegation_token import issue_delegation_token
from agent_bom.api.routes.identities import issue_agent_delegation, propagate_agent_delegation, verify_agent_delegation


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path, monkeypatch):
    result = InMemoryAgentIdentityStore() if request.param == "memory" else SQLiteAgentIdentityStore(str(tmp_path / "identities.db"))
    set_agent_identity_store(result)
    monkeypatch.setattr("agent_bom.api.routes.identities.log_action", lambda *a, **kw: None)
    monkeypatch.setattr("agent_bom.api.routes.identities._emit", lambda *a, **kw: None)
    yield result
    set_agent_identity_store(None)


def request_for(tenant="tenant-a"):
    request = Request({"type": "http"})
    request.state.tenant_id = tenant
    return request


def source(store):
    return issue_identity(store, agent_id="same-agent", tenant_id="tenant-a", allowed_tools=["read_repo"], ttl_seconds=600)[0]


def delegate(identity):
    return issue_agent_delegation(request_for(), identity.identity_id, {"delegatee": "worker", "scopes": ["read_repo"], "ttl_seconds": 300})


@pytest.mark.parametrize("state", ["revoked", "expired", "unknown", "past_expiry", "malformed_expiry", "naive_expiry"])
def test_inactive_identity_cannot_issue(store, state):
    identity = source(store)
    if state == "past_expiry":
        identity.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    elif state == "malformed_expiry":
        identity.expires_at = "invalid"
    elif state == "naive_expiry":
        identity.expires_at = "2099-01-01T00:00:00"
    else:
        identity.status = state
    store.put(identity)
    with pytest.raises(HTTPException) as exc:
        delegate(identity)
    assert exc.value.status_code == 403


def test_identity_tool_ceiling_applies_to_issue(store):
    identity = source(store)
    with pytest.raises(HTTPException) as exc:
        issue_agent_delegation(request_for(), identity.identity_id, {"delegatee": "worker", "scopes": ["delete_repo"]})
    assert exc.value.status_code == 403


def test_delegation_expiry_is_bounded_by_identity(store):
    identity = source(store)
    identity.expires_at = (datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat()
    store.put(identity)
    issued = delegate(identity)
    assert issued["delegation"]["expires_at"] <= int(datetime.fromisoformat(identity.expires_at).timestamp())


@pytest.mark.parametrize("mutation", ["revoked", "expired", "narrowed", "rotation_ended"])
def test_root_authority_rechecked_for_parent_and_child(store, mutation):
    identity = source(store)
    parent = delegate(identity)["token"]
    child = propagate_agent_delegation(request_for(), {"token": parent, "next_delegatee": "worker-2"})["token"]
    assert verify_agent_delegation(request_for(), {"token": child})["valid"] is True
    if mutation == "revoked":
        revoke_identity(store, identity.identity_id, tenant_id="tenant-a")
    else:
        if mutation == "narrowed":
            identity.allowed_tools = ["list_files"]
        else:
            identity.status = "rotating" if mutation == "rotation_ended" else "active"
            identity.expires_at = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        store.put(identity)
    for token in [parent, child]:
        assert verify_agent_delegation(request_for(), {"token": token})["valid"] is False
        with pytest.raises(HTTPException) as exc:
            propagate_agent_delegation(request_for(), {"token": token, "next_delegatee": "worker-3"})
        assert exc.value.status_code == 400


def test_same_agent_name_cannot_replace_revoked_source(store):
    identity = source(store)
    token = delegate(identity)["token"]
    revoke_identity(store, identity.identity_id, tenant_id="tenant-a")
    source(store)
    assert verify_agent_delegation(request_for(), {"token": token})["valid"] is False


def test_unbound_legacy_token_is_not_live_identity_authority(store):
    source(store)
    token, _ = issue_delegation_token(
        tenant_id="tenant-a", delegator="same-agent", delegatee="worker", scopes=["read_repo"], ttl_seconds=300
    )
    assert verify_agent_delegation(request_for(), {"token": token})["valid"] is False


def test_foreign_identity_and_token_fail_closed(store):
    identity = source(store)
    token = delegate(identity)["token"]
    with pytest.raises(HTTPException) as exc:
        issue_agent_delegation(request_for("tenant-b"), identity.identity_id, {"delegatee": "worker", "scopes": ["read_repo"]})
    assert exc.value.status_code == 404
    assert verify_agent_delegation(request_for("tenant-b"), {"token": token})["valid"] is False


def test_storage_outage_never_grants_or_leaks_authority(store, monkeypatch):
    identity = source(store)
    token = delegate(identity)["token"]
    secret = "postgres://private-user:private-password@internal"

    def unavailable(*args, **kwargs):
        raise RuntimeError(secret)

    monkeypatch.setattr(store, "get", unavailable)
    with pytest.raises(HTTPException) as exc:
        delegate(identity)
    assert exc.value.status_code == 503
    assert secret not in str(exc.value.detail)
    result = verify_agent_delegation(request_for(), {"token": token})
    assert result["valid"] is False
    assert secret not in str(result)
    with pytest.raises(HTTPException) as exc:
        propagate_agent_delegation(request_for(), {"token": token, "next_delegatee": "worker-2"})
    assert exc.value.status_code == 400
    assert secret not in str(exc.value.detail)


def test_sqlite_restart_preserves_root_revocation(tmp_path, monkeypatch):
    path = str(tmp_path / "restart.db")
    first = SQLiteAgentIdentityStore(path)
    identity = source(first)
    from agent_bom.api.delegation_service import issue_identity_delegation, verify_identity_delegation
    from agent_bom.api.delegation_token import DelegationTokenError

    token, claims = issue_identity_delegation(
        first, tenant_id="tenant-a", identity_id=identity.identity_id, delegatee="worker", scopes=["read_repo"], ttl_seconds=300
    )
    second = SQLiteAgentIdentityStore(path)
    assert verify_identity_delegation(second, token, tenant_id="tenant-a") == claims
    revoke_identity(second, identity.identity_id, tenant_id="tenant-a")
    with pytest.raises(DelegationTokenError):
        verify_identity_delegation(SQLiteAgentIdentityStore(path), token, tenant_id="tenant-a")


def test_service_rejects_missing_tenant_before_storage(store, monkeypatch):
    from agent_bom.api.delegation_service import issue_identity_delegation

    def forbidden(*a, **kw):
        pytest.fail("invalid tenant reached storage")

    monkeypatch.setattr(store, "get", forbidden)
    for tenant in (None, "", " "):
        with pytest.raises(ValueError):
            issue_identity_delegation(store, tenant_id=tenant, identity_id="id", delegatee="worker", scopes=["read_repo"], ttl_seconds=300)


def test_authenticated_http_delegation_and_role_scope_boundaries(store, monkeypatch):
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
    from agent_bom.api.middleware import APIKeyMiddleware
    from agent_bom.api.routes.identities import router

    for name in ("AGENT_BOM_API_KEY", "AGENT_BOM_OIDC_ISSUER", "AGENT_BOM_TRUST_PROXY_AUTH", "AGENT_BOM_DEMO_ESTATE"):
        monkeypatch.delenv(name, raising=False)
    identity = source(store)
    original = get_key_store()
    set_key_store(KeyStore())
    app = FastAPI()
    app.include_router(router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="")
    try:
        with TestClient(app) as client:
            for role, tenant, scopes, status in [
                (Role.ADMIN, "tenant-a", ["identity:write", "identity.delegation:write"], 201),
                (Role.ADMIN, "tenant-b", ["identity:write"], 404),
                (Role.VIEWER, "tenant-a", ["identity:write"], 403),
                (Role.ANALYST, "tenant-a", ["identity:write"], 403),
                (Role.ADMIN, "tenant-a", ["scan:write"], 403),
            ]:
                raw, key = create_api_key(name="delegation-contract", role=role, tenant_id=tenant, scopes=scopes)
                get_key_store().add(key)
                client.headers["X-API-Key"] = raw
                response = client.post(
                    f"/v1/identities/{identity.identity_id}/delegations", json={"delegatee": "worker", "scopes": ["read_repo"]}
                )
                assert response.status_code == status, response.text
                if status == 201:
                    token = response.json()["token"]
                    verification = client.post("/v1/delegations/verify", json={"token": token})
                    assert verification.status_code == 200, verification.text
                    assert verification.json()["valid"] is True
                    revoke_identity(store, identity.identity_id, tenant_id="tenant-a")
                    assert client.post("/v1/delegations/verify", json={"token": token}).json()["valid"] is False
            client.headers.pop("X-API-Key")
            assert (
                client.post(
                    f"/v1/identities/{identity.identity_id}/delegations", json={"delegatee": "worker", "scopes": ["read_repo"]}
                ).status_code
                == 401
            )
    finally:
        set_key_store(original)
