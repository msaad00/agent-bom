"""Agent identity lifecycle: issue, rotate, revoke, and verify (incl. proxy tie-in)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom import agent_identity
from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    hash_token,
    issue_identity,
    revoke_identity,
    rotate_identity,
    set_agent_identity_store,
    verify_token,
)


@pytest.fixture()
def store():
    s = InMemoryAgentIdentityStore()
    set_agent_identity_store(s)
    try:
        yield s
    finally:
        set_agent_identity_store(None)


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
