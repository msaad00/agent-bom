"""JIT grant authority must be tenant-bound below HTTP handlers."""

from dataclasses import replace

import pytest

from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    SQLiteAgentIdentityStore,
    approve_jit_grant,
    deny_jit_grant,
    request_jit_grant,
    revoke_jit_grant,
)


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return InMemoryAgentIdentityStore() if request.param == "memory" else SQLiteAgentIdentityStore(str(tmp_path / "jit.db"))


def pending(store):
    return request_jit_grant(store, tenant_id="a", identity_id="identity-a", agent_id="agent-a", tool_name="read_repo")


def test_exact_id_read_is_tenant_scoped(store):
    grant = pending(store)
    assert store.get_jit_grant(grant.grant_id, tenant_id="b") is None
    assert store.get_jit_grant(grant.grant_id, tenant_id="a") == grant


@pytest.mark.parametrize("action", [approve_jit_grant, deny_jit_grant, revoke_jit_grant])
def test_foreign_service_mutation_does_not_change_grant(store, action):
    grant = pending(store)
    kwargs = {"ttl_seconds": 300} if action is approve_jit_grant else {}
    assert action(store, grant.grant_id, tenant_id="b", **kwargs) is None
    assert store.get_jit_grant(grant.grant_id, tenant_id="a").status == "requested"


def test_write_requires_matching_tenant_and_cannot_take_over_id(store):
    grant = pending(store)
    with pytest.raises(ValueError):
        store.put_jit_grant(grant, tenant_id="b")
    with pytest.raises(ValueError):
        store.put_jit_grant(replace(grant, tenant_id="b"), tenant_id="b")
    assert store.get_jit_grant(grant.grant_id, tenant_id="a") == grant


@pytest.mark.parametrize("tenant", [None, "", " "])
def test_missing_tenant_is_rejected(store, tenant):
    grant = pending(store)
    with pytest.raises(ValueError):
        store.get_jit_grant(grant.grant_id, tenant_id=tenant)
    with pytest.raises(ValueError):
        store.put_jit_grant(grant, tenant_id=tenant)
    with pytest.raises(ValueError):
        approve_jit_grant(store, grant.grant_id, tenant_id=tenant, ttl_seconds=300)


def test_returned_records_do_not_mutate_authority(store):
    grant = pending(store)
    grant.tenant_id = "b"
    assert len(store.list_jit_grants("a", include_inactive=True)) == 1
    listed = store.list_jit_grants("a", include_inactive=True)[0]
    listed.status = "active"
    assert store.get_jit_grant(grant.grant_id, tenant_id="a").status == "requested"


def test_sqlite_scoped_upsert_survives_reopen_and_rejected_write(tmp_path):
    path = str(tmp_path / "restart.db")
    first = SQLiteAgentIdentityStore(path)
    grant = pending(first)
    with pytest.raises(ValueError):
        first.put_jit_grant(replace(grant, tenant_id="b"), tenant_id="b")
    approved = approve_jit_grant(first, grant.grant_id, tenant_id="a", ttl_seconds=300)
    assert approved.status == "active"
    second = SQLiteAgentIdentityStore(path)
    assert second.get_jit_grant(grant.grant_id, tenant_id="a") == approved
    assert second.get_jit_grant(grant.grant_id, tenant_id="b") is None
