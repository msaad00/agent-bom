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


def test_service_rejects_wrong_record_from_adapter():
    from agent_bom.api.identity_grants import AgentJITGrant

    class WrongStore:
        def get_jit_grant(self, grant_id, *, tenant_id):
            return AgentJITGrant("foreign", "id", "agent", "b", "read_repo", "requested", "")

        def put_jit_grant(self, grant, *, tenant_id):
            pytest.fail("foreign grant reached write")

    with pytest.raises(ValueError):
        approve_jit_grant(WrongStore(), "foreign", tenant_id="a", ttl_seconds=300)


def test_sqlite_payload_ownership_cannot_override_scoped_row(tmp_path):
    import json
    from dataclasses import asdict

    store = SQLiteAgentIdentityStore(str(tmp_path / "corrupt.db"))
    grant = pending(store)
    store._conn.execute(
        "UPDATE agent_identity_jit_grants SET data = ? WHERE grant_id = ?",
        (json.dumps(asdict(replace(grant, tenant_id="b"))), grant.grant_id),
    )
    store._conn.commit()
    with pytest.raises(ValueError):
        store.get_jit_grant(grant.grant_id, tenant_id="a")


def test_live_postgres_exact_id_authority_and_rls():
    import os
    from uuid import uuid4

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires an isolated, migrated Postgres contract database")
    from psycopg.errors import InsufficientPrivilege

    from agent_bom.api.postgres_agent_identity import PostgresAgentIdentityStore
    from agent_bom.api.postgres_common import _new_application_pool, reset_current_tenant, set_current_tenant

    tenant_a, tenant_b = f"jit-a-{uuid4()}", f"jit-b-{uuid4()}"
    pool = _new_application_pool(min_size=1, max_size=2)
    store = PostgresAgentIdentityStore(pool)
    context = set_current_tenant(tenant_a)
    try:
        with pool.connection() as conn:
            is_super, bypass = conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
        assert not is_super and not bypass
        grant = request_jit_grant(store, tenant_id=tenant_a, identity_id="id", agent_id="agent", tool_name="read_repo")
        assert store.get_jit_grant(grant.grant_id, tenant_id=tenant_b) is None
        assert approve_jit_grant(store, grant.grant_id, tenant_id=tenant_b, ttl_seconds=300) is None
        other_context = set_current_tenant(tenant_b)
        try:
            assert store.get_jit_grant(grant.grant_id, tenant_id=tenant_a) is None
            with pytest.raises((ValueError, InsufficientPrivilege)):
                store.put_jit_grant(replace(grant, tenant_id=tenant_b), tenant_id=tenant_b)
        finally:
            reset_current_tenant(other_context)
        assert store.get_jit_grant(grant.grant_id, tenant_id=tenant_a).status == "requested"
        assert approve_jit_grant(store, grant.grant_id, tenant_id=tenant_a, ttl_seconds=300).status == "active"
        assert revoke_jit_grant(store, grant.grant_id, tenant_id=tenant_a).status == "revoked"
    finally:
        reset_current_tenant(context)
        pool.close()


def test_concurrent_tenants_cannot_claim_the_same_grant_id(store):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from uuid import uuid4

    from agent_bom.api.identity_grants import AgentJITGrant

    barrier = Barrier(2)
    grant_id = f"jit-race-{uuid4()}"

    def claim(tenant):
        grant = AgentJITGrant(grant_id, "id", "agent", tenant, "read_repo", "requested", "")
        barrier.wait(timeout=5)
        try:
            store.put_jit_grant(grant, tenant_id=tenant)
        except ValueError:
            return None
        return tenant

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(claim, ["a", "b"]))
    winners = [tenant for tenant in results if tenant is not None]
    assert len(winners) == 1
    winner = winners[0]
    loser = "b" if winner == "a" else "a"
    assert store.get_jit_grant(grant_id, tenant_id=winner).tenant_id == winner
    assert store.get_jit_grant(grant_id, tenant_id=loser) is None
