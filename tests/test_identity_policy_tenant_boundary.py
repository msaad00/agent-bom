"""Conditional policy authority is enforced below HTTP routes."""

from copy import deepcopy
from dataclasses import replace

import pytest

from agent_bom.api.agent_identity_store import (
    InMemoryAgentIdentityStore,
    SQLiteAgentIdentityStore,
    create_conditional_policy,
    set_conditional_policy_status,
)


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return InMemoryAgentIdentityStore() if request.param == "memory" else SQLiteAgentIdentityStore(str(tmp_path / "policy.db"))


def create(store, tenant="a"):
    return create_conditional_policy(store, tenant_id=tenant, name="guard", tools=["read_repo"], allowed_groups=["operators"])


def test_exact_id_and_status_change_require_tenant_authority(store):
    policy = create(store)
    assert store.get_conditional_policy(policy.policy_id, tenant_id="b") is None
    assert set_conditional_policy_status(store, policy.policy_id, tenant_id="b", status="disabled") is None
    assert store.get_conditional_policy(policy.policy_id, tenant_id="a").status == "active"
    assert set_conditional_policy_status(store, policy.policy_id, tenant_id="a", status="disabled").status == "disabled"


def test_policy_id_cannot_be_taken_over_by_another_tenant(store):
    policy = create(store)
    with pytest.raises(ValueError):
        store.put_conditional_policy(policy, tenant_id="b")
    with pytest.raises(ValueError):
        store.put_conditional_policy(replace(policy, tenant_id="b"), tenant_id="b")
    assert store.get_conditional_policy(policy.policy_id, tenant_id="a") == policy


@pytest.mark.parametrize("tenant", [None, "", " "])
def test_missing_tenant_is_rejected_before_access(store, tenant):
    policy = create(store)
    with pytest.raises(ValueError):
        store.get_conditional_policy(policy.policy_id, tenant_id=tenant)
    with pytest.raises(ValueError):
        store.put_conditional_policy(policy, tenant_id=tenant)
    with pytest.raises(ValueError):
        create(store, tenant)
    with pytest.raises(ValueError):
        store.list_conditional_policies(tenant)


def test_mutable_policy_conditions_are_not_shared_with_storage(store):
    policy = create(store)
    original = deepcopy(policy)
    policy.allowed_groups.append("intruder")
    policy.tenant_id = "b"
    listed = store.list_conditional_policies("a")[0]
    listed.allowed_groups.append("second-intruder")
    listed.tools.clear()
    assert store.get_conditional_policy(original.policy_id, tenant_id="a") == original


def test_rejected_sqlite_takeover_preserves_policy_after_reopen(tmp_path):
    path = str(tmp_path / "restart.db")
    first = SQLiteAgentIdentityStore(path)
    policy = create(first)
    with pytest.raises(ValueError):
        first.put_conditional_policy(replace(policy, tenant_id="b"), tenant_id="b")
    set_conditional_policy_status(first, policy.policy_id, tenant_id="a", status="disabled")
    second = SQLiteAgentIdentityStore(path)
    assert second.get_conditional_policy(policy.policy_id, tenant_id="a").status == "disabled"
    assert second.get_conditional_policy(policy.policy_id, tenant_id="b") is None


def test_foreign_payload_is_rejected(tmp_path):
    import json
    from dataclasses import asdict

    store = SQLiteAgentIdentityStore(str(tmp_path / "corrupt.db"))
    policy = create(store)
    store._conn.execute(
        "UPDATE agent_conditional_access_policies SET data = ? WHERE policy_id = ?",
        (json.dumps(asdict(replace(policy, tenant_id="b"))), policy.policy_id),
    )
    store._conn.commit()
    with pytest.raises(ValueError):
        store.get_conditional_policy(policy.policy_id, tenant_id="a")


def test_wrong_adapter_record_cannot_reach_mutation():
    class WrongStore:
        def get_conditional_policy(self, policy_id, *, tenant_id):
            return create(InMemoryAgentIdentityStore(), "b")

        def put_conditional_policy(self, policy, *, tenant_id):
            pytest.fail("foreign policy reached write")

    with pytest.raises(ValueError):
        set_conditional_policy_status(WrongStore(), "foreign", tenant_id="a", status="disabled")


def test_live_postgres_policy_authority_and_rls():
    import os
    from uuid import uuid4

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires an isolated, migrated Postgres contract database")
    from psycopg.errors import InsufficientPrivilege

    from agent_bom.api.postgres_agent_identity import PostgresAgentIdentityStore
    from agent_bom.api.postgres_common import _new_application_pool, reset_current_tenant, set_current_tenant

    tenant_a, tenant_b = f"policy-a-{uuid4()}", f"policy-b-{uuid4()}"
    pool = _new_application_pool(min_size=1, max_size=2)
    store = PostgresAgentIdentityStore(pool)
    context = set_current_tenant(tenant_a)
    try:
        with pool.connection() as conn:
            is_super, bypass = conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
        assert not is_super and not bypass
        policy = create(store, tenant_a)
        assert store.get_conditional_policy(policy.policy_id, tenant_id=tenant_b) is None
        assert set_conditional_policy_status(store, policy.policy_id, tenant_id=tenant_b, status="disabled") is None
        other_context = set_current_tenant(tenant_b)
        try:
            assert store.get_conditional_policy(policy.policy_id, tenant_id=tenant_a) is None
            with pytest.raises((ValueError, InsufficientPrivilege)):
                store.put_conditional_policy(replace(policy, tenant_id=tenant_b), tenant_id=tenant_b)
        finally:
            reset_current_tenant(other_context)
        assert store.get_conditional_policy(policy.policy_id, tenant_id=tenant_a).status == "active"
        assert set_conditional_policy_status(store, policy.policy_id, tenant_id=tenant_a, status="disabled").status == "disabled"
    finally:
        reset_current_tenant(context)
        pool.close()


def test_policy_evaluation_rejects_foreign_adapter_results():
    from agent_bom.api.identity_policies import AccessContext, evaluate_conditional_access_for_request

    class WrongStore:
        def list_conditional_policies(self, tenant_id, **kwargs):
            return [create(InMemoryAgentIdentityStore(), "b")]

    with pytest.raises(ValueError):
        evaluate_conditional_access_for_request(WrongStore(), tenant_id="a", ctx=AccessContext())


def test_concurrent_tenants_cannot_claim_same_policy_id(store):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    template = create(InMemoryAgentIdentityStore())
    barrier = Barrier(2)

    def claim(tenant):
        barrier.wait(timeout=5)
        try:
            store.put_conditional_policy(replace(template, tenant_id=tenant), tenant_id=tenant)
        except ValueError:
            return None
        return tenant

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(claim, ["a", "b"]))
    winners = [tenant for tenant in results if tenant is not None]
    assert len(winners) == 1
    winner = winners[0]
    loser = "b" if winner == "a" else "a"
    assert store.get_conditional_policy(template.policy_id, tenant_id=winner).tenant_id == winner
    assert store.get_conditional_policy(template.policy_id, tenant_id=loser) is None
