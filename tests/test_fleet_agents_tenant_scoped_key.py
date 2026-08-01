"""One tenant may not squat the fleet identity of another.

``fleet_agents`` was keyed ``PRIMARY KEY (agent_id)`` — no tenant component —
while ``PostgresFleetStore.put`` upserts ``ON CONFLICT (agent_id) DO UPDATE``.
Postgres finds the conflicting row through the unique index, which is NOT
RLS-filtered, so the ``DO UPDATE`` targets a row the second tenant cannot see
and the write is rejected by the row-level security policy.

``canonical_ids.canonical_agent_id`` is a UUIDv5 over content with no tenant
component, so two customers running a stock agent of the same type collide on
sight. The first tenant to register wins permanently and the second is denied
its own agent.

The key must be tenant-scoped. These tests are the cross-tenant isolation guard:
both rows persist, neither leaks, and same-tenant re-registration still upserts
rather than duplicating.
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="AGENT_BOM_POSTGRES_URL is required for the live fleet tenant-isolation contract",
)


@pytest.fixture
def fleet_store():
    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_fleet_store import PostgresFleetStore

    postgres_common.reset_pool()
    token = set_current_tenant("bootstrap")
    store = PostgresFleetStore()
    reset_current_tenant(token)
    try:
        yield store
    finally:
        pool = postgres_common._pool
        if pool is not None:
            pool.close()
        postgres_common.reset_pool()


def agent_for(tenant: str, agent_id: str, *, name: str | None = None, trust: float = 0.0):
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState

    return FleetAgent(
        agent_id=agent_id,
        canonical_id=agent_id,
        name=name or f"stock-agent-{tenant}",
        agent_type="claude-desktop",
        lifecycle_state=FleetLifecycleState.DISCOVERED,
        trust_score=trust,
        tenant_id=tenant,
        created_at="2026-08-01T00:00:00Z",
        updated_at="2026-08-01T00:00:00Z",
    )


def as_tenant(tenant: str):
    from agent_bom.api.postgres_common import set_current_tenant

    return set_current_tenant(tenant)


def test_two_tenants_register_the_same_canonical_agent_id(fleet_store):
    """The shipped defect: tenant B's registration was rejected outright."""
    from agent_bom.api.postgres_common import reset_current_tenant

    shared_id = f"CANON-AGENT-{uuid4().hex[:8]}"
    tenant_a = f"tenant-a-{uuid4().hex[:8]}"
    tenant_b = f"tenant-b-{uuid4().hex[:8]}"

    token = as_tenant(tenant_a)
    try:
        fleet_store.put(agent_for(tenant_a, shared_id))
    finally:
        reset_current_tenant(token)

    token = as_tenant(tenant_b)
    try:
        fleet_store.put(agent_for(tenant_b, shared_id))
    finally:
        reset_current_tenant(token)

    token = as_tenant(tenant_a)
    try:
        seen_by_a = fleet_store.get(shared_id, tenant_id=tenant_a)
    finally:
        reset_current_tenant(token)

    token = as_tenant(tenant_b)
    try:
        seen_by_b = fleet_store.get(shared_id, tenant_id=tenant_b)
    finally:
        reset_current_tenant(token)

    assert seen_by_a is not None, "tenant A lost its agent to tenant B"
    assert seen_by_b is not None, "tenant B was denied registration of its own agent"
    assert seen_by_a.tenant_id == tenant_a
    assert seen_by_b.tenant_id == tenant_b
    assert seen_by_a.name != seen_by_b.name


def test_same_tenant_re_registration_still_upserts(fleet_store):
    """Paired guard: tenant-scoping the key may not turn upsert into insert."""
    from agent_bom.api.postgres_common import reset_current_tenant

    agent_id = f"CANON-AGENT-{uuid4().hex[:8]}"
    tenant = f"tenant-{uuid4().hex[:8]}"

    token = as_tenant(tenant)
    try:
        fleet_store.put(agent_for(tenant, agent_id, name="first", trust=1.0))
        fleet_store.put(agent_for(tenant, agent_id, name="second", trust=9.0))
        stored = fleet_store.get(agent_id, tenant_id=tenant)
        listed = [row for row in fleet_store.list_by_tenant(tenant) if row.agent_id == agent_id]
    finally:
        reset_current_tenant(token)

    assert stored is not None
    assert stored.name == "second"
    assert stored.trust_score == 9.0
    assert len(listed) == 1, "re-registration duplicated the agent instead of updating it"


def test_one_tenants_delete_does_not_remove_anothers_agent(fleet_store):
    from agent_bom.api.postgres_common import reset_current_tenant

    shared_id = f"CANON-AGENT-{uuid4().hex[:8]}"
    tenant_a = f"tenant-a-{uuid4().hex[:8]}"
    tenant_b = f"tenant-b-{uuid4().hex[:8]}"

    for tenant in (tenant_a, tenant_b):
        token = as_tenant(tenant)
        try:
            fleet_store.put(agent_for(tenant, shared_id))
        finally:
            reset_current_tenant(token)

    token = as_tenant(tenant_a)
    try:
        assert fleet_store.delete(shared_id, tenant_id=tenant_a) is True
    finally:
        reset_current_tenant(token)

    token = as_tenant(tenant_b)
    try:
        survivor = fleet_store.get(shared_id, tenant_id=tenant_b)
    finally:
        reset_current_tenant(token)

    assert survivor is not None, "deleting tenant A's agent removed tenant B's"
    assert survivor.tenant_id == tenant_b


def test_the_unique_key_on_fleet_agents_is_tenant_scoped():
    """Schema authority: no unique index on ``fleet_agents`` may omit the tenant.

    A row-level fix alone is not enough — the physical key is what Postgres
    uses to find the conflicting row, and it is what makes the RLS rejection
    happen in the first place.
    """
    import psycopg

    admin_url = os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL")
    if not admin_url:
        pytest.skip("AGENT_BOM_POSTGRES_ADMIN_URL is required to inspect index definitions")

    with psycopg.connect(admin_url) as conn:
        rows = conn.execute(
            """
            SELECT i.relname,
                   ARRAY(
                     SELECT pg_get_indexdef(x.indexrelid, k + 1, true)
                       FROM generate_subscripts(x.indkey, 1) AS k
                      ORDER BY k
                   )
              FROM pg_index x
              JOIN pg_class i ON i.oid = x.indexrelid
             WHERE x.indrelid = 'public.fleet_agents'::regclass
               AND x.indisunique
            """
        ).fetchall()

    assert rows, "fleet_agents has no unique key at all"
    for index_name, columns in rows:
        assert "tenant_id" in columns, f"{index_name} is a tenant-less unique key over {columns}"
