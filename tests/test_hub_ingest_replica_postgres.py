"""Real application-role PostgreSQL replicas, rollback and RLS contracts."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="private Postgres required")


@pytest.fixture
def pg_pool():
    from psycopg_pool import ConnectionPool

    from agent_bom.api.postgres_common import resolve_postgres_secret, resolve_postgres_url

    password = resolve_postgres_secret()
    kwargs = {"password": password} if password is not None else {}
    pool = ConnectionPool(resolve_postgres_url(), kwargs=kwargs, min_size=1, max_size=5, open=True)
    yield pool
    pool.close()


def test_postgres_replicas_concurrent_totals_restart_clear_and_tenant_isolation(pg_pool):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    tenant = "replica-" + uuid4().hex
    barrier = Barrier(4)

    def writer(number):
        store = PostgresComplianceHubStore(pg_pool)
        token = set_current_tenant(tenant)
        try:
            barrier.wait(timeout=20)
            return [
                store.add(
                    tenant, [{"id": f"{number}-{batch}-{i}", "severity": "high"} for i in range(10)] + [{"id": "shared"}, {"id": "shared"}]
                )
                for batch in range(10)
            ]
        finally:
            reset_current_tenant(token)

    with ThreadPoolExecutor(max_workers=4) as executor:
        totals = list(executor.map(writer, range(4)))
    assert max(map(max, totals)) == 401
    assert all(values == sorted(values) for values in totals)
    store = PostgresComplianceHubStore(pg_pool)
    token = set_current_tenant(tenant)
    try:
        assert store.add(tenant, []) == store.count(tenant) == 401
        assert store.clear(tenant) == 401
        assert PostgresComplianceHubStore(pg_pool).add(tenant, []) == 0
        assert store.add(tenant, [{"id": "replacement"}]) == 1
    finally:
        reset_current_tenant(token)
    other = tenant + "-other"
    token = set_current_tenant(other)
    try:
        assert store.add(other, [{"id": "replacement"}]) == 1
        assert store.count(tenant) == 0
    finally:
        reset_current_tenant(token)


def test_postgres_state_rolls_back_with_current_failure(pg_pool, monkeypatch):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    store = PostgresComplianceHubStore(pg_pool)
    tenant = "rollback-" + uuid4().hex
    token = set_current_tenant(tenant)
    try:
        assert store.add(tenant, [{"id": "existing"}]) == 1

        def fail(*args, **kwargs):
            raise RuntimeError("injected current failure")

        monkeypatch.setattr(store, "_write_current_batch", fail)
        with pytest.raises(RuntimeError, match="injected"):
            store.ingest_batch_atomic(
                tenant,
                [{"id": "new"}],
                observed_at="2026-09-28T00:00:00Z",
                batch_id="fail",
                source="test",
                reconcile_absent=False,
                present_canonical_ids=set(),
            )
        assert PostgresComplianceHubStore(pg_pool).add(tenant, []) == store.count(tenant) == 1
    finally:
        reset_current_tenant(token)


def test_postgres_state_rls_denies_unbound_reads_and_writes(pg_pool):
    import psycopg

    with pg_pool.connection() as conn:
        role = conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
        assert role == (False, False)
        assert conn.execute("SELECT * FROM hub_ledger_ingest_state").fetchall() == []
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("INSERT INTO hub_ledger_ingest_state VALUES (%s, 0, 1)", ("unbound-" + uuid4().hex,))
        conn.rollback()
