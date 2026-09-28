"""Real RLS and dispatch recovery with tenant-colliding IDs."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.api.postgres_common import _new_application_pool, reset_current_tenant, set_current_tenant
from agent_bom.api.postgres_job_store import PostgresJobStore

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")


@pytest.fixture
def store():
    pool = _new_application_pool(min_size=1, max_size=4)
    try:
        yield PostgresJobStore(pool)
    finally:
        pool.close()


def seed(store, owner, ident):
    token = set_current_tenant(owner)
    try:
        record = ScanJob(job_id=ident, tenant_id=owner, created_at="2020-01-01T00:00:00Z", request=ScanRequest())
        store.put_many_and_enqueue_atomic([record], [record])
        return record
    finally:
        reset_current_tenant(token)


def test_colliding_dispatch_leases_survive_restart_and_fence_stale_owner(store):
    a, b, ident = uuid4().hex, uuid4().hex, uuid4().hex
    for owner in (a, b):
        seed(store, owner, ident)
    claimed = [store.claim_next("worker", 600), store.claim_next("worker", 600)]
    assert {j.tenant_id for j in claimed} == {a, b}
    claims = {(j.tenant_id, j.job_id): j._dispatch_claim_owner for j in claimed}
    with store._scope_connection(all_tenants=True) as conn:
        conn.execute("UPDATE scan_dispatch_queue SET lease_expires_at='2000-01-01T00:00:00Z' WHERE tenant_id=%s", (a,))
        conn.commit()
    # A new adapter represents a restarted replica; old owners never remove or
    # extend a successor's lease, even when both tenants use the same job ID.
    restarted = PostgresJobStore(store._pool)
    successor = restarted.claim_next("restarted", 600)
    assert successor.tenant_id == a
    assert successor._dispatch_claim_owner != claims[(a, ident)]
    restarted.renew_leases(claims, 900)
    restarted.complete_dispatch(ident, tenant_id=a, claim_owner=claims[(a, ident)])
    restarted.complete_dispatch(ident, tenant_id=b, claim_owner=successor._dispatch_claim_owner)
    with store._scope_connection(all_tenants=True) as conn:
        rows = conn.execute("SELECT tenant_id, claimed_by FROM scan_dispatch_queue WHERE job_id=%s", (ident,)).fetchall()
    assert dict(rows) == {a: successor._dispatch_claim_owner, b: claims[(b, ident)]}
    for owner, token in ((a, successor._dispatch_claim_owner), (b, claims[(b, ident)])):
        restarted.complete_dispatch(ident, tenant_id=owner, claim_owner=token)
        context = set_current_tenant(owner)
        try:
            restarted.delete(ident, tenant_id=owner)
        finally:
            reset_current_tenant(context)


def test_atomic_dispatch_failure_rolls_back_jobs_and_cis(store, monkeypatch):
    owner, ident = uuid4().hex, uuid4().hex
    original = store._put_on_connection

    def fail_after_insert(conn, job, **kwargs):
        original(conn, job, **kwargs)
        raise RuntimeError("injected after job persistence")

    monkeypatch.setattr(store, "_put_on_connection", fail_after_insert)
    with pytest.raises(RuntimeError, match="injected"):
        seed(store, owner, ident)
    context = set_current_tenant(owner)
    try:
        assert store.get(ident, tenant_id=owner) is None
        with store._scope_connection() as conn:
            assert (
                conn.execute("SELECT count(*) FROM scan_dispatch_queue WHERE tenant_id=%s AND job_id=%s", (owner, ident)).fetchone()[0] == 0
            )
    finally:
        reset_current_tenant(context)


def test_application_role_cannot_reference_foreign_job(store):
    import psycopg

    from agent_bom.api.postgres_common import _tenant_connection

    a, b, ident = uuid4().hex, uuid4().hex, uuid4().hex
    seed(store, a, ident)
    context = set_current_tenant(b)
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with _tenant_connection(store._pool) as conn:
                conn.execute("INSERT INTO scan_dispatch_queue(job_id,tenant_id,created_at) VALUES (%s,%s,%s)", (ident, b, "2020"))
        assert store.get(ident, tenant_id=a) is None
    finally:
        reset_current_tenant(context)
    context = set_current_tenant(a)
    try:
        store.delete(ident, tenant_id=a)
    finally:
        reset_current_tenant(context)


def test_concurrent_workers_claim_colliding_ids_once_each(store):
    from concurrent.futures import ThreadPoolExecutor

    owners, ident = [uuid4().hex for _ in range(3)], uuid4().hex
    for owner in owners:
        seed(store, owner, ident)
    with ThreadPoolExecutor(max_workers=3) as executor:
        claimed = list(executor.map(lambda worker: store.claim_next(worker, 600), ["one", "two", "three"]))
    assert {(j.tenant_id, j.job_id) for j in claimed} == {(owner, ident) for owner in owners}
    for j in claimed:
        store.complete_dispatch(j.job_id, tenant_id=j.tenant_id, claim_owner=j._dispatch_claim_owner)
        context = set_current_tenant(j.tenant_id)
        try:
            store.delete(j.job_id, tenant_id=j.tenant_id)
        finally:
            reset_current_tenant(context)
