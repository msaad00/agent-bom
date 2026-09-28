"""Shared job identity, transaction and restart contracts on primary backends."""

import os
from contextlib import contextmanager
from uuid import uuid4

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore


@contextmanager
def tenant(value):
    token = set_current_tenant(value)
    try:
        yield
    finally:
        reset_current_tenant(token)


def job(tenant_id, job_id="same"):
    return ScanJob(
        job_id=job_id,
        tenant_id=tenant_id,
        created_at="2026-09-28T12:00:00Z",
        request=ScanRequest(),
        child_job_ids=["child"],
        target={"kind": "cloud", "name": "test"},
    )


@pytest.fixture(
    params=[
        "memory",
        "sqlite",
        pytest.param(
            "postgres", marks=pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")
        ),
    ]
)
def store(request, tmp_path):
    if request.param == "memory":
        yield InMemoryJobStore()
    elif request.param == "sqlite":
        yield SQLiteJobStore(str(tmp_path / "jobs.db"))
    else:
        from agent_bom.api.postgres_common import _new_application_pool
        from agent_bom.api.postgres_job_store import PostgresJobStore

        pool = _new_application_pool(min_size=1, max_size=3)
        try:
            yield PostgresJobStore(pool)
        finally:
            pool.close()


def test_job_roundtrip_update_and_insert_once(store):
    owner = "jobs-" + uuid4().hex
    original = job(owner, uuid4().hex)
    with tenant(owner):
        store.put(original)
        assert store.get(original.job_id, tenant_id=owner) == original
        updated = original.model_copy(update={"status": JobStatus.DONE, "completed_at": "2026-09-28T13:00:00Z"})
        store.put(updated)
        assert store.put_many_if_absent_atomic([original]) == []
        assert store.get(original.job_id, tenant_id=owner) == updated
        assert store.delete(original.job_id, tenant_id=owner)


def test_same_job_id_is_independent_per_tenant(store):
    a, b, ident = uuid4().hex, uuid4().hex, uuid4().hex
    for owner in (a, b):
        with tenant(owner):
            assert store.put_many_if_absent_atomic([job(owner, ident)]) == [ident]
    for owner in (a, b):
        with tenant(owner):
            assert store.get(ident, tenant_id=owner).tenant_id == owner
    with tenant(a):
        assert store.delete(ident, tenant_id=a)
    with tenant(b):
        assert store.get(ident, tenant_id=b).tenant_id == b
        store.delete(ident, tenant_id=b)


def test_sqlite_legacy_upgrade_preserves_payload_and_restart(tmp_path):
    import sqlite3

    path = str(tmp_path / "legacy.db")
    original = job("legacy")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE jobs (job_id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at TEXT NOT NULL, "
            "completed_at TEXT, tenant_id TEXT NOT NULL, data TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO jobs VALUES (?,?,?,?,?,?)",
            (original.job_id, original.status.value, original.created_at, None, original.tenant_id, original.model_dump_json()),
        )
    for _ in range(2):
        reopened = SQLiteJobStore(path)
        assert reopened.get("same", tenant_id="legacy") == original
        assert reopened.list_summary(tenant_id="legacy")[0]["child_job_ids"] == ["child"]
        reopened.put(job("other"))
    assert reopened.get("same", tenant_id="legacy") == original
    assert reopened.get("same", tenant_id="other").tenant_id == "other"


def test_hot_cache_keeps_equal_ids_tenant_scoped(monkeypatch):
    from agent_bom.api import stores

    monkeypatch.setattr(stores, "_jobs", {})
    first, second = job("a"), job("b")
    stores._jobs_put(first.job_id, first)
    stores._jobs_put(second.job_id, second)
    assert stores._jobs_get("same", tenant_id="a") == first
    assert stores._jobs_get("same", tenant_id="b") == second
    assert stores._jobs_pop("same", tenant_id="a") == first
    assert stores._jobs_get("same", tenant_id="b") == second


def test_explicit_maintenance_delete_covers_equal_ids(store):
    a, b, ident = uuid4().hex, uuid4().hex, uuid4().hex
    for owner in (a, b):
        with tenant(owner):
            store.put(job(owner, ident))
    with pytest.raises(ValueError, match="Ambiguous"):
        store.get(ident, all_tenants=True)
    assert store.delete(ident, all_tenants=True)
    for owner in (a, b):
        with tenant(owner):
            assert store.get(ident, tenant_id=owner) is None
