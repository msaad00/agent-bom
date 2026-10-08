"""Job payloads are reused only for the exact committed row version, per tenant."""

from __future__ import annotations

import os
from contextlib import contextmanager
from uuid import uuid4

import pytest

from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.storage.job_payload_cache import JobPayloadCache


def test_cache_returns_only_exact_tokens_and_lists_them_per_tenant():
    cache = JobPayloadCache(max_bytes=1_000)
    cache.put("alpha", "alpha\x1fjob\x1f10\x1f5", "{...}")
    cache.put("beta", "beta\x1fjob\x1f10\x1f5", "{beta}")
    assert cache.get("alpha\x1fjob\x1f10\x1f5") == "{...}"
    assert cache.get("alpha\x1fjob\x1f11\x1f5") is None
    assert cache.tokens("alpha") == ["alpha\x1fjob\x1f10\x1f5"]
    assert sorted(cache.tokens(None)) == ["alpha\x1fjob\x1f10\x1f5", "beta\x1fjob\x1f10\x1f5"]


def test_cache_is_byte_bounded_and_never_holds_an_oversized_payload():
    cache = JobPayloadCache(max_bytes=10)
    cache.put("t", "a", "x" * 6)
    cache.put("t", "b", "y" * 6)
    assert cache.get("a") is None
    assert cache.get("b") == "y" * 6
    cache.put("t", "c", "z" * 11)
    assert cache.get("c") is None
    assert cache.tokens("t") == ["b"]


def test_disabled_cache_holds_nothing():
    cache = JobPayloadCache(max_bytes=0)
    cache.put("t", "a", "x")
    cache.put("t", "empty", "")
    assert cache.get("a") is None and cache.tokens("t") == []


def test_cache_budget_counts_serialized_utf8_bytes():
    cache = JobPayloadCache(max_bytes=4)
    cache.put("t", "oversized", "😀" * 4)
    assert cache.get("oversized") is None
    cache.put("t", "first", "éé")
    cache.put("t", "second", "é")
    assert cache.tokens("t") == ["second"]


def test_replacement_and_forget_release_the_recorded_byte_size():
    cache = JobPayloadCache(max_bytes=8)
    token = "t\x1fjob\x1f10\x1f8"
    cache.put("t", token, "😀😀")
    cache.put("t", token, "é")
    cache.put("t", "other", "ééé")
    assert cache.tokens("t") == [token, "other"]
    cache.forget("t", "job")
    cache.put("t", "new", "é")
    assert cache.tokens("t") == ["other", "new"]
    cache.put("t", "last", "é")
    assert cache.tokens("t") == ["new", "last"]


live = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")


@contextmanager
def tenant_scope(tenant):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant)
    try:
        yield
    finally:
        reset_current_tenant(token)


def _job(tenant, value):
    return ScanJob(
        job_id="shared-id",
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at="2026-10-08T00:00:00Z",
        request=ScanRequest(),
        result={"value": value},
    )


@pytest.fixture
def replicas():
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_job_store import PostgresJobStore

    pools = [_new_application_pool(min_size=1, max_size=2) for _ in range(2)]
    try:
        yield tuple(PostgresJobStore(pool=pool) for pool in pools)
    finally:
        for pool in pools:
            pool.close()


@live
def test_unchanged_rows_reuse_payload_and_other_replica_writes_invalidate(replicas):
    a, b = replicas
    tenant = "payload-" + uuid4().hex
    with tenant_scope(tenant):
        a.put(_job(tenant, 1))
        assert a.list_all(tenant_id=tenant)[0].result == {"value": 1}
        fetched = a._payloads.fetched
        assert a.list_all(tenant_id=tenant)[0].result == {"value": 1}
        assert a.get("shared-id", tenant_id=tenant).result == {"value": 1}
        assert a._payloads.fetched == fetched
        b.put(_job(tenant, 2))
        assert a.list_all(tenant_id=tenant)[0].result == {"value": 2}
        assert a.get("shared-id", tenant_id=tenant).result == {"value": 2}
        assert a._payloads.fetched == fetched + 1


@live
def test_cached_payload_never_crosses_tenants(replicas):
    a, _ = replicas
    first, second = ("payload-" + uuid4().hex for _ in range(2))
    with tenant_scope(first):
        a.put(_job(first, "first"))
        assert a.list_all(tenant_id=first)[0].result == {"value": "first"}
    with tenant_scope(second):
        assert a.list_all(tenant_id=second) == []
        assert a.get("shared-id", tenant_id=second) is None
        a.put(_job(second, "second"))
        assert [job.result for job in a.list_all(tenant_id=second)] == [{"value": "second"}]
    with tenant_scope(first):
        assert [job.result for job in a.list_all(tenant_id=first)] == [{"value": "first"}]


@live
def test_returned_jobs_are_independent_objects(replicas):
    a, _ = replicas
    tenant = "payload-" + uuid4().hex
    with tenant_scope(tenant):
        a.put(_job(tenant, 1))
        a.list_all(tenant_id=tenant)[0].result["value"] = "mutated"
        assert a.list_all(tenant_id=tenant)[0].result == {"value": 1}


@live
def test_one_read_scope_parses_an_unchanged_payload_once_and_sees_replica_writes(replicas):
    a, b = replicas
    tenant = "payload-" + uuid4().hex
    with tenant_scope(tenant):
        a.put(_job(tenant, 1))
        with finding_read_scope():
            listed = a.list_all(tenant_id=tenant)[0]
            assert a.get("shared-id", tenant_id=tenant) is listed
            assert a.list_all(tenant_id=tenant)[0] is listed
            b.put(_job(tenant, 2))
            assert a.list_all(tenant_id=tenant)[0].result == {"value": 2}
            assert a.get("shared-id", tenant_id=tenant).result == {"value": 2}
        assert a.list_all(tenant_id=tenant)[0] is not a.list_all(tenant_id=tenant)[0]


@live
def test_one_read_scope_never_shares_jobs_across_tenants(replicas):
    a, _ = replicas
    first, second = ("payload-" + uuid4().hex for _ in range(2))
    with tenant_scope(first):
        a.put(_job(first, "same"))
    with tenant_scope(second):
        a.put(_job(second, "same"))
    with finding_read_scope():
        with tenant_scope(first):
            mine = a.list_all(tenant_id=first)
        with tenant_scope(second):
            theirs = a.list_all(tenant_id=second)
            assert a.get("shared-id", tenant_id=second).tenant_id == second
    assert [job.tenant_id for job in mine] == [first]
    assert [job.tenant_id for job in theirs] == [second]
