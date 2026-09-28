"""Tenant, transaction and concurrent observation contracts for current findings."""

import os
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgres", marks=pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")
        ),
    ]
)
def store(request, tmp_path):
    if request.param == "sqlite":
        yield SQLiteComplianceHubStore(str(tmp_path / "current.db"))
    else:
        from agent_bom.api.postgres_common import _new_application_pool
        from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

        pool = _new_application_pool(min_size=1, max_size=4)
        try:
            yield PostgresComplianceHubStore(pool)
        finally:
            pool.close()


def observe(store, tenant, batch, *, findings=None):
    context = set_current_tenant(tenant)
    try:
        store.upsert_current_batch(
            tenant,
            findings or [{"id": "finding", "canonical_id": "current", "severity": "high"}],
            observed_at="2026-09-28T12:00:00Z",
            batch_id=batch,
            source="connector",
        )
    finally:
        reset_current_tenant(context)


def test_distinct_concurrent_observations_do_not_lose_scan_count(store, monkeypatch):
    from agent_bom.api import finding_lifecycle

    tenant = "current-" + uuid4().hex
    observe(store, tenant, "initial")
    original = finding_lifecycle.apply_observation_to_current
    first_read = threading.Event()
    release_first = threading.Event()
    calls = 0
    lock = threading.Lock()

    def pause_first(*args, **kwargs):
        nonlocal calls
        with lock:
            calls += 1
            first = calls == 1
        if first:
            first_read.set()
            assert release_first.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(finding_lifecycle, "apply_observation_to_current", pause_first)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(observe, store, tenant, "first")
        assert first_read.wait(10)
        second = executor.submit(observe, store, tenant, "second")
        try:
            second.result(timeout=1)
        except TimeoutError:
            pass
        finally:
            release_first.set()
        first.result(timeout=10)
        second.result(timeout=10)
    context = set_current_tenant(tenant)
    try:
        assert store.get_current(tenant, "finding")["scan_count"] == 3
    finally:
        reset_current_tenant(context)


def test_current_page_count_and_rows_share_sqlite_snapshot(tmp_path):
    reader = SQLiteComplianceHubStore(str(tmp_path / "snapshot.db"))
    writer = SQLiteComplianceHubStore(str(tmp_path / "snapshot.db"))
    observe(reader, "tenant", "one")
    inserted = False

    def concurrent_insert(sql):
        nonlocal inserted
        if not inserted and "SELECT canonical_id, first_seen" in sql:
            inserted = True
            observe(writer, "tenant", "two", findings=[{"id": "other", "severity": "high"}])

    reader._conn.set_trace_callback(concurrent_insert)
    try:
        rows, total, _ = reader.list_current_page("tenant", limit=10)
        assert inserted and total == len(rows) == 1
    finally:
        reader._conn.set_trace_callback(None)
    assert reader.list_current_page("tenant", limit=10)[1] == 2


@pytest.mark.parametrize("tenant", [None, "", " ", 42])
def test_current_operations_reject_invalid_tenants_before_access(store, tenant):
    operations = [
        lambda: store.get_current(tenant, "id"),
        lambda: store.lookup_current_ids(tenant, []),
        lambda: store.list_current_page(tenant, limit=1),
        lambda: store.upsert_current_batch(tenant, [], observed_at="2026-09-28T12:00:00Z", batch_id="batch"),
        lambda: store.reconcile_current_absent(tenant, present_canonical_ids=set(), observed_at="2026-09-28T12:00:00Z"),
    ]
    for operation in operations:
        with pytest.raises(ValueError):
            operation()


def test_failure_after_observation_rolls_back_entire_ingest(store, monkeypatch):
    from agent_bom.api.storage import finding_current_writes
    from agent_bom.api.storage.sql import PostgresBackend, SQLiteBackend

    tenant = "rollback-" + uuid4().hex
    payload = {
        "id": "new",
        "severity": "high",
        "source": "connector",
        "cve_id": "CVE-2026-3513",
        "summary": "private rollback reference",
        "owasp_tags": ["LLM01"],
        "origin": "bulk_ingest",
    }
    token = set_current_tenant(tenant)
    try:
        original = finding_current_writes.current_upsert

        def fail_after_observation(*args):
            raise RuntimeError("injected after observation")

        monkeypatch.setattr(finding_current_writes, "current_upsert", fail_after_observation)
        with pytest.raises(RuntimeError, match="injected"):
            store.ingest_batch_atomic(
                tenant,
                [payload],
                observed_at="2026-09-28T12:00:00Z",
                batch_id="same-retry",
                source="connector",
                reconcile_absent=True,
                present_canonical_ids={"new"},
            )
        backend = PostgresBackend(store._pool) if hasattr(store, "_pool") else SQLiteBackend(store._db_path)
        with backend.transaction(read_only=True) as tx:
            for table in (
                "compliance_hub_findings",
                "hub_findings_current",
                "hub_findings_current_observations",
                "hub_cve_intel",
                "hub_framework_refs",
                "hub_overview_revisions",
            ):
                assert tx.execute(f"SELECT COUNT(*) FROM {table} WHERE tenant_id = ?", (tenant,)).fetchone()[0] == 0
        assert store.count(tenant) == store.overview_evidence_revision(tenant) == 0
        monkeypatch.setattr(finding_current_writes, "current_upsert", original)
        for _ in range(2):
            assert store.ingest_batch_atomic(
                tenant,
                [payload],
                observed_at="2026-09-28T12:00:00Z",
                batch_id="same-retry",
                source="connector",
                reconcile_absent=False,
                present_canonical_ids={"new"},
            ) == (1, 0)
        assert store.get_current(tenant, "new")["scan_count"] == 1
        assert store.list(tenant)[0]["summary"] == payload["summary"]
    finally:
        reset_current_tenant(token)


def test_current_lookup_and_reconcile_keep_same_ids_in_other_tenants(store):
    a, b = "scope-" + uuid4().hex, "scope-" + uuid4().hex
    observe(store, a, "first")
    observe(store, b, "first")
    token = set_current_tenant(a)
    try:
        assert store.lookup_current_ids(a, ["finding", "absent"]) == {"finding"}
        assert store.lookup_current_ids(a, ["finding"], origin="absent") == set()
        assert store.reconcile_current_absent(a, present_canonical_ids=set(), observed_at="2026-09-28T13:00:00Z") == 1
        assert store.get_current(a, "finding")["status"] == "resolved"
    finally:
        reset_current_tenant(token)
    token = set_current_tenant(b)
    try:
        assert store.get_current(b, "finding")["status"] == "open"
        if hasattr(store, "_pool"):
            assert store.get_current(a, "finding") is None
            assert store.lookup_current_ids(a, ["finding"]) == set()
            assert store.list_current_page(a, limit=10) == ([], 0, None)
    finally:
        reset_current_tenant(token)


@pytest.mark.parametrize("tenant", [None, "", " ", 42])
def test_memory_current_operations_reject_invalid_tenants(tenant):
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore

    test_current_operations_reject_invalid_tenants_before_access(InMemoryComplianceHubStore(), tenant)
