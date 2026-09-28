"""Backend parity and snapshot consistency for finding ledger reads."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, SQLiteComplianceHubStore
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant


@pytest.fixture(
    params=[
        "memory",
        "sqlite",
        pytest.param(
            "postgres", marks=pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private migrated Postgres")
        ),
    ]
)
def store(request, tmp_path):
    if request.param == "memory":
        yield InMemoryComplianceHubStore()
    elif request.param == "sqlite":
        yield SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    else:
        from agent_bom.api.postgres_common import _new_application_pool
        from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

        pool = _new_application_pool(min_size=1, max_size=2)
        with pool.connection() as conn:
            assert conn.execute("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone() == (False,)
        try:
            yield PostgresComplianceHubStore(pool)
        finally:
            pool.close()


@pytest.mark.parametrize("sort", ["ordinal", "cvss", "severity", "effective_reach"])
def test_ledger_pages_filter_and_preserve_tied_ingest_order(store, sort):
    tenant = "findings-" + uuid4().hex
    other = "findings-" + uuid4().hex
    rows = [
        {
            "id": f"finding-{i}",
            "severity": "high",
            "cvss_score": 7.0,
            "origin": "bulk_ingest",
            "batch_id": "scan-a",
            "title": f"Finding {i}",
        }
        for i in range(7)
    ]
    token = set_current_tenant(tenant)
    try:
        store.add(tenant, rows)
        store.add(tenant, [{"id": "excluded", "severity": "critical", "origin": "other", "scan_id": "scan-b"}])
        foreign = set_current_tenant(other)
        try:
            store.add(other, [{"id": "foreign", "severity": "high", "batch_id": "scan-a", "origin": "bulk_ingest"}])
        finally:
            reset_current_tenant(foreign)
        page, total = store.list_page(tenant, limit=3, offset=2, sort=sort, severity="HIGH", origin="bulk_ingest", scan_id="scan-a")
        assert total == 7
        assert [r["id"] for r in page] == ["finding-2", "finding-3", "finding-4"]
        assert store.list_page(tenant, limit=3, sort=sort, scan_id="missing") == ([], 0)
        assert store.list_page(tenant, limit=3, sort=sort, include_total=False)[1] is None
        assert store.count(tenant) == 8
        assert store.severity_breakdown(tenant)["high"] == 7
        assert len(store.list(tenant)) == 8
    finally:
        reset_current_tenant(token)


def test_count_and_page_use_one_sqlite_snapshot_during_concurrent_ingest(tmp_path):
    path = str(tmp_path / "snapshot.db")
    reader = SQLiteComplianceHubStore(path)
    writer = SQLiteComplianceHubStore(path)
    reader.add("tenant", [{"id": "before", "severity": "high"}])
    inserted = False

    def concurrent_insert(sql):
        nonlocal inserted
        if not inserted and sql.startswith("SELECT payload FROM compliance_hub_findings"):
            inserted = True
            writer.add("tenant", [{"id": "after", "severity": "high"}])

    reader._conn.set_trace_callback(concurrent_insert)
    try:
        page, total = reader.list_page("tenant", limit=10)
        assert inserted
        assert total == len(page) == 1
        assert page[0]["id"] == "before"
    finally:
        reader._conn.set_trace_callback(None)
    assert reader.count("tenant") == 2


@pytest.mark.parametrize("tenant", [None, "", " ", 42])
def test_ledger_reads_reject_missing_or_invalid_tenant(store, tenant):
    for method in (store.list, store.count, store.severity_breakdown, store.overview_evidence_revision):
        with pytest.raises(ValueError):
            method(tenant)
    with pytest.raises(ValueError):
        store.list_page(tenant, limit=1)


def test_postgres_reads_cannot_override_ambient_tenant(store):
    if not hasattr(store, "_pool"):
        pytest.skip("Postgres RLS contract")
    owner, foreign = "findings-" + uuid4().hex, "findings-" + uuid4().hex
    context = set_current_tenant(owner)
    try:
        store.add(owner, [{"id": "owned", "severity": "high"}])
        other = set_current_tenant(foreign)
        try:
            assert store.list(owner) == []
            assert store.list_page(owner, limit=10) == ([], 0)
            assert store.count(owner) == 0
            assert store.overview_evidence_revision(owner) == 0
            assert store.severity_breakdown(owner)["high"] == 0
        finally:
            reset_current_tenant(other)
        assert store.count(owner) == 1
    finally:
        reset_current_tenant(context)


def test_postgres_count_and_page_share_repeatable_read_snapshot(store):
    if not hasattr(store, "_pool"):
        pytest.skip("Postgres snapshot contract")
    from contextlib import contextmanager

    from agent_bom.api.storage.finding_reads import SqlFindingReads
    from agent_bom.api.storage.sql import PostgresBackend

    tenant = "findings-" + uuid4().hex
    context = set_current_tenant(tenant)
    try:
        store.add(tenant, [{"id": "before", "severity": "high"}])
        backend = PostgresBackend(store._pool)
        inserted = False

        class ReadBackend:
            dialect = "postgres"

            @contextmanager
            def transaction(self, **kwargs):
                nonlocal inserted
                with backend.transaction(**kwargs) as tx:
                    assert tx.execute("SHOW transaction_read_only").fetchone()[0] == "on"
                    assert tx.execute("SHOW transaction_isolation").fetchone()[0] == "repeatable read"

                    class Session:
                        def execute(self, sql, params=()):
                            nonlocal inserted
                            if not inserted and sql.startswith("SELECT payload FROM compliance_hub_findings"):
                                inserted = True
                                store.add(tenant, [{"id": "after", "severity": "high"}])
                            return tx.execute(sql, params)

                    yield Session()

        rows, total = SqlFindingReads(ReadBackend()).list_page(tenant, limit=10)
        assert inserted and total == len(rows) == 1
        assert rows[0]["id"] == "before"
        assert store.count(tenant) == 2
    finally:
        reset_current_tenant(context)
