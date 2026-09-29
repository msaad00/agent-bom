"""Independent writers must agree on committed totals and cursor ordinals."""

from __future__ import annotations

import pytest

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore


def finding(key: str) -> dict:
    return {"id": key, "canonical_id": key, "severity": "high", "source": "replica-contract"}


@pytest.fixture
def replicas(tmp_path):
    path = str(tmp_path / "hub.db")
    stores = [SQLiteComplianceHubStore(path), SQLiteComplianceHubStore(path)]
    yield stores
    for store in stores:
        store._conn.close()


def test_independent_writer_returns_the_committed_tenant_total(replicas):
    first, second = replicas
    assert first.add("tenant-a", [finding("first")]) == 1
    assert second.add("tenant-a", [finding("second")]) == 2
    assert first.add("tenant-a", [finding("third")]) == 3
    assert first.add("tenant-a", []) == second.add("tenant-a", []) == 3
    assert second.add("tenant-b", [finding("first")]) == 1


def test_independent_writers_do_not_reuse_cursor_ordinals(replicas):
    first, second = replicas
    first.add("tenant-a", [finding("first")])
    second.add("tenant-a", [finding("second")])
    first.add("tenant-a", [finding("third")])
    rows = first._conn.execute("SELECT ordinal FROM compliance_hub_findings WHERE tenant_id = ? ORDER BY ordinal", ("tenant-a",)).fetchall()
    assert rows == [(1,), (2,), (3,)]


def test_replica_empty_ingest_observes_another_replica_clear(replicas):
    first, second = replicas
    first.add("tenant-a", [finding("first")])
    assert second.clear("tenant-a") == 1
    assert first.add("tenant-a", []) == 0
    assert first.add("tenant-a", [finding("replacement")]) == 1


def _process_writer(path, number, ready, start, results):
    """Spawned workers have independent connections, schema init and counters."""
    store = SQLiteComplianceHubStore(path)
    ready.put(number)
    if not start.wait(20):
        raise RuntimeError("writer start timed out")
    totals = []
    for batch in range(10):
        rows = [finding(f"{number}-{batch}-{i}") for i in range(10)]
        total, _ = store.ingest_batch_atomic(
            "processes",
            [*rows, finding("shared"), finding("shared")],
            observed_at="2026-09-28T00:00:00Z",
            batch_id=f"{number}-{batch}",
            source="replica-contract",
            reconcile_absent=False,
            present_canonical_ids=set(),
        )
        totals.append(total)
    results.put(totals)
    store._conn.close()


def test_spawned_writers_and_restart_preserve_exact_count_and_paging(tmp_path):
    import multiprocessing

    ctx = multiprocessing.get_context("spawn")
    ready, results, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    path = str(tmp_path / "processes.db")
    workers = [ctx.Process(target=_process_writer, args=(path, n, ready, start, results)) for n in range(4)]
    try:
        for worker in workers:
            worker.start()
        for _ in workers:
            ready.get(timeout=30)
        start.set()
        totals = [results.get(timeout=60) for _ in workers]
        for worker in workers:
            worker.join(timeout=30)
            assert worker.exitcode == 0
        assert max(max(values) for values in totals) == 401
        assert all(values == sorted(values) for values in totals)
        store = SQLiteComplianceHubStore(path)
        assert store.add("processes", []) == store.count("processes") == 401
        seen, cursor = [], None
        while True:
            page, total, cursor = store.list_current_page("processes", limit=13, cursor=cursor, sort="ordinal")
            seen.extend(row["id"] for row in page)
            assert total in (None, 401)
            if not cursor:
                break
        assert len(seen) == len(set(seen)) == 401
        store._conn.close()
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
            worker.join(timeout=10)
        ready.close()
        results.close()


def test_skipped_input_offsets_and_duplicate_ids_do_not_reuse_ordinals(replicas):
    first, second = replicas
    assert first.add("offsets", [None, finding("a"), finding("a"), None, finding("b")]) == 2
    assert second.add("offsets", [finding("c")]) == 3
    assert first._conn.execute(
        "SELECT finding_id, ordinal FROM compliance_hub_findings WHERE tenant_id='offsets' ORDER BY ordinal"
    ).fetchall() == [("a", 2), ("b", 5), ("c", 6)]


def test_warm_batches_use_indexed_state_without_ledger_aggregate(replicas):
    first, _ = replicas
    first.add("warm", [finding(str(i)) for i in range(1000)])
    queries = []
    first._conn.set_trace_callback(queries.append)
    first.add("warm", [finding("new")])
    first.add("warm", [])
    first._conn.set_trace_callback(None)
    assert not any("COUNT(" in sql.upper() or "MAX(" in sql.upper() for sql in queries)
    plan = first._conn.execute(
        "EXPLAIN QUERY PLAN SELECT finding_count FROM hub_ledger_ingest_state WHERE tenant_id=?", ("warm",)
    ).fetchall()
    assert "USING INDEX" in str(plan)


def _legacy_database(path):
    store = SQLiteComplianceHubStore(str(path))
    for tenant in ("legacy-a", "legacy-b"):
        store.ingest_batch_atomic(
            tenant,
            [finding("a"), finding("b"), finding("c")],
            observed_at="2026-09-28T00:00:00Z",
            batch_id="legacy",
            source="replica-contract",
            reconcile_absent=False,
            present_canonical_ids=set(),
        )
    conn = store._conn
    with conn:
        conn.execute("DROP TABLE hub_ledger_ingest_state")
        conn.execute("DROP INDEX idx_hub_findings_tenant_order")
        conn.execute("CREATE INDEX idx_hub_findings_tenant_order ON compliance_hub_findings(tenant_id, ordinal)")
        conn.execute("UPDATE compliance_hub_findings SET ordinal=1 WHERE finding_id='b'")
        conn.execute("UPDATE hub_findings_current SET ledger_ordinal=1 WHERE ledger_finding_id='b'")
        conn.execute("UPDATE control_plane_schema_versions SET version=2 WHERE component='compliance_hub'")
    payloads = conn.execute("SELECT tenant_id, finding_id, payload FROM compliance_hub_findings ORDER BY 1,2").fetchall()
    conn.close()
    return payloads


def test_legacy_ordinal_repair_preserves_payloads_pointers_and_restart(tmp_path):
    path = tmp_path / "legacy.db"
    payloads = _legacy_database(path)
    store = SQLiteComplianceHubStore(str(path))
    assert store._conn.execute("SELECT tenant_id, finding_id, payload FROM compliance_hub_findings ORDER BY 1,2").fetchall() == payloads
    for tenant in ("legacy-a", "legacy-b"):
        assert store._conn.execute(
            "SELECT finding_id, ordinal FROM compliance_hub_findings WHERE tenant_id=? ORDER BY ordinal", (tenant,)
        ).fetchall() == [("a", 1), ("c", 3), ("b", 4)]
        assert store._conn.execute(
            "SELECT ledger_ordinal FROM hub_findings_current WHERE tenant_id=? AND ledger_finding_id='b'", (tenant,)
        ).fetchone() == (4,)
        assert store.add(tenant, []) == 3
    store._conn.close()
    restarted = SQLiteComplianceHubStore(str(path))
    assert restarted.add("legacy-a", [finding("d")]) == 4
    assert restarted._conn.execute(
        "SELECT ordinal FROM compliance_hub_findings WHERE tenant_id='legacy-a' AND finding_id='d'"
    ).fetchone() == (5,)
    restarted._conn.close()


def test_legacy_migration_failure_rolls_back_schema_and_ordinals(tmp_path, monkeypatch):
    import sqlite3

    from agent_bom.api import compliance_hub_store as module

    path = tmp_path / "rollback.db"
    _legacy_database(path)
    real = module.ensure_sqlite_ingest_state

    def fail_after_repair(conn):
        real(conn)
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr(module, "ensure_sqlite_ingest_state", fail_after_repair)
    with pytest.raises(RuntimeError, match="injected"):
        SQLiteComplianceHubStore(str(path))
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT version FROM control_plane_schema_versions WHERE component='compliance_hub'").fetchone() == (2,)
        assert conn.execute("SELECT ordinal FROM compliance_hub_findings WHERE finding_id='b'").fetchall() == [(1,), (1,)]
        assert conn.execute("SELECT name FROM sqlite_master WHERE name='hub_ledger_ingest_state'").fetchone() is None
    monkeypatch.setattr(module, "ensure_sqlite_ingest_state", real)
    store = SQLiteComplianceHubStore(str(path))
    assert store.add("legacy-a", []) == 3
    store._conn.close()


def test_failed_atomic_batch_rolls_back_durable_state(replicas, monkeypatch):
    first, second = replicas
    first.add("rollback", [finding("existing")])
    before = first._conn.execute("SELECT * FROM hub_ledger_ingest_state").fetchall()

    def fail(*args, **kwargs):
        raise RuntimeError("injected current write failure")

    monkeypatch.setattr(first, "_upsert_current_no_commit", fail)
    with pytest.raises(RuntimeError, match="injected"):
        first.ingest_batch_atomic(
            "rollback",
            [finding("new")],
            observed_at="2026-09-28T00:00:00Z",
            batch_id="fail",
            source="replica-contract",
            reconcile_absent=False,
            present_canonical_ids=set(),
        )
    assert second._conn.execute("SELECT * FROM hub_ledger_ingest_state").fetchall() == before
    assert second.add("rollback", []) == 1


def test_clear_waits_for_atomic_writer_and_preserves_next_ordinal(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    from agent_bom.api import compliance_hub_store as module

    path = str(tmp_path / "clear-race.db")
    SQLiteComplianceHubStore(path)._conn.close()
    entered, release, clearing = Event(), Event(), Event()
    real = module.write_ledger_batch

    def hold_writer(*args, **kwargs):
        result = real(*args, **kwargs)
        entered.set()
        assert release.wait(15)
        return result

    monkeypatch.setattr(module, "write_ledger_batch", hold_writer)

    def write():
        store = SQLiteComplianceHubStore(path)
        try:
            return store.add("clear-race", [finding("first")])
        finally:
            store._conn.close()

    # Construct the clearer before the writer owns the schema/ingest lock.
    clearer = SQLiteComplianceHubStore(path)

    def clear():
        clearing.set()
        try:
            return clearer.clear("clear-race")
        finally:
            clearer._conn.close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        pending_write = pool.submit(write)
        assert entered.wait(15)
        pending_clear = pool.submit(clear)
        assert clearing.wait(15)
        release.set()
        assert pending_write.result(timeout=15) == 1
        assert pending_clear.result(timeout=15) == 1
    monkeypatch.setattr(module, "write_ledger_batch", real)
    assert clearer.add("clear-race", []) == 0
    assert clearer.add("clear-race", [finding("after")]) == 1
    assert clearer._conn.execute("SELECT ordinal FROM compliance_hub_findings").fetchone() == (2,)
    clearer._conn.close()


@pytest.mark.parametrize("tenant", [None, "", " "])
def test_empty_ingest_requires_explicit_tenant(replicas, tenant):
    with pytest.raises(ValueError):
        replicas[0].add(tenant, [])
