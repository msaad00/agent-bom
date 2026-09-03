"""Tests for schedule store backends and cron scheduler."""

import asyncio
from datetime import datetime, timezone
from threading import Event, Thread
from unittest.mock import patch

from agent_bom.api import stores as _stores
from agent_bom.api.models import ScanJob, SourceKind, SourceRecord
from agent_bom.api.schedule_store import (
    InMemoryScheduleStore,
    ScanSchedule,
    SQLiteScheduleStore,
)
from agent_bom.api.scheduler import parse_cron_next, validate_cron_expression
from agent_bom.api.source_store import InMemorySourceStore
from agent_bom.api.store import InMemoryJobStore

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _make_schedule(
    schedule_id: str = "sched-1",
    name: str = "nightly-scan",
    cron: str = "0 */6 * * *",
    enabled: bool = True,
    next_run: str | None = "2025-01-01T00:00:00+00:00",
    tenant_id: str = "default",
) -> ScanSchedule:
    return ScanSchedule(
        schedule_id=schedule_id,
        name=name,
        cron_expression=cron,
        scan_config={"images": ["nginx:latest"]},
        enabled=enabled,
        next_run=next_run,
        created_at="2025-01-01T00:00:00+00:00",
        updated_at="2025-01-01T00:00:00+00:00",
        tenant_id=tenant_id,
    )


# ─── InMemoryScheduleStore ────────────────────────────────────────────────────


class TestInMemoryScheduleStore:
    def test_put_and_get(self):
        store = InMemoryScheduleStore()
        s = _make_schedule()
        store.put(s)
        assert store.get("sched-1") is not None
        assert store.get("sched-1").name == "nightly-scan"

    def test_get_missing(self):
        store = InMemoryScheduleStore()
        assert store.get("nonexistent") is None

    def test_delete(self):
        store = InMemoryScheduleStore()
        store.put(_make_schedule())
        assert store.delete("sched-1") is True
        assert store.get("sched-1") is None

    def test_delete_missing(self):
        store = InMemoryScheduleStore()
        assert store.delete("nonexistent") is False

    def test_list_all(self):
        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1"))
        store.put(_make_schedule("s2"))
        assert len(store.list_all()) == 2

    def test_list_all_empty(self):
        store = InMemoryScheduleStore()
        assert store.list_all() == []

    def test_list_due(self):
        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1", next_run="2025-01-01T00:00:00+00:00", enabled=True))
        store.put(_make_schedule("s2", next_run="2099-12-31T23:59:59+00:00", enabled=True))
        store.put(_make_schedule("s3", next_run="2025-01-01T00:00:00+00:00", enabled=False))
        due = store.list_due("2025-06-15T12:00:00+00:00")
        assert len(due) == 1
        assert due[0].schedule_id == "s1"

    def test_list_due_no_next_run(self):
        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1", next_run=None))
        assert store.list_due("2025-06-15T12:00:00+00:00") == []

    def test_upsert_overwrites(self):
        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1", name="original"))
        store.put(_make_schedule("s1", name="updated"))
        assert store.get("s1").name == "updated"
        assert len(store.list_all()) == 1


# ─── SQLiteScheduleStore ─────────────────────────────────────────────────────


class TestSQLiteScheduleStore:
    def test_put_and_get(self, tmp_path):
        store = SQLiteScheduleStore(str(tmp_path / "sched.db"))
        store.put(_make_schedule())
        got = store.get("sched-1")
        assert got is not None
        assert got.name == "nightly-scan"
        assert got.cron_expression == "0 */6 * * *"

    def test_get_missing(self, tmp_path):
        store = SQLiteScheduleStore(str(tmp_path / "sched.db"))
        assert store.get("nonexistent") is None

    def test_delete(self, tmp_path):
        store = SQLiteScheduleStore(str(tmp_path / "sched.db"))
        store.put(_make_schedule())
        assert store.delete("sched-1") is True
        assert store.get("sched-1") is None

    def test_delete_missing(self, tmp_path):
        store = SQLiteScheduleStore(str(tmp_path / "sched.db"))
        assert store.delete("nonexistent") is False

    def test_list_all(self, tmp_path):
        store = SQLiteScheduleStore(str(tmp_path / "sched.db"))
        store.put(_make_schedule("s1"))
        store.put(_make_schedule("s2"))
        assert len(store.list_all()) == 2

    def test_list_due(self, tmp_path):
        store = SQLiteScheduleStore(str(tmp_path / "sched.db"))
        store.put(_make_schedule("s1", next_run="2025-01-01T00:00:00+00:00", enabled=True))
        store.put(_make_schedule("s2", next_run="2099-12-31T23:59:59+00:00", enabled=True))
        store.put(_make_schedule("s3", next_run="2025-01-01T00:00:00+00:00", enabled=False))
        due = store.list_due("2025-06-15T12:00:00+00:00")
        assert len(due) == 1
        assert due[0].schedule_id == "s1"

    def test_upsert_overwrites(self, tmp_path):
        store = SQLiteScheduleStore(str(tmp_path / "sched.db"))
        store.put(_make_schedule("s1", name="original"))
        store.put(_make_schedule("s1", name="updated"))
        assert store.get("s1").name == "updated"

    def test_idempotent_init(self, tmp_path):
        """Creating store twice on same DB is safe."""
        db = str(tmp_path / "sched.db")
        SQLiteScheduleStore(db)
        store2 = SQLiteScheduleStore(db)
        store2.put(_make_schedule())
        assert store2.get("sched-1") is not None

    def test_uses_scan_schedules_table_name(self, tmp_path):
        import sqlite3

        db = tmp_path / "sched.db"
        store = SQLiteScheduleStore(str(db))
        store.put(_make_schedule())

        with sqlite3.connect(db) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "scan_schedules" in tables
        assert "schedules" not in tables

    def test_migrates_legacy_schedules_table(self, tmp_path):
        import sqlite3

        db = tmp_path / "sched.db"
        schedule = _make_schedule("legacy-sched", tenant_id="tenant-alpha")
        with sqlite3.connect(db) as conn:
            conn.execute(
                """
                CREATE TABLE schedules (
                    schedule_id TEXT PRIMARY KEY,
                    enabled INTEGER DEFAULT 1,
                    next_run TEXT,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    data TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "INSERT INTO schedules (schedule_id, enabled, next_run, tenant_id, data) VALUES (?, ?, ?, ?, ?)",
                (schedule.schedule_id, int(schedule.enabled), schedule.next_run, schedule.tenant_id, schedule.model_dump_json()),
            )

        store = SQLiteScheduleStore(str(db))

        assert store.get("legacy-sched", tenant_id="tenant-alpha") is not None


def test_source_schedule_resolves_canonical_source_request_and_links_job(monkeypatch):
    from agent_bom.api.server import _enqueue_scheduled_scan

    source_store = InMemorySourceStore()
    schedule_store = InMemoryScheduleStore()
    source_store.put(
        SourceRecord(
            source_id="source-repo",
            tenant_id="tenant-alpha",
            display_name="Repository",
            kind=SourceKind.SCAN_REPO,
            config={"scan_request": {"repo_url": "https://example.com/acme/repo"}},
        )
    )
    schedule_store.put(
        ScanSchedule(
            schedule_id="schedule-source",
            tenant_id="tenant-alpha",
            name="Repository schedule",
            cron_expression="* * * * *",
            scan_config={"source_id": "source-repo"},
        )
    )
    old_source_store = _stores._source_store
    old_schedule_store = _stores._schedule_store
    old_job_store = _stores._store
    _stores.set_source_store(source_store)
    _stores.set_schedule_store(schedule_store)
    _stores.set_job_store(InMemoryJobStore())
    captured = {}

    def _fake_enqueue(**kwargs):
        captured.update(kwargs)
        return ScanJob(
            job_id="scheduled-source-job",
            tenant_id=kwargs["tenant_id"],
            source_id=kwargs["source_id"],
            schedule_id=kwargs["schedule_id"],
            triggered_by=kwargs["triggered_by"],
            created_at="2026-08-27T00:00:00+00:00",
            request=kwargs["request_body"],
        )

    monkeypatch.setattr("agent_bom.api.routes.scan.enqueue_scan_job", _fake_enqueue)
    try:
        job_id = _enqueue_scheduled_scan(
            {"source_id": "source-repo"},
            schedule_id="schedule-source",
            tenant_id="tenant-alpha",
        )
    finally:
        _stores._source_store = old_source_store
        _stores._schedule_store = old_schedule_store
        _stores._store = old_job_store

    assert job_id == "scheduled-source-job"
    assert captured["tenant_id"] == "tenant-alpha"
    assert captured["source_id"] == "source-repo"
    assert captured["schedule_id"] == "schedule-source"
    assert captured["request_body"].repo_url == "https://example.com/acme/repo"
    updated = source_store.get("source-repo")
    assert updated is not None
    assert updated.last_job_id == "scheduled-source-job"
    assert updated.last_run_status == "pending"


def test_source_cohort_schedule_launches_one_exact_durable_cohort_per_occurrence(tmp_path, monkeypatch):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.server import _enqueue_scheduled_scan
    from agent_bom.api.store import SQLiteJobStore

    source_store = InMemorySourceStore()
    schedule_store = InMemoryScheduleStore()
    for source in (
        SourceRecord(
            source_id="source-repo",
            tenant_id="tenant-alpha",
            display_name="Repository",
            kind=SourceKind.SCAN_REPO,
            config={"scan_request": {"repo_url": "https://example.com/acme/repo"}},
        ),
        SourceRecord(
            source_id="source-image",
            tenant_id="tenant-alpha",
            display_name="Image",
            kind=SourceKind.SCAN_IMAGE,
            config={"scan_request": {"images": ["example/app@sha256:" + "a" * 64]}},
        ),
    ):
        source_store.put(source)
    schedule = ScanSchedule(
        schedule_id="schedule-cohort",
        tenant_id="tenant-alpha",
        name="Evidence cohort",
        cron_expression="0 * * * *",
        scan_config={"source_ids": ["source-repo", "source-image"], "max_age_hours": 24},
    )
    schedule_store.put(schedule)
    jobs = SQLiteJobStore(tmp_path / "jobs.db")
    old_source_store = _stores._source_store
    old_schedule_store = _stores._schedule_store
    old_job_store = _stores._store
    old_graph_store = _stores._graph_store
    _stores.set_source_store(source_store)
    _stores.set_schedule_store(schedule_store)
    _stores.set_job_store(jobs)
    _stores.set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))
    dispatched: list[str] = []
    # Observe actual local submissions, not recovery attempts entering the
    # dispatch boundary. ``dispatch_scan_job`` owns the process-local claim
    # that collapses a replay of still-pending durable children.
    monkeypatch.setattr("agent_bom.api.routes.scan.submit_scan_job", lambda job: dispatched.append(job.job_id))
    config = {"source_ids": ["source-image", "source-repo"], "max_age_hours": 24}
    try:
        first_id = _enqueue_scheduled_scan(
            config,
            schedule_id=schedule.schedule_id,
            tenant_id="tenant-alpha",
            scheduled_for="2026-09-03T12:00:00+00:00",
        )
        replay_id = _enqueue_scheduled_scan(
            config,
            schedule_id=schedule.schedule_id,
            tenant_id="tenant-alpha",
            scheduled_for="2026-09-03T12:00:00+00:00",
        )
        next_id = _enqueue_scheduled_scan(
            config,
            schedule_id=schedule.schedule_id,
            tenant_id="tenant-alpha",
            scheduled_for="2026-09-03T13:00:00+00:00",
        )
    finally:
        _stores._source_store = old_source_store
        _stores._schedule_store = old_schedule_store
        _stores._store = old_job_store
        _stores._graph_store = old_graph_store

    assert replay_id == first_id
    assert next_id != first_id
    first = jobs.get(first_id, tenant_id="tenant-alpha")
    assert first is not None
    assert first.correlation_cohort_id == first.batch_id
    assert first.correlation_max_age_hours == 24
    assert [jobs.get(child_id, tenant_id="tenant-alpha").source_id for child_id in first.child_job_ids] == [
        "source-image",
        "source-repo",
    ]
    assert dispatched[:2] == first.child_job_ids
    assert len(dispatched) == 4


def test_source_schedule_resolution_and_enqueue_are_fenced_against_delete(monkeypatch):
    from agent_bom.api.server import _enqueue_scheduled_scan
    from agent_bom.api.tenant_quota import tenant_quota_guard

    source_store = InMemorySourceStore()
    schedule_store = InMemoryScheduleStore()
    source = SourceRecord(
        source_id="source-race",
        tenant_id="tenant-alpha",
        display_name="Repository",
        kind=SourceKind.SCAN_REPO,
        config={"scan_request": {"repo_url": "https://example.com/acme/repo"}},
    )
    schedule = ScanSchedule(
        schedule_id="schedule-race",
        tenant_id="tenant-alpha",
        name="Repository schedule",
        cron_expression="* * * * *",
        scan_config={"source_id": source.source_id},
        enabled=True,
    )
    source_store.put(source)
    schedule_store.put(schedule)
    old_source_store = _stores._source_store
    old_schedule_store = _stores._schedule_store
    old_job_store = _stores._store
    _stores.set_source_store(source_store)
    _stores.set_schedule_store(schedule_store)
    _stores.set_job_store(InMemoryJobStore())

    request_resolved = Event()
    release_request = Event()
    delete_started = Event()
    delete_finished = Event()
    enqueued: list[str] = []
    original_request = __import__("agent_bom.api.routes.sources", fromlist=["_request_for_source"])._request_for_source

    def _blocking_request(current):
        request = original_request(current)
        request_resolved.set()
        assert release_request.wait(timeout=5)
        return request

    def _fake_enqueue(**kwargs):
        enqueued.append(kwargs["source_id"])
        return ScanJob(
            job_id="fenced-job",
            tenant_id=kwargs["tenant_id"],
            source_id=kwargs["source_id"],
            schedule_id=kwargs["schedule_id"],
            triggered_by=kwargs["triggered_by"],
            created_at="2026-08-27T00:00:00+00:00",
            request=kwargs["request_body"],
        )

    def _delete_source_and_schedule():
        delete_started.set()
        with tenant_quota_guard("tenant-alpha"):
            schedule_store.delete(schedule.schedule_id, tenant_id="tenant-alpha")
            source_store.delete(source.source_id)
        delete_finished.set()

    monkeypatch.setattr("agent_bom.api.routes.sources._request_for_source", _blocking_request)
    monkeypatch.setattr("agent_bom.api.routes.scan.enqueue_scan_job", _fake_enqueue)
    schedule_thread = Thread(
        target=_enqueue_scheduled_scan,
        args=({"source_id": source.source_id},),
        kwargs={"schedule_id": schedule.schedule_id, "tenant_id": "tenant-alpha"},
    )
    delete_thread = Thread(target=_delete_source_and_schedule)
    try:
        schedule_thread.start()
        assert request_resolved.wait(timeout=5)
        delete_thread.start()
        assert delete_started.wait(timeout=5)
        assert delete_finished.wait(timeout=0.1) is False
        release_request.set()
        schedule_thread.join(timeout=5)
        delete_thread.join(timeout=5)
    finally:
        release_request.set()
        schedule_thread.join(timeout=5)
        delete_thread.join(timeout=5)
        _stores._source_store = old_source_store
        _stores._schedule_store = old_schedule_store
        _stores._store = old_job_store

    assert enqueued == [source.source_id]
    assert source_store.get(source.source_id) is None
    assert schedule_store.get(schedule.schedule_id, tenant_id="tenant-alpha") is None


# ─── parse_cron_next ──────────────────────────────────────────────────────────


class TestParseCronNext:
    def test_every_minute(self):
        after = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        result = parse_cron_next("* * * * *", after)
        assert result is not None
        assert result > after
        assert result.minute == 1  # next minute

    def test_every_6_hours(self):
        after = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = parse_cron_next("0 */6 * * *", after)
        assert result is not None
        assert result.hour == 6
        assert result.minute == 0

    def test_fixed_minute_and_hour(self):
        after = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = parse_cron_next("30 2 * * *", after)
        assert result is not None
        assert result.hour == 2
        assert result.minute == 30

    def test_already_past_today(self):
        after = datetime(2025, 1, 1, 15, 0, 0, tzinfo=timezone.utc)
        result = parse_cron_next("0 6 * * *", after)
        # Should find 06:00 the next day
        assert result is not None
        assert result.day == 2
        assert result.hour == 6

    def test_invalid_cron_parts(self):
        after = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert parse_cron_next("bad cron", after) is None

    def test_wrong_field_count(self):
        after = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        assert parse_cron_next("* * *", after) is None

    def test_step_zero_returns_none(self):
        after = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        result = parse_cron_next("*/0 * * * *", after)
        assert result is None

    def test_validation_rejects_invalid_ignored_fields(self):
        assert validate_cron_expression("0 0 bad * *") is False
        assert parse_cron_next("0 0 bad * *", datetime(2025, 1, 1, tzinfo=timezone.utc)) is None

    def test_validation_accepts_basic_five_field_cron(self):
        assert validate_cron_expression("0 0 * * *") is True

    def test_validation_accepts_lists_ranges_and_steps(self):
        assert validate_cron_expression("5,35 1-6/2 * * 1-5") is True

    def test_list_and_range_expression_finds_next_run(self):
        after = datetime(2025, 1, 6, 0, 0, 0, tzinfo=timezone.utc)
        result = parse_cron_next("5,35 1-6/2 * * 1-5", after)

        assert result == datetime(2025, 1, 6, 1, 5, tzinfo=timezone.utc)

    def test_validation_rejects_descending_ranges(self):
        assert validate_cron_expression("0 5-1 * * *") is False


# ─── scheduler_loop ───────────────────────────────────────────────────────────


class TestSchedulerLoop:
    def test_triggers_due_schedule(self):
        """Scheduler loop triggers due scans."""
        from agent_bom.api.scheduler import scheduler_loop

        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1", next_run="2020-01-01T00:00:00+00:00", enabled=True))

        triggered = []

        def mock_scan(config, **metadata):
            triggered.append({"config": config, "metadata": metadata})
            return "job-123"

        async def _run():
            task = asyncio.create_task(scheduler_loop(store, mock_scan, interval_seconds=0))
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(_run())
        assert len(triggered) >= 1

    def test_in_memory_store_ignores_postgres_env(self, monkeypatch):
        """Global Postgres env should not block non-Postgres schedule stores."""
        from agent_bom.api.scheduler import scheduler_loop

        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1", next_run="2020-01-01T00:00:00+00:00", enabled=True))
        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example.invalid/agent_bom")

        triggered = []

        def mock_scan(config, **metadata):
            triggered.append({"config": config, "metadata": metadata})
            return "job-123"

        async def _run():
            task = asyncio.create_task(scheduler_loop(store, mock_scan, interval_seconds=0))
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(_run())
        assert len(triggered) >= 1

    def test_in_memory_store_does_not_enter_postgres_rls_bypass(self, monkeypatch):
        """SQLite/in-memory scheduling must not log Postgres RLS bypass activation."""
        import contextlib

        from agent_bom.api import postgres_store
        from agent_bom.api.scheduler import scheduler_loop

        @contextlib.contextmanager
        def fail_if_called():
            raise AssertionError("in-memory scheduler should not enter Postgres RLS bypass")
            yield

        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1", next_run="2020-01-01T00:00:00+00:00", enabled=True))
        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example.invalid/agent_bom")
        monkeypatch.setattr(postgres_store, "bypass_tenant_rls", fail_if_called)

        triggered = []

        def mock_scan(config, **metadata):
            triggered.append({"config": config, "metadata": metadata})
            return "job-123"

        async def _run():
            task = asyncio.create_task(scheduler_loop(store, mock_scan, interval_seconds=0))
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(_run())
        assert len(triggered) >= 1

    def test_skips_disabled_schedule(self):
        """Scheduler loop skips disabled schedules."""
        from agent_bom.api.scheduler import scheduler_loop

        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1", next_run="2020-01-01T00:00:00+00:00", enabled=False))

        triggered = []

        def mock_scan(config, **metadata):
            triggered.append({"config": config, "metadata": metadata})
            return "job-123"

        async def _run():
            task = asyncio.create_task(scheduler_loop(store, mock_scan, interval_seconds=0))
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(_run())
        assert len(triggered) == 0

    def test_updates_last_run(self):
        """Scheduler updates last_run after triggering."""
        from agent_bom.api.scheduler import scheduler_loop

        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1", next_run="2020-01-01T00:00:00+00:00", enabled=True))
        triggered = []

        def mock_scan(config, **metadata):
            triggered.append({"config": config, "metadata": metadata})
            return "job-456"

        async def _run():
            task = asyncio.create_task(scheduler_loop(store, mock_scan, interval_seconds=0))
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(_run())
        updated = store.get("s1")
        assert updated.last_run is not None
        assert updated.last_job_id == "job-456"
        assert triggered[0]["metadata"]["schedule_id"] == "s1"
        assert triggered[0]["metadata"]["tenant_id"] == "default"
        assert triggered[0]["metadata"]["scheduled_for"] == "2020-01-01T00:00:00+00:00"

    def test_deleted_schedule_is_not_resurrected_after_trigger(self):
        """A concurrent source deletion can remove a schedule during dispatch."""
        from agent_bom.api.scheduler import scheduler_loop

        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1", next_run="2020-01-01T00:00:00+00:00", enabled=True))

        def mock_scan(config, **metadata):
            store.delete(metadata["schedule_id"], tenant_id=metadata["tenant_id"])
            return "job-after-delete"

        async def _run():
            task = asyncio.create_task(scheduler_loop(store, mock_scan, interval_seconds=0))
            await asyncio.sleep(0.1)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.run(_run())
        assert store.get("s1") is None

    def test_postgres_scheduler_binds_tenant_before_dispatch(self, monkeypatch):
        """Maintenance discovery must not leave the dispatch callback on the default RLS tenant."""
        from agent_bom.api.postgres_common import _current_tenant
        from agent_bom.api.scheduler import scheduler_loop

        class PostgresScheduleStore(InMemoryScheduleStore):
            pass

        store = PostgresScheduleStore()
        store.put(
            _make_schedule(
                "tenant-schedule",
                next_run="2020-01-01T00:00:00+00:00",
                enabled=True,
                tenant_id="tenant-alpha",
            )
        )
        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example.invalid/agent_bom")
        observed_tenants: list[str] = []

        class _FakeCursor:
            def fetchone(self):
                return (True,)

        class _FakeConn:
            def execute(self, sql, params):
                return _FakeCursor()

        class _FakePool:
            def getconn(self):
                return _FakeConn()

            def putconn(self, conn):
                return None

        def mock_scan(config, **metadata):
            observed_tenants.append(_current_tenant.get())
            return "tenant-job"

        async def _run():
            task = asyncio.create_task(scheduler_loop(store, mock_scan, interval_seconds=0))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with patch("agent_bom.api.postgres_store._get_pool", return_value=_FakePool()):
            asyncio.run(_run())

        assert observed_tenants
        assert set(observed_tenants) == {"tenant-alpha"}
        assert _current_tenant.get() == "default"

    def test_skips_due_scans_without_postgres_leader_lock(self, monkeypatch):
        """Only the replica holding the advisory lock should trigger schedules."""
        from agent_bom.api.scheduler import scheduler_loop

        class PostgresScheduleStore(InMemoryScheduleStore):
            pass

        store = PostgresScheduleStore()
        store.put(_make_schedule("s1", next_run="2020-01-01T00:00:00+00:00", enabled=True))
        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://example.invalid/agent_bom")

        triggered = []

        class _FakeCursor:
            def fetchone(self):
                return (False,)

        class _FakeConn:
            def execute(self, sql, params):
                return _FakeCursor()

        class _FakePool:
            def getconn(self):
                return _FakeConn()

            def putconn(self, conn):
                return None

        def mock_scan(config, **metadata):
            triggered.append({"config": config, "metadata": metadata})
            return "job-123"

        async def _run():
            task = asyncio.create_task(scheduler_loop(store, mock_scan, interval_seconds=0))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with patch("agent_bom.api.postgres_store._get_pool", return_value=_FakePool()):
            asyncio.run(_run())

        assert triggered == []
