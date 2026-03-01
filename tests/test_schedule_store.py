"""Tests for schedule store backends and cron scheduler."""

import asyncio
from datetime import datetime, timezone

from agent_bom.api.schedule_store import (
    InMemoryScheduleStore,
    ScanSchedule,
    SQLiteScheduleStore,
)
from agent_bom.api.scheduler import parse_cron_next

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


# ─── scheduler_loop ───────────────────────────────────────────────────────────


class TestSchedulerLoop:
    def test_triggers_due_schedule(self):
        """Scheduler loop triggers due scans."""
        from agent_bom.api.scheduler import scheduler_loop

        store = InMemoryScheduleStore()
        store.put(_make_schedule("s1", next_run="2020-01-01T00:00:00+00:00", enabled=True))

        triggered = []

        def mock_scan(config):
            triggered.append(config)
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

        def mock_scan(config):
            triggered.append(config)
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

        def mock_scan(config):
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
