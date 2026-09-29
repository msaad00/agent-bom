"""Workers cannot restore deleted configuration or undo a schedule claim."""

import asyncio
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from agent_bom.api.export_destination_store import ExportDestinationRecord, InMemoryExportDestinationStore, SQLiteExportDestinationStore
from agent_bom.api.export_schedule_store import ExportSchedule, InMemoryExportScheduleStore, SQLiteExportScheduleStore
from agent_bom.api.export_scheduler import run_due_exports_once
from agent_bom.api.routes import exports
from agent_bom.export.destinations import ExportResult

NOW = datetime(2026, 9, 29, 12, tzinfo=timezone.utc)


@pytest.fixture(params=["memory", "sqlite"])
def stores(request, tmp_path):
    if request.param == "memory":
        return InMemoryExportScheduleStore(), InMemoryExportDestinationStore()
    path = str(tmp_path / "export.db")
    return SQLiteExportScheduleStore(path), SQLiteExportDestinationStore(path)


def seed(stores):
    schedules, destinations = stores
    schedule = ExportSchedule(
        schedule_id="schedule",
        name="daily",
        cron_expression="0 3 * * *",
        destination_id="destination",
        tenant_id="a",
        next_run="2026-09-28T03:00:00+00:00",
        created_at="v1",
        updated_at="v1",
    )
    destination = ExportDestinationRecord(
        id="destination", tenant_id="a", kind="s3", display_name="original", created_at="v1", updated_at="v1"
    )
    schedules.put(schedule, tenant_id="a")
    destinations.put(destination, tenant_id="a")
    return schedule, destination


def success(**kwargs):
    return ExportResult(kind="s3", destination_uri="s3://fixture/export", row_count=3)


def test_completed_schedule_keeps_claimed_next_run_after_reopen(stores, monkeypatch):
    schedules, destinations = stores
    seed(stores)
    monkeypatch.setattr("agent_bom.api.export_scheduler.run_findings_export", success)
    assert asyncio.run(run_due_exports_once(schedules, destinations, NOW)) == 1
    if isinstance(schedules, SQLiteExportScheduleStore):
        schedules = SQLiteExportScheduleStore(schedules._db_path)
    assert schedules.get("schedule", "a").next_run > NOW.isoformat()
    assert schedules.get("schedule", "a").last_row_count == 3
    assert schedules.list_due(NOW.isoformat()) == []
    assert asyncio.run(run_due_exports_once(schedules, destinations, NOW)) == 0


@pytest.mark.parametrize("operation", ["delete", "edit"])
@pytest.mark.parametrize("one_off", [False, True])
def test_completion_preserves_concurrent_destination_change(stores, monkeypatch, operation, one_off):
    schedules, destinations = stores
    _, original = seed(stores)
    edited = replace(original, display_name="edited", secret_encrypted="rotated", updated_at="v2")

    def run(**kwargs):
        if operation == "delete":
            destinations.delete("a", "destination")
        else:
            destinations.put(edited, tenant_id="a")
        return success()

    monkeypatch.setattr("agent_bom.api.export_scheduler.run_findings_export", run)
    monkeypatch.setattr("agent_bom.export.runner.run_findings_export", run)
    monkeypatch.setattr(exports, "get_export_destination_store", lambda: destinations)
    if one_off:
        exports._run_export_sync("a", "destination", "run")
    else:
        asyncio.run(run_due_exports_once(schedules, destinations, NOW))
    assert destinations.get("a", "destination") == (None if operation == "delete" else edited)


@pytest.mark.parametrize("operation", ["disable", "edit"])
def test_claim_rejects_changed_schedule(stores, operation):
    schedules, _ = stores
    observed, _ = seed(stores)
    changed = observed.model_copy(update={"enabled": False} if operation == "disable" else {"destination_id": "other"})
    schedules.put(changed, tenant_id="a")
    assert not schedules.claim_due(observed, "2026-09-30T03:00:00+00:00", tenant_id="a")
    assert schedules.get("schedule", "a") == changed


@pytest.mark.parametrize("operation", ["delete", "edit", "reclaim"])
def test_schedule_completion_is_fenced(stores, monkeypatch, operation):
    schedules, destinations = stores
    seed(stores)
    expected = []

    def run(**kwargs):
        current = schedules.get("schedule", "a")
        if operation == "delete":
            schedules.delete("schedule", "a")
            expected.append(None)
        elif operation == "edit":
            current.name = "edited"
            current.enabled = False
            schedules.put(current, tenant_id="a")
            expected.append(current)
        else:
            assert schedules.claim_due(current, "2026-10-01T03:00:00+00:00", tenant_id="a")
            expected.append(schedules.get("schedule", "a"))
        return success()

    monkeypatch.setattr("agent_bom.api.export_scheduler.run_findings_export", run)
    asyncio.run(run_due_exports_once(schedules, destinations, NOW))
    assert schedules.get("schedule", "a") == expected[0]


def test_sqlite_reads_legacy_claimed_column_and_repairs_payload(tmp_path):
    store = SQLiteExportScheduleStore(str(tmp_path / "legacy.db"))
    observed, _ = seed((store, InMemoryExportDestinationStore()))
    store._conn.execute("UPDATE export_schedules SET next_run=?", ("2026-09-30T03:00:00+00:00",))
    store._conn.commit()
    claimed = store.get(observed.schedule_id, "a")
    assert claimed.next_run == "2026-09-30T03:00:00+00:00"
    assert store.record_run(claimed, tenant_id="a", at=NOW.isoformat(), status="success", row_count=1)
    assert store.list_due(NOW.isoformat()) == []
    payload = store._conn.execute("SELECT data FROM export_schedules").fetchone()[0]
    assert ExportSchedule.model_validate_json(payload).next_run == claimed.next_run


def test_large_backlog_only_claims_a_bounded_batch(stores, monkeypatch):
    schedules, destinations = stores
    schedule, _ = seed(stores)
    for index in range(31):
        schedules.put(schedule.model_copy(update={"schedule_id": f"schedule-{index}"}), tenant_id="a")
    sizes = []
    original = schedules.list_due

    def bounded(now_iso, *, limit=100):
        result = original(now_iso, limit=limit)
        sizes.append(len(result))
        return result

    monkeypatch.setattr(schedules, "list_due", bounded)
    monkeypatch.setattr("agent_bom.api.export_scheduler.run_findings_export", success)
    assert asyncio.run(run_due_exports_once(schedules, destinations, NOW, max_concurrency=3)) == 32
    assert max(sizes) == 3
    assert sizes[-1] == 0


def test_sqlite_replica_claim_has_one_winner(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    path = str(tmp_path / "replicas.db")
    store = SQLiteExportScheduleStore(path)
    schedule, _ = seed((store, InMemoryExportDestinationStore()))

    def claim(_):
        replica = SQLiteExportScheduleStore(path)
        return replica.claim_due(schedule, "2026-09-30T03:00:00+00:00", tenant_id="a")

    with ThreadPoolExecutor(max_workers=4) as workers:
        assert sum(workers.map(claim, range(4))) == 1


def test_completion_requires_matching_explicit_tenant(stores):
    schedules, destinations = stores
    schedule, destination = seed(stores)
    with pytest.raises(ValueError, match="authorized tenant"):
        schedules.record_run(schedule, tenant_id="b", at=NOW.isoformat(), status="success", row_count=1)
    with pytest.raises(ValueError, match="authorized tenant"):
        destinations.record_run(destination, tenant_id="b", completed_at=NOW.isoformat(), status="active", detail="", run_status="success")
    assert schedules.get("schedule", "a") == schedule
    assert destinations.get("a", "destination") == destination


def test_destination_recreation_and_newer_outcome_reject_stale_completion(stores):
    _, destinations = stores
    _, original = seed(stores)
    kwargs = dict(tenant_id="a", completed_at="2026-09-29T12:00:00+00:00", status="active", detail="", run_status="success")
    newer = replace(original, last_run_at="2026-09-29T13:00:00+00:00", status="error", last_run_status="error")
    destinations.put(newer, tenant_id="a")
    assert not destinations.record_run(original, **kwargs)
    assert destinations.get("a", "destination") == newer
    destinations.delete("a", "destination")
    replacement = replace(original, created_at="v2")
    destinations.put(replacement, tenant_id="a")
    assert not destinations.record_run(original, **kwargs)
    assert destinations.get("a", "destination") == replacement
