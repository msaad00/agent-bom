"""Export schedules enforce ownership at the storage boundary."""

from __future__ import annotations

import pytest

from agent_bom.api.export_schedule_store import ExportSchedule, InMemoryExportScheduleStore, SQLiteExportScheduleStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryExportScheduleStore()
    return SQLiteExportScheduleStore(str(tmp_path / "schedules.db"))


def schedule(tenant_id: str = "tenant-a", schedule_id: str = "shared-id") -> ExportSchedule:
    return ExportSchedule(
        schedule_id=schedule_id,
        name="nightly",
        cron_expression="0 3 * * *",
        destination_id="destination-a",
        tenant_id=tenant_id,
        next_run="2026-09-28T03:00:00+00:00",
        created_at="2026-09-27T00:00:00+00:00",
        updated_at="2026-09-27T00:00:00+00:00",
    )


def test_store_requires_explicit_tenant_for_public_crud(store):
    item = schedule()
    for operation in (
        lambda: store.put(item),
        lambda: store.get(item.schedule_id, None),
        lambda: store.delete(item.schedule_id, ""),
        lambda: store.list_all("   "),
    ):
        with pytest.raises((TypeError, ValueError)):
            operation()


def test_record_tenant_must_match_explicit_authority(store):
    with pytest.raises(ValueError, match="authorized tenant"):
        store.put(schedule("tenant-b"), tenant_id="tenant-a")
    assert store.list_all("tenant-a") == []
    assert store.list_all("tenant-b") == []


def test_schedule_id_cannot_be_taken_over_by_another_tenant(store):
    store.put(schedule(), tenant_id="tenant-a")

    with pytest.raises(ValueError, match="different tenant"):
        store.put(schedule("tenant-b"), tenant_id="tenant-b")

    persisted = store.get("shared-id", "tenant-a")
    assert persisted is not None
    assert persisted.tenant_id == "tenant-a"
    assert store.get("shared-id", "tenant-b") is None


def test_due_claim_rejects_a_schedule_with_mismatched_tenant_authority(store):
    store.put(schedule(), tenant_id="tenant-a")

    with pytest.raises(ValueError, match="authorized tenant"):
        store.claim_due(schedule("tenant-b"), "2026-09-29T03:00:00+00:00", tenant_id="tenant-a")


def test_caller_mutation_cannot_change_persisted_schedule_tenant(store):
    item = schedule()
    store.put(item, tenant_id="tenant-a")
    item.tenant_id = "tenant-b"

    loaded = store.get(item.schedule_id, "tenant-a")
    assert loaded is not None
    loaded.tenant_id = "tenant-b"
    assert store.get(item.schedule_id, "tenant-a").tenant_id == "tenant-a"
    assert store.get(item.schedule_id, "tenant-b") is None
