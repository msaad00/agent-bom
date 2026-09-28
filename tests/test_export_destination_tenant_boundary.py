"""Export destinations require caller-supplied tenant authority."""

from __future__ import annotations

import pytest

from agent_bom.api.export_destination_store import ExportDestinationRecord, InMemoryExportDestinationStore, SQLiteExportDestinationStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryExportDestinationStore()
    return SQLiteExportDestinationStore(str(tmp_path / "destinations.db"))


def destination(tenant_id: str = "tenant-a", destination_id: str = "shared-id") -> ExportDestinationRecord:
    return ExportDestinationRecord(
        id=destination_id,
        tenant_id=tenant_id,
        kind="s3",
        display_name="Findings",
        config={"bucket": "private", "options": {"region": "us-east-1"}},
        created_at="2026-09-28T00:00:00Z",
        updated_at="2026-09-28T00:00:00Z",
    )


def test_store_requires_explicit_tenant_for_every_operation(store):
    record = destination()
    for operation in (
        lambda: store.put(record),
        lambda: store.get(None, record.id),
        lambda: store.delete("", record.id),
        lambda: store.list_for_tenant("   "),
    ):
        with pytest.raises((TypeError, ValueError)):
            operation()


def test_record_owner_must_match_explicit_tenant(store):
    with pytest.raises(ValueError, match="authorized tenant"):
        store.put(destination("tenant-b"), tenant_id="tenant-a")
    assert store.list_for_tenant("tenant-a") == []
    assert store.list_for_tenant("tenant-b") == []


def test_write_cannot_transfer_destination_id_between_tenants(store):
    store.put(destination(), tenant_id="tenant-a")

    with pytest.raises(ValueError, match="different tenant"):
        store.put(destination("tenant-b"), tenant_id="tenant-b")

    persisted = store.get("tenant-a", "shared-id")
    assert persisted is not None
    assert persisted.tenant_id == "tenant-a"
    assert store.get("tenant-b", "shared-id") is None


def test_nested_config_mutations_do_not_change_persisted_destination(store):
    record = destination()
    store.put(record, tenant_id="tenant-a")
    record.config["options"]["region"] = "eu-west-1"

    loaded = store.get("tenant-a", record.id)
    assert loaded is not None
    loaded.config["options"]["region"] = "ap-southeast-2"
    assert store.list_for_tenant("tenant-a")[0].config["options"]["region"] == "us-east-1"
