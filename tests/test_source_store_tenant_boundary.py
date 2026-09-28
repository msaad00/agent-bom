"""Source storage must enforce the tenant independently of its caller's route."""

from __future__ import annotations

import pytest

from agent_bom.api.models import SourceKind, SourceRecord
from agent_bom.api.source_store import InMemorySourceStore, SQLiteSourceStore


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemorySourceStore()
    return SQLiteSourceStore(str(tmp_path / "sources.db"))


def source(tenant="tenant-a", identifier="same-id"):
    return SourceRecord(source_id=identifier, tenant_id=tenant, display_name="shared", kind=SourceKind.SCAN_MCP_CONFIG)


def test_unscoped_operations_are_rejected(store):
    record = source()
    for operation in (
        lambda: store.put(record),
        lambda: store.get(record.source_id),
        lambda: store.delete(record.source_id),
        lambda: store.list_all(),
    ):
        with pytest.raises((TypeError, ValueError)):
            operation()


def test_foreign_exact_id_read_delete_and_list_are_denied(store):
    store.put(source(), tenant_id="tenant-a")
    assert store.get("same-id", tenant_id="tenant-b") is None
    assert store.delete("same-id", tenant_id="tenant-b") is False
    assert store.list_all(tenant_id="tenant-b") == []
    assert store.get("same-id", tenant_id="tenant-a").tenant_id == "tenant-a"


def test_write_cannot_move_an_existing_id_to_another_tenant(store):
    store.put(source(), tenant_id="tenant-a")
    with pytest.raises(ValueError):
        store.put(source("tenant-b"), tenant_id="tenant-b")
    assert store.get("same-id", tenant_id="tenant-a").tenant_id == "tenant-a"


def test_record_tenant_cannot_override_explicit_authority(store):
    with pytest.raises(ValueError):
        store.put(source("tenant-b"), tenant_id="tenant-a")
    assert store.list_all(tenant_id="tenant-b") == []


def test_caller_mutation_cannot_change_persisted_ownership(store):
    record = source()
    store.put(record, tenant_id="tenant-a")
    record.tenant_id = "tenant-b"
    loaded = store.get("same-id", tenant_id="tenant-a")
    assert loaded.tenant_id == "tenant-a"
    loaded.tenant_id = "tenant-b"
    store.list_all(tenant_id="tenant-a")[0].tenant_id = "tenant-b"
    assert store.get("same-id", tenant_id="tenant-b") is None
    assert store.get("same-id", tenant_id="tenant-a").tenant_id == "tenant-a"


@pytest.mark.parametrize("tenant", [None, "", "   "])
def test_missing_tenant_is_never_an_all_tenants_read(store, tenant):
    with pytest.raises((TypeError, ValueError)):
        store.list_all(tenant_id=tenant)
