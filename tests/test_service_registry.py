import pytest

from agent_bom.api import stores
from agent_bom.api.connection_store import (
    CloudConnectionRecord,
    InMemoryConnectionStore,
    get_connection_store,
    set_connection_store,
)
from agent_bom.api.cost_store import InMemoryCostStore, set_cost_store
from agent_bom.api.fleet_store import InMemoryFleetStore
from agent_bom.api.models import SourceRecord
from agent_bom.api.service_registry import derive_service_registry
from agent_bom.api.source_store import InMemorySourceStore
from agent_bom.api.stores import set_fleet_store, set_mcp_observation_store, set_source_store


class _EmptyObservationStore:
    def list_by_tenant(self, tenant_id: str) -> list[object]:
        return []


@pytest.fixture(autouse=True)
def _reset_stores():
    set_connection_store(InMemoryConnectionStore())
    set_source_store(InMemorySourceStore())
    set_fleet_store(InMemoryFleetStore())
    set_mcp_observation_store(_EmptyObservationStore())
    set_cost_store(InMemoryCostStore())
    yield


def test_service_registry_locked_by_default():
    registry = derive_service_registry("tenant-a", {"scan_count": 0, "has_proxy": False})
    assert registry["schema_version"] == "agent-bom.services/v1"
    assert registry["services"]["cloud_accounts"]["state"] == "locked"
    assert registry["services"]["data_sources"]["state"] == "locked"
    assert registry["services"]["ai_spend"]["state"] == "locked"


def test_cloud_accounts_connected_without_scan():
    store = get_connection_store()
    store.put(
        CloudConnectionRecord(
            id="conn-1",
            tenant_id="tenant-a",
            provider="aws",
            display_name="prod",
            role_ref="arn:aws:iam::123:role/read",
            external_id_encrypted="cipher",
            status="active",
        )
    )
    registry = derive_service_registry("tenant-a", {"scan_count": 0})
    assert registry["services"]["cloud_accounts"]["state"] == "connected"
    assert registry["services"]["cloud_accounts"]["count"] == 1


def test_cloud_accounts_live_after_scan():
    store = get_connection_store()
    store.put(
        CloudConnectionRecord(
            id="conn-1",
            tenant_id="tenant-a",
            provider="aws",
            display_name="prod",
            role_ref="arn:aws:iam::123:role/read",
            external_id_encrypted="cipher",
            status="active",
            last_scan_at="2026-07-09T12:00:00Z",
        )
    )
    registry = derive_service_registry("tenant-a", {"scan_count": 0})
    assert registry["services"]["cloud_accounts"]["state"] == "live"


def test_data_sources_live_after_run():
    store = InMemorySourceStore()
    set_source_store(store)
    store.put(
        SourceRecord(
            source_id="src-1",
            tenant_id="tenant-a",
            display_name="repo scan",
            kind="scan.repo",
            enabled=True,
            last_run_at="2026-07-09T12:00:00Z",
            last_run_status="success",
            last_job_id="job-1",
            created_at="2026-07-09T10:00:00Z",
            updated_at="2026-07-09T12:00:00Z",
        )
    )
    registry = derive_service_registry("tenant-a", {"scan_count": 0})
    assert registry["services"]["data_sources"]["state"] == "live"


def test_data_sources_locked_when_source_store_uninitialized(monkeypatch):
    monkeypatch.setattr(stores, "_source_store", None)
    registry = derive_service_registry("tenant-a", {"scan_count": 0})
    assert registry["services"]["data_sources"]["state"] == "locked"


def test_ai_spend_requires_runtime_when_locked():
    registry = derive_service_registry("tenant-a", {"scan_count": 0, "has_proxy": False})
    assert registry["services"]["ai_spend"]["requires"] == ["runtime_proxy"]

    connected = derive_service_registry("tenant-a", {"scan_count": 0, "has_proxy": True})
    assert connected["services"]["ai_spend"]["state"] == "connected"


def test_compliance_live_when_scans_exist():
    registry = derive_service_registry("tenant-a", {"scan_count": 2})
    assert registry["services"]["compliance"]["state"] == "live"
    assert registry["services"]["compliance"]["count"] == 2
