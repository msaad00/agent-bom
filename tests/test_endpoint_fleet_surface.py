"""Endpoint inventory persistence and graph contracts."""

from __future__ import annotations

from pathlib import Path

from starlette.testclient import TestClient

from agent_bom.api.fleet_store import InMemoryFleetStore, SQLiteFleetStore, endpoint_summary_from_inventory
from agent_bom.api.server import app, set_fleet_store, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType


def _endpoint_inventory(*, process_count: int = 2) -> dict:
    return {
        "schema_version": "1",
        "platform": {"system": "Darwin", "release": "25.6", "machine": "arm64"},
        "privacy": {
            "process_arguments_collected": False,
            "environment_values_collected": False,
            "browser_history_collected": False,
            "arbitrary_home_directory_scan": False,
            "network_remote_addresses_collected": False,
        },
        "collectors": [
            {"name": "applications", "status": "complete", "item_count": 1, "message": ""},
            {"name": "processes", "status": "complete", "item_count": process_count, "message": ""},
            {"name": "services", "status": "complete", "item_count": 3, "message": ""},
            {"name": "listeners", "status": "complete", "item_count": 1, "message": ""},
            {"name": "containers", "status": "unavailable", "item_count": None, "message": "runtime unavailable"},
            {"name": "images", "status": "unavailable", "item_count": None, "message": "runtime unavailable"},
        ],
        "applications": [{"name": "Visual Studio Code", "version": "1.99"}],
        "processes": [
            {"pid": 10, "name": "Code", "username": "developer"},
            {"pid": 11, "name": "node", "username": "developer"},
        ],
        "services": [{"name": "com.example.agent", "state": "running"}],
        "listeners": [{"pid": 11, "process": "node", "address_scope": "loopback", "port": 8422}],
        "containers": [],
        "images": [],
    }


def test_results_push_upserts_tenant_scoped_endpoint_summary() -> None:
    store = InMemoryFleetStore()
    job_store = InMemoryJobStore()
    set_fleet_store(store)
    set_job_store(job_store)
    client = TestClient(app)

    first = client.post(
        "/v1/results/push",
        json={"source_id": "device-a", "endpoint_inventory": _endpoint_inventory()},
    )
    second = client.post(
        "/v1/results/push",
        json={"source_id": "device-a", "endpoint_inventory": _endpoint_inventory(process_count=4)},
    )

    assert first.status_code == 201
    assert second.status_code == 201
    response = client.get("/v1/fleet/endpoints?limit=25&offset=0")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["endpoints"][0]["endpoint_id"] == "device-a"
    assert payload["endpoints"][0]["counts"]["processes"] == 4
    assert payload["endpoints"][0]["completeness"] == "partial"
    serialized = str(payload)
    assert "username" not in serialized
    assert "pid" not in serialized

    persisted = job_store.get(second.json()["job_id"], all_tenants=True)
    assert persisted is not None
    persisted_inventory = persisted.result["endpoint_inventory"]
    assert set(persisted_inventory) == {"schema_version", "platform", "privacy", "collectors"}
    persisted_text = str(persisted_inventory)
    assert "Visual Studio Code" not in persisted_text
    assert "developer" not in persisted_text
    assert "com.example.agent" not in persisted_text
    assert "pid" not in persisted_text


def test_results_push_rejects_endpoint_inventory_without_stable_source_id() -> None:
    set_fleet_store(InMemoryFleetStore())
    response = TestClient(app).post("/v1/results/push", json={"endpoint_inventory": _endpoint_inventory()})
    assert response.status_code == 422
    assert response.json()["detail"] == "endpoint_inventory requires a stable source_id"


def test_results_push_rejects_unbounded_endpoint_source_id() -> None:
    set_fleet_store(InMemoryFleetStore())
    response = TestClient(app).post(
        "/v1/results/push",
        json={"source_id": "e" * 201, "endpoint_inventory": _endpoint_inventory()},
    )
    assert response.status_code == 422


def test_endpoint_inventory_is_a_privacy_safe_fleet_graph_node() -> None:
    report = {
        "source_id": "device-a",
        "scan_id": "scan-a",
        "scan_sources": ["endpoint_inventory"],
        "endpoint_inventory": _endpoint_inventory(),
    }

    graph = build_unified_graph_from_report(report, tenant_id="tenant-a")
    endpoints = graph.nodes_by_type(EntityType.FLEET)

    assert len(endpoints) == 1
    endpoint = endpoints[0]
    assert endpoint.id == "endpoint:device-a"
    assert endpoint.attributes["counts"]["applications"] == 1
    assert endpoint.attributes["collector_status"]["containers"] == "unavailable"
    assert endpoint.attributes["privacy"]["process_arguments_collected"] is False
    serialized = str(endpoint.to_dict())
    assert "developer" not in serialized
    assert "Visual Studio Code" not in serialized
    assert "com.example.agent" not in serialized


def test_sqlite_endpoint_registry_is_tenant_scoped_filterable_and_paged(tmp_path: Path) -> None:
    store = SQLiteFleetStore(str(tmp_path / "fleet.db"))
    for tenant_id, endpoint_id, system in (
        ("tenant-a", "device-a", "Darwin"),
        ("tenant-a", "device-b", "Windows"),
        ("tenant-b", "device-a", "Linux"),
    ):
        inventory = _endpoint_inventory()
        inventory["platform"]["system"] = system
        store.put_endpoint(
            endpoint_summary_from_inventory(
                endpoint_id=endpoint_id,
                tenant_id=tenant_id,
                inventory=inventory,
            )
        )

    page, total = store.query_endpoints("tenant-a", search="windows", limit=1, offset=0)
    assert total == 1
    assert [endpoint.endpoint_id for endpoint in page] == ["device-b"]
    assert store.get_endpoint("device-a", tenant_id="tenant-b").platform["system"] == "Linux"
    assert store.get_endpoint("device-a", tenant_id="tenant-a").platform["system"] == "Darwin"
