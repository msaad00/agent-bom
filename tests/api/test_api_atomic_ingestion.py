"""Atomic admission and rollback contracts for scan and push ingestion."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.fleet_store import InMemoryFleetStore, SQLiteFleetStore, endpoint_summary_from_inventory
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.idempotency_store import (
    InMemoryIdempotencyStore,
    SQLiteIdempotencyStore,
    deterministic_batch_id,
    idempotency_request_fingerprint,
)
from agent_bom.api.models import PushPayload, ScanRequest
from agent_bom.api.routes import scan as scan_routes
from agent_bom.api.server import app, set_fleet_store, set_graph_store, set_job_store
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore
from agent_bom.api.stores import set_idempotency_store
from agent_bom.graph.container import UnifiedGraph


def _endpoint_inventory(*, processes: int = 1) -> dict:
    return {
        "schema_version": "1",
        "platform": {"system": "Linux", "release": "6", "machine": "x86_64"},
        "privacy": {},
        "collectors": [
            {"name": "processes", "status": "complete", "item_count": processes, "message": ""},
        ],
    }


@pytest.fixture(autouse=True)
def _isolated_stores(monkeypatch: pytest.MonkeyPatch):
    original_job = stores._get_store()
    original_fleet = stores._get_fleet_store()
    original_graph = stores._get_graph_store()
    original_idempotency = stores._get_idempotency_store()
    set_job_store(InMemoryJobStore())
    set_fleet_store(InMemoryFleetStore())
    set_idempotency_store(InMemoryIdempotencyStore())
    stores._jobs.clear()
    monkeypatch.setattr("agent_bom.api.routes.scan.submit_scan_job", lambda _job: None)
    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", lambda _job, _report: None)
    yield
    stores._jobs.clear()
    set_job_store(original_job)
    set_fleet_store(original_fleet)
    set_graph_store(original_graph)
    set_idempotency_store(original_idempotency)


def test_scan_concurrent_same_key_creates_and_dispatches_one_job(monkeypatch: pytest.MonkeyPatch) -> None:
    idem = stores._get_idempotency_store()
    original_get = idem.get
    barrier = threading.Barrier(2)

    def _racing_get(*args, **kwargs):
        result = original_get(*args, **kwargs)
        if result is None:
            barrier.wait(timeout=2)
        return result

    monkeypatch.setattr(idem, "get", _racing_get)
    dispatched: list[str] = []
    monkeypatch.setattr("agent_bom.api.routes.scan.submit_scan_job", lambda job: dispatched.append(job.job_id))

    def _post() -> tuple[int, dict]:
        response = TestClient(app, raise_server_exceptions=False).post(
            "/v1/scan",
            headers={"Idempotency-Key": "scan-same-key"},
            json={"images": ["redis:7"]},
        )
        return response.status_code, response.json()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: _post(), range(2)))

    assert {status for status, _body in results} == {202}
    assert len({body["job_id"] for _status, body in results}) == 1
    assert len(stores._get_store().list_all(all_tenants=True)) == 1
    assert len(dispatched) == 1


def test_push_concurrent_same_key_commits_one_job_endpoint_and_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    graph_calls: list[str] = []
    monkeypatch.setattr(
        "agent_bom.api.routes.observability._persist_graph_snapshot",
        lambda job, _report: graph_calls.append(job.job_id),
    )

    payload = {
        "source_id": "endpoint-a",
        "idempotency_key": "push-same-key",
        "endpoint_inventory": _endpoint_inventory(),
    }

    def _post() -> tuple[int, dict]:
        response = TestClient(app, raise_server_exceptions=False).post("/v1/results/push", json=payload)
        return response.status_code, response.json()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: _post(), range(2)))

    assert {status for status, _body in results} == {201}
    assert len({body["job_id"] for _status, body in results}) == 1
    assert len(stores._get_store().list_all(all_tenants=True)) == 1
    endpoints, total = stores._get_fleet_store().query_endpoints("default")
    assert total == 1
    assert endpoints[0].endpoint_id == "endpoint-a"
    assert len(graph_calls) == 1


def test_push_same_key_different_payload_is_rejected_without_mutation() -> None:
    client = TestClient(app, raise_server_exceptions=False)
    first = client.post(
        "/v1/results/push",
        json={
            "source_id": "endpoint-a",
            "idempotency_key": "push-conflict",
            "endpoint_inventory": _endpoint_inventory(processes=1),
        },
    )
    conflict = client.post(
        "/v1/results/push",
        json={
            "source_id": "endpoint-a",
            "idempotency_key": "push-conflict",
            "endpoint_inventory": _endpoint_inventory(processes=9),
        },
    )

    assert first.status_code == 201
    assert conflict.status_code == 409
    assert len(stores._get_store().list_all(all_tenants=True)) == 1
    endpoint = stores._get_fleet_store().get_endpoint("endpoint-a", tenant_id="default")
    assert endpoint is not None
    assert endpoint.counts["processes"] == 1


def test_scan_retry_reclaims_expired_crash_reservation_without_duplicate_job(monkeypatch: pytest.MonkeyPatch) -> None:
    idem = stores._get_idempotency_store()
    body = ScanRequest(images=["redis:7"])
    request_hash = idempotency_request_fingerprint(body)
    reserved_job_id = deterministic_batch_id(f"/v1/scan:default:scan:crashed-scan:{request_hash}")
    key = ("/v1/scan", "default", "scan", "crashed-scan")
    idem.claim(*key, {"job_id": reserved_job_id, "committed": False}, request_hash=request_hash)
    idem._records[key].created_at = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()  # type: ignore[attr-defined]  # noqa: SLF001
    dispatched: list[str] = []
    monkeypatch.setenv("AGENT_BOM_IDEMPOTENCY_RESERVATION_LEASE_SECONDS", "30")
    monkeypatch.setattr("agent_bom.api.routes.scan.submit_scan_job", lambda job: dispatched.append(job.job_id))

    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/scan",
        headers={"Idempotency-Key": "crashed-scan"},
        json={"images": ["redis:7"]},
    )

    assert response.status_code == 202
    assert response.json()["job_id"] == reserved_job_id
    assert len(stores._get_store().list_all(all_tenants=True)) == 1
    assert dispatched == [reserved_job_id]
    assert idem.get(*key, request_hash=request_hash) == {"job_id": reserved_job_id, "committed": True}


def test_scan_retry_reconciles_durable_job_before_receipt_without_redispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    dispatched: list[str] = []
    monkeypatch.setattr("agent_bom.api.routes.scan.submit_scan_job", lambda job: dispatched.append(job.job_id))
    client = TestClient(app, raise_server_exceptions=False)
    headers = {"Idempotency-Key": "scan-crash-after-job"}
    payload = {"images": ["redis:7"]}
    first = client.post("/v1/scan", headers=headers, json=payload)
    assert first.status_code == 202

    idem = stores._get_idempotency_store()
    key = ("/v1/scan", "default", "scan", "scan-crash-after-job")
    record = idem._records[key]  # type: ignore[attr-defined]  # noqa: SLF001
    record.response_json = json.dumps({"job_id": first.json()["job_id"], "committed": False})

    replay = client.post("/v1/scan", headers=headers, json=payload)

    assert replay.status_code == 202
    assert replay.json()["job_id"] == first.json()["job_id"]
    assert len(stores._get_store().list_all(all_tenants=True)) == 1
    assert dispatched == [first.json()["job_id"]]
    assert idem.get(*key)["committed"] is True


def test_multi_target_scan_retry_repairs_missing_child_before_committed_receipt(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    jobs = SQLiteJobStore(str(tmp_path / "jobs.db"))
    idempotency = SQLiteIdempotencyStore(str(tmp_path / "idempotency.db"))
    set_job_store(jobs)
    set_idempotency_store(idempotency)
    dispatched: list[str] = []
    monkeypatch.setattr("agent_bom.api.routes.scan.submit_scan_job", lambda job: dispatched.append(job.job_id))
    client = TestClient(app, raise_server_exceptions=False)
    headers = {"Idempotency-Key": "multi-target-crash"}
    payload = {"images": ["redis:7", "nginx:1.27"], "no_scan": True}

    first = client.post("/v1/scan", headers=headers, json=payload)
    assert first.status_code == 202
    parent = jobs.get(first.json()["job_id"], tenant_id="default")
    assert parent is not None
    missing_child_id = parent.child_job_ids[0]
    assert jobs.delete(missing_child_id, tenant_id="default") is True
    dispatched.clear()

    replay = client.post("/v1/scan", headers=headers, json=payload)

    assert replay.status_code == 202
    assert replay.json()["job_id"] == parent.job_id
    repaired = jobs.get(missing_child_id, tenant_id="default")
    assert repaired is not None
    assert repaired.parent_job_id == parent.job_id
    assert dispatched == [missing_child_id]


def test_two_replicas_dispatch_only_the_winning_multi_target_child_repair(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    jobs = SQLiteJobStore(str(tmp_path / "jobs.db"))
    set_job_store(jobs)
    dispatched: list[str] = []
    monkeypatch.setattr(scan_routes, "dispatch_scan_job", lambda job: dispatched.append(job.job_id))
    parent = scan_routes.enqueue_scan_job(
        tenant_id="default",
        triggered_by="api-test",
        request_body=ScanRequest(images=["redis:7", "postgres:17"], no_scan=True),
    )
    missing_id = parent.child_job_ids[0]
    jobs.delete(missing_id, tenant_id="default")
    dispatched.clear()
    barrier = threading.Barrier(2)
    real_insert = jobs.put_many_if_absent_atomic

    def synchronized_insert(children):
        barrier.wait(timeout=5)
        return real_insert(children)

    monkeypatch.setattr(jobs, "put_many_if_absent_atomic", synchronized_insert)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: scan_routes._repair_scan_batch(parent), range(2)))

    assert [item.job_id for item in results] == [parent.job_id, parent.job_id]
    assert dispatched == [missing_id]


def test_push_retry_reclaims_expired_crash_reservation_without_duplicate_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph_calls: list[str] = []
    monkeypatch.setattr(
        "agent_bom.api.routes.observability._persist_graph_snapshot",
        lambda job, _report: graph_calls.append(job.job_id),
    )
    payload = {
        "source_id": "endpoint-a",
        "idempotency_key": "push-crash-after-claim",
        "endpoint_inventory": _endpoint_inventory(),
    }
    body = PushPayload.model_validate(payload)
    request_hash = idempotency_request_fingerprint(body)
    reserved_job_id = deterministic_batch_id(f"/v1/results/push:default:endpoint-a:push-crash-after-claim:{request_hash}")
    idem = stores._get_idempotency_store()
    key = ("/v1/results/push", "default", "endpoint-a", "push-crash-after-claim")
    idem.claim(*key, {"job_id": reserved_job_id, "committed": False}, request_hash=request_hash)
    idem._records[key].created_at = (datetime.now(timezone.utc) - timedelta(seconds=31)).isoformat()  # type: ignore[attr-defined]  # noqa: SLF001
    monkeypatch.setenv("AGENT_BOM_IDEMPOTENCY_RESERVATION_LEASE_SECONDS", "30")

    response = TestClient(app, raise_server_exceptions=False).post("/v1/results/push", json=payload)

    assert response.status_code == 201
    assert response.json()["job_id"] == reserved_job_id
    assert len(stores._get_store().list_all(all_tenants=True)) == 1
    assert graph_calls == [reserved_job_id]
    _endpoints, total = stores._get_fleet_store().query_endpoints("default")
    assert total == 1
    assert idem.get(*key, request_hash=request_hash)["committed"] is True


def test_push_retry_reconciles_committed_job_before_receipt_without_duplicate_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    graph_calls: list[str] = []
    monkeypatch.setattr(
        "agent_bom.api.routes.observability._persist_graph_snapshot",
        lambda job, _report: (
            (
                job.result.__setitem__("graph_persistence", {"status": "persisted", "scan_id": job.job_id})
                if isinstance(job.result, dict)
                else None
            )
            or graph_calls.append(job.job_id)
        ),
    )
    payload = {
        "source_id": "endpoint-a",
        "idempotency_key": "push-crash-after-commit",
        "endpoint_inventory": _endpoint_inventory(),
    }
    client = TestClient(app, raise_server_exceptions=False)
    first = client.post("/v1/results/push", json=payload)
    assert first.status_code == 201

    idem = stores._get_idempotency_store()
    key = ("/v1/results/push", "default", "endpoint-a", "push-crash-after-commit")
    record = idem._records[key]  # type: ignore[attr-defined]  # noqa: SLF001
    record.response_json = json.dumps({"job_id": first.json()["job_id"], "committed": False})

    replay = client.post("/v1/results/push", json=payload)

    assert replay.status_code == 201
    assert replay.json() == first.json()
    assert len(stores._get_store().list_all(all_tenants=True)) == 1
    assert graph_calls == [first.json()["job_id"]]
    endpoints, total = stores._get_fleet_store().query_endpoints("default")
    assert total == 1
    assert endpoints[0].last_scan_id == first.json()["job_id"]
    assert idem.get(*key)["committed"] is True


def test_push_first_job_write_failure_restores_prior_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FailFirstPutStore(InMemoryJobStore):
        def put(self, job) -> None:
            raise RuntimeError("job store unavailable")

    fleet = stores._get_fleet_store()
    previous = endpoint_summary_from_inventory(
        endpoint_id="endpoint-a",
        tenant_id="default",
        inventory=_endpoint_inventory(processes=2),
        scan_id="previous",
    )
    fleet.put_endpoint(previous)
    set_job_store(_FailFirstPutStore())

    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/results/push",
        json={
            "source_id": "endpoint-a",
            "idempotency_key": "job-write-fails",
            "endpoint_inventory": _endpoint_inventory(processes=9),
        },
    )

    assert response.status_code == 503
    restored = fleet.get_endpoint("endpoint-a", tenant_id="default")
    assert restored is not None
    assert restored.last_scan_id == "previous"
    assert restored.counts["processes"] == 2


def test_push_graph_failure_rolls_back_job_endpoint_and_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    fleet = stores._get_fleet_store()
    previous = endpoint_summary_from_inventory(
        endpoint_id="endpoint-a",
        tenant_id="default",
        inventory=_endpoint_inventory(processes=2),
        scan_id="previous",
    )
    fleet.put_endpoint(previous)
    graph_rollbacks: list[tuple[str, str]] = []

    class _GraphStore:
        def delete_snapshot(self, *, tenant_id: str, scan_id: str) -> int:
            graph_rollbacks.append((tenant_id, scan_id))
            return 0

    monkeypatch.setattr("agent_bom.api.routes.observability._get_graph_store", lambda: _GraphStore())
    monkeypatch.setattr(
        "agent_bom.api.routes.observability._persist_graph_snapshot",
        lambda _job, _report: (_ for _ in ()).throw(RuntimeError("postgresql://user:secret@db/private")),
    )

    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/results/push",
        json={
            "source_id": "endpoint-a",
            "idempotency_key": "push-fails",
            "endpoint_inventory": _endpoint_inventory(processes=9),
        },
    )

    assert response.status_code == 503
    assert "secret" not in response.text
    assert "/private" not in response.text
    assert stores._get_store().list_all(all_tenants=True) == []
    restored = fleet.get_endpoint("endpoint-a", tenant_id="default")
    assert restored is not None
    assert restored.last_scan_id == "previous"
    assert restored.counts["processes"] == 2
    assert len(graph_rollbacks) == 1
    assert graph_rollbacks[0][0] == "default"
    assert graph_rollbacks[0][1]
    assert stores._get_idempotency_store().get("/v1/results/push", "default", "endpoint-a", "push-fails") is None


def test_sqlite_graph_snapshot_rollback_is_tenant_scoped(tmp_path) -> None:
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    graph_store.save_graph(UnifiedGraph(scan_id="same-scan", tenant_id="tenant-a"))
    graph_store.save_graph(UnifiedGraph(scan_id="same-scan", tenant_id="tenant-b"))

    graph_store.delete_snapshot(tenant_id="tenant-a", scan_id="same-scan")

    assert graph_store.latest_snapshot_id(tenant_id="tenant-a") == ""
    assert graph_store.latest_snapshot_id(tenant_id="tenant-b") == "same-scan"


def test_push_final_job_receipt_failure_rolls_back_all_projections(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FailSecondPutStore(InMemoryJobStore):
        def __init__(self) -> None:
            super().__init__()
            self.put_count = 0

        def put(self, job) -> None:
            self.put_count += 1
            if self.put_count == 2:
                raise RuntimeError("postgresql://user:secret@db/private")
            super().put(job)

    job_store = _FailSecondPutStore()
    set_job_store(job_store)
    graph_rollbacks: list[tuple[str, str]] = []

    class _GraphStore:
        def delete_snapshot(self, *, tenant_id: str, scan_id: str) -> int:
            graph_rollbacks.append((tenant_id, scan_id))
            return 1

    monkeypatch.setattr("agent_bom.api.routes.observability._get_graph_store", lambda: _GraphStore())

    response = TestClient(app, raise_server_exceptions=False).post(
        "/v1/results/push",
        json={
            "source_id": "endpoint-a",
            "idempotency_key": "final-receipt-fails",
            "endpoint_inventory": _endpoint_inventory(),
        },
    )

    assert response.status_code == 503
    assert "secret" not in response.text
    assert job_store.list_all(all_tenants=True) == []
    assert stores._get_fleet_store().get_endpoint("endpoint-a", tenant_id="default") is None
    assert len(graph_rollbacks) == 1


def test_sqlite_push_replay_keeps_job_endpoint_graph_and_idempotency_aligned(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.pipeline import _persist_graph_snapshot

    job_store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    fleet_store = SQLiteFleetStore(str(tmp_path / "fleet.db"))
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    set_job_store(job_store)
    set_fleet_store(fleet_store)
    set_graph_store(graph_store)
    set_idempotency_store(SQLiteIdempotencyStore(str(tmp_path / "idempotency.db")))
    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", _persist_graph_snapshot)
    payload = {
        "source_id": "endpoint-a",
        "idempotency_key": "sqlite-push",
        "endpoint_inventory": _endpoint_inventory(),
    }
    client = TestClient(app, raise_server_exceptions=False)

    first = client.post("/v1/results/push", json=payload)
    second = client.post("/v1/results/push", json=payload)

    assert first.status_code == second.status_code == 201
    assert first.json()["job_id"] == second.json()["job_id"]
    job_id = first.json()["job_id"]
    assert len(job_store.list_all(tenant_id="default")) == 1
    assert fleet_store.get_endpoint("endpoint-a", tenant_id="default").last_scan_id == job_id
    assert graph_store.latest_snapshot_id(tenant_id="default") == job_id
