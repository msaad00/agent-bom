"""Push/runtime producers complete only preassigned correlation-cohort children."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.auto_correlation import AutoCorrelationPolicy, reconcile_auto_correlations_once
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.idempotency_store import InMemoryIdempotencyStore
from agent_bom.api.server import app, configure_api
from agent_bom.api.source_store import InMemorySourceStore
from agent_bom.api.store import InMemoryJobStore, SQLiteJobStore
from agent_bom.cloud.runtime_workload_evidence import (
    RuntimeEvidenceSource,
    RuntimeSourceRegistry,
    set_runtime_source_registry,
)
from agent_bom.cloud.runtime_workload_evidence_store import (
    InMemoryRuntimeWorkloadEvidenceStore,
    set_runtime_workload_evidence_store,
)
from agent_bom.graph.correlation_service import GraphCorrelationService
from tests.auth_helpers import PROXY_SECRET

TENANT = "tenant-alpha"
OTHER_TENANT = "tenant-beta"
RUNTIME_SECRET = "runtime-source-secret-value"
HEADERS = {
    "X-Agent-Bom-Role": "analyst",
    "X-Agent-Bom-Tenant-ID": TENANT,
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}
ADMIN_HEADERS = {**HEADERS, "X-Agent-Bom-Role": "admin"}


def _headers(tenant_id: str = TENANT) -> dict[str, str]:
    return {**HEADERS, "X-Agent-Bom-Tenant-ID": tenant_id}


@pytest.fixture
def cohort_client(tmp_path, monkeypatch: pytest.MonkeyPatch):
    prior = {
        "job": stores._store,
        "graph": stores._graph_store,
        "source": stores._source_store,
        "idempotency": stores._idempotency_store,
    }
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    monkeypatch.setenv("AGENT_BOM_GRAPH_AUTO_CORRELATE", "1")
    configure_api(api_key=None)
    job_store = SQLiteJobStore(tmp_path / "jobs.db")
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    stores.set_job_store(job_store)
    stores.set_graph_store(graph_store)
    stores.set_source_store(InMemorySourceStore())
    stores.set_idempotency_store(InMemoryIdempotencyStore())
    with stores._jobs_lock:
        stores._jobs.clear()
        stores._job_locks.clear()
    set_runtime_workload_evidence_store(InMemoryRuntimeWorkloadEvidenceStore())
    set_runtime_source_registry(RuntimeSourceRegistry())
    try:
        with TestClient(app) as client:
            yield client, job_store, graph_store
    finally:
        set_runtime_source_registry(None)
        set_runtime_workload_evidence_store(None)
        stores._store = prior["job"]
        stores._graph_store = prior["graph"]
        stores._source_store = prior["source"]
        stores._idempotency_store = prior["idempotency"]
        with stores._jobs_lock:
            stores._jobs.clear()
            stores._job_locks.clear()
        monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
        monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", raising=False)
        configure_api(api_key=None)


def _create_external_cohort(client: TestClient, *, max_age_hours: int = 24) -> dict[str, Any]:
    source_ids: dict[str, str] = {}
    for label, kind in (("result", "ingest.result_push"), ("runtime", "runtime.gateway")):
        response = client.post(
            "/v1/sources",
            headers=HEADERS,
            json={"display_name": f"{label} producer", "kind": kind},
        )
        assert response.status_code == 201, response.text
        source_ids[label] = response.json()["source_id"]
    registry = RuntimeSourceRegistry()
    registry.add(
        RuntimeEvidenceSource.register(
            source_id=source_ids["runtime"],
            tenant_id=TENANT,
            provider="aws",
            account_id="123456789012",
            kind="gateway",
            secret=RUNTIME_SECRET,
        )
    )
    set_runtime_source_registry(registry)
    response = client.post(
        "/v1/sources/run-cohort",
        headers={**HEADERS, "Idempotency-Key": "external-deploy-1"},
        json={"source_ids": list(source_ids.values()), "max_age_hours": max_age_hours},
    )
    assert response.status_code == 202, response.text
    body = response.json()
    receipts = {receipt["source_id"]: receipt for receipt in body["child_receipts"]}
    assert set(receipts) == set(source_ids.values())
    assert all(receipt["cohort_manifest_hash"] == body["cohort_manifest_hash"] for receipt in receipts.values())
    return {**body, "source_ids_by_kind": source_ids, "receipts": receipts}


def _result_payload(cohort: dict[str, Any], *, suffix: str = "") -> dict[str, Any]:
    source_id = cohort["source_ids_by_kind"]["result"]
    return {
        "source_id": source_id,
        "idempotency_key": f"result-1{suffix}",
        "correlation_cohort_id": cohort["correlation_cohort_id"],
        "correlation_child_receipt": cohort["receipts"][source_id],
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "agents": [{"name": f"gateway{suffix}", "type": "custom", "mcp_servers": []}],
    }


def _runtime_payload(cohort: dict[str, Any], *, dedup_key: str = "evt-1") -> dict[str, Any]:
    source_id = cohort["source_ids_by_kind"]["runtime"]
    return {
        "source_id": source_id,
        "secret": RUNTIME_SECRET,
        "correlation_cohort_id": cohort["correlation_cohort_id"],
        "correlation_child_receipt": cohort["receipts"][source_id],
        "signals": [
            {
                "workload_ref": "i-0abc",
                "signal_type": "ioc_detection",
                "dedup_key": dedup_key,
                "severity": "high",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "title": "beacon",
            }
        ],
    }


def test_external_cohort_receipts_complete_exact_children_and_parent(cohort_client) -> None:
    client, jobs, graph_store = cohort_client
    cohort = _create_external_cohort(client)

    pushed = client.post("/v1/results/push", headers=HEADERS, json=_result_payload(cohort))
    assert pushed.status_code == 201, pushed.text
    assert pushed.json()["correlation_cohort_id"] == cohort["correlation_cohort_id"]
    runtime = client.post(
        "/v1/cloud/runtime-evidence/ingest",
        headers=ADMIN_HEADERS,
        json=_runtime_payload(cohort),
    )
    assert runtime.status_code == 200, runtime.text
    assert runtime.json()["correlation_cohort_id"] == cohort["correlation_cohort_id"]

    parent = jobs.get(cohort["parent_job_id"], tenant_id=TENANT)
    assert parent is not None
    assert parent.status.value == "done"
    assert parent.result["auto_correlation"]["status"] == "pending"
    assert parent.result["aggregation"]["succeeded_targets"] == 2
    snapshots = graph_store.snapshots_by_ids(tenant_id=TENANT, scan_ids=set(cohort["child_job_ids"]))
    assert {row["scan_id"] for row in snapshots} == set(cohort["child_job_ids"])
    assert all(row["node_count"] > 0 for row in snapshots)

    async def _correlate() -> dict[str, Any]:
        service = GraphCorrelationService(graph_store)
        await service.start(tenants=[TENANT])
        try:
            decisions = await reconcile_auto_correlations_once(
                jobs,
                graph_store,
                policy=AutoCorrelationPolicy(enabled=True, max_age_hours=24),
                service=service,
            )
            assert decisions[0]["status"] == "scheduled"
            correlation_id = decisions[0]["correlation_id"]
            completed = await service.wait(TENANT, correlation_id, timeout_seconds=5)
            await reconcile_auto_correlations_once(
                jobs,
                graph_store,
                policy=AutoCorrelationPolicy(enabled=True, max_age_hours=24),
                service=service,
            )
            return completed.to_dict()
        finally:
            await service.stop()

    import asyncio

    completed = asyncio.run(_correlate())
    assert completed["status"] == "complete"
    assert completed["output_scan_id"] == completed["correlation_id"]
    assert graph_store.load_graph(tenant_id=TENANT, scan_id=completed["output_scan_id"]).nodes


def test_cohort_result_replay_is_idempotent_but_changed_duplicate_is_rejected(cohort_client) -> None:
    client, jobs, _graph_store = cohort_client
    cohort = _create_external_cohort(client)
    payload = _result_payload(cohort)
    first = client.post("/v1/results/push", headers=HEADERS, json=payload)
    replay = client.post("/v1/results/push", headers=HEADERS, json=payload)
    assert first.status_code == replay.status_code == 201
    assert replay.json() == first.json()

    changed = dict(payload)
    changed["agents"] = [{"name": "different", "type": "custom", "mcp_servers": []}]
    conflict = client.post("/v1/results/push", headers=HEADERS, json=changed)
    assert conflict.status_code == 409
    child = jobs.get(first.json()["job_id"], tenant_id=TENANT)
    assert child is not None
    assert child.result["agents"][0]["name"] == "gateway"


@pytest.mark.parametrize("tamper", ["manifest", "source", "signature"])
def test_forged_or_wrong_member_receipt_is_rejected_without_partial_state(cohort_client, tamper: str) -> None:
    client, jobs, graph_store = cohort_client
    cohort = _create_external_cohort(client)
    payload = _result_payload(cohort)
    receipt = dict(payload["correlation_child_receipt"])
    if tamper == "manifest":
        receipt["cohort_manifest_hash"] = "f" * 64
    elif tamper == "source":
        receipt["source_id"] = cohort["source_ids_by_kind"]["runtime"]
    else:
        receipt["signature"] = "sha256:" + "0" * 64
    payload["correlation_child_receipt"] = receipt

    response = client.post("/v1/results/push", headers=HEADERS, json=payload)
    assert response.status_code == 409
    assert response.json()["detail"] == "Correlation cohort receipt is invalid"
    result_child_id = cohort["receipts"][cohort["source_ids_by_kind"]["result"]]["child_job_id"]
    child = jobs.get(result_child_id, tenant_id=TENANT)
    assert child is not None and child.status.value == "pending"
    assert graph_store.load_graph(tenant_id=TENANT, scan_id=result_child_id).nodes == {}


def test_cross_tenant_receipt_is_generic_and_does_not_reveal_membership(cohort_client) -> None:
    client, jobs, _graph_store = cohort_client
    cohort = _create_external_cohort(client)
    response = client.post("/v1/results/push", headers=_headers(OTHER_TENANT), json=_result_payload(cohort))
    assert response.status_code == 409
    assert response.json()["detail"] == "Correlation cohort receipt is invalid"
    child_id = cohort["receipts"][cohort["source_ids_by_kind"]["result"]]["child_job_id"]
    assert jobs.get(child_id, tenant_id=TENANT).status.value == "pending"


def test_stale_cohort_evidence_is_rejected_before_child_completion(cohort_client) -> None:
    client, jobs, graph_store = cohort_client
    cohort = _create_external_cohort(client, max_age_hours=1)
    payload = _result_payload(cohort)
    payload["observed_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    response = client.post("/v1/results/push", headers=HEADERS, json=payload)
    assert response.status_code == 409
    assert response.json()["detail"] == "Correlation cohort evidence is stale"
    child_id = cohort["receipts"][cohort["source_ids_by_kind"]["result"]]["child_job_id"]
    assert jobs.get(child_id, tenant_id=TENANT).status.value == "pending"
    assert graph_store.load_graph(tenant_id=TENANT, scan_id=child_id).nodes == {}


def test_missing_cohort_pair_preserves_plain_push_but_rejects_partial_claim(cohort_client) -> None:
    client, _jobs, _graph_store = cohort_client
    plain = client.post(
        "/v1/results/push",
        headers=HEADERS,
        json={
            "source_id": "plain-source",
            "agents": [{"name": "plain", "type": "custom", "mcp_servers": []}],
        },
    )
    assert plain.status_code == 201

    partial = client.post(
        "/v1/results/push",
        headers=HEADERS,
        json={
            "source_id": "plain-source",
            "correlation_cohort_id": "00000000-0000-0000-0000-000000000001",
            "agents": [{"name": "plain", "type": "custom", "mcp_servers": []}],
        },
    )
    assert partial.status_code == 422
    assert partial.json()["detail"] == "Correlation cohort id and child receipt must be provided together"


def test_unsupported_store_rejects_child_completion(cohort_client) -> None:
    client, _jobs, graph_store = cohort_client
    stores.set_job_store(InMemoryJobStore())
    with stores._jobs_lock:
        stores._jobs.clear()
        stores._job_locks.clear()
    cohort = _create_external_cohort(client)
    response = client.post("/v1/results/push", headers=HEADERS, json=_result_payload(cohort))
    assert response.status_code == 409
    assert response.json()["detail"] == "Correlation cohort ingest requires durable stores"
    child_id = cohort["receipts"][cohort["source_ids_by_kind"]["result"]]["child_job_id"]
    assert stores._get_store().get(child_id, tenant_id=TENANT).status.value == "pending"
    assert graph_store.load_graph(tenant_id=TENANT, scan_id=child_id).nodes == {}


def test_graph_commit_failure_rolls_back_snapshot_and_sanitizes_error(cohort_client, monkeypatch: pytest.MonkeyPatch) -> None:
    client, jobs, graph_store = cohort_client
    cohort = _create_external_cohort(client)
    from agent_bom.api import pipeline

    real_persist = pipeline._persist_graph_snapshot

    def _partial_then_fail(job, result):
        real_persist(job, result)
        raise RuntimeError("password=super-secret-database-value")

    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", _partial_then_fail)
    response = client.post("/v1/results/push", headers=HEADERS, json=_result_payload(cohort))
    assert response.status_code == 503
    assert response.json()["detail"] == "Correlation cohort result could not be committed"
    assert "super-secret" not in response.text
    child_id = cohort["receipts"][cohort["source_ids_by_kind"]["result"]]["child_job_id"]
    assert jobs.get(child_id, tenant_id=TENANT).status.value == "pending"
    assert graph_store.load_graph(tenant_id=TENANT, scan_id=child_id).nodes == {}


def test_runtime_graph_commit_failure_leaves_no_selectable_cohort_snapshot(cohort_client, monkeypatch: pytest.MonkeyPatch) -> None:
    client, jobs, graph_store = cohort_client
    cohort = _create_external_cohort(client)
    real_save = graph_store.save_graph

    def _partial_then_fail(graph) -> None:
        real_save(graph)
        raise RuntimeError("postgresql://operator:secret@internal/runtime")

    monkeypatch.setattr(graph_store, "save_graph", _partial_then_fail)
    response = client.post(
        "/v1/cloud/runtime-evidence/ingest",
        headers=ADMIN_HEADERS,
        json=_runtime_payload(cohort),
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Runtime evidence ingest failed; see server logs."
    assert "operator" not in response.text
    child_id = cohort["receipts"][cohort["source_ids_by_kind"]["runtime"]]["child_job_id"]
    assert jobs.get(child_id, tenant_id=TENANT).status.value == "pending"
    assert graph_store.load_graph(tenant_id=TENANT, scan_id=child_id).nodes == {}


def test_runtime_stale_or_wrong_child_receipt_never_completes_child(cohort_client) -> None:
    client, jobs, graph_store = cohort_client
    cohort = _create_external_cohort(client, max_age_hours=1)
    payload = _runtime_payload(cohort)
    payload["signals"][0]["observed_at"] = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    stale = client.post("/v1/cloud/runtime-evidence/ingest", headers=ADMIN_HEADERS, json=payload)
    assert stale.status_code == 409
    assert stale.json()["detail"] == "Correlation cohort evidence is stale"

    payload = _runtime_payload(cohort, dedup_key="wrong-receipt")
    result_source = cohort["source_ids_by_kind"]["result"]
    payload["correlation_child_receipt"] = cohort["receipts"][result_source]
    wrong = client.post("/v1/cloud/runtime-evidence/ingest", headers=ADMIN_HEADERS, json=payload)
    assert wrong.status_code == 409
    assert wrong.json()["detail"] == "Correlation cohort receipt is invalid"
    runtime_source = cohort["source_ids_by_kind"]["runtime"]
    child_id = cohort["receipts"][runtime_source]["child_job_id"]
    assert jobs.get(child_id, tenant_id=TENANT).status.value == "pending"
    assert graph_store.load_graph(tenant_id=TENANT, scan_id=child_id).nodes == {}
