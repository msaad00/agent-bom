"""Authenticated API contract for durable graph correlations."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.middleware import APIKeyMiddleware
from agent_bom.api.server import app, configure_api
from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.correlation import (
    CorrelationRunStatus,
    GraphCorrelationRun,
    correlation_graph_digest,
    correlation_manifest_digest,
)
from agent_bom.runtime.correlation_facts import verify_runtime_facts_bundle


def _snapshot(scan_id: str, *, tenant_id: str = "default") -> UnifiedGraph:
    graph = UnifiedGraph(
        scan_id=scan_id,
        tenant_id=tenant_id,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    graph.add_node(
        UnifiedNode(
            id=f"package:{scan_id}",
            entity_type=EntityType.PACKAGE,
            label=scan_id,
            attributes={"purl": f"pkg:pypi/{scan_id}@1.0.0"},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="agent:runtime",
            entity_type=EntityType.AGENT,
            label="runtime-agent",
            attributes={"runtime_id": "runtime-agent"},
        )
    )
    graph.add_node(UnifiedNode(id="tool:secret", entity_type=EntityType.TOOL, label="read_secret"))
    graph.add_edge(
        UnifiedEdge(
            source="agent:runtime",
            target="tool:secret",
            relationship=RelationshipType.REACHES_TOOL,
            source_scan_id=scan_id,
            provenance={"source": "runtime"},
        )
    )
    return graph


@pytest.fixture
def correlation_client(tmp_path, monkeypatch):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_snapshot("repo-scan"))
    store.save_graph(_snapshot("image-scan"))
    monkeypatch.setattr(api_stores, "_graph_store", store)
    configure_api(api_key=None, allow_unauthenticated=True)
    try:
        with TestClient(app) as client:
            yield client, store
    finally:
        configure_api(api_key=None)


def test_create_requires_idempotency_key(correlation_client) -> None:
    client, _store = correlation_client

    response = client.post(
        "/v1/graph/correlations",
        json={
            "name": "reference proof",
            "scan_ids": ["repo-scan", "image-scan"],
            "max_age_hours": 168,
        },
    )

    assert response.status_code == 422
    assert "Idempotency-Key" in response.text


def test_create_list_status_and_tenant_isolation(correlation_client, monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_HMAC_KEY", "correlation-receipt-api-test-key-material")
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_KEY_ID", "api-test-v1")
    client, store = correlation_client

    created = client.post(
        "/v1/graph/correlations",
        headers={"Idempotency-Key": "idem-reference-proof"},
        json={
            "name": "reference proof",
            "scan_ids": ["repo-scan", "image-scan"],
            "max_age_hours": 168,
        },
    )

    assert created.status_code == 202
    payload = created.json()
    assert payload["correlation_id"]
    assert payload["tenant_id"] == "default"
    assert payload["max_age_hours"] == 168
    assert [row["scan_id"] for row in payload["input_manifest"]] == ["image-scan", "repo-scan"]
    assert payload["receipt_verification"]["status"] == "verified"
    assert payload["receipt_verification"]["verified"] == 2
    assert {row["verification"] for row in payload["input_manifest"]} == {"verified"}
    assert {row["signature"]["key_id"] for row in payload["input_manifest"]} == {"api-test-v1"}

    replay = client.post(
        "/v1/graph/correlations",
        headers={"Idempotency-Key": "idem-reference-proof"},
        json={
            "name": "reference proof",
            "scan_ids": ["repo-scan", "image-scan"],
            "max_age_hours": 168,
        },
    )
    assert replay.status_code == 202
    assert replay.json()["correlation_id"] == payload["correlation_id"]

    listed = client.get("/v1/graph/correlations")
    assert listed.status_code == 200
    assert [row["correlation_id"] for row in listed.json()["items"]] == [payload["correlation_id"]]

    status = client.get(f"/v1/graph/correlations/{payload['correlation_id']}")
    assert status.status_code == 200
    assert status.json()["correlation_id"] == payload["correlation_id"]
    assert status.json()["receipt_verification"]["status"] == "verified"

    assert store.get_correlation_run(tenant_id="tenant-b", correlation_id=payload["correlation_id"]) is None


def test_idempotency_key_rejects_a_different_request(correlation_client) -> None:
    client, _store = correlation_client
    headers = {"Idempotency-Key": "idem-conflict"}
    body = {"name": "proof", "scan_ids": ["repo-scan", "image-scan"], "max_age_hours": 168}

    assert client.post("/v1/graph/correlations", headers=headers, json=body).status_code == 202
    response = client.post(
        "/v1/graph/correlations",
        headers=headers,
        json={**body, "max_age_hours": 24},
    )

    assert response.status_code == 409
    assert "different correlation request" not in response.text


def test_runtime_facts_rejects_incomplete_or_missing_signing_configuration(correlation_client) -> None:
    client, _store = correlation_client
    created = client.post(
        "/v1/graph/correlations",
        headers={"Idempotency-Key": "idem-runtime"},
        json={"name": "runtime", "scan_ids": ["repo-scan", "image-scan"], "max_age_hours": 168},
    ).json()

    response = client.get(f"/v1/graph/correlations/{created['correlation_id']}/runtime-facts")

    assert response.status_code in {409, 503}
    assert "signing" not in response.text.lower() or "not configured" in response.text.lower()


def test_runtime_facts_returns_a_tenant_bound_verifiable_bundle(correlation_client, monkeypatch) -> None:
    client, _store = correlation_client
    signing_key = "correlation-runtime-facts-test-key-32-bytes"
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_HMAC_KEY", signing_key)
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_HMAC_KEY_FILE", "")
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_KEY_ID", "test-key")
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_TTL_SECONDS", 60)
    created = client.post(
        "/v1/graph/correlations",
        headers={"Idempotency-Key": "idem-runtime-success"},
        json={"name": "runtime", "scan_ids": ["repo-scan", "image-scan"], "max_age_hours": 168},
    ).json()

    deadline = time.monotonic() + 2
    status = created
    while status["status"] not in {"complete", "failed"} and time.monotonic() < deadline:
        time.sleep(0.01)
        status = client.get(f"/v1/graph/correlations/{created['correlation_id']}").json()

    assert status["status"] == "complete"
    response = client.get(f"/v1/graph/correlations/{created['correlation_id']}/runtime-facts")
    assert response.status_code == 200, response.text
    bundle = response.json()
    verified = verify_runtime_facts_bundle(bundle, signing_key=signing_key.encode(), tenant_id="default")
    assert verified.correlation_id == created["correlation_id"]
    assert verified.manifest_sha256 == status["manifest_sha256"]
    assert verified.analysis_complete is True
    assert bundle["signature"]["key_id"] == "test-key"


def test_runtime_facts_refetch_rejects_inputs_that_aged_out_after_correlation(correlation_client, monkeypatch) -> None:
    from agent_bom.runtime import correlation_facts

    client, _store = correlation_client
    signing_key = "correlation-runtime-facts-test-key-32-bytes"
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_HMAC_KEY", signing_key)
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_HMAC_KEY_FILE", "")
    created = client.post(
        "/v1/graph/correlations",
        headers={"Idempotency-Key": "idem-runtime-aging"},
        json={"name": "runtime", "scan_ids": ["repo-scan", "image-scan"], "max_age_hours": 1},
    ).json()

    deadline = time.monotonic() + 2
    status = created
    while status["status"] not in {"complete", "failed"} and time.monotonic() < deadline:
        time.sleep(0.01)
        status = client.get(f"/v1/graph/correlations/{created['correlation_id']}").json()
    assert status["status"] == "complete"

    first = client.get(f"/v1/graph/correlations/{created['correlation_id']}/runtime-facts")
    assert first.status_code == 200, first.text
    first_issued_at = datetime.fromisoformat(first.json()["payload"]["issued_at"])

    class _AgedClock(datetime):
        @classmethod
        def now(cls, tz=None):
            aged = first_issued_at + timedelta(hours=2)
            return aged if tz is None else aged.astimezone(tz)

    monkeypatch.setattr(correlation_facts, "datetime", _AgedClock)
    second = client.get(f"/v1/graph/correlations/{created['correlation_id']}/runtime-facts")

    assert second.status_code == 409
    assert second.json()["detail"] == "correlation_inputs_stale"
    assert second.json()["error"]["code"] == "CONFLICT"


def test_runtime_facts_rejects_a_purged_completed_output(correlation_client, monkeypatch) -> None:
    client, store = correlation_client
    signing_key = "correlation-runtime-facts-test-key-32-bytes"
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_HMAC_KEY", signing_key)
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_HMAC_KEY_FILE", "")
    created = client.post(
        "/v1/graph/correlations",
        headers={"Idempotency-Key": "idem-runtime-purge"},
        json={"name": "runtime", "scan_ids": ["repo-scan", "image-scan"], "max_age_hours": 168},
    ).json()
    deadline = time.monotonic() + 2
    status = created
    while status["status"] not in {"complete", "failed"} and time.monotonic() < deadline:
        time.sleep(0.01)
        status = client.get(f"/v1/graph/correlations/{created['correlation_id']}").json()
    assert status["status"] == "complete"

    with sqlite_graph_store.open_graph_db(store._db_path) as conn:
        conn.execute(
            "UPDATE graph_snapshots SET created_at = ? WHERE tenant_id = ? AND scan_id = ?",
            ("2026-01-01T00:00:00+00:00", "default", created["correlation_id"]),
        )
        sqlite_graph_store.purge_expired_graph_snapshots(
            conn,
            retention_days=1,
            now=datetime(2026, 8, 30, tzinfo=timezone.utc),
            tenant_id="default",
        )

    response = client.get(f"/v1/graph/correlations/{created['correlation_id']}/runtime-facts")

    assert response.status_code == 409
    assert response.json()["detail"] == "correlation_output_unavailable"


def test_completed_correlation_exposes_exact_remediation_decision(correlation_client, monkeypatch) -> None:
    client, store = correlation_client
    root = Path(__file__).resolve().parents[1]
    payload = json.loads(
        (root / "examples" / "reference-evidence-lab" / "generated" / "correlation-proof.json").read_text(
            encoding="utf-8"
        )
    )
    graph = UnifiedGraph.from_dict(payload["capture_fixture"]["graph"])
    graph.tenant_id = "default"
    vulnerability = graph.nodes["vulnerability:mcp:cve-2023-4863"]
    vulnerability.attributes.update(
        {
            "finding_id": "reference-finding-cve-2023-4863",
            "fixed_version": "10.0.1",
            "is_kev": True,
            "kev_due_date": "2023-10-04",
            "evidence_scope": {
                "name": "reference_evidence_lab",
                "infrastructure": "modeled_local",
                "customer_evidence": False,
                "live_cloud": False,
            },
        }
    )
    graph.nodes["package:sbom:pillow"].attributes.update(
        {"package_name": "pillow", "ecosystem": "pypi", "version": "9.0.0"}
    )
    graph.attack_paths[0].finding_ids = ["reference-finding-cve-2023-4863"]
    store.save_graph(graph)
    result_manifest = {
        "schema_version": "agent-bom.graph-correlation-manifest/v1",
        "correlation_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "output": {
            "scan_id": graph.scan_id,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "attack_path_count": len(graph.attack_paths),
            "graph_digest_sha256": correlation_graph_digest(graph),
        },
    }
    manifest_sha256 = correlation_manifest_digest(result_manifest)
    run = GraphCorrelationRun(
        correlation_id=graph.scan_id,
        tenant_id=graph.tenant_id,
        idempotency_key="reference-remediation",
        name="reference remediation",
        status=CorrelationRunStatus.COMPLETE,
        max_age_hours=168,
        allow_stale=False,
        input_manifest=[
            {"scan_id": "repo", "created_at": graph.created_at, "digest": "sha256:" + "a" * 64},
            {"scan_id": "image", "created_at": graph.created_at, "digest": "sha256:" + "b" * 64},
        ],
        result_manifest=result_manifest,
        manifest_sha256=manifest_sha256,
        output_scan_id=graph.scan_id,
        completed_at=graph.created_at,
    )
    monkeypatch.setattr("agent_bom.api.routes.graph_correlations._get_run", lambda *_args: run)

    response = client.get(f"/v1/graph/correlations/{graph.scan_id}/remediation")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["correlation_id"] == graph.scan_id
    assert body["snapshot_id"] == graph.scan_id
    assert body["correlation_manifest_sha256"] == manifest_sha256
    assert body["count"] == 1
    decision = body["remediation_decisions"][0]
    assert decision["finding"]["finding_id"] == "reference-finding-cve-2023-4863"
    assert decision["package"]["purl"] == "pkg:pypi/pillow@9.0.0"
    assert decision["container"]["image_digest"] == payload["container_digest"]
    assert decision["path"]["hops"] == graph.attack_paths[0].hops
    assert decision["ownership"]["status"] == "unassigned"
    assert decision["recommendation"]["fixed_version"] == "10.0.1"
    assert decision["verification"]["status"] == "not_run"
    assert decision["reverification"] == {
        "rescan_status": "not_run",
        "recorrelation_status": "not_run",
        "predecessor_snapshot_id": graph.scan_id,
    }


def test_correlation_routes_enforce_scan_write_and_graph_read_scopes() -> None:
    async def ok(_request):
        return JSONResponse({"ok": True})

    original_store = get_key_store()
    store = KeyStore()
    raw_read, read_key = create_api_key("read", Role.ANALYST, tenant_id="tenant-a", scopes=["graph:read"])
    raw_write, write_key = create_api_key("write", Role.ANALYST, tenant_id="tenant-a", scopes=["scan:write"])
    store.add(read_key)
    store.add(write_key)
    set_key_store(store)
    try:
        scoped_app = Starlette(
            routes=[
                Route("/v1/graph/correlations", ok, methods=["GET", "POST"]),
                Route("/v1/graph/correlations/corr-1", ok, methods=["GET"]),
            ]
        )
        scoped_app.add_middleware(APIKeyMiddleware, api_key="configured")
        client = TestClient(scoped_app)

        assert client.post("/v1/graph/correlations", headers={"Authorization": f"Bearer {raw_read}"}).status_code == 403
        assert client.post("/v1/graph/correlations", headers={"Authorization": f"Bearer {raw_write}"}).status_code == 200
        assert client.get("/v1/graph/correlations/corr-1", headers={"Authorization": f"Bearer {raw_write}"}).status_code == 403
        assert client.get("/v1/graph/correlations/corr-1", headers={"Authorization": f"Bearer {raw_read}"}).status_code == 200
    finally:
        set_key_store(original_store)
