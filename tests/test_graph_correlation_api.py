"""Authenticated API contract for durable graph correlations."""

from __future__ import annotations

import time
from datetime import datetime, timezone

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
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
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


def test_create_list_status_and_tenant_isolation(correlation_client) -> None:
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
    assert response.status_code == 200
    bundle = response.json()
    verified = verify_runtime_facts_bundle(bundle, signing_key=signing_key.encode(), tenant_id="default")
    assert verified.correlation_id == created["correlation_id"]
    assert verified.manifest_sha256 == status["manifest_sha256"]
    assert bundle["signature"]["key_id"] == "test-key"


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
