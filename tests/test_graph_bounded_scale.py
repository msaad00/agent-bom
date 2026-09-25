"""Stored-estate scale contract for bounded graph navigation (SQLite)."""

from __future__ import annotations

import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agent_bom.api import auth, stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.middleware import APIKeyMiddleware, TrustHeadersMiddleware
from agent_bom.api.routes import graph as routes
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode


@pytest.mark.graph_performance
@pytest.mark.parametrize("assets", [5_000, 25_000, 100_000])
def test_stored_scale_keeps_summary_and_relationship_payloads_bounded(tmp_path, monkeypatch, assets):
    store = SQLiteGraphStore(tmp_path / "scale.db")

    def nodes():
        for i in range(10):
            yield UnifiedNode(id=f"account:{i}", entity_type=EntityType.ACCOUNT, label=f"Account {i}")
        for i in range(assets - 10):
            yield UnifiedNode(id=f"asset:{i}", entity_type=EntityType.CLOUD_RESOURCE, label=f"Asset {i}")

    store.save_graph_streaming(
        scan_id="scale",
        tenant_id="scale-tenant",
        nodes=nodes(),
        edges=(
            UnifiedEdge(source=f"account:{i % 10}", target=f"asset:{i}", relationship=RelationshipType.CONTAINS) for i in range(assets - 10)
        ),
        created_at="2026-09-24T00:00:00Z",
    )
    monkeypatch.setattr(stores, "_graph_store", store)
    keys = auth.KeyStore()
    monkeypatch.setattr(auth, "_key_store", keys)
    token, key = auth.create_api_key("scale-viewer", auth.Role.VIEWER, tenant_id="scale-tenant")
    keys.add(key)
    app = FastAPI()
    app.include_router(routes.router, prefix="/v1")
    app.add_middleware(APIKeyMiddleware, api_key="", allow_unauthenticated=False)
    app.add_middleware(TrustHeadersMiddleware)
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(app) as client:
        for endpoint, params, max_bytes in [
            ("snapshots", {"limit": 10}, 10_000),
            ("rollup", {"scan_id": "scale"}, 100_000),
            ("incident-edges", {"scan_id": "scale", "node_id": "account:0", "limit": 25}, 100_000),
        ]:
            times = []
            for _ in range(2):
                started = time.perf_counter()
                response = client.get(f"/v1/graph/{endpoint}", params=params, headers=headers)
                times.append(round((time.perf_counter() - started) * 1000, 2))
                assert response.status_code == 200
                assert len(response.content) < max_bytes
            body = response.json()
            if endpoint == "rollup":
                assert body["summary"]["total_nodes"] == assets
                assert len(body["top_level"]) == 10
            if endpoint == "incident-edges":
                assert len(body["edges"]) == 25
                assert len(body["nodes"]) == 26
                assert body["next_cursor"]
                assert not body["completeness"]["complete"]
                assert body["snapshot_generation"]
            print(
                json.dumps(
                    {"storedAssets": assets, "endpoint": endpoint, "coldMs": times[0], "warmMs": times[1], "bytes": len(response.content)}
                )
            )
