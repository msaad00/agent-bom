"""Regression: v1 API paths are mounted via a single router prefix (#3666)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.api.versioning import API_V1_PREFIX, create_v1_api_router


def test_v1_prefix_constant() -> None:
    assert API_V1_PREFIX == "/v1"


def test_create_v1_api_router_has_prefix() -> None:
    router = create_v1_api_router()
    assert router.prefix == API_V1_PREFIX


def test_versioned_and_infra_paths_unchanged_at_runtime() -> None:
    client = TestClient(app)
    schema_paths = set(client.get("/openapi.json").json()["paths"])

    assert "/v1/health" not in schema_paths
    assert "/v1/findings" in schema_paths
    assert "/metrics" in schema_paths
    assert "/metrics" not in {p for p in schema_paths if p.startswith("/v1/")}


def test_proxy_websocket_stays_at_root_unversioned() -> None:
    client = TestClient(app)
    with client.websocket_connect("/ws/proxy/metrics"):
        pass
