"""Honest 501 (not a generic 500) when the experimental Neptune graph backend
hits an unsupported GraphStoreProtocol operation.

The Neptune adapter implements only a partial protocol surface (snapshots +
``load_graph`` + ``snapshot_stats``); the ~16 read/traversal ops raise
``NeptuneGraphStoreUnsupportedOperationError``. The route wrappers used to catch
only backpressure, so under ``AGENT_BOM_GRAPH_BACKEND=neptune`` these surfaced as
opaque 500s. They must degrade honestly: HTTP 501 Not Implemented with a
sanitized message that names the unsupported op and steers to SQLite/Postgres —
no stack trace, URL, or filesystem path leaked. SQLite/Postgres backends are
unaffected.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.neptune_graph import NeptuneGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store


class _EmptyGremlinClient:
    """Gremlin-compatible client that returns no rows for every query.

    Lets the real ``NeptuneGraphStore`` run its genuine code path: the supported
    snapshot/``load_graph``/``snapshot_stats`` ops return empty results, while the
    unsupported read/traversal ops raise the real unsupported-operation error.
    """

    def submit(self, query: str, bindings: dict[str, Any] | None = None) -> list[Any]:
        return []


@pytest.fixture
def neptune_client(monkeypatch):
    # The adapter is fail-closed: it refuses to construct unless the operator has
    # explicitly opted into the experimental backend.
    monkeypatch.setenv("AGENT_BOM_GRAPH_BACKEND", "neptune")
    monkeypatch.setenv("AGENT_BOM_EXPERIMENTAL_NEPTUNE_GRAPH", "1")
    monkeypatch.setenv("AGENT_BOM_NEPTUNE_ENDPOINT", "wss://neptune.example.invalid:8182/gremlin")
    set_graph_store(NeptuneGraphStore(client=_EmptyGremlinClient()))
    try:
        yield TestClient(app)
    finally:
        set_graph_store(None)


@pytest.fixture
def sqlite_client():
    # None forces re-selection of the default durable SQLite backend.
    set_graph_store(None)
    try:
        yield TestClient(app)
    finally:
        set_graph_store(None)


# (method, path, op-name-fragment) — each endpoint's first store interaction is
# an unsupported Neptune op, so each must return 501 (not 500).
_UNSUPPORTED_ENDPOINTS = [
    ("GET", "/v1/inventory/assets", "page_nodes"),
    ("GET", "/v1/inventory/assets/agent:a", "node_context"),
    ("GET", "/v1/graph/attack-paths?limit=5", "attack_paths"),
    ("GET", "/v1/graph/impact?node=agent:a", "impact_of"),
    ("GET", "/v1/graph/search?q=agent", "search_nodes"),
    ("GET", "/v1/graph/node/agent:a/neighbors", "node_context"),
    ("GET", "/v1/graph/history?limit=10", "graph_history"),
    ("GET", "/v1/graph/evidence-manifest", "evidence_manifest"),
    ("GET", "/v1/graph/compliance", "compliance_summary"),
]


@pytest.mark.parametrize("method,path,op", _UNSUPPORTED_ENDPOINTS)
def test_unsupported_neptune_op_returns_501(neptune_client, method, path, op):
    resp = neptune_client.request(method, path)
    assert resp.status_code == 501, (path, resp.status_code, resp.text)

    body = resp.json()
    detail = body.get("detail")
    assert isinstance(detail, str), body
    # Names the unsupported op and the backend, steering to SQLite/Postgres.
    assert op in detail
    assert "Neptune" in detail
    assert "experimental" in detail
    assert "SQLite" in detail and "Postgres" in detail


@pytest.mark.parametrize("method,path,op", _UNSUPPORTED_ENDPOINTS)
def test_501_detail_is_sanitized(neptune_client, method, path, op):
    """The 501 message must not leak a stack trace, URL, or filesystem path."""
    resp = neptune_client.request(method, path)
    assert resp.status_code == 501
    detail = resp.json()["detail"]
    assert "Traceback" not in detail
    assert "http://" not in detail and "https://" not in detail
    # sanitize_error collapses any absolute path to a placeholder token.
    assert "/Users/" not in detail
    assert ".py" not in detail


def test_query_traversal_endpoint_returns_501(neptune_client):
    """POST /v1/graph/query (traverse_subgraph) also degrades to 501."""
    resp = neptune_client.post(
        "/v1/graph/query",
        json={"roots": ["agent:a"], "max_depth": 2},
    )
    assert resp.status_code == 501, resp.text
    # The handler resolves roots then traverses; whichever unsupported op it hits
    # first (nodes_by_ids / traverse_subgraph) must degrade honestly, not 500.
    detail = resp.json()["detail"]
    assert "Neptune" in detail and "experimental" in detail


def test_supported_neptune_op_is_unaffected(neptune_client):
    """snapshot_stats IS implemented, so /v1/inventory/summary stays 200."""
    resp = neptune_client.get("/v1/inventory/summary")
    assert resp.status_code == 200, resp.text


@pytest.mark.parametrize("method,path,op", _UNSUPPORTED_ENDPOINTS)
def test_sqlite_backend_never_501(sqlite_client, method, path, op):
    """The default SQLite backend implements every op — it must never 501/500."""
    resp = sqlite_client.request(method, path)
    assert resp.status_code != 501, (path, resp.text)
    assert resp.status_code < 500, (path, resp.status_code, resp.text)
