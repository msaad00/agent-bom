"""One graph response must use one current-estate generation and revision read."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.exceptions import HTTPException

from agent_bom.api import stores
from agent_bom.api.finding_read_context import finding_read_snapshot
from tests.api import test_current_graph_estate as estate_helpers

estate = estate_helpers.estate
record = estate_helpers.record


def test_current_generation_resolves_once_in_existing_read_context(estate, monkeypatch):
    record(estate, 8, "repo-a", "package-a")
    graph = stores._get_graph_store()
    summaries = estate[0].list_summary
    calls = []

    def counted(**kwargs):
        calls.append(kwargs["tenant_id"])
        return summaries(**kwargs)

    monkeypatch.setattr(estate[0], "list_summary", counted)

    @finding_read_snapshot
    def read():
        first = graph.latest_snapshot_id(tenant_id="history-tenant")
        graph.snapshot_identity(tenant_id="history-tenant", for_paging=True)
        assert graph.load_graph(tenant_id="history-tenant").scan_id == first

    read()
    assert calls == ["history-tenant"]
    read()
    assert calls == ["history-tenant", "history-tenant"]


def test_graph_http_request_establishes_read_context(estate, monkeypatch):
    from agent_bom.api.routes import graph as routes

    record(estate, 8, "repo-a", "package-a")
    summaries = estate[0].list_summary
    calls = []

    def counted(**kwargs):
        calls.append(kwargs["tenant_id"])
        return summaries(**kwargs)

    monkeypatch.setattr(estate[0], "list_summary", counted)
    monkeypatch.setattr(routes, "_tenant", lambda request: "history-tenant")
    app = FastAPI()
    app.include_router(routes.router, prefix="/v1")
    with TestClient(app) as client:
        response = client.get("/v1/graph?limit=10")
    assert response.status_code == 200, response.text
    assert calls == ["history-tenant"]


def test_concurrent_replacement_rejects_retired_generation_instead_of_empty_graph(estate):
    record(estate, 8, "repo-a", "package-a")
    graph = stores._get_graph_store()

    @finding_read_snapshot
    def read_old():
        original = graph.latest_snapshot_id(tenant_id="history-tenant")
        record(estate, 9, "repo-a", "package-b")
        with ThreadPoolExecutor(max_workers=1) as workers:
            replacement = workers.submit(graph.load_graph, tenant_id="history-tenant").result(timeout=5)
        assert replacement.scan_id != original
        with pytest.raises(HTTPException) as error:
            graph.load_graph(tenant_id="history-tenant")
        assert error.value.status_code == 409

    read_old()
    assert set(graph.load_graph(tenant_id="history-tenant").nodes) == {"package-b"}
