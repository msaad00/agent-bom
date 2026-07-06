from __future__ import annotations

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def demo_estate_client(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "demo-estate.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "demo-graph.db"))

    from agent_bom.api import server as api_server
    from agent_bom.api import stores as api_stores

    api_server._runtime_api_key_seeded = False
    api_server._shutting_down = False
    original_graph_store = api_stores._graph_store
    api_stores._graph_store = None

    try:
        with TestClient(api_server.app) as client:
            yield client
    finally:
        api_stores._graph_store = original_graph_store


def test_demo_estate_bootstrap_seeds_jobs_and_graph(demo_estate_client: TestClient) -> None:
    jobs_payload = demo_estate_client.get(
        "/v1/jobs",
        headers={"X-Agent-Bom-Role": "admin"},
        params={"include_details": "true"},
    ).json()
    jobs = jobs_payload.get("jobs") or []
    assert jobs, "expected at least one demo job after bootstrap"
    job_id = jobs[0]["job_id"]
    detail = demo_estate_client.get(f"/v1/scan/{job_id}", headers={"X-Agent-Bom-Role": "admin"}).json()
    sources = (detail.get("result") or {}).get("scan_sources", [])
    assert any("demo" in str(src).lower() for src in sources)

    graph = demo_estate_client.get("/v1/graph", headers={"X-Agent-Bom-Role": "viewer"})
    assert graph.status_code == 200
    payload = graph.json()
    node_count = len(payload.get("nodes") or [])
    assert node_count > 0


def test_demo_estate_bootstrap_is_idempotent(demo_estate_client: TestClient) -> None:
    first = demo_estate_client.get("/v1/jobs", headers={"X-Agent-Bom-Role": "admin"}).json()
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    second = maybe_bootstrap_demo_estate()
    assert second.get("reason") == "demo_jobs_present"
    again = demo_estate_client.get("/v1/jobs", headers={"X-Agent-Bom-Role": "admin"}).json()
    assert again.get("total") == first.get("total")
