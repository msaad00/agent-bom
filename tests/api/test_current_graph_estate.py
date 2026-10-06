"""Default graph reads retain current evidence across independent scan targets."""

import pytest

from agent_bom.api import stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
from tests.api.test_scan_job_sla_history import job


@pytest.fixture
def estate(tmp_path, monkeypatch):
    jobs = InMemoryJobStore()
    graph_store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    monkeypatch.setattr(stores, "_store", jobs)
    monkeypatch.setattr(stores, "_graph_store", graph_store)
    return jobs, graph_store


def record(estate, month, target, *nodes, tenant="history-tenant", partial=False):
    jobs, graph_store = estate
    scan = job(month, tenant=tenant, target=target, findings=[])
    scan.result.update(scan_id=scan.job_id, scan_run={"outcome": "partial" if partial else "complete"})
    graph = UnifiedGraph(scan_id=scan.job_id, tenant_id=tenant, created_at=scan.completed_at)
    for name in nodes:
        graph.add_node(UnifiedNode(id=name, entity_type=EntityType.PACKAGE, label=name))
    graph_store.save_graph(graph)
    jobs.put(scan)
    return scan.job_id


def current(tenant="history-tenant"):
    return stores._get_graph_store().load_graph(tenant_id=tenant)


def test_clean_push_replaces_only_its_own_target_and_preserves_history(estate):
    first = record(estate, 7, "repo-a", "clean-package-a")
    record(estate, 8, "repo-b", "package-b")
    record(estate, 9, "repo-b")
    assert set(current().nodes) == {"clean-package-a"}
    assert current().scan_id.startswith("current-estate:")
    assert set(stores._get_graph_store().load_graph(tenant_id="history-tenant", scan_id=first).nodes) == {"clean-package-a"}
    assert not current("other-tenant").nodes


def test_partial_push_retains_prior_assets_and_older_arrival_does_not_replace(estate):
    record(estate, 8, "repo-a", "package-a")
    record(estate, 9, "repo-a", "package-b", partial=True)
    record(estate, 7, "repo-a", "obsolete-package")
    assert set(current().nodes) == {"package-a", "package-b"}
    generation = current().scan_id
    assert current().scan_id == generation
    record(estate, 10, "repo-a")
    assert not current().nodes
    assert current().scan_id != generation


def test_replay_changes_generation_and_rejects_stale_continuation(estate):
    from fastapi import HTTPException

    from agent_bom.api.graph_generation import pin_generation

    record(estate, 8, "repo-a", "before")
    store = stores._get_graph_store()
    before = store.snapshot_identity(tenant_id="history-tenant", for_paging=True)
    record(estate, 8, "repo-a", "after")
    assert set(current().nodes) == {"after"}
    with pytest.raises(HTTPException) as exc:
        pin_generation(store, tenant="history-tenant", scan_id=before[0], generation=before[1], offset=1)
    assert exc.value.status_code == 409


def test_warm_reads_do_not_deserialize_historical_reports(estate, monkeypatch):
    record(estate, 8, "repo-a", "package-a")
    current()

    def fail(*args, **kwargs):
        raise AssertionError("warm read reloaded a report")

    monkeypatch.setattr(estate[0], "get", fail)
    assert set(current().nodes) == {"package-a"}


def test_inventory_projects_the_same_current_assets(estate):
    import asyncio

    from agent_bom.api.inventory_service import build_asset_list

    record(estate, 8, "repo-a", "package-a")
    record(estate, 9, "repo-b")
    page = asyncio.run(build_asset_list(store=stores._get_graph_store(), tenant_id="history-tenant"))
    assert {row["id"] for row in page["assets"]} == {"package-a"}
    assert page["evidence_scope"] == "current_estate"


def test_current_projection_does_not_add_to_recorded_scan_history(estate):
    record(estate, 8, "repo-a", "package-a")
    before = estate[1].list_snapshots(tenant_id="history-tenant")
    current()
    assert estate[1].list_snapshots(tenant_id="history-tenant") == before


def test_current_generation_is_stable_across_projection_workers(estate):
    from agent_bom.api.current_graph import CurrentGraphStore

    record(estate, 8, "repo-a", "package-a")
    a = CurrentGraphStore(estate[1], estate[0])
    b = CurrentGraphStore(estate[1], estate[0])
    assert a.snapshot_identity(tenant_id="history-tenant", for_paging=True) == b.snapshot_identity(
        tenant_id="history-tenant", for_paging=True
    )
    assert set(a.load_rollup_graph(tenant_id="history-tenant").nodes) == {"package-a"}


def test_rest_and_mcp_inventory_share_current_and_historical_scope(estate, monkeypatch):
    import asyncio
    import json

    from starlette.testclient import TestClient

    from agent_bom.api.server import app
    from agent_bom.mcp_tools.inventory import inventory_summary_impl
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    old = record(estate, 7, "repo-a", "old")
    record(estate, 8, "repo-a", "current")
    record(estate, 9, "repo-b")
    enable_trusted_proxy_env()
    try:
        with TestClient(app, headers=proxy_headers(tenant="history-tenant")) as client:
            assets = client.get("/v1/inventory/assets").json()
            assert {node["id"] for node in assets["assets"]} == {"current"}
            graph = client.get("/v1/graph", params={"limit": 100})
            assert graph.status_code == 200, graph.text
            assert {node["id"] for node in graph.json()["nodes"]} == {"current"}
            historical = client.get("/v1/inventory/assets", params={"scan_id": old}).json()
            assert {node["id"] for node in historical["assets"]} == {"old"}
        monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "history-tenant")
        mcp = json.loads(asyncio.run(inventory_summary_impl(tenant_id="history-tenant")))
        assert mcp["total_assets"] == 1
        assert mcp["evidence_scope"] == "current_estate"
    finally:
        disable_trusted_proxy_env()


def test_legacy_agent_inventory_retires_only_completed_target(estate):
    from agent_bom.api.estate_agents import scanned_estate_agents

    jobs, _ = estate
    record(estate, 7, "repo-a", "asset-a")
    record(estate, 8, "repo-b", "asset-b")
    for row in jobs.list_all(tenant_id="history-tenant"):
        row.result["agents"] = [{"name": row.target["path"], "canonical_id": row.target["path"]}]
        jobs.put(row)
    record(estate, 9, "repo-b")
    assert [a["name"] for a in scanned_estate_agents(jobs.list_all(tenant_id="history-tenant"))] == ["repo-a"]


def test_partial_current_scope_retains_a_visible_collection_gap(estate):
    import asyncio

    from agent_bom.api.inventory_service import build_summary

    record(estate, 8, "repo-a", "package-a")
    record(estate, 9, "repo-a", partial=True)
    summary = asyncio.run(build_summary(store=stores._get_graph_store(), tenant_id="history-tenant"))
    assert summary["total_assets"] == 1
    assert summary["collection_coverage"]["status"] == "partial"
    assert "scan_partial" in summary["collection_coverage"]["reason_codes"]


def test_inventory_only_observation_keeps_assets_without_erasing_findings(estate):
    record(estate, 8, "repo-a", "package-a")
    latest = record(estate, 9, "repo-a", "unassessed-package")
    row = estate[0].get(latest, tenant_id="history-tenant")
    row.result["no_scan"] = True
    estate[0].put(row)
    assert set(current().nodes) == {"package-a", "unassessed-package"}


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_in_place_authority_change_invalidates_current_projection(estate, tmp_path, backend):
    from agent_bom.api.current_graph import CurrentGraphStore
    from agent_bom.api.store import SQLiteJobStore

    old = record(estate, 8, "repo-a", "package-a")
    latest = record(estate, 9, "repo-a", "unassessed-package")
    jobs = estate[0]
    if backend == "sqlite":
        jobs = SQLiteJobStore(str(tmp_path / "jobs.db"))
        for scan_id in (old, latest):
            jobs.put(estate[0].get(scan_id, tenant_id="history-tenant"))
    store = CurrentGraphStore(estate[1], jobs)
    before = store.load_graph(tenant_id="history-tenant")
    assert set(before.nodes) == {"unassessed-package"}
    row = jobs.get(latest, tenant_id="history-tenant")
    row.result["no_scan"] = True
    jobs.put(row)
    after = store.load_graph(tenant_id="history-tenant")
    assert set(after.nodes) == {"package-a", "unassessed-package"}
    assert before.scan_id != after.scan_id


def test_derived_cache_retires_superseded_generations_but_keeps_observations(estate):
    store = stores._get_graph_store()
    for month in (7, 8, 9):
        record(estate, month, "repo-a", f"asset-{month}")
        assert set(current().nodes) == {f"asset-{month}"}
    assert len(store._projection_store.list_snapshots(tenant_id="history-tenant")) == 1
    assert len(estate[1].list_snapshots(tenant_id="history-tenant")) == 3


def test_current_incident_pages_accept_returned_generation(estate):
    from starlette.testclient import TestClient

    from agent_bom.api.server import app
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    record(estate, 8, "repo-a", "package-a")
    enable_trusted_proxy_env()
    try:
        with TestClient(app, headers=proxy_headers(tenant="history-tenant")) as client:
            first = client.get("/v1/graph/incident-edges", params={"node_id": "package-a"})
            assert first.status_code == 200, first.text
            body = first.json()
            second = client.get(
                "/v1/graph/incident-edges",
                params={"node_id": "package-a", "scan_id": body["scan_id"], "snapshot_generation": body["snapshot_generation"]},
            )
            assert second.status_code == 200, second.text
    finally:
        disable_trusted_proxy_env()
