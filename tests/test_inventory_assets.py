"""Tests for the unified asset-inventory API (/v1/inventory/*).

The inventory is a read-only projection over the one unified graph snapshot, so
these seed a graph containing AI + cloud + Snowflake + identity nodes (plus a
finding that must be excluded) and exercise the summary, faceted list, detail,
filters, pagination, and tenant isolation.
"""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import (
    EntityType,
    NodeDimensions,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)

_PROXY_SECRET = "test-inventory-proxy-secret-32-bytes-min"


def _node(node_id: str, entity_type: EntityType, label: str, **kw: Any) -> UnifiedNode:
    dims = NodeDimensions(
        environment=kw.pop("environment", ""),
        cloud_provider=kw.pop("provider", ""),
    )
    return UnifiedNode(id=node_id, entity_type=entity_type, label=label, dimensions=dims, **kw)


def _seed_graph(store: SQLiteGraphStore, *, tenant_id: str = "default", scan_id: str = "inv-scan-1") -> None:
    """Persist one snapshot spanning AI + cloud + Snowflake + identity + a finding."""
    g = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    # ── AI ──
    g.add_node(_node("agent:a", EntityType.AGENT, "orders-agent", environment="production", data_sources=["mcp-scan"]))
    g.add_node(_node("server:mcp", EntityType.SERVER, "mcp-filesystem", environment="production", data_sources=["mcp-scan"]))
    g.add_node(_node("model:gpt", EntityType.MODEL, "gpt-4o"))
    g.add_node(_node("framework:lc", EntityType.FRAMEWORK, "langchain"))
    g.add_node(_node("tool:sh", EntityType.TOOL, "run_shell"))
    g.add_node(_node("credential:k", EntityType.CREDENTIAL, "AWS_SECRET_ACCESS_KEY"))
    # ── Cloud (AWS) ──
    g.add_node(
        _node(
            "cloud_resource:ec2", EntityType.CLOUD_RESOURCE, "ec2-web", environment="production", provider="aws", data_sources=["cloud:aws"]
        )
    )
    g.add_node(
        _node("data_store:s3", EntityType.DATA_STORE, "s3-bucket", environment="staging", provider="aws", data_sources=["cloud:aws"])
    )
    g.add_node(_node("account:aws", EntityType.ACCOUNT, "aws-acct-123", provider="aws", data_sources=["cloud:aws"]))
    # ── Snowflake ──
    g.add_node(
        _node("account:snowflake:acct1", EntityType.ACCOUNT, "snowflake-acct1", provider="snowflake", data_sources=["cloud:snowflake"])
    )
    g.add_node(
        _node(
            "cloud_resource:snowflake:warehouse:WH_ETL",
            EntityType.CLOUD_RESOURCE,
            "warehouse: WH_ETL",
            provider="snowflake",
            data_sources=["cloud:snowflake"],
            attributes={"resource_kind": "snowflake-warehouse"},
        )
    )
    g.add_node(
        _node(
            "data_store:snowflake:db:DB", EntityType.DATA_STORE, "snowflake-db: DB", provider="snowflake", data_sources=["cloud:snowflake"]
        )
    )
    g.add_node(_node("role:snowflake:SYSADMIN", EntityType.ROLE, "SYSADMIN", provider="snowflake", data_sources=["cloud:snowflake"]))
    g.add_node(_node("user:snowflake:SVC_PIPE", EntityType.USER, "SVC_PIPE", provider="snowflake", data_sources=["cloud:snowflake"]))
    # ── Identity ──
    g.add_node(_node("user:alice", EntityType.USER, "alice"))
    g.add_node(_node("role:admin", EntityType.ROLE, "AdministratorAccess"))
    # ── Finding (must be excluded from the asset inventory) ──
    g.add_node(_node("vuln:CVE-2024-1", EntityType.VULNERABILITY, "CVE-2024-1", severity="critical", risk_score=9.0))
    # ── Edges (for the detail drawer) ──
    g.add_edge(UnifiedEdge(source="agent:a", target="server:mcp", relationship=RelationshipType.USES))
    g.add_edge(UnifiedEdge(source="server:mcp", target="vuln:CVE-2024-1", relationship=RelationshipType.VULNERABLE_TO))
    store.save_graph(g)


@pytest.fixture
def inventory_store(tmp_path):
    from agent_bom.api.stores import _get_graph_store

    original = _get_graph_store()
    store = SQLiteGraphStore(tmp_path / "inventory.db")
    _seed_graph(store)
    set_graph_store(store)
    try:
        yield store
    finally:
        set_graph_store(original)


# ── Summary ──


def test_summary_counts_assets_by_type_and_group_excluding_findings(inventory_store):
    client = TestClient(app)
    resp = client.get("/v1/inventory/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["schema_version"] == "inventory.summary.v1"
    # 16 non-finding nodes seeded; the vulnerability is not an asset.
    assert body["total_assets"] == 16
    assert body["finding_count"] == 1
    assert "vulnerability" not in body["by_type"]
    assert body["by_type"]["account"] == 2  # aws + snowflake
    assert body["by_type"]["role"] == 2
    assert body["by_type"]["cloud_resource"] == 2
    # Group roll-up spans every source uniformly.
    assert body["by_group"]["ai"] == 5  # agent, server, model, framework, tool
    assert body["by_group"]["cloud"] == 6  # ec2, s3, aws-acct, snowflake-acct, warehouse, snowflake-db
    assert body["by_group"]["identity"] == 4  # snowflake role+user, alice, admin
    assert body["by_group"]["secrets"] == 1  # credential


# ── Faceted list ──


def test_list_returns_asset_rows_and_excludes_findings(inventory_store):
    client = TestClient(app)
    resp = client.get("/v1/inventory/assets?limit=100")
    assert resp.status_code == 200
    body = resp.json()
    assert body["schema_version"] == "inventory.assets.v1"
    types = {row["type"] for row in body["assets"]}
    assert "vulnerability" not in types
    assert {"agent", "cloud_resource", "account", "role", "user"} <= types
    row = next(r for r in body["assets"] if r["id"] == "cloud_resource:ec2")
    assert row["name"] == "ec2-web"
    assert row["environment"] == "production"
    assert row["provider"] == "aws"
    assert row["source"] == "cloud:aws"


def test_list_type_filter(inventory_store):
    client = TestClient(app)
    resp = client.get("/v1/inventory/assets?type=role&limit=100")
    assert resp.status_code == 200
    rows = resp.json()["assets"]
    assert {r["id"] for r in rows} == {"role:snowflake:SYSADMIN", "role:admin"}


def test_list_type_filter_rejects_finding_type(inventory_store):
    client = TestClient(app)
    resp = client.get("/v1/inventory/assets?type=vulnerability")
    assert resp.status_code == 422


def test_list_multi_type_filter_spans_sources(inventory_store):
    client = TestClient(app)
    resp = client.get("/v1/inventory/assets?type=account,warehouse&limit=100")
    # 'warehouse' is not an entity type; ensure only valid types accepted.
    assert resp.status_code == 422
    resp = client.get("/v1/inventory/assets?type=account,cloud_resource&limit=100")
    assert resp.status_code == 200
    ids = {r["id"] for r in resp.json()["assets"]}
    assert "account:snowflake:acct1" in ids and "cloud_resource:ec2" in ids


def test_list_search_filter(inventory_store):
    client = TestClient(app)
    resp = client.get("/v1/inventory/assets?search=warehouse&limit=100")
    assert resp.status_code == 200
    ids = {r["id"] for r in resp.json()["assets"]}
    assert "cloud_resource:snowflake:warehouse:WH_ETL" in ids
    assert "account:aws" not in ids


def test_list_environment_facet_filter(inventory_store):
    client = TestClient(app)
    resp = client.get("/v1/inventory/assets?environment=production&limit=100")
    assert resp.status_code == 200
    body = resp.json()
    assert body["pagination"]["facet_filtered"] is True
    ids = {r["id"] for r in body["assets"]}
    assert ids == {"agent:a", "server:mcp", "cloud_resource:ec2"}


def test_list_provider_facet_filter(inventory_store):
    client = TestClient(app)
    resp = client.get("/v1/inventory/assets?provider=snowflake&limit=100")
    assert resp.status_code == 200
    ids = {r["id"] for r in resp.json()["assets"]}
    assert ids == {
        "account:snowflake:acct1",
        "cloud_resource:snowflake:warehouse:WH_ETL",
        "data_store:snowflake:db:DB",
        "role:snowflake:SYSADMIN",
        "user:snowflake:SVC_PIPE",
    }


def test_list_pagination_with_cursor(inventory_store):
    client = TestClient(app)
    seen: set[str] = set()
    cursor = ""
    pages = 0
    while True:
        url = "/v1/inventory/assets?limit=5"
        if cursor:
            url += f"&cursor={cursor}"
        body = client.get(url).json()
        page_ids = [r["id"] for r in body["assets"]]
        assert len(page_ids) <= 5
        assert not (set(page_ids) & seen)  # no duplicates across pages
        seen.update(page_ids)
        pages += 1
        cursor = body["pagination"]["next_cursor"]
        if not cursor:
            break
        assert pages < 10
    assert len(seen) == 16  # every asset, no finding, no drop, no dup


# ── Detail ──


def test_detail_returns_node_with_edges(inventory_store):
    client = TestClient(app)
    resp = client.get("/v1/inventory/assets/server:mcp")
    assert resp.status_code == 200
    body = resp.json()
    assert body["schema_version"] == "inventory.asset.v1"
    assert body["asset"]["id"] == "server:mcp"
    assert body["node"]["entity_type"] == "server"
    neighbors = set(body["neighbors"]) | set(body["sources"])
    assert "agent:a" in neighbors or "vuln:CVE-2024-1" in neighbors
    edge_targets = {e["target"] for e in body["edges_out"]} | {e["source"] for e in body["edges_in"]}
    assert edge_targets  # has relationships


def test_detail_unknown_id_404(inventory_store):
    client = TestClient(app)
    resp = client.get("/v1/inventory/assets/does-not-exist")
    assert resp.status_code == 404


# ── Tenant isolation ──


def test_tenant_isolation_no_cross_tenant_leak(tmp_path):
    """The endpoint scopes to the caller's tenant and never leaks another's nodes."""
    from agent_bom.api.stores import _get_graph_store

    original = _get_graph_store()
    store = SQLiteGraphStore(tmp_path / "iso.db")
    _seed_graph(store, tenant_id="default", scan_id="default-scan")
    # A different tenant's node must never surface in the default tenant's view.
    g = UnifiedGraph(scan_id="tenant-b-scan", tenant_id="tenant-b")
    g.add_node(_node("agent:tenant-b-only", EntityType.AGENT, "tenant-b-agent"))
    store.save_graph(g)
    set_graph_store(store)
    try:
        client = TestClient(app)
        # Unauthenticated requests resolve to the "default" tenant.
        summary = client.get("/v1/inventory/summary").json()
        assert summary["total_assets"] == 16  # only default's assets, not tenant-b's

        asset_ids = {r["id"] for r in client.get("/v1/inventory/assets?limit=100").json()["assets"]}
        assert "agent:tenant-b-only" not in asset_ids
        # tenant-b's asset is 404 from the default tenant's detail view.
        assert client.get("/v1/inventory/assets/agent:tenant-b-only").status_code == 404

        # The data is genuinely tenant-scoped in the store the endpoint reads.
        assert store.snapshot_stats(tenant_id="tenant-b").get("total_nodes") == 1
        assert store.snapshot_stats(tenant_id="default").get("total_nodes") == 17  # 16 assets + 1 finding
    finally:
        set_graph_store(original)
