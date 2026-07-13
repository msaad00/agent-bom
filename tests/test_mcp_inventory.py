"""Tests for the agent-native MCP unified asset-inventory tools.

These exercise the ``inventory_summary`` / ``inventory_list`` / ``inventory_asset``
MCP tools that project the ONE tenant-scoped unified graph snapshot through the
same ``agent_bom.api.inventory_service`` helper the ``/v1/inventory/*`` HTTP
routes use, so the human cockpit and the headless agent surface stay in lockstep.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from agent_bom.graph import (
    EntityType,
    NodeDimensions,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
)
from agent_bom.mcp_tools.inventory import (
    inventory_asset_impl,
    inventory_list_impl,
    inventory_summary_impl,
)


def _node(node_id: str, entity_type: EntityType, label: str, **kw: Any) -> UnifiedNode:
    dims = NodeDimensions(
        environment=kw.pop("environment", ""),
        cloud_provider=kw.pop("provider", ""),
    )
    return UnifiedNode(id=node_id, entity_type=entity_type, label=label, dimensions=dims, **kw)


def _seed_graph(store, *, tenant_id: str = "default", scan_id: str = "inv-scan-1") -> None:
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
            "data_store:snowflake:db:DB",
            EntityType.DATA_STORE,
            "snowflake-db: DB",
            provider="snowflake",
            data_sources=["cloud:snowflake"],
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
def seeded_store(tmp_path):
    from agent_bom.api.graph_store import SQLiteGraphStore

    store = SQLiteGraphStore(tmp_path / "mcp-inventory.db")
    _seed_graph(store)
    return store


def _store_factory(store):
    return lambda: store


# ── Registration / advertisement ────────────────────────────────────────────


def test_inventory_tools_are_advertised_read_only() -> None:
    """All three inventory tools appear in the server card, flagged read-only."""
    from agent_bom.mcp_server_metadata import _TOOL_CAPABILITY_CLASSES, build_server_card, server_card_tool_names

    names = server_card_tool_names()
    tools = {t["name"]: t for t in build_server_card()["tools"]}
    for name in ("inventory_summary", "inventory_list", "inventory_asset"):
        assert name in names
        assert tools[name]["annotations"].get("readOnlyHint") is True
        assert "WRITE" not in set(_TOOL_CAPABILITY_CLASSES[name])


def test_live_mcp_server_exposes_inventory_tools_read_only() -> None:
    """Live FastMCP registration exposes the inventory tools with readOnlyHint."""
    pytest.importorskip("mcp", reason="mcp SDK not installed")
    from agent_bom.mcp_server import create_mcp_server

    server = create_mcp_server()
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    for name in ("inventory_summary", "inventory_list", "inventory_asset"):
        assert name in tools, f"{name} missing from live tools/list"
        annotations = getattr(tools[name], "annotations", None)
        assert annotations is not None and annotations.readOnlyHint is True


# ── Summary ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_inventory_summary_counts_by_type_and_group(seeded_store) -> None:
    response = await inventory_summary_impl(_get_graph_store=_store_factory(seeded_store), _truncate_response=lambda v: v)
    body = json.loads(response)
    assert body["schema_version"] == "inventory.summary.v1"
    assert body["total_assets"] == 16
    assert body["finding_count"] == 1
    assert "vulnerability" not in body["by_type"]
    assert body["by_type"]["account"] == 2
    assert body["by_group"]["ai"] == 5
    assert body["by_group"]["cloud"] == 6
    assert body["by_group"]["identity"] == 4
    assert body["by_group"]["secrets"] == 1


# ── List ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_inventory_list_type_filter(seeded_store) -> None:
    response = await inventory_list_impl(
        type="role", limit=100, _get_graph_store=_store_factory(seeded_store), _truncate_response=lambda v: v
    )
    body = json.loads(response)
    assert body["schema_version"] == "inventory.assets.v1"
    assert {r["id"] for r in body["assets"]} == {"role:snowflake:SYSADMIN", "role:admin"}


@pytest.mark.asyncio
async def test_inventory_list_provider_facet(seeded_store) -> None:
    response = await inventory_list_impl(
        provider="snowflake", limit=100, _get_graph_store=_store_factory(seeded_store), _truncate_response=lambda v: v
    )
    body = json.loads(response)
    assert body["pagination"]["facet_filtered"] is True
    assert {r["id"] for r in body["assets"]} == {
        "account:snowflake:acct1",
        "cloud_resource:snowflake:warehouse:WH_ETL",
        "data_store:snowflake:db:DB",
        "role:snowflake:SYSADMIN",
        "user:snowflake:SVC_PIPE",
    }


@pytest.mark.asyncio
async def test_inventory_list_excludes_findings(seeded_store) -> None:
    response = await inventory_list_impl(limit=100, _get_graph_store=_store_factory(seeded_store), _truncate_response=lambda v: v)
    body = json.loads(response)
    assert "vulnerability" not in {r["type"] for r in body["assets"]}


@pytest.mark.asyncio
async def test_inventory_list_rejects_finding_type(seeded_store) -> None:
    response = await inventory_list_impl(
        type="vulnerability", _get_graph_store=_store_factory(seeded_store), _truncate_response=lambda v: v
    )
    body = json.loads(response)
    assert "error" in body
    assert body["error"]["category"] == "validation"


@pytest.mark.asyncio
async def test_inventory_list_rejects_out_of_range_limit(seeded_store) -> None:
    response = await inventory_list_impl(limit=9999, _get_graph_store=_store_factory(seeded_store), _truncate_response=lambda v: v)
    body = json.loads(response)
    assert "error" in body


# ── Detail ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_inventory_asset_detail_returns_edges(seeded_store) -> None:
    response = await inventory_asset_impl(
        asset_id="server:mcp", _get_graph_store=_store_factory(seeded_store), _truncate_response=lambda v: v
    )
    body = json.loads(response)
    assert body["schema_version"] == "inventory.asset.v1"
    assert body["asset"]["id"] == "server:mcp"
    assert body["node"]["entity_type"] == "server"
    edge_targets = {e["target"] for e in body["edges_out"]} | {e["source"] for e in body["edges_in"]}
    assert edge_targets


@pytest.mark.asyncio
async def test_inventory_asset_unknown_id_clean_not_found(seeded_store) -> None:
    response = await inventory_asset_impl(
        asset_id="does-not-exist", _get_graph_store=_store_factory(seeded_store), _truncate_response=lambda v: v
    )
    body = json.loads(response)
    assert "error" in body
    assert body["error"]["category"] == "not_found"


@pytest.mark.asyncio
async def test_inventory_asset_empty_id_rejected(seeded_store) -> None:
    response = await inventory_asset_impl(asset_id="   ", _get_graph_store=_store_factory(seeded_store), _truncate_response=lambda v: v)
    body = json.loads(response)
    assert "error" in body
    assert body["error"]["category"] == "validation"
