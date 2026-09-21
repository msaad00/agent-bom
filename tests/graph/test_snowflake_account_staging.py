"""Snowflake account isolation retains the bounded store-backed producer."""

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.store_backed import open_store_backed_unified_graph

NOW = "2026-09-20T00:00:00Z"


def _report():
    return {
        "snowflake_object_graph": {
            "status": "ok",
            "account": "ACCT1",
            "objects": [{"fqn": f"DB.PUBLIC.T{i}", "object_type": "table"} for i in range(12)],
            "grants": [{"role": "ANALYST", "privilege": "SELECT", "object_fqn": f"DB.PUBLIC.T{i}"} for i in range(12)],
            "role_memberships": [{"user": "ALICE", "role": "ANALYST"}],
        },
        "snowflake_governance": {
            "status": "ok",
            "account": "ACCT2",
            "access_records": [
                {"user_name": "ALICE", "object_name": f"DB.PUBLIC.T{i}", "operation": "READ", "is_write": False} for i in range(12)
            ],
        },
    }


def test_store_backed_account_staging_eviction_matches_memory_and_cleans_workspaces(monkeypatch):
    from agent_bom.graph import store_backed

    monkeypatch.setattr("agent_bom.graph.node._now_iso", lambda: NOW)
    monkeypatch.setattr("agent_bom.graph.edge._now_iso", lambda: NOW, raising=False)
    memory = build_unified_graph_from_report(_report(), container=UnifiedGraph(scan_id="scope", tenant_id="tenant", created_at=NOW))
    staged = []
    with open_store_backed_unified_graph(
        scan_id="scope", tenant_id="tenant", created_at=NOW, backend="sqlite", capacity=2, page_size=2
    ) as output:

        def bounded_stage(**kwargs):
            assert kwargs["backend"] == "sqlite"
            graph = open_store_backed_unified_graph(**kwargs, capacity=2, page_size=2)
            staged.append(graph)
            return graph

        monkeypatch.setattr(store_backed, "open_store_backed_unified_graph", bounded_stage)
        result = build_unified_graph_from_report(_report(), container=output)
        assert len(staged) == 2
        assert result.to_dict() == memory.to_dict()
        assert all(len(graph._cache) <= 2 for graph in staged)
        assert all(not graph._backend._path.exists() for graph in staged)
        assert all("_snowflake_projection_id" not in node.attributes for node in result.nodes.values())


def test_store_backed_account_staging_closes_workspace_on_projection_error(monkeypatch):
    from agent_bom.graph import builder, store_backed

    staged = []
    with open_store_backed_unified_graph(backend="sqlite") as output:

        def stage(**kwargs):
            graph = open_store_backed_unified_graph(**kwargs)
            staged.append(graph)
            return graph

        def fail(*_args, **_kwargs):
            raise RuntimeError("controlled projection failure")

        monkeypatch.setattr(store_backed, "open_store_backed_unified_graph", stage)
        monkeypatch.setattr(builder, "_project_snowflake_lanes", fail)
        with pytest.raises(RuntimeError, match="controlled projection failure"):
            build_unified_graph_from_report(_report(), container=output)
        assert len(staged) == 1
        assert not staged[0]._backend._path.exists()
