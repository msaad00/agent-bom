"""Auto-enable store-backed graph build above an entity threshold."""

from __future__ import annotations

import agent_bom.api.pipeline as pipeline


def test_estimate_graph_entities_counts_nested_servers_and_packages() -> None:
    report = {
        "agents": [
            {
                "name": "a1",
                "mcp_servers": [
                    {"name": "s1", "packages": [{"name": "p1"}, {"name": "p2"}]},
                    {"name": "s2", "packages": []},
                ],
            }
        ],
        "packages": [{"name": "top"}],
        "findings": [{"id": "f1"}, {"id": "f2"}],
        "blast_radius": [{"id": "b1"}],
    }
    # 1 agent + 2 servers + 2 nested packages + 1 top package + 2 findings + 1 blast
    assert pipeline._estimate_graph_entities(report) == 9


def test_store_backed_explicit_off_wins_over_threshold(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", "0")
    monkeypatch.setenv("AGENT_BOM_GRAPH_STORE_BACKED_MIN_ENTITIES", "1")
    report = {"agents": [{"name": "a", "mcp_servers": []}], "packages": [], "findings": [{"id": "1"}]}
    assert pipeline._graph_store_backed_build_enabled(report) is False


def test_store_backed_explicit_on(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", "1")
    assert pipeline._graph_store_backed_build_enabled({"agents": []}) is True


def test_store_backed_auto_on_above_threshold(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", raising=False)
    monkeypatch.setenv("AGENT_BOM_GRAPH_STORE_BACKED_MIN_ENTITIES", "3")
    small = {"agents": [{"name": "a", "mcp_servers": []}], "packages": [], "findings": []}
    large = {
        "agents": [{"name": "a", "mcp_servers": [{"name": "s", "packages": [{"name": "p"}]}]}],
        "packages": [{"name": "t"}],
        "findings": [{"id": "f"}],
    }
    assert pipeline._estimate_graph_entities(small) < 3
    assert pipeline._graph_store_backed_build_enabled(small) is False
    assert pipeline._estimate_graph_entities(large) >= 3
    assert pipeline._graph_store_backed_build_enabled(large) is True


def test_store_backed_unset_without_report_is_off(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", raising=False)
    assert pipeline._graph_store_backed_build_enabled(None) is False
