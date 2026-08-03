"""Signals the scanner computed must survive serialization to a consumer.

A value derived correctly in the backend and then dropped by its own
``to_dict`` is worse than one never computed: the product knows the answer and
tells no one, and the consumer reads the silence as good news. Both cases here
turn an incomplete scan into an indistinguishable clean bill of health.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.graph.container import UnifiedGraph, apply_node_budget
from agent_bom.graph.node import EntityType, UnifiedNode


def _graph_with_nodes(count: int) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="scan-trunc", tenant_id="default")
    for index in range(count):
        graph.add_node(
            UnifiedNode(
                id=f"n-{index:04d}",
                entity_type=EntityType.PACKAGE,
                label=f"pkg-{index}",
                risk_score=float(index),
            )
        )
    return graph


def test_unified_graph_to_dict_declares_a_budget_truncated_load():
    """A graph trimmed to a node budget must not serialize as the whole estate."""
    graph = apply_node_budget(_graph_with_nodes(50), 10)

    assert graph.completeness.truncated is True
    assert graph.completeness.total_nodes == 50
    assert graph.completeness.returned_nodes == 10

    payload = graph.to_dict()
    assert "completeness" in payload, (
        "to_dict() drops the completeness descriptor — every file/CLI/session consumer reads 10 of 50 nodes as the complete estate"
    )
    completeness = payload["completeness"]
    assert completeness["truncated"] is True
    assert completeness["complete"] is False
    assert completeness["returned"] == 10
    assert completeness["total"] == 50
    assert completeness["reason"] == "node_budget"


def test_unified_graph_to_dict_declares_a_complete_load():
    """A graph that fit inside its budget must say so, not stay silent."""
    payload = apply_node_budget(_graph_with_nodes(5), 10).to_dict()
    assert payload["completeness"]["complete"] is True
    assert payload["completeness"]["truncated"] is False


def test_unified_graph_round_trip_preserves_completeness():
    """``from_dict(to_dict(g))`` must not launder a truncated graph clean."""
    graph = apply_node_budget(_graph_with_nodes(50), 10)
    restored = UnifiedGraph.from_dict(graph.to_dict())
    assert restored.completeness.truncated is True
    assert restored.completeness.total_nodes == 50
    assert restored.completeness.returned_nodes == 10


# ── Secret scan: a partial or refused scan must not read as a clean one ────


def test_secret_scan_to_dict_surfaces_a_refused_scan(tmp_path: Path):
    """A path that is not a directory reports zero secrets — say why."""
    from agent_bom.secret_scanner import scan_secrets

    not_a_dir = tmp_path / "config.json"
    not_a_dir.write_text("{}", encoding="utf-8")

    result = scan_secrets(str(not_a_dir))
    assert result.warnings, "scan_secrets should record why it scanned nothing"

    payload = result.to_dict()
    assert payload["total"] == 0
    assert payload["warnings"] == result.warnings, (
        "to_dict() reports 'total: 0' with no indication the scan never ran — indistinguishable from a repo with no secrets"
    )


def test_secret_scan_to_dict_surfaces_a_file_capped_scan(monkeypatch, tmp_path: Path):
    """A scan that blew the file cap covered part of the tree — say so."""
    import agent_bom.secret_scanner as secret_scanner

    monkeypatch.setattr(secret_scanner, "_MAX_FILES", 2)
    for index in range(6):
        (tmp_path / f"mod_{index}.py").write_text(f"VALUE = {index}\n", encoding="utf-8")

    result = secret_scanner.scan_secrets(str(tmp_path))
    assert result.warnings, "hitting _MAX_FILES should record a warning"

    payload = result.to_dict()
    assert payload["warnings"] == result.warnings
    assert any("Stopped at" in w for w in payload["warnings"])


def test_secret_scan_to_dict_stays_quiet_on_a_complete_scan(tmp_path: Path):
    """A genuinely complete scan carries no warnings — no false alarm."""
    from agent_bom.secret_scanner import scan_secrets

    (tmp_path / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    payload = scan_secrets(str(tmp_path)).to_dict()
    assert payload["warnings"] == []
