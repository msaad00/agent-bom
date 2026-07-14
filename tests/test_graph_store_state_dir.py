"""``default_graph_db_path`` must honor ``AGENT_BOM_STATE_DIR``.

Without this the graph snapshot always lands in the real ``~/.agent-bom/db``
even when an operator (or the test suite's conftest) redirects state off
``$HOME`` via ``AGENT_BOM_STATE_DIR`` — leaking demo/test snapshots into the
user's home dir and shadowing fresh scans with accumulated pollution.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.db.graph_store import default_graph_db_path


def test_state_dir_places_graph_db_under_state_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("AGENT_BOM_GRAPH_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))

    resolved = default_graph_db_path()

    assert resolved == tmp_path / "db" / "graph.db"
    # The real home dir is never referenced when a state dir is configured.
    assert Path.home() not in resolved.parents


def test_explicit_graph_db_overrides_state_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    explicit = tmp_path / "explicit-graph.db"
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(explicit))
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "shared.db"))
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))

    assert default_graph_db_path() == explicit


def test_shared_db_overrides_state_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    shared = tmp_path / "shared.db"
    monkeypatch.delenv("AGENT_BOM_GRAPH_DB", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", str(shared))
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))

    assert default_graph_db_path() == shared


def test_home_default_only_when_nothing_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AGENT_BOM_GRAPH_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_STATE_DIR", raising=False)

    assert default_graph_db_path() == Path.home() / ".agent-bom" / "db" / "graph.db"
