"""CLI AST gate must match analyze_project language coverage (#3499 audit)."""

from __future__ import annotations

from pathlib import Path

from agent_bom.ast_analyzer import project_has_analyzable_sources


def test_project_has_analyzable_sources_php_only(tmp_path: Path) -> None:
    (tmp_path / "server.php").write_text("<?php echo 'mcp';", encoding="utf-8")
    assert project_has_analyzable_sources(tmp_path) is True


def test_project_has_analyzable_sources_swift_only(tmp_path: Path) -> None:
    (tmp_path / "Tool.swift").write_text("struct Tool {}", encoding="utf-8")
    assert project_has_analyzable_sources(tmp_path) is True


def test_project_has_analyzable_sources_empty_dir(tmp_path: Path) -> None:
    assert project_has_analyzable_sources(tmp_path) is False


def test_project_has_analyzable_sources_skips_node_modules(tmp_path: Path) -> None:
    nested = tmp_path / "node_modules" / "pkg"
    nested.mkdir(parents=True)
    (nested / "index.ts").write_text("export {}", encoding="utf-8")
    assert project_has_analyzable_sources(tmp_path) is False
