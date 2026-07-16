"""CLI AST gate must match analyze_project language coverage (#3499 audit)."""

from __future__ import annotations

from pathlib import Path

from agent_bom.ast_analyzer import analyze_project, project_has_analyzable_sources


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


def test_analyzable_sources_ignores_ancestor_skip_dir_names(tmp_path: Path) -> None:
    """A project kept under an ancestor dir named like a skip dir is still analyzed.

    The skip list (`build`, `test`, `fixtures`, ...) must only apply to path
    components RELATIVE to the scan root, never to ancestor directories of where
    the user happens to keep the project (e.g. ~/dev/test/proj, /ci/build/app).
    """
    for ancestor in ("build", "test", "fixtures", "vendor", "env"):
        project = tmp_path / ancestor / "myapp"
        project.mkdir(parents=True)
        (project / "server.py").write_text("def handler():\n    return 1\n", encoding="utf-8")
        assert project_has_analyzable_sources(project) is True, ancestor
        result = analyze_project(project)
        assert result.files_analyzed == 1, ancestor


def test_analyze_project_still_skips_tests_subdir_inside_project(tmp_path: Path) -> None:
    """A `tests/` subtree INSIDE the scan root is still skipped (relative match)."""
    (tmp_path / "app.py").write_text("def handler():\n    return 1\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "helper.py").write_text("def helper():\n    return 2\n", encoding="utf-8")

    assert project_has_analyzable_sources(tmp_path) is True
    result = analyze_project(tmp_path)
    assert result.files_analyzed == 1
