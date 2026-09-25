"""Traversal is bounded and excludes nested VCS worktrees / vendored trees.

Regression coverage for the Codex-audit findings that project/skill discovery
recursed into nested git worktrees (``.claude/worktrees/*`` full checkouts),
duplicating inventory and materialising millions of paths (memory blow-up).
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.parsers.dataset_cards import discover_dataset_files
from agent_bom.parsers.dataset_pii_scanner import scan_directory_for_pii
from agent_bom.parsers.node_parsers import _workspace_package_versions
from agent_bom.parsers.prompt_scanner import discover_prompt_files
from agent_bom.parsers.skills import discover_skill_files
from agent_bom.parsers.training_pipeline import discover_training_files
from agent_bom.python_agents import _collect_requirements
from agent_bom.repo_auto_detect import project_has_notebooks, project_has_terraform
from agent_bom.traversal import (
    VENDOR_SKIP_DIRS,
    is_nested_worktree_root,
    iter_discovery_files,
)


def _make_worktree(path: Path) -> None:
    """Create a directory that looks like a linked git worktree (``.git`` file)."""
    path.mkdir(parents=True, exist_ok=True)
    (path / ".git").write_text("gitdir: /elsewhere/.git/worktrees/wt\n")


def test_is_nested_worktree_root_detects_git_file_not_dir(tmp_path):
    primary = tmp_path / "primary"
    (primary / ".git").mkdir(parents=True)  # real repo: .git is a directory
    worktree = tmp_path / "wt"
    _make_worktree(worktree)  # linked worktree: .git is a file
    assert is_nested_worktree_root(worktree) is True
    assert is_nested_worktree_root(primary) is False


def test_iter_discovery_files_skips_nested_worktrees_and_vendor(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.0\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "requirements.txt").write_text("vendored==1.0\n")
    nested = tmp_path / ".claude" / "worktrees" / "agent-abc"
    _make_worktree(nested)
    (nested / "requirements.txt").write_text("dup==9.9\n")

    files = {p.name for p in iter_discovery_files(tmp_path)}
    assert "requirements.txt" in files
    found = [p for p in iter_discovery_files(tmp_path) if p.name == "requirements.txt"]
    # Only the real top-level manifest — not the vendored or worktree copies.
    assert len(found) == 1
    assert found[0] == tmp_path / "requirements.txt"


def test_iter_discovery_files_walks_root_even_if_worktree(tmp_path):
    """A worktree passed explicitly as the scan root is still scanned."""
    _make_worktree(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    names = {p.name for p in iter_discovery_files(tmp_path)}
    assert "pyproject.toml" in names


def test_iter_discovery_files_respects_max_files(tmp_path):
    for i in range(20):
        (tmp_path / f"f{i}.txt").write_text("x")
    got = list(iter_discovery_files(tmp_path, max_files=5))
    assert len(got) == 5


def test_iter_discovery_files_does_not_follow_directory_symlinks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "sentinel.txt").write_text("outside")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)

    assert not list(iter_discovery_files(root))


def test_repo_auto_detection_skips_nested_worktree_targets(tmp_path):
    nested = tmp_path / ".cursor" / "worktrees" / "copy"
    _make_worktree(nested)
    (nested / "copy.ipynb").write_text("{}")
    (nested / "copy.tf").write_text('resource "null_resource" "copy" {}')

    assert project_has_notebooks(tmp_path) is False
    assert project_has_terraform(tmp_path) is False

    (tmp_path / "real.ipynb").write_text("{}")
    (tmp_path / "real.tfvars").write_text('region = "us-east-1"')
    assert project_has_notebooks(tmp_path) is True
    assert project_has_terraform(tmp_path) is True


def test_dataset_and_training_discovery_skip_nested_worktrees(tmp_path):
    (tmp_path / "dataset_info.json").write_text("{}")
    (tmp_path / "MLmodel").write_text("name: real")
    nested = tmp_path / ".claude" / "worktrees" / "copy"
    _make_worktree(nested)
    (nested / "dataset_info.json").write_text("{}")
    (nested / "MLmodel").write_text("name: duplicate")

    assert discover_dataset_files(tmp_path) == [tmp_path / "dataset_info.json"]
    assert discover_training_files(tmp_path) == [tmp_path / "MLmodel"]


def test_prompt_and_pii_discovery_skip_nested_worktrees(tmp_path):
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "real.prompt").write_text("Be helpful")
    (tmp_path / "real.csv").write_text("email\nreal@example.com\n")
    nested = tmp_path / ".cursor" / "worktrees" / "copy"
    _make_worktree(nested)
    (nested / "duplicate.prompt").write_text("duplicate")
    (nested / "duplicate.csv").write_text("email\nduplicate@example.com\n")

    assert discover_prompt_files(tmp_path) == [prompts / "real.prompt"]
    result = scan_directory_for_pii(tmp_path)
    assert result.files_scanned == 1
    assert [Path(item.file_path).name for item in result.file_results] == ["real.csv"]


def test_recursive_node_workspace_discovery_skips_nested_worktrees(tmp_path):
    (tmp_path / "pnpm-workspace.yaml").write_text("packages:\n  - packages/**\n")
    real = tmp_path / "packages" / "real"
    real.mkdir(parents=True)
    (real / "package.json").write_text('{"name":"real-package","version":"1.2.3"}')
    nested = tmp_path / "packages" / "copy"
    _make_worktree(nested)
    (nested / "package.json").write_text('{"name":"duplicate-package","version":"9.9.9"}')

    _workspace_package_versions.cache_clear()
    versions = _workspace_package_versions(str(tmp_path))

    assert versions == {"real-package": "1.2.3"}


def test_collect_requirements_not_inflated_by_worktrees(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0\n")
    nested = tmp_path / ".claude" / "worktrees" / "agent-xyz"
    _make_worktree(nested)
    (nested / "requirements.txt").write_text("flask==3.0\ndjango==5.0\n")

    pkgs = _collect_requirements(tmp_path)
    assert "flask" in pkgs
    # The worktree-only package must not leak into the real project inventory.
    assert "django" not in pkgs


def test_discover_skill_files_skips_worktree_copies(tmp_path):
    (tmp_path / "AGENTS.md").write_text("# guidelines\n")
    nested = tmp_path / ".claude" / "worktrees" / "agent-1"
    _make_worktree(nested)
    (nested / "AGENTS.md").write_text("# duplicate guidelines\n")

    found = discover_skill_files(tmp_path)
    agents = [p for p in found if p.name == "AGENTS.md"]
    assert len(agents) == 1
    assert agents[0].resolve() == (tmp_path / "AGENTS.md").resolve()


def test_vendor_skip_dirs_cover_common_generated_trees():
    for name in {".git", ".venv", "node_modules", "__pycache__", "site-packages"}:
        assert name in VENDOR_SKIP_DIRS


def test_all_consumers_record_ancestor_pruning(tmp_path, caplog):
    from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings

    reset_scan_warnings()
    try:
        for directory in ("env", "testing", "build/output"):
            path = tmp_path / directory
            path.mkdir(parents=True)
            (path / "rules.prompt").write_text("secret prompt")
        # This list-returning consumer has no on_prune callback of its own.
        discover_prompt_files(tmp_path)
        warnings = consume_coverage_warnings()
        assert warnings
        assert sum(w["excluded_count"] for w in warnings) >= 1
        assert "contents were not inspected" in caplog.text
        assert str(tmp_path) not in caplog.text
    finally:
        reset_scan_warnings()


def test_traversal_limit_requires_an_actual_uninspected_file(tmp_path):
    from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings

    reset_scan_warnings()
    try:
        (tmp_path / "one.txt").write_text("one")
        limits = []
        assert len(list(iter_discovery_files(tmp_path, max_files=1, on_limit=limits.append))) == 1
        assert limits == []
        assert consume_coverage_warnings() == []
        (tmp_path / "two.txt").write_text("two")
        assert len(list(iter_discovery_files(tmp_path, max_files=1, on_limit=limits.append))) == 1
        assert limits == [1]
        assert consume_coverage_warnings()[0]["reason"] == "discovery_file_limit"
        assert list(iter_discovery_files(tmp_path, max_files=0)) == []
    finally:
        reset_scan_warnings()


def test_pruning_counts_ancestors_without_exposing_paths(tmp_path):
    from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings

    reset_scan_warnings()
    try:
        for directory in ("build", "dist", "node_modules"):
            (tmp_path / directory).mkdir()
        list(iter_discovery_files(tmp_path))
        warnings = consume_coverage_warnings()
        assert len(warnings) == 1
        assert warnings[0]["excluded_count"] == 3
        assert str(tmp_path) not in str(warnings)
    finally:
        reset_scan_warnings()


def _skip_without_posix_permissions():
    import os
    import sys

    import pytest

    if sys.platform.startswith("win") or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("directory permission bits are not enforced here")


def test_unreadable_directory_is_skipped_and_counted_not_fatal(tmp_path):
    from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings

    _skip_without_posix_permissions()
    (tmp_path / "skills").mkdir()
    (tmp_path / "skills" / "SKILL.md").write_text("# ok\n")
    (tmp_path / "CLAUDE.md").write_text("# root\n")
    locked = tmp_path / "locked"
    (locked / "inner").mkdir(parents=True)
    reset_scan_warnings()
    locked.chmod(0)
    try:
        files = {p.relative_to(tmp_path).as_posix() for p in iter_discovery_files(tmp_path)}
        assert files == {"skills/SKILL.md", "CLAUDE.md"}
        skills = discover_skill_files(tmp_path)
        assert {p.name for p in skills} == {"SKILL.md", "CLAUDE.md"}
        warnings = consume_coverage_warnings()
        read_errors = [w for w in warnings if w["reason"] == "directory_read_error"]
        assert read_errors and all(w["excluded_count"] >= 1 for w in read_errors)
        assert str(tmp_path) not in str(warnings)
    finally:
        locked.chmod(0o755)
        reset_scan_warnings()


def test_listable_but_unsearchable_directory_yields_nothing_and_is_counted(tmp_path):
    # r-- without x: names can be listed but no entry can be stat'ed or opened,
    # so yielding them only moves the PermissionError into every consumer.
    from agent_bom.iac import scan_iac_directory
    from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings

    _skip_without_posix_permissions()
    (tmp_path / "CLAUDE.md").write_text("# root\n")
    listable = tmp_path / "listable"
    (listable / "skills").mkdir(parents=True)
    (listable / "skills" / "SKILL.md").write_text("# hidden\n")
    (listable / "AGENTS.md").write_text("# hidden\n")
    (listable / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    reset_scan_warnings()
    listable.chmod(0o444)
    try:
        assert [p.name for p in iter_discovery_files(tmp_path)] == ["CLAUDE.md"]
        assert [p.name for p in discover_skill_files(tmp_path)] == ["CLAUDE.md"]
        scan_iac_directory(tmp_path)
        warnings = consume_coverage_warnings()
        assert any(w["reason"] == "directory_read_error" for w in warnings)
    finally:
        listable.chmod(0o755)
        reset_scan_warnings()


def test_is_nested_worktree_root_unreadable_directory_is_not_a_worktree(tmp_path):
    _skip_without_posix_permissions()
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        assert is_nested_worktree_root(locked) is False
    finally:
        locked.chmod(0o755)
