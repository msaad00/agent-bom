"""Traversal is bounded and excludes nested VCS worktrees / vendored trees.

Regression coverage for the Codex-audit findings that project/skill discovery
recursed into nested git worktrees (``.claude/worktrees/*`` full checkouts),
duplicating inventory and materialising millions of paths (memory blow-up).
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.parsers.skills import discover_skill_files
from agent_bom.python_agents import _collect_requirements
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
