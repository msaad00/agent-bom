from __future__ import annotations

from pathlib import Path

from agent_bom.secret_scanner import scan_secrets

_SECRET = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'


def _make_worktree(root: Path, relative: str) -> Path:
    """Create a nested linked-worktree checkout under *root*."""
    worktree = root / relative
    worktree.mkdir(parents=True)
    # A linked worktree/submodule marks itself with a .git *file* holding a
    # gitdir: pointer, unlike a primary checkout's .git directory.
    (worktree / ".git").write_text(f"gitdir: {root}/.git/worktrees/{worktree.name}\n")
    return worktree


def test_nested_agent_worktree_is_not_rescanned(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "app.py").write_text(_SECRET)

    worktree = _make_worktree(tmp_path, ".cursor/worktrees/feature-branch")
    (worktree / "app.py").write_text(_SECRET)

    result = scan_secrets(str(tmp_path))

    paths = {str(f.file_path) for f in result.findings}
    assert not any(".cursor" in p for p in paths), f"scanned the nested worktree: {paths}"
    assert len(result.findings) == 1, f"expected the primary copy only, got {paths}"


def test_pruning_is_not_limited_to_one_vendor(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / "app.py").write_text(_SECRET)

    for vendor in (".cursor", ".claude", ".codex", "vendored"):
        worktree = _make_worktree(tmp_path, f"{vendor}/worktrees/wt")
        (worktree / "app.py").write_text(_SECRET)

    result = scan_secrets(str(tmp_path))

    assert len(result.findings) == 1, [str(f.file_path) for f in result.findings]


def test_primary_checkout_is_still_scanned(tmp_path: Path) -> None:
    """The walk root must never be pruned, even when it is itself a worktree."""
    (tmp_path / ".git").write_text("gitdir: /elsewhere/.git/worktrees/root\n")
    (tmp_path / "app.py").write_text(_SECRET)

    result = scan_secrets(str(tmp_path))

    assert len(result.findings) == 1
