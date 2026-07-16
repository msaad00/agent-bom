"""Bounded, worktree-aware filesystem traversal shared by discovery scanners.

Discovery that walks a project tree with ``Path.rglob("*")`` has two failure
modes on real developer machines:

* It descends into **nested VCS worktrees** — ``git worktree add`` checkouts and
  submodules — each of which is a full copy of the repository. Inventory then
  re-counts every manifest once per worktree (badly inflated package counts).
* ``sorted(root.rglob("*"))`` **materialises every path in the tree into memory**
  before any filtering. A repository that keeps agent worktrees under
  ``.claude/worktrees`` / ``.cursor/worktrees`` can expose millions of paths,
  and building + sorting that list costs multiple GB of RSS (OOM/abort).

This module provides a single ``os.walk``-based traversal that prunes vendored,
generated, and worktree directories *during* the walk (so their subtrees are
never entered) and enforces a file-count budget as a safety valve.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

# Directory names never worth descending for source/manifest discovery: VCS
# metadata, virtualenvs, vendored dependencies, build output, and tool caches.
VENDOR_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".eggs",
        "site-packages",
        ".next",
        "dist",
        "build",
        ".ipynb_checkpoints",
    }
)

# Safety valve: refuse to yield more than this many files from a single walk.
# The pruning below removes the pathological blow-up cases; this bound guards
# against any remaining giant tree quietly consuming unbounded memory upstream.
DEFAULT_MAX_FILES: int = 500_000


def is_nested_worktree_root(dirpath: Path) -> bool:
    """Return True when *dirpath* is a linked git worktree or submodule root.

    A primary git checkout keeps its metadata in a ``.git`` **directory**. A
    linked worktree (``git worktree add``) or a submodule checkout instead has a
    ``.git`` **file** containing a ``gitdir:`` pointer. Matching the file form
    lets us prune nested checkouts while never pruning the primary repository (or
    a worktree the caller explicitly asked to scan, which is used as the walk
    root and so is never tested here).
    """
    return (dirpath / ".git").is_file()


def _prune_dirnames(dirpath: Path, dirnames: list[str], skip: frozenset[str]) -> None:
    """Filter *dirnames* in place, removing skip dirs and nested worktrees."""
    dirnames[:] = [
        name
        for name in dirnames
        if name not in skip and not is_nested_worktree_root(dirpath / name)
    ]


def iter_discovery_files(
    root: Path,
    *,
    extra_skip_dirs: frozenset[str] = frozenset(),
    max_files: int | None = DEFAULT_MAX_FILES,
) -> Iterator[Path]:
    """Yield files under *root*, pruning vendored/worktree subtrees while walking.

    Unlike ``root.rglob("*")`` this never enters a skipped or nested-worktree
    directory (bounding both wall-clock and peak memory) and stops after
    *max_files* files as a safety valve. *root* itself is always walked even if
    it is a worktree checkout, since the caller asked for it explicitly.

    Yields files in ``os.walk`` order; callers that need determinism should sort
    the (already filtered, typically small) result.
    """
    root = Path(root)
    if not root.is_dir():
        return
    skip = VENDOR_SKIP_DIRS | extra_skip_dirs
    yielded = 0
    for dirpath_str, dirnames, filenames in os.walk(root, followlinks=False):
        dirpath = Path(dirpath_str)
        _prune_dirnames(dirpath, dirnames, skip)
        for name in filenames:
            yield dirpath / name
            yielded += 1
            if max_files is not None and yielded >= max_files:
                return
