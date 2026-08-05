"""Bounded, worktree-aware filesystem traversal shared by discovery scanners.

Discovery that walks a project tree with ``Path.rglob("*")`` has two failure
modes on real developer machines:

* It descends into **nested VCS worktrees** — ``git worktree add`` checkouts,
  each a full copy of the repository. Inventory then re-counts every manifest
  once per worktree (badly inflated package counts). Submodules look the same
  from the outside but are *not* copies, so they stay in scope; see
  ``is_nested_worktree_root``.
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
from pathlib import Path, PurePosixPath

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
    """Return True when *dirpath* is a linked git worktree root.

    A primary git checkout keeps its metadata in a ``.git`` **directory**. A
    linked worktree (``git worktree add``) instead has a ``.git`` **file**
    holding a ``gitdir:`` pointer into ``.git/worktrees/``. Pruning those is
    pure dedup: the worktree is a second copy of the surrounding project, so
    walking it counts every manifest twice. The primary repository is never
    pruned (it has no pointer file), nor is a worktree the caller explicitly
    passed as the walk root, which is never tested here.

    A **submodule** carries the same pointer-file shape but points into
    ``.git/modules/``, and the dedup rationale does not transfer: a submodule is
    distinct vendored code that appears nowhere else in the tree and ships in the
    build. Matching the file alone pruned both, silently dropping the
    submodule's manifests — and their vulnerabilities — from the report. Only
    the ``worktrees`` payload prunes; anything else is scanned, because for a
    security scanner a duplicate is a lesser failure than a miss.
    """
    pointer = dirpath / ".git"
    if not pointer.is_file():
        return False
    try:
        content = pointer.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    for line in content.splitlines():
        prefix, separator, target = line.partition("gitdir:")
        if not separator or prefix.strip():
            continue
        return "worktrees" in PurePosixPath(target.strip().replace("\\", "/")).parts
    return False


def _prune_dirnames(dirpath: Path, dirnames: list[str], skip: frozenset[str]) -> None:
    """Filter *dirnames* in place, removing skip dirs and nested worktrees."""
    dirnames[:] = [name for name in dirnames if name not in skip and not is_nested_worktree_root(dirpath / name)]


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
