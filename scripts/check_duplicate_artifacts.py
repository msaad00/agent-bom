#!/usr/bin/env python3
"""Fail when Finder-style duplicate artifacts are present.

macOS Finder copies such as ``foo 2.py`` and duplicated directories such as
``contracts/v1 2`` are easy to miss in reviews but can be included in source
distributions and release archives. CI checks tracked paths. Local operators can
use ``--working-tree`` to catch untracked copies that would still be collected by
tools such as pytest.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

_DUPLICATE_COMPONENT_RE = re.compile(r"^.+ [2-9](?:\.[^.\\/]+)?$")
_IGNORED_PREFIXES = (
    ".git/",
    ".venv/",
    "venv/",
    "dist/",
    "build/",
    "node_modules/",
    ".mypy_cache/",
    ".pytest_cache/",
    ".ruff_cache/",
    "ui/node_modules/",
    "ui/.next/",
    "ui/out/",
    "site/",
)
_IGNORED_DIR_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "site",
    "venv",
}


def _tracked_paths() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    return [part.decode("utf-8", errors="replace") for part in result.stdout.split(b"\0") if part]


def _working_tree_paths(root: Path) -> list[str]:
    paths: list[str] = []
    for path in root.rglob("*"):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        parts = relative.parts
        if any(part in _IGNORED_DIR_NAMES for part in parts):
            continue
        paths.append(relative.as_posix())
    return paths


def _load_paths(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def find_duplicate_artifacts(paths: list[str]) -> list[str]:
    matches: list[str] = []
    for raw in paths:
        normalized = raw.replace("\\", "/")
        if normalized.startswith("./"):
            normalized = normalized[2:]
        if not normalized or normalized.startswith(_IGNORED_PREFIXES):
            continue
        components = normalized.split("/")
        if any(_DUPLICATE_COMPONENT_RE.match(component) for component in components):
            matches.append(normalized)
    return sorted(set(matches))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--paths-file",
        type=Path,
        help="Optional newline-delimited path list for tests; defaults to git ls-files.",
    )
    parser.add_argument(
        "--working-tree",
        action="store_true",
        help="Scan the local working tree, including untracked files, while skipping build/cache directories.",
    )
    args = parser.parse_args(argv)

    if args.paths_file:
        paths = _load_paths(args.paths_file)
    elif args.working_tree:
        paths = _working_tree_paths(Path.cwd())
    else:
        paths = _tracked_paths()
    duplicates = find_duplicate_artifacts(paths)
    if not duplicates:
        scope = "working-tree" if args.working_tree else "tracked"
        print(f"No {scope} Finder-style duplicate artifacts found.")
        return 0

    scope = "Working-tree" if args.working_tree else "Tracked"
    print(f"{scope} Finder-style duplicate artifacts found:", file=sys.stderr)
    for path in duplicates:
        print(f"- {path}", file=sys.stderr)
    print(
        "\nRemove these files or rename them intentionally before merging/releasing.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
