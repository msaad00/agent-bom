#!/usr/bin/env python3
"""Fail when Finder-style duplicate artifacts are tracked.

macOS Finder copies such as ``foo 2.py`` and duplicated directories such as
``contracts/v1 2`` are easy to miss in reviews but can be included in source
distributions and release archives. This guard checks tracked paths only, so
local virtualenvs, node_modules, and generated build output do not create noise.
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
    "node_modules/",
    "ui/node_modules/",
    "ui/out/",
    "site/",
)


def _tracked_paths() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    return [part.decode("utf-8", errors="replace") for part in result.stdout.split(b"\0") if part]


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
    args = parser.parse_args(argv)

    paths = _load_paths(args.paths_file) if args.paths_file else _tracked_paths()
    duplicates = find_duplicate_artifacts(paths)
    if not duplicates:
        print("No tracked Finder-style duplicate artifacts found.")
        return 0

    print("Tracked Finder-style duplicate artifacts found:", file=sys.stderr)
    for path in duplicates:
        print(f"- {path}", file=sys.stderr)
    print(
        "\nRemove these files or rename them intentionally before merging/releasing.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
