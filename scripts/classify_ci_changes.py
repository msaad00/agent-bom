#!/usr/bin/env python3
"""Classify changed repository paths for fail-closed CI routing.

The classifier intentionally recognizes only one narrow fast path:
documentation-only changes. Any empty, malformed, mixed, or unknown path set
falls back to the full validation lanes.
"""

from __future__ import annotations

import argparse
import dataclasses
from pathlib import PurePosixPath
from typing import Iterable

_ROOT_DOCUMENTS = {
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "LICENSE.md",
    "NOTICE",
    "NOTICE.md",
    "PYPI_README.md",
    "README.md",
    "SECURITY.md",
    "mkdocs.yml",
}
_DOCUMENTATION_PREFIXES = (
    ".github/ISSUE_TEMPLATE/",
    "docs/",
    "site-docs/",
)


@dataclasses.dataclass(frozen=True)
class ChangeClassification:
    docs_only: bool
    changed_count: int


def _normalize_path(raw: str) -> str | None:
    value = raw.strip().replace("\\", "/")
    if not value or value.startswith("/"):
        return None
    path = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def _is_documentation_path(path: str) -> bool:
    if path in _ROOT_DOCUMENTS:
        return True
    if "/" not in path and path.lower().endswith(".md"):
        return True
    return path.startswith(_DOCUMENTATION_PREFIXES)


def classify_paths(paths: Iterable[str]) -> ChangeClassification:
    """Return a narrow docs-only classification, failing closed on ambiguity."""
    raw_paths = list(paths)
    normalized = [_normalize_path(path) for path in raw_paths]
    valid_paths = [path for path in normalized if path is not None]
    docs_only = bool(valid_paths) and len(valid_paths) == len(raw_paths) and all(_is_documentation_path(path) for path in valid_paths)
    return ChangeClassification(docs_only=docs_only, changed_count=len(valid_paths))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--github-output",
        help="Optional GitHub Actions output file to append docs_only/count values to.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    import sys

    classification = classify_paths(sys.stdin.read().splitlines())
    lines = f"docs_only={'true' if classification.docs_only else 'false'}\nchanged_count={classification.changed_count}\n"
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as output:
            output.write(lines)
    else:
        sys.stdout.write(lines)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
