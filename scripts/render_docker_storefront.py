#!/usr/bin/env python3
"""Render the published Docker Hub README from lifecycle-neutral source docs."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def render_published_readme(text: str, version: str) -> str:
    """Promote exactly one matching neutral row to stable for external publication."""

    neutral = f"| `{version}` | Version used by the examples below; verify registry availability before pinning |"
    stable = f"| `{version}` | Current stable version (pinned) |"
    if stable in text and neutral not in text:
        return text
    if text.count(neutral) != 1:
        raise ValueError(f"expected exactly one lifecycle-neutral row for {version}")
    rendered = text.replace(neutral, stable)
    unresolved = re.findall(
        r"^\| `([^`]+)` \| Version used by the examples below; verify registry availability before pinning \|$",
        rendered,
        re.MULTILINE,
    )
    if unresolved:
        raise ValueError(f"unresolved lifecycle-neutral rows remain: {unresolved}")
    return rendered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(render_published_readme(args.input.read_text(), args.version))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
