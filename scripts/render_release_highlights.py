#!/usr/bin/env python3
"""Render concise human-written release highlights from the changelog."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def render_highlights(changelog: str, tag: str, *, limit: int = 3) -> str:
    """Return the first ``limit`` bullets from a versioned changelog entry."""
    version = tag.removeprefix("v")
    heading = re.compile(rf"^## \[{re.escape(version)}\](?:\s+-.*)?$", re.MULTILINE)
    match = heading.search(changelog)
    if match is None:
        raise ValueError(f"CHANGELOG.md has no release entry for {version}")

    following = changelog[match.end() :]
    next_heading = re.search(r"^## \[", following, re.MULTILINE)
    section = following[: next_heading.start()] if next_heading else following

    bullets: list[str] = []
    current: list[str] | None = None
    for line in section.splitlines():
        if line.startswith("- "):
            if current:
                bullets.append(" ".join(current))
                if len(bullets) == limit:
                    break
            current = [line[2:].strip()]
        elif current is not None and (line.startswith("  ") or not line.strip()):
            if line.strip():
                current.append(line.strip())
        elif current is not None:
            bullets.append(" ".join(current))
            if len(bullets) == limit:
                break
            current = None
    if current and len(bullets) < limit:
        bullets.append(" ".join(current))

    if len(bullets) < 2:
        raise ValueError(f"CHANGELOG.md release entry for {version} needs at least two highlight bullets")
    return "## Highlights\n\n" + "\n".join(f"- {bullet}" for bullet in bullets[:limit]) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="release tag, for example v1.2.3")
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    args = parser.parse_args()
    print(render_highlights(args.changelog.read_text(encoding="utf-8"), args.tag), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
