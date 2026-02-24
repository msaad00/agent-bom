#!/usr/bin/env python3
"""Bump agent-bom version across all files in one command.

Usage:
    python scripts/bump-version.py 0.29.0
    python scripts/bump-version.py 0.29.0 --dry-run
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Every file + regex pattern that contains the version string.
# Each entry: (relative_path, compiled_regex, replacement_template)
# The replacement_template uses \g<1> for the prefix capture group.
VERSION_LOCATIONS: list[tuple[str, re.Pattern, str]] = [
    # Core
    ("pyproject.toml", re.compile(r'^(version\s*=\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    ("src/agent_bom/__init__.py", re.compile(r'(__version__\s*=\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    # Dockerfiles
    ("Dockerfile.sse", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    ("integrations/toolhive/Dockerfile.mcp", re.compile(r"^(ARG VERSION=)\S+", re.M), r"\g<1>{v}"),
    # MCP Registry server.json (version field + pypi identifier version)
    ("integrations/mcp-registry/server.json", re.compile(r'("version":\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    # ToolHive server.json (version field + OCI image tags)
    ("integrations/toolhive/server.json", re.compile(r'("version":\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    ("integrations/toolhive/server.json", re.compile(r"(ghcr\.io/msaad00/agent-bom:v)[^\s\"]+"), r"\g<1>{v}"),
    # OpenClaw SKILL.md
    ("integrations/openclaw/SKILL.md", re.compile(r"^(version:\s*)\S+", re.M), r"\g<1>{v}"),
]

# Patterns that reference the version in docs/tests (updated separately)
DOC_TEST_LOCATIONS: list[tuple[str, re.Pattern, str]] = [
    # README.md — GitHub Action version references
    ("README.md", re.compile(r"(msaad00/agent-bom@v)[^\s\"]+"), r"\g<1>{v}"),
    # tests/test_core.py — version assertions
    ("tests/test_core.py", re.compile(r'(assert\s+__version__\s*==\s*")[^"]+(")', re.M), r"\g<1>{v}\g<2>"),
    # Only match version assertions that currently contain a semver pattern (avoids clobbering SARIF "2.1.0")
    ("tests/test_core.py", re.compile(r'(assert\s+data\["version"\]\s*==\s*")0\.\d+\.\d+(")', re.M), r"\g<1>{v}\g<2>"),
]


def bump(new_version: str, *, dry_run: bool = False) -> int:
    """Replace version strings across all tracked files."""
    if not re.match(r"^\d+\.\d+\.\d+$", new_version):
        print(f"ERROR: Invalid semver: {new_version}", file=sys.stderr)
        return 1

    all_locations = VERSION_LOCATIONS + DOC_TEST_LOCATIONS
    changed = 0

    for rel_path, pattern, template in all_locations:
        path = ROOT / rel_path
        if not path.exists():
            print(f"  SKIP (not found): {rel_path}")
            continue

        text = path.read_text()
        replacement = template.format(v=new_version)
        new_text, count = pattern.subn(replacement, text)

        if count == 0:
            print(f"  WARN (no match):  {rel_path}  pattern={pattern.pattern!r}")
        elif new_text == text:
            print(f"  OK (already {new_version}): {rel_path}")
        else:
            changed += count
            if dry_run:
                print(f"  DRY-RUN ({count} hit): {rel_path}")
            else:
                path.write_text(new_text)
                print(f"  UPDATED ({count} hit): {rel_path}")

    print(f"\n{'Would update' if dry_run else 'Updated'} {changed} occurrence(s)")

    if not dry_run and changed > 0:
        print("\nNext steps:")
        print(f"  git add -A && git commit -m 'chore: bump version to {new_version}'")
        print(f"  git tag v{new_version}")
        print(f"  git push origin main v{new_version}")

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Bump agent-bom version everywhere")
    parser.add_argument("version", help="New version (e.g. 0.29.0)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would change without writing")
    args = parser.parse_args()
    sys.exit(bump(args.version, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
