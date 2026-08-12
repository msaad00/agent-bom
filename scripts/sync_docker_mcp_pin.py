#!/usr/bin/env python3
"""Own the Docker MCP submission's ``source.commit`` from the release run.

``integrations/docker-mcp-registry/server.yaml`` pins the commit Docker builds
the published server from. Its correct value is the commit a release tag points
at, which does not exist until the tag does — so it cannot be written by
``bump-version.py`` along with the version, and it was instead carried as a
manual step in ``SUBMISSION.md``. It was last updated by hand in a release that
predates several since.

``--set`` writes the pin; ``--check`` asserts it is a full commit SHA that is
reachable in this repository. Freshness is not asserted here on purpose: the
release run opens a PR to move the pin *after* the tag exists, so between the
tag and that merge the pin is legitimately one release behind, and a gate that
failed on it would fail every release.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_YAML = ROOT / "integrations" / "docker-mcp-registry" / "server.yaml"

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
COMMIT_LINE = re.compile(r"^([ \t]+commit:[ \t]+)([0-9a-f]{7,40})[ \t]*$")


def _pin_line_index(lines: list[str]) -> int | None:
    """Index of the ``commit:`` line inside the top-level ``source:`` block.

    Scanned by line rather than matched across the document so an unrelated
    ``commit:`` key elsewhere in the file can never be rewritten by accident.
    """
    in_source = False
    for index, line in enumerate(lines):
        if not line[:1].isspace() and line.strip():
            in_source = line.startswith("source:")
            continue
        if in_source and COMMIT_LINE.match(line):
            return index
    return None


def read_pin(text: str) -> str | None:
    lines = text.splitlines()
    index = _pin_line_index(lines)
    if index is None:
        return None
    match = COMMIT_LINE.match(lines[index])
    assert match is not None
    return match.group(2)


def write_pin(text: str, commit: str) -> str:
    lines = text.splitlines(keepends=True)
    index = _pin_line_index([line.rstrip("\n") for line in lines])
    if index is None:
        raise ValueError("no source.commit pin to write")
    ending = "\n" if lines[index].endswith("\n") else ""
    match = COMMIT_LINE.match(lines[index].rstrip("\n"))
    assert match is not None
    lines[index] = f"{match.group(1)}{commit}{ending}"
    return "".join(lines)


def _object_exists(commit: str) -> bool:
    """True when the SHA names a commit present in this checkout.

    A shallow or partial clone legitimately lacks older history, so absence is
    reported by the caller as unknown rather than as a failure.
    """
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=ROOT,
        capture_output=True,
    )
    return result.returncode == 0


def _is_shallow() -> bool:
    result = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() == "true"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--set", metavar="SHA", help="write this commit as the pin")
    group.add_argument("--check", action="store_true", help="validate the pin without writing")
    parser.add_argument(
        "--print-current",
        action="store_true",
        help="print the pin currently in the file and exit",
    )
    args = parser.parse_args()

    if not SERVER_YAML.exists():
        print(f"FAIL: {SERVER_YAML.relative_to(ROOT)} does not exist", file=sys.stderr)
        return 1

    text = SERVER_YAML.read_text(encoding="utf-8")
    current = read_pin(text)
    if current is None:
        print(
            f"FAIL: no source.commit pin found in {SERVER_YAML.relative_to(ROOT)}",
            file=sys.stderr,
        )
        return 1

    if args.print_current:
        print(current)
        return 0

    if args.check:
        if not FULL_SHA.match(current):
            print(
                f"FAIL: source.commit is not a full 40-character SHA: {current!r}",
                file=sys.stderr,
            )
            return 1
        if _object_exists(current):
            print(f"Docker MCP pin OK — {current} is a commit in this repository")
        elif _is_shallow():
            print(f"Docker MCP pin {current} not verifiable in a shallow clone")
        else:
            print(
                f"FAIL: source.commit {current} is not a commit in this repository",
                file=sys.stderr,
            )
            return 1
        return 0

    commit = args.set.strip().lower()
    if not FULL_SHA.match(commit):
        print(
            f"FAIL: --set expects a full 40-character SHA, got {args.set!r}",
            file=sys.stderr,
        )
        return 1

    if commit == current:
        print(f"Docker MCP pin already {commit} — nothing to do")
        return 0

    SERVER_YAML.write_text(write_pin(text, commit), encoding="utf-8")
    print(f"Docker MCP pin {current} -> {commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
