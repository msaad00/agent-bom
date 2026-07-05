#!/usr/bin/env python3
"""Reject LLM/tool co-author attribution in git commit messages.

Commit trailers like ``Co-authored-by: Cursor <cursoragent@cursor.com>`` and
``Made with [Cursor](...)`` belong in neither product source nor git history.
Used as a pre-commit ``commit-msg`` hook.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

FORBIDDEN: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"co-?authored-by:\s*(claude|gpt|codex|copilot|cursor|gemini)", re.I), "LLM co-author attribution"),
    (re.compile(r"made with \[cursor\]", re.I), "Cursor marketing trailer"),
)


def is_forbidden_line(line: str) -> bool:
    return any(pattern.search(line) for pattern, _ in FORBIDDEN)


def check_commit_message(text: str) -> list[str]:
    violations: list[str] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern, reason in FORBIDDEN:
            if pattern.search(line):
                violations.append(f"line {line_no}: {reason}: {line.strip()}")
    return violations


def strip_forbidden_trailers(text: str) -> str:
    kept = [line for line in text.splitlines() if not is_forbidden_line(line)]
    if not kept:
        return ""
    body = "\n".join(kept).rstrip()
    return f"{body}\n"


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: check_commit_message.py [--strip] <commit-msg-file>", file=sys.stderr)
        return 2
    strip = False
    positional = args
    if args[0] == "--strip":
        strip = True
        positional = args[1:]
    if not positional:
        print("usage: check_commit_message.py [--strip] <commit-msg-file>", file=sys.stderr)
        return 2
    path = Path(positional[0])
    text = path.read_text(encoding="utf-8")
    if strip:
        path.write_text(strip_forbidden_trailers(text), encoding="utf-8")
        return 0
    violations = check_commit_message(text)
    if violations:
        print("Commit message hygiene check failed:", file=sys.stderr)
        for item in violations:
            print(f"  - {item}", file=sys.stderr)
        print("Remove assistant co-author trailers before committing.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
