#!/usr/bin/env python3
"""Comment-hygiene guard: keep conversation, POC, and task-tracking noise out of source.

Product source is read by strangers. Three classes of text must never ship in it:

  1. Chat-style / conversational comments that address the reader or echo a
     working session ("tell me if you do", "let me know", "as you requested").
     Comments must explain the non-obvious *why* — never talk to a person.
  2. LLM / assistant self-references ("as an AI", "I am Claude",
     "Co-Authored-By: <assistant>"). Authorship attribution belongs nowhere in
     the tree, least of all in code.
  3. Internal task / audit-cycle breadcrumbs ("P1-18 v0.86.5 audit: ...").
     The prioritisation id means nothing to an external reader; keep the
     explanation, drop the tracking prefix (it belongs in the commit/PR).

The check scans tracked product surfaces (src, deploy, scripts, workflows, UI
source) and fails with the offending file:line + reason so a regression cannot
land silently. Test fixtures, snapshots, lockfiles, and vendored trees are
excluded because they legitimately carry arbitrary strings. A rare false
positive can be silenced with a trailing ``# hygiene: allow`` pragma on the line.

Exit 0 = clean. Exit 1 = a violation. Pure stdlib so it runs anywhere in CI.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Directories/files whose subtree we scan. Kept narrow and explicit so the guard
# is fast and never wanders into vendored or generated trees.
INCLUDE_GLOBS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("src/agent_bom", (".py",)),
    ("deploy", (".tf", ".yaml", ".yml", ".sh")),
    ("scripts", (".py", ".sh")),
    (".github/workflows", (".yml", ".yaml")),
    ("ui/app", (".ts", ".tsx", ".js", ".jsx")),
    ("ui/components", (".ts", ".tsx", ".js", ".jsx")),
    ("ui/lib", (".ts", ".tsx", ".js", ".jsx")),
)

# Path fragments that exclude a file even inside an included subtree.
EXCLUDE_FRAGMENTS: tuple[str, ...] = (
    "/test",
    "test_",
    "_test.",
    ".test.",
    "/tests/",
    "/fixtures/",
    "/__snapshots__/",
    "/node_modules/",
    "/.next/",
    "/dist/",
    "/build/",
    "conftest.py",
)

# This guard names the patterns it forbids, so it must exempt itself.
SELF = "scripts/check_comment_hygiene.py"

PRAGMA = "hygiene: allow"

# (compiled pattern, human reason). Patterns are specific enough that genuine
# code/strings do not trip them; the excludes cover the test-data case.
FORBIDDEN: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\btell me if\b", re.I), "chat-style comment addressing the reader"),
    (re.compile(r"\blet me know\b", re.I), "chat-style comment addressing the reader"),
    (re.compile(r"\byou asked\b", re.I), "conversational reference to a working session"),
    (re.compile(r"\bas you requested\b", re.I), "conversational reference to a working session"),
    (re.compile(r"\bas we discussed\b", re.I), "conversational reference to a working session"),
    (re.compile(r"\bper our (chat|conversation|discussion)\b", re.I), "conversational reference"),
    (re.compile(r"\bchange only if your\b", re.I), "second-person directive (belongs in docs, not code)"),
    (re.compile(r"\bas an ai\b", re.I), "LLM/assistant self-reference"),
    (re.compile(r"\bi am claude\b|\bi'?m claude\b", re.I), "LLM/assistant self-reference"),
    (re.compile(r"co-?authored-by:\s*(claude|gpt|codex|copilot|cursor)", re.I), "LLM co-author attribution"),
    (re.compile(r"\bP\d-\d+\s+v\d", re.I), "internal task/audit-cycle breadcrumb (keep the why, drop the id)"),
)


def _included(path: Path) -> bool:
    rel = path.relative_to(REPO_ROOT).as_posix()
    if rel == SELF:
        return False
    if any(frag in "/" + rel for frag in EXCLUDE_FRAGMENTS):
        return False
    for root, suffixes in INCLUDE_GLOBS:
        if rel == root or rel.startswith(root + "/"):
            return path.suffix in suffixes
    return False


def _iter_files() -> list[Path]:
    out: list[Path] = []
    for root, _suffixes in INCLUDE_GLOBS:
        base = REPO_ROOT / root
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p.is_file() and _included(p):
                out.append(p)
    return sorted(set(out))


def main() -> int:
    violations: list[str] = []
    for path in _iter_files():
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        for i, line in enumerate(lines, start=1):
            if PRAGMA in line:
                continue
            for pat, reason in FORBIDDEN:
                if pat.search(line):
                    violations.append(f"{rel}:{i}: {reason}\n    {line.strip()[:120]}")
                    break

    if violations:
        print("Comment-hygiene check FAILED — remove conversation/POC/tracking noise from source:\n")
        for v in violations:
            print(f"  {v}")
        print(
            "\nComments must explain the non-obvious *why* only. Move task ids to the "
            "commit/PR. Silence a rare false positive with a trailing '# hygiene: allow'."
        )
        return 1

    print(f"Comment-hygiene check passed ({len(_iter_files())} files scanned).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
