#!/usr/bin/env python3
"""Public-docs hygiene: keep private strategy and agent audits out of the OSS tree.

The public repo is read by strangers. These classes of material must never ship:

  1. Strategy artifacts (filenames like STRATEGIC_AUDIT*, PRIVATE_STRATEGY*,
     *GTM*AUDIT*, *COMMERCIAL_SCORECARD*).
  2. Agent-session / persona audit ledgers under docs/audits/ or
     docs/archive/AUDIT*.
  3. Private pilot scorecard phrases ("harsh re-rate", "absolute pilot
     readiness") and deleted strategic-audit banners.

Public docs are product evidence and operator runbooks only — not
Cursor/Claude/Codex review write-ups or commercial scorecards.

Exit 0 = clean. Exit 1 = a violation. Pure stdlib so it runs anywhere in CI.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SELF = "scripts/check_public_docs_hygiene.py"

# Basename patterns for files that must not exist in the public tree.
FORBIDDEN_BASENAME_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^STRATEGIC_AUDIT", re.I),
    re.compile(r"^PRIVATE_STRATEGY", re.I),
    re.compile(r"GTM.*AUDIT|AUDIT.*GTM", re.I),
    re.compile(r"COMMERCIAL_SCORECARD", re.I),
    # Persona / codebase audit ledgers (agent-session write-ups).
    re.compile(r"^AUDIT(-\d|\.md$|$)", re.I),
)

# Entire trees that must stay empty / absent in the public checkout.
FORBIDDEN_PATH_PREFIXES: tuple[str, ...] = (
    "docs/audits/",
)

# Content scan roots (markdown / copy surfaces strangers read).
CONTENT_ROOTS: tuple[str, ...] = (
    "docs",
    "site-docs",
    "ui",
    "CHANGELOG.md",
    "README.md",
    "AGENTS.md",
)

CONTENT_SUFFIXES: tuple[str, ...] = (".md", ".mdx", ".tsx", ".ts", ".jsx", ".js")

EXCLUDE_FRAGMENTS: tuple[str, ...] = (
    "/node_modules/",
    "/.next/",
    "/dist/",
    "/build/",
    "/__snapshots__/",
    "/fixtures/",
)

# Policy files that name the forbidden classes so agents know what not to add.
# Filename bans still apply; phrase scan skips these so the rule text itself
# does not fail the guard.
CONTENT_SCAN_SKIP: frozenset[str] = frozenset(
    {
        SELF,
        "AGENTS.md",
        "CLAUDE.md",
        "docs/archive/README.md",
    }
)

# Phrase patterns unique to private scorecard / strategy memos.
FORBIDDEN_CONTENT: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bharsh re-?rates?\b", re.I),
        "private pilot scorecard phrase (keep in private notes)",
    ),
    (
        re.compile(r"\babsolute pilot readiness\b", re.I),
        "private pilot scorecard phrase (keep in private notes)",
    ),
    (
        re.compile(r"#\s*agent-bom\s+Strategic\s+Audit\b", re.I),
        "private strategic-audit memo title (do not reintroduce)",
    ),
    (
        re.compile(r"#\s*agent-bom\s+Codebase\s+Audit\b", re.I),
        "agent-session codebase audit ledger (do not reintroduce)",
    ),
    (
        re.compile(r"\bTrademark\s*&\s*IP\s+Protection\b", re.I),
        "private IP/GTM plan section (do not reintroduce)",
    ),
)


def _excluded(rel: str) -> bool:
    if rel == SELF:
        return True
    return any(frag in "/" + rel for frag in EXCLUDE_FRAGMENTS)


def _iter_tracked_ish() -> list[Path]:
    """Walk content roots without requiring git (CI checkout is enough)."""
    out: list[Path] = []
    for root in CONTENT_ROOTS:
        base = REPO_ROOT / root
        if base.is_file():
            out.append(base)
            continue
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(REPO_ROOT).as_posix()
            if _excluded(rel):
                continue
            if p.suffix.lower() in CONTENT_SUFFIXES or p.name.upper().startswith(
                ("STRATEGIC", "AUDIT")
            ):
                out.append(p)
    # Also catch a resurrected docs/audits tree even if empty of md later.
    audits = REPO_ROOT / "docs" / "audits"
    if audits.is_dir():
        for p in audits.rglob("*"):
            if p.is_file():
                out.append(p)
    return sorted(set(out))


def main() -> int:
    violations: list[str] = []

    audits_dir = REPO_ROOT / "docs" / "audits"
    if audits_dir.exists():
        violations.append(
            "docs/audits/: forbidden agent-session audit ledger directory "
            "(keep persona reviews in private notes)"
        )

    for path in _iter_tracked_ish():
        rel = path.relative_to(REPO_ROOT).as_posix()
        if any(rel == p.rstrip("/") or rel.startswith(p) for p in FORBIDDEN_PATH_PREFIXES):
            violations.append(f"{rel}: forbidden path under docs/audits/")
            continue
        for pat in FORBIDDEN_BASENAME_RES:
            if pat.search(path.name):
                # Allow non-ledger uses outside docs/ (e.g. test fixtures).
                if not rel.startswith("docs/"):
                    continue
                violations.append(f"{rel}: forbidden audit/strategy filename ({path.name})")
                break

    for path in _iter_tracked_ish():
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in CONTENT_SCAN_SKIP or rel.startswith(".cursor/"):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(lines, start=1):
            for pat, reason in FORBIDDEN_CONTENT:
                if pat.search(line):
                    violations.append(f"{rel}:{i}: {reason}\n    {line.strip()[:120]}")
                    break

    if violations:
        print(
            "Public-docs hygiene check FAILED — private strategy/scorecard "
            "and agent audit ledgers must stay out of the OSS tree:\n"
        )
        for v in violations:
            print(f"  {v}")
        print(
            "\nKeep strategy, named-prospect lists, harsh scorecards, and "
            "Cursor/Claude persona audits in private notes — not docs/."
        )
        return 1

    scanned = len(_iter_tracked_ish())
    print(f"Public-docs hygiene check passed ({scanned} files scanned).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
