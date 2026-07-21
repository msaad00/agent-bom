#!/usr/bin/env python3
"""Structural version-alignment gate for agent-bom release surfaces.

Every user-facing surface that pins a published image (``agentbom/agent-bom*:X``)
or a GitHub Action ref (``msaad00/agent-bom@vX``) must track the single canonical
version declared in ``pyproject.toml``. Unlike a hand-maintained per-file
allowlist, this gate walks whole shipping-surface *trees*, so a NEW file that
introduces a managed reference is covered automatically and cannot silently
drift away from the release version.

Usage::

    python scripts/check_version_alignment.py            # verify, exit 1 on drift
    python scripts/check_version_alignment.py --fix 0.97.1   # rewrite every ref

``scripts/`` and ``tests/`` are deliberately NOT scanned: they carry these
patterns as guard literals / fixtures with intentionally-stale versions.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterator, NamedTuple

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"

# Surfaces that ship to users, so any pinned ref inside them must be the current
# release. Directories are scanned recursively; individual files are scanned as-is.
SCAN_ROOTS: tuple[Path, ...] = (
    ROOT / "README.md",
    ROOT / "PYPI_README.md",
    ROOT / "DOCKER_HUB_README.md",
    ROOT / "docs",
    ROOT / "site-docs",
    ROOT / "deploy",
    ROOT / "integrations",
)

_BINARY_SUFFIXES = {
    ".gif", ".png", ".jpg", ".jpeg", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".gz",
}
_EXCLUDE_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__"}


class ManagedPattern(NamedTuple):
    """A version-bearing reference whose semver must equal the canonical version.

    Group 1 captures the literal prefix; group 2 captures the semver.
    """

    label: str
    regex: re.Pattern[str]


MANAGED_PATTERNS: tuple[ManagedPattern, ...] = (
    ManagedPattern(
        "published image pin",
        re.compile(r"(agentbom/agent-bom(?:-[a-z]+)?:)(\d+\.\d+\.\d+)"),
    ),
    ManagedPattern(
        "GitHub Action ref",
        re.compile(r"(msaad00/agent-bom@v)(\d+\.\d+\.\d+)"),
    ),
)

# Hosted-demo composes that must ALWAYS run ``:latest`` (redeployed on every
# release), so they can never be silently frozen on a stale semver pin. Each
# entry: (path relative to ROOT, literal image ref that must be present).
LATEST_REQUIRED: tuple[tuple[str, str], ...] = (
    ("deploy/docker-compose.platform.yml", "image: agent-bom:latest"),
)


def canonical_version() -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(), re.M)
    if not match:
        raise SystemExit("pyproject.toml version not found")
    return match.group(1)


def _iter_files() -> Iterator[Path]:
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        if root.is_file():
            yield root
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            if any(part in _EXCLUDE_DIRS for part in path.parts):
                continue
            if path.suffix.lower() in _BINARY_SUFFIXES:
                continue
            yield path


def scan_text(rel_path: str, text: str, version: str) -> list[str]:
    """Return one drift line per managed reference in *text* that != *version*."""
    drift: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for managed in MANAGED_PATTERNS:
            for match in managed.regex.finditer(line):
                found = match.group(2)
                if found != version:
                    drift.append(
                        f"{rel_path}:{lineno}: {managed.label} pinned to "
                        f"{found} (expected {version}) -> {line.strip()}"
                    )
    return drift


def find_drift(version: str) -> list[str]:
    """Return every version-alignment violation across the shipping surfaces."""
    drift: list[str] = []
    for path in _iter_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        drift.extend(scan_text(_rel(path), text, version))

    for rel, needle in LATEST_REQUIRED:
        path = ROOT / rel
        if not path.exists():
            drift.append(f"{rel}: hosted-demo compose missing (expected '{needle}')")
        elif needle not in path.read_text(encoding="utf-8", errors="ignore"):
            drift.append(
                f"{rel}: hosted-demo runtime must stay ':latest' "
                f"('{needle}' not found) — do not pin the always-redeployed demo"
            )
    return sorted(drift)


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def rewrite(version: str) -> tuple[int, list[Path]]:
    """Rewrite every managed reference to *version*. Returns (count, changed)."""
    total = 0
    changed: list[Path] = []
    for path in _iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        new_text = text
        file_hits = 0
        for managed in MANAGED_PATTERNS:
            new_text, count = managed.regex.subn(rf"\g<1>{version}", new_text)
            file_hits += count
        if file_hits and new_text != text:
            path.write_text(new_text, encoding="utf-8")
            total += file_hits
            changed.append(path)
    return total, changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify or fix version alignment")
    parser.add_argument(
        "--fix",
        metavar="VERSION",
        help="Rewrite every managed reference to VERSION instead of checking",
    )
    args = parser.parse_args(argv)

    if args.fix:
        if not re.match(r"^\d+\.\d+\.\d+$", args.fix):
            print(f"ERROR: invalid semver: {args.fix}", file=sys.stderr)
            return 1
        count, changed = rewrite(args.fix)
        for path in changed:
            print(f"  UPDATED: {_rel(path)}")
        print(f"Rewrote {count} managed reference(s) across {len(changed)} file(s)")
        return 0

    version = canonical_version()
    drift = find_drift(version)
    if drift:
        print(f"ERROR: version drift from canonical {version}:", file=sys.stderr)
        for line in drift:
            print(f"  {line}")
        print(
            f"\n{len(drift)} drifted reference(s). "
            f"Fix with: python scripts/check_version_alignment.py --fix {version}",
            file=sys.stderr,
        )
        return 1
    print(f"Version alignment OK: every managed reference == {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
