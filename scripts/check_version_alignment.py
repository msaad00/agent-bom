#!/usr/bin/env python3
"""Structural version-alignment gate for agent-bom release surfaces.

Two versions are in play:

* the SOURCE version (``pyproject.toml``) — what this tree builds. ``main`` is
  prepped as the next release before that release is tagged.
* the PUBLISHED version (``PUBLISHED_VERSION``) — the latest release whose tag,
  images, chart and PyPI package actually exist.

Copy-paste surfaces a user runs against a registry — GitHub Action refs
(``msaad00/agent-bom@vX``), pull-only image pins (``agentbom/agent-bom*:X``),
consumer pre-commit ``rev: vX`` and "Latest release" lines — must name the
PUBLISHED version, or a user following ``main``'s docs gets a 404. Image pins in
compose files that build that image from this tree (``SOURCE_BUILT``) name the
SOURCE version, because there the tag labels the local build.

This gate walks whole shipping-surface *trees*, so a NEW file that introduces a
managed reference is covered automatically. The release run advances
``PUBLISHED_VERSION`` only after publishing (``bump-version.py --published``).

Usage::

    python scripts/check_version_alignment.py            # verify, exit 1 on drift
    python scripts/check_version_alignment.py --fix 0.97.1   # rewrite every ref

``scripts/`` and ``tests/`` are deliberately NOT scanned: they carry these
patterns as guard literals / fixtures with intentionally-stale versions.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterator, NamedTuple

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
PUBLISHED_VERSION_FILE = ROOT / "PUBLISHED_VERSION"

# Surfaces that ship to users, so any pinned ref inside them must be aligned.
# Directories are scanned recursively; individual files are scanned as-is.
SCAN_ROOTS: tuple[Path, ...] = (
    ROOT / "README.md",
    ROOT / ".pre-commit-hooks.yaml",
    ROOT / "PYPI_README.md",
    ROOT / "DOCKER_HUB_README.md",
    ROOT / "docs",
    ROOT / "site-docs",
    ROOT / "deploy",
    ROOT / "integrations",
)

_BINARY_SUFFIXES = {
    ".gif",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".pdf",
    ".zip",
    ".gz",
}
_EXCLUDE_DIRS = {"node_modules", ".git", ".next", "dist", "build", "__pycache__"}


class ManagedPattern(NamedTuple):
    """A version-bearing reference. Group 1 is the literal prefix; group 2 the semver.

    ``tracks`` is ``"published"`` (must name a release that exists) or
    ``"image"`` (published, unless the file builds the image from source).
    """

    label: str
    regex: re.Pattern[str]
    tracks: str


MANAGED_PATTERNS: tuple[ManagedPattern, ...] = (
    ManagedPattern(
        "published image pin",
        re.compile(r"(agentbom/agent-bom(?:-[a-z]+)?:)(\d+\.\d+\.\d+)"),
        "image",
    ),
    ManagedPattern(
        "GitHub Action ref",
        re.compile(r"(msaad00/agent-bom@v)(\d+\.\d+\.\d+)"),
        "published",
    ),
    ManagedPattern(
        "consumer pre-commit rev",
        re.compile(r"(repo: https://github\.com/msaad00/agent-bom\n[#\s]*rev:[ \t]+v)(\d+\.\d+\.\d+)"),
        "published",
    ),
    ManagedPattern(
        "latest release line",
        re.compile(r"(Latest release: \*\*v)(\d+\.\d+\.\d+)"),
        "published",
    ),
)

# Compose files whose every pinned service builds its image from this tree, so
# the tag labels the local build and tracks the SOURCE version. Everything else
# (pull-only compose, k8s manifests, docs) pulls from a registry and must name
# the PUBLISHED version. tests/test_version_alignment.py keeps this list honest
# against the compose files themselves.
SOURCE_BUILT: dict[str, str] = {
    "deploy/docker-compose.fullstack.yml": "developer stack; every pinned service has a build: from this repo",
    "deploy/docker-compose.platform.yml": "UI service has a build: from ../ui; the API builds agent-bom:latest",
    "deploy/docker-compose.runtime-example.yml": "runtime proxy has a build: from Dockerfile.runtime",
}

# Hosted-demo composes that must ALWAYS run ``:latest`` (redeployed on every
# release), so they can never be silently frozen on a stale semver pin. Each
# entry: (path relative to ROOT, literal image ref that must be present).
LATEST_REQUIRED: tuple[tuple[str, str], ...] = (("deploy/docker-compose.platform.yml", "image: agent-bom:latest"),)


def canonical_version() -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(), re.M)
    if not match:
        raise SystemExit("pyproject.toml version not found")
    return match.group(1)


def published_version() -> str:
    """Return the latest release that actually exists (tag, images, chart, PyPI)."""
    value = PUBLISHED_VERSION_FILE.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", value):
        raise SystemExit(f"{PUBLISHED_VERSION_FILE.name} must hold one X.Y.Z version, got {value!r}")
    return value


def parse_semver(value: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in value.split("."))
    return major, minor, patch


def _release_tags() -> set[str]:
    """Local ``vX.Y.Z`` tags; empty when git or tags are unavailable (shallow CI)."""
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "tag", "--list", "v[0-9]*"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    if result.returncode != 0:
        return set()
    return {tag for tag in (line.strip() for line in result.stdout.splitlines()) if re.fullmatch(r"v\d+\.\d+\.\d+", tag)}


def expected_version(rel_path: str, tracks: str, version: str, published: str) -> str:
    """Return the version a managed reference in *rel_path* must carry."""
    if tracks == "image" and rel_path in SOURCE_BUILT:
        return version
    return published


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


def scan_text(rel_path: str, text: str, version: str, *, published: str | None = None) -> list[str]:
    """Return one drift line per managed reference in *text* that is misaligned."""
    published = version if published is None else published
    drift: list[str] = []
    lines = text.splitlines()
    for managed in MANAGED_PATTERNS:
        want = expected_version(rel_path, managed.tracks, version, published)
        for match in managed.regex.finditer(text):
            found = match.group(2)
            if found == want:
                continue
            lineno = text.count("\n", 0, match.start(2)) + 1
            line = lines[lineno - 1].strip() if lineno <= len(lines) else ""
            drift.append(f"{rel_path}:{lineno}: {managed.label} pinned to {found} (expected {want}) -> {line}")
    return drift


def find_drift(version: str, *, published: str | None = None) -> list[str]:
    """Return every version-alignment violation across the shipping surfaces."""
    published = version if published is None else published
    drift: list[str] = []
    if parse_semver(published) > parse_semver(version):
        drift.append(f"{PUBLISHED_VERSION_FILE.name}: published version {published} is ahead of the source version {version}")
    tags = _release_tags()
    if tags and f"v{published}" not in tags:
        drift.append(
            f"{PUBLISHED_VERSION_FILE.name}: published version {published} has no v{published} release tag — "
            "advance it only after the release is published"
        )
    for path in _iter_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        drift.extend(scan_text(_rel(path), text, version, published=published))

    for rel, needle in LATEST_REQUIRED:
        path = ROOT / rel
        if not path.exists():
            drift.append(f"{rel}: hosted-demo compose missing (expected '{needle}')")
        elif needle not in path.read_text(encoding="utf-8", errors="ignore"):
            drift.append(f"{rel}: hosted-demo runtime must stay ':latest' ('{needle}' not found) — do not pin the always-redeployed demo")
    return sorted(drift)


def _rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def rewrite(version: str, *, published: str | None = None) -> tuple[int, list[Path]]:
    """Rewrite every managed reference to its expected version. Returns (count, changed)."""
    published = version if published is None else published
    total = 0
    changed: list[Path] = []
    for path in _iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = _rel(path)
        new_text = text
        file_hits = 0
        for managed in MANAGED_PATTERNS:
            want = expected_version(rel, managed.tracks, version, published)
            new_text, count = managed.regex.subn(rf"\g<1>{want}", new_text)
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
        help="Rewrite source-built refs to VERSION and copy-paste refs to PUBLISHED_VERSION instead of checking",
    )
    args = parser.parse_args(argv)

    if args.fix:
        if not re.match(r"^\d+\.\d+\.\d+$", args.fix):
            print(f"ERROR: invalid semver: {args.fix}", file=sys.stderr)
            return 1
        count, changed = rewrite(args.fix, published=published_version())
        for path in changed:
            print(f"  UPDATED: {_rel(path)}")
        print(f"Rewrote {count} managed reference(s) across {len(changed)} file(s)")
        return 0

    version = canonical_version()
    published = published_version()
    drift = find_drift(version, published=published)
    if drift:
        print(f"ERROR: version drift (source {version}, published {published}):", file=sys.stderr)
        for line in drift:
            print(f"  {line}")
        print(
            f"\n{len(drift)} drifted reference(s). Fix with: python scripts/check_version_alignment.py --fix {version}",
            file=sys.stderr,
        )
        return 1
    print(f"Version alignment OK: copy-paste refs == published {published}; source-built image pins == {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
