#!/usr/bin/env python3
"""Refuse a release version that has already shipped.

On 2026-08-10 ``scripts/preflight_release.sh 0.99.0`` printed
**"Pre-flight OK — safe to tag"**. ``v0.99.0`` had been tagged five days
earlier and was already live on PyPI, Docker Hub and Glama, with 24 further
commits sitting on ``main``.

Every gate the pre-flight runs was green, and every one of them answers the
same shape of question: *are the managed files consistent with the version
string I was handed?* None of them asked the question that separates a release
from a re-release — *does this tag already exist?* — so the one script
positioned as the release go/no-go could not detect the most consequential
release error there is.

Two checks, both cheap, both otherwise discovered too late:

* **The tag must not exist**, locally or on the remote. Annotated or
  lightweight is irrelevant; a tag is a tag.
* **The CHANGELOG must already carry the heading.** ``release.yml``'s
  version-guard requires ``## [<version>]``, so a tag pushed without one fails
  in CI *after the tag exists*, which is the expensive place to find out.

It also prints how far ``main`` has moved past the newest tag. That number is
what made the 0.99.0 situation obvious once someone looked, so the pre-flight
should say it out loud rather than leave it to be discovered.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

# git must never wait for a human here. Without this, `ls-remote` against a
# private remote blocks on a credential prompt — which is exactly what happened
# in the Alpine CI container: the test suite produced no output for 44 minutes
# and the job hit its timeout with no failing test to point at.
_GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true", "GCM_INTERACTIVE": "never"}
# Generous: a slow network should still answer. Short enough that a wedged
# process fails the check rather than the job.
_GIT_TIMEOUT_S = 30


def _run_git(args: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run git, returning None when it fails, times out, or is absent."""
    try:
        return subprocess.run(["git", *args], capture_output=True, text=True, env=_GIT_ENV, timeout=_GIT_TIMEOUT_S)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _git(*args: str) -> str:
    result = _run_git(list(args))
    return result.stdout.strip() if result is not None and result.returncode == 0 else ""


def _normalize(version: str) -> str:
    """``0.99.0`` and ``v0.99.0`` name the same release."""
    return version[1:] if version.startswith("v") else version


def _local_tags() -> set[str]:
    return {line.strip() for line in _git("tag", "--list").splitlines() if line.strip()}


def _remote_tags() -> tuple[set[str], bool]:
    """Return (tags, reachable).

    Never fatal: an offline pre-flight still checks local tags. But it must not
    report the *failure* as "no tags there" — a silently empty answer reads
    exactly like a clean one, which is how a shipped version can look new. The
    caller says so out loud instead.
    """
    result = _run_git(["ls-remote", "--tags", "origin"])
    if result is None or result.returncode != 0:
        return set(), False
    return {
        ref.split("refs/tags/", 1)[1].removesuffix("^{}") for line in result.stdout.splitlines() if "refs/tags/" in line for ref in [line]
    }, True


def _commits_since_newest_tag() -> tuple[str, int]:
    newest = _git("describe", "--tags", "--abbrev=0")
    if not newest:
        return "", 0
    count = _git("rev-list", "--count", f"{newest}..HEAD")
    return newest, int(count) if count.isdigit() else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="the version you intend to tag, e.g. 0.99.1")
    parser.add_argument(
        "--changelog",
        default="CHANGELOG.md",
        help="path to the changelog that must already carry the heading",
    )
    args = parser.parse_args()

    version = _normalize(args.version)
    tag = f"v{version}"
    problems: list[str] = []

    local = _local_tags()
    remote, remote_reachable = _remote_tags()
    existing = local | remote
    if not remote_reachable:
        print(
            "WARNING: could not reach 'origin' to list tags; this check saw only the "
            f"{len(local)} local tag(s). A shallow or tagless checkout can make a "
            "shipped version look new.",
            file=sys.stderr,
        )
    if tag in existing:
        problems.append(
            f"{tag} has ALREADY been tagged. Re-tagging republishes a shipped version.\n"
            f"    Pick the next version instead, and check what has landed since:\n"
            f"      git log --oneline {tag}..HEAD"
        )

    changelog = Path(args.changelog)
    if not changelog.exists():
        problems.append(f"{changelog} not found, so the release notes cannot be checked.")
    elif not re.search(rf"^## \[{re.escape(version)}\]", changelog.read_text(), re.MULTILINE):
        problems.append(
            f"{changelog} has no '## [{version}]' heading.\n"
            f"    release.yml's version-guard requires it, so the tag would fail in CI\n"
            f"    after it already exists. Move the [Unreleased] entries under it."
        )

    newest, ahead = _commits_since_newest_tag()
    if newest:
        print(f"newest tag: {newest} · main is {ahead} commit{'' if ahead == 1 else 's'} ahead")

    if problems:
        print("\nRELEASE TAG CHECK FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"OK: {tag} is new and {changelog} documents it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
