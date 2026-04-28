#!/usr/bin/env python3
"""Enforce the Docker base-image policy across every Dockerfile in the repo.

Closes #1961 (the policy gate piece). The audit found three real drift
problems this script prevents from recurring:

1. ui/Dockerfile drifted to ``node:25-slim`` while ui/package.json's
   ``engines.node`` insisted on ``>=20 <23``. The policy table below pins
   the major version that the Dockerfile is allowed to reference; if the
   two ever disagree again, this script fails.
2. integrations/glama/Dockerfile carried a comment claiming "pinned to same
   digest as main Dockerfile" while in fact using a different base image
   and a different digest. The policy table now records the deliberate
   divergence (Debian slim vs Alpine) so the comment cannot lie again.
3. Every FROM line in every Dockerfile must include an immutable
   ``@sha256:...`` digest pin so dependabot can take responsibility for the
   bump cadence and supply-chain provenance stays signed. A short
   ``# pending-digest`` marker is allowed for at most the duration of a
   transitional PR — dependabot's daily docker job replaces it.

Usage:
    python scripts/check_docker_base_policy.py
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FROM_RE = re.compile(r"^\s*FROM\s+(?P<image>\S+)(?:\s+AS\s+\S+)?\s*$", re.IGNORECASE)
DIGEST_RE = re.compile(r"@sha256:[a-f0-9]{64}$")

# A `# pending-digest` marker is a transitional escape hatch: dependabot's
# daily docker job is supposed to replace it within 24h. Anything older
# than this window is the marker overstaying its purpose, which is what
# the audit-3 finding flagged. Override via `PENDING_DIGEST_MAX_AGE_SECONDS`
# for one-off bootstraps where dependabot needs a longer cycle.
_PENDING_DIGEST_DEFAULT_MAX_AGE_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class BasePolicy:
    image: str
    """Image repository, e.g. ``node`` or ``python``."""

    expected_tags: tuple[str, ...]
    """Acceptable tag prefixes; the FROM tag must equal one of these or
    start with one followed by ``-`` (so ``22`` matches ``22-bookworm-slim``)."""

    rationale: str
    """One-line operator-facing explanation of why this Dockerfile uses this
    base. Surfaced in error messages so reviewers don't have to dig."""


# Per-Dockerfile policy. Add entries here when a new Dockerfile lands.
# An empty `expected_tags` tuple means the image is identified by digest
# alone (no tag); the digest pin is still mandatory.
POLICY: dict[str, BasePolicy] = {
    "Dockerfile": BasePolicy(
        image="python",
        expected_tags=("3.14.3-alpine3.23",),
        rationale="Alpine + Python 3.14 is the canonical scanner runtime; smallest attack surface.",
    ),
    "ui/Dockerfile": BasePolicy(
        image="node",
        expected_tags=("22-bookworm-slim", "22-slim"),
        rationale="Node 22 LTS sits inside ui/package.json engines: '>=20 <23' and is Next 16's recommended production node.",
    ),
    "integrations/glama/Dockerfile": BasePolicy(
        image="python",
        expected_tags=("3.12.13-slim",),
        rationale="Debian slim avoids Alpine musl-incompatibility for cryptography/lxml wheels.",
    ),
    "deploy/docker/Dockerfile.mcp": BasePolicy(
        image="python",
        expected_tags=("3.12.13-slim",),
        rationale="MCP-over-stdio runtime; Debian slim matches glama base for parity.",
    ),
    "deploy/docker/Dockerfile.runtime": BasePolicy(
        image="python",
        expected_tags=("3.12.13-slim",),
        rationale="Generic runtime image; Debian slim chosen for wheel compatibility.",
    ),
    "deploy/docker/Dockerfile.sse": BasePolicy(
        image="python",
        expected_tags=("3.12.13-slim",),
        rationale="MCP-over-SSE runtime; Debian slim matches the rest of deploy/docker/.",
    ),
    "deploy/docker/Dockerfile.snowpark": BasePolicy(
        image="python",
        expected_tags=("3.11.12-slim",),
        rationale="Snowpark requires Python 3.11; held back from 3.12 for snowflake-snowpark-python compatibility.",
    ),
    ".clusterfuzzlite/Dockerfile": BasePolicy(
        image="gcr.io/oss-fuzz-base/base-builder-python",
        expected_tags=(),
        rationale="OSS-Fuzz upstream base image — controlled by ClusterFuzzLite/dependabot at the digest layer; no tag.",
    ),
}


def _split_image(image: str) -> tuple[str, str | None, str | None]:
    """Return (repository, tag, digest) from a Docker image reference."""
    digest: str | None = None
    if "@sha256:" in image:
        image, _, dg = image.partition("@")
        digest = f"sha256:{dg.split(':', 1)[1]}" if ":" in dg else None
    if ":" in image:
        repo, _, tag = image.rpartition(":")
        return repo, tag, digest
    return image, None, digest


def _find_pending_digest_marker_line(lines: list[str], from_line_idx: int) -> int | None:
    """Return the 1-based line number of the marker, or None if absent.

    Marker lives on the immediately preceding non-blank line as a comment.
    """
    for i in range(from_line_idx - 1, -1, -1):
        stripped = lines[i].strip()
        if not stripped:
            continue
        if stripped.startswith("#") and "pending-digest" in stripped:
            return i + 1
        return None
    return None


def _pending_digest_max_age_seconds() -> int:
    raw = (os.environ.get("PENDING_DIGEST_MAX_AGE_SECONDS") or "").strip()
    if not raw:
        return _PENDING_DIGEST_DEFAULT_MAX_AGE_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return _PENDING_DIGEST_DEFAULT_MAX_AGE_SECONDS
    return max(value, 0)


def _git_blame_commit_timestamp(path: Path, line_number: int) -> int | None:
    """Return the commit Unix timestamp for a given line, or None on failure."""
    try:
        result = subprocess.run(
            ["git", "blame", "--porcelain", "-L", f"{line_number},{line_number}", "--", str(path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    for entry in result.stdout.splitlines():
        if entry.startswith("committer-time "):
            try:
                return int(entry.split(" ", 1)[1].strip())
            except (IndexError, ValueError):
                return None
    return None


def _is_git_tracked_in_repo(path: Path) -> bool:
    """Whether ``path`` lives inside an active git repo and is tracked.

    Used to distinguish "shallow checkout in CI dropped the commit history"
    (gate must fail closed) from "synthetic test fixture or non-git checkout"
    (gate should pass through to the legacy 24h grace semantics — the
    policy was always advisory in non-git contexts).
    """
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H", "--", str(path)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return bool(result.stdout.strip())


def _policy_key(path: Path) -> str | None:
    rel = path.relative_to(ROOT).as_posix()
    return rel if rel in POLICY else None


def _collect_dockerfiles() -> list[Path]:
    skip = {"node_modules", ".venv", ".git", "build", "dist", "site"}
    out: list[Path] = []
    for path in ROOT.rglob("Dockerfile*"):
        if any(part in skip for part in path.parts):
            continue
        if not path.is_file():
            continue
        out.append(path)
    return sorted(out)


def main() -> int:
    problems: list[str] = []
    seen_keys: set[str] = set()

    for path in _collect_dockerfiles():
        rel = path.relative_to(ROOT).as_posix()
        key = _policy_key(path)
        if key is None:
            problems.append(
                f"{rel}: no entry in scripts/check_docker_base_policy.py POLICY. "
                "Add a BasePolicy entry with the expected base image, tag, and rationale."
            )
            continue
        seen_keys.add(key)
        policy = POLICY[key]

        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            match = FROM_RE.match(line)
            if not match:
                continue
            image = match.group("image")
            repo, tag, digest = _split_image(image)
            if repo != policy.image:
                problems.append(
                    f"{rel}:{idx + 1}: FROM image {repo!r} does not match policy {policy.image!r}. Rationale: {policy.rationale}"
                )
                continue
            if policy.expected_tags:
                if tag is None or not any(tag == t or tag.startswith(f"{t}") for t in policy.expected_tags):
                    problems.append(
                        f"{rel}:{idx + 1}: FROM tag {tag!r} not in allowed tags {policy.expected_tags}. Rationale: {policy.rationale}"
                    )
            elif tag is not None:
                problems.append(
                    f"{rel}:{idx + 1}: FROM image carries a tag ({tag!r}) but the policy only allows digest pinning. "
                    f"Rationale: {policy.rationale}"
                )
            if digest is None:
                marker_line = _find_pending_digest_marker_line(lines, idx)
                if marker_line is None:
                    problems.append(
                        f"{rel}:{idx + 1}: FROM line is not digest-pinned (@sha256:...) and no "
                        "`# pending-digest` marker on the preceding line. Either pin the digest "
                        "or add the marker (transitional only — dependabot's daily docker job "
                        "fills it in within 24h)."
                    )
                    continue
                marker_ts = _git_blame_commit_timestamp(path, marker_line)
                max_age = _pending_digest_max_age_seconds()
                if max_age > 0 and marker_ts is None and _is_git_tracked_in_repo(path):
                    # Fail-closed only when the file IS git-tracked but
                    # blame still returns no timestamp. That distinguishes
                    # the bad case (shallow checkout in CI dropped the
                    # commit history → previously skipped the age check
                    # silently → stale markers passed CI) from the benign
                    # cases (synthetic test fixture, uncommitted working-
                    # tree change, non-git checkout). For the bad case
                    # the operator-side fix is `fetch-depth: 0` on the
                    # checkout step that runs this script (see
                    # `.github/workflows/ci.yml` "Lint and Type Check"),
                    # but the script must not depend on that to enforce
                    # the SLA.
                    problems.append(
                        f"{rel}:{marker_line}: `# pending-digest` marker timestamp could not be "
                        "derived (file is git-tracked but blame returned nothing — likely a "
                        "shallow checkout). Re-run with "
                        "`actions/checkout@... with: { fetch-depth: 0 }` so the gate can verify "
                        "the marker is within its 24h SLA, or pin the digest manually."
                    )
                elif marker_ts is not None and max_age > 0:
                    age = int(time.time()) - marker_ts
                    if age > max_age:
                        age_hours = age // 3600
                        max_hours = max_age // 3600
                        problems.append(
                            f"{rel}:{marker_line}: `# pending-digest` marker is {age_hours}h old "
                            f"(policy max {max_hours}h). Dependabot should have replaced it by now — "
                            "either pin the digest manually, retrigger dependabot's docker job, or "
                            "rebump the marker line if the bump was deliberately delayed."
                        )

    missing = sorted(set(POLICY) - seen_keys)
    if missing:
        problems.append("Policy entries reference Dockerfiles that no longer exist on disk: " + ", ".join(missing))

    if problems:
        print("Docker base-image policy violations:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"OK: {len(POLICY)} Dockerfile(s) match the base-image policy.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
