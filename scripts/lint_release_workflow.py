#!/usr/bin/env python3
"""Static pre-flight linter for the release workflow call-graph.

Catches the two startup-failure classes that GitHub reports with no logs and
that ``actionlint`` does not model:

1. **Undeclared ``needs`` references** — a job referencing
   ``needs.<other>.outputs.*`` without listing ``<other>`` in its ``needs``.
   (actionlint also catches this; we keep it as a backstop.)

2. **Reusable-workflow permission under-grant** — a job that calls a reusable
   workflow (``uses: ./.github/workflows/X.yml``) whose *effective* granted
   ``GITHUB_TOKEN`` permissions (its own ``permissions:`` block, else the
   workflow's top-level default) are *less* than the union of permissions the
   called workflow's jobs request. GitHub forbids a reusable workflow from
   requesting more than its caller holds and aborts the whole run at startup.

Run before tagging a release. Exits non-zero with a precise message on any
violation so a bad release.yml never reaches a tag push.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WF_DIR = ROOT / ".github" / "workflows"

# GitHub token permission levels, ordered. "none" < "read" < "write".
_LEVEL = {"none": 0, "read": 1, "write": 2}
# Scopes that GitHub recognises for GITHUB_TOKEN.
_SCOPES = {
    "actions",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "id-token",
    "issues",
    "models",
    "packages",
    "pages",
    "pull-requests",
    "repository-projects",
    "security-events",
    "statuses",
}


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text()) or {}


def _on(doc: dict[str, Any]) -> Any:
    # PyYAML parses the bare ``on:`` key as the boolean True.
    return doc.get("on", doc.get(True))


def _perms_map(perms: Any) -> dict[str, int]:
    """Normalise a ``permissions:`` value to {scope: level-int}.

    A missing block means GitHub's default; for our deny-all release workflow
    the top-level is ``{}`` so we treat *absent at top level* conservatively as
    the caller's responsibility (handled by the caller resolution below).
    ``read-all`` / ``write-all`` strings expand to every scope.
    """
    if perms is None:
        return {}
    if isinstance(perms, str):
        lvl = "read" if perms == "read-all" else "write" if perms == "write-all" else None
        return {s: _LEVEL[lvl] for s in _SCOPES} if lvl else {}
    out: dict[str, int] = {}
    for scope, level in (perms or {}).items():
        if level in _LEVEL:
            out[scope] = _LEVEL[level]
    return out


def _requested_by_callee(callee: dict[str, Any]) -> dict[str, int]:
    """Union of permissions the callee's jobs request (job-level, else top)."""
    top = _perms_map(callee.get("permissions"))
    union = dict(top)
    for job in (callee.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        jp = _perms_map(job.get("permissions")) if "permissions" in job else top
        for scope, lvl in jp.items():
            union[scope] = max(union.get(scope, 0), lvl)
    return union


def check_workflow(path: Path) -> list[str]:
    doc = _load(path)
    jobs = doc.get("jobs") or {}
    top_perms = _perms_map(doc.get("permissions"))
    has_top_perms = "permissions" in doc
    errors: list[str] = []

    job_ids = set(jobs)
    for jid, job in jobs.items():
        if not isinstance(job, dict):
            continue

        # (1) undeclared needs references
        declared = job.get("needs") or []
        if isinstance(declared, str):
            declared = [declared]
        declared_set = set(declared)
        blob = yaml.safe_dump(job)
        for other in job_ids:
            token = f"needs.{other}."
            if token in blob and other not in declared_set:
                errors.append(f"{path.name}: job '{jid}' references {token}* but does not declare '{other}' in its needs:")

        # (2) reusable-workflow permission parity
        uses = job.get("uses")
        if isinstance(uses, str) and uses.startswith("./.github/workflows/"):
            callee_path = ROOT / uses.removeprefix("./")
            if not callee_path.exists():
                errors.append(f"{path.name}: job '{jid}' uses missing workflow {uses}")
                continue
            # Effective grant: job-level permissions if present, else top-level.
            if "permissions" in job:
                granted = _perms_map(job.get("permissions"))
            elif has_top_perms:
                granted = dict(top_perms)
            else:
                granted = None  # inherits repo default; cannot statically prove
            requested = _requested_by_callee(_load(callee_path))
            if granted is None:
                continue
            for scope, need in requested.items():
                have = granted.get(scope, 0)
                if have < need:
                    want = [k for k, v in _LEVEL.items() if v == need][0]
                    got = [k for k, v in _LEVEL.items() if v == have][0]
                    errors.append(
                        f"{path.name}: job '{jid}' calls {uses} which requests "
                        f"'{scope}: {want}', but the job is only granted "
                        f"'{scope}: {got}'. A reusable workflow cannot request "
                        f"more than its caller. Add 'permissions: {{{scope}: {want}}}' "
                        f"to job '{jid}' (top-level default is deny-all)."
                    )
    return errors


def main(argv: list[str]) -> int:
    targets = [Path(a) for a in argv[1:]] or [WF_DIR / "release.yml"]
    all_errors: list[str] = []
    for t in targets:
        all_errors.extend(check_workflow(t))
    if all_errors:
        print("Release workflow lint FAILED:\n")
        for e in all_errors:
            print(f"  ✗ {e}\n")
        return 1
    print(f"Release workflow lint OK ({', '.join(t.name for t in targets)}).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
