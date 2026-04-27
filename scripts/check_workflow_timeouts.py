#!/usr/bin/env python3
"""Fail when any GitHub workflow job is missing ``timeout-minutes``.

Closes the audit-4 P1 finding that #1995 only covered release.yml +
post-merge + container-rescan; the rest of ``.github/workflows/`` still
had jobs that could run unbounded and hold scarce runners. This gate
walks every workflow and lists every job whose top-level mapping is
missing ``timeout-minutes``. Reusable workflow callers (``uses:``) are
exempt because the timeout lives in the called workflow, not the caller.

Usage:
    python scripts/check_workflow_timeouts.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = ROOT / ".github" / "workflows"


def _is_reusable_caller(job: dict[str, Any]) -> bool:
    """A job that uses a reusable workflow has its timeout in the callee."""
    return isinstance(job.get("uses"), str)


def _collect_problems() -> list[str]:
    problems: list[str] = []
    for path in sorted(WORKFLOWS_DIR.glob("*.yml")):
        # Skip macOS Finder duplicates ("filename 2.yml") — these are not
        # actual workflows and the audit-2 hygiene PR already gates them
        # at the artifact level.
        if " " in path.name:
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            problems.append(f"{path.relative_to(ROOT)}: yaml parse error: {exc}")
            continue
        if not isinstance(doc, dict):
            continue
        jobs = doc.get("jobs") or {}
        if not isinstance(jobs, dict):
            continue
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            if _is_reusable_caller(job):
                continue
            if "timeout-minutes" not in job:
                problems.append(f"{path.relative_to(ROOT)}: job '{job_name}' has no timeout-minutes")
    return problems


def main() -> int:
    if not WORKFLOWS_DIR.is_dir():
        print(f"ERROR: workflows directory not found: {WORKFLOWS_DIR}", file=sys.stderr)
        return 1
    problems = _collect_problems()
    if problems:
        print("Workflow jobs missing timeout-minutes:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "Every job must declare timeout-minutes so a stuck job cannot hold a runner. "
            "Pick a reasonable bound (CI tests 30m, release/build 45m, scheduled cron 60m).",
            file=sys.stderr,
        )
        return 1
    print(f"OK: every job in {WORKFLOWS_DIR.relative_to(ROOT)} declares timeout-minutes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
