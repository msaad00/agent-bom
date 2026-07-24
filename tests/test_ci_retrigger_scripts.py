"""Regression tests for PR check recovery scripts."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

CANCEL_HELPER = ROOT / "scripts" / "cancel_superseded_run.sh"


def _gh_stub(tmp_path: Path, body: str) -> Path:
    """Install a fake `gh` on PATH and return the directory holding it."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "gh"
    stub.write_text(body, encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return bin_dir


def _run_cancel_helper(bin_dir: Path) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    env["CANCEL_POLL_SECONDS"] = "0"
    return subprocess.run(
        ["bash", str(CANCEL_HELPER), "owner/repo", "12345"],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )


def test_dispatch_required_ci_runs_all_required_workflows() -> None:
    script = (ROOT / "scripts" / "dispatch_required_ci.sh").read_text(encoding="utf-8")

    assert 'gh workflow run ci.yml --repo "${REPO}" --ref "${head_ref}"' in script
    assert 'gh workflow run pr-security-gate.yml --repo "${REPO}" --ref "${head_ref}"' in script
    assert 'gh workflow run codeql.yml --repo "${REPO}" --ref "${head_ref}"' in script


def test_recovery_scripts_guard_queued_workflows_by_head_sha() -> None:
    dispatch = (ROOT / "scripts" / "dispatch_required_ci.sh").read_text(encoding="utf-8")
    retrigger = (ROOT / "scripts" / "retrigger_stranded_pr.sh").read_text(encoding="utf-8")

    for script, sha in ((dispatch, "head_sha"), (retrigger, "HEAD_SHA")):
        assert f"actions/runs?head_sha=${{{sha}}}" in script
        assert ".status != \"completed\"" in script
        assert "not dispatching a duplicate" in script or "not retriggering" in script


def test_recovery_scripts_cancel_only_superseded_required_runs_on_branch() -> None:
    dispatch = (ROOT / "scripts" / "dispatch_required_ci.sh").read_text(encoding="utf-8")
    retrigger = (ROOT / "scripts" / "retrigger_stranded_pr.sh").read_text(encoding="utf-8")

    for script in (dispatch, retrigger):
        assert 'actions/runs"' in script
        assert '-f branch=' in script
        assert '.head_sha != $current_sha' in script
        assert "cancel_superseded_run.sh" in script
        assert '"CI/CD Pipeline" or .name == "PR Security Gate" or .name == "CodeQL"' in script


def test_force_cancel_helper_has_bounded_grace_and_race_safe_fallback() -> None:
    helper = CANCEL_HELPER.read_text(encoding="utf-8")

    assert "for attempt in 1 2 3 4 5" in helper
    assert 'gh run cancel "${RUN_ID}"' in helper
    assert 'actions/runs/${RUN_ID}/force-cancel' in helper
    assert helper.count('if [ "${status}" = "completed" ]') == 3


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")
def test_cancel_helper_treats_already_completed_run_as_success(tmp_path: Path) -> None:
    """A run that finishes between listing and cancel is the desired end state.

    GitHub rejects `gh run cancel` on a completed run ("Cannot cancel a workflow
    run that is completed"). Under `set -e` that aborted the whole stranded-PR
    recovery step, which is how the recovery workflow went red on an otherwise
    healthy PR.
    """
    bin_dir = _gh_stub(
        tmp_path,
        """#!/usr/bin/env bash
if [ "$1 $2" = "run cancel" ]; then
  echo "Cannot cancel a workflow run that is completed" >&2
  exit 1
fi
if [ "$1 $2" = "run view" ]; then
  echo completed
  exit 0
fi
echo "unexpected gh invocation: $*" >&2
exit 70
""",
    )

    result = _run_cancel_helper(bin_dir)

    assert result.returncode == 0, result.stderr
    assert "force-cancel" not in result.stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")
def test_cancel_helper_still_fails_when_run_stays_active(tmp_path: Path) -> None:
    """A rejected cancel on a still-running workflow must not be swallowed."""
    bin_dir = _gh_stub(
        tmp_path,
        """#!/usr/bin/env bash
if [ "$1 $2" = "run cancel" ]; then
  echo "HTTP 409" >&2
  exit 1
fi
if [ "$1 $2" = "run view" ]; then
  echo in_progress
  exit 0
fi
if [ "$1" = "api" ]; then
  echo "HTTP 403" >&2
  exit 1
fi
echo "unexpected gh invocation: $*" >&2
exit 70
""",
    )

    result = _run_cancel_helper(bin_dir)

    assert result.returncode == 1
    assert "failed to cancel superseded workflow run 12345" in result.stderr


def test_recovery_required_checks_match_branch_protection() -> None:
    canonical = "Lint and Type Check,Test (Python 3.13),Build Package,Security Scan,CodeQL"
    paths = (
        ROOT / "scripts" / "dispatch_required_ci.sh",
        ROOT / "scripts" / "retrigger_stranded_pr.sh",
        ROOT / ".github" / "workflows" / "auto-retrigger-stranded.yml",
    )

    for path in paths:
        text = path.read_text(encoding="utf-8")
        assert canonical in text
        assert "Test (Python 3.11)" not in text
        assert "Test (Python 3.14)" not in text


def test_ci_runbook_documents_fallback_workflows() -> None:
    runbook = (ROOT / "docs" / "operations" / "CI_RUNBOOK.md").read_text(encoding="utf-8")

    assert "`ci.yml`" in runbook
    assert "`pr-security-gate.yml`" in runbook
    assert "`codeql.yml`" in runbook
