"""Regression tests for PR check recovery scripts."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
        assert 'gh run cancel "${' in script
        assert '"CI/CD Pipeline" or .name == "PR Security Gate" or .name == "CodeQL"' in script


def test_ci_runbook_documents_fallback_workflows() -> None:
    runbook = (ROOT / "docs" / "operations" / "CI_RUNBOOK.md").read_text(encoding="utf-8")

    assert "`ci.yml`" in runbook
    assert "`pr-security-gate.yml`" in runbook
    assert "`codeql.yml`" in runbook
