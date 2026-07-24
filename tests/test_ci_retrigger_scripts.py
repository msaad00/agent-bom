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
        assert "cancel_superseded_run.sh" in script
        assert '"CI/CD Pipeline" or .name == "PR Security Gate" or .name == "CodeQL"' in script


def test_force_cancel_helper_has_bounded_grace_and_race_safe_fallback() -> None:
    helper = (ROOT / "scripts" / "cancel_superseded_run.sh").read_text(encoding="utf-8")

    assert "for attempt in 1 2 3 4 5" in helper
    assert 'gh run cancel "${RUN_ID}"' in helper
    assert 'actions/runs/${RUN_ID}/force-cancel' in helper
    assert helper.count('if [ "${status}" = "completed" ]') == 2


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
