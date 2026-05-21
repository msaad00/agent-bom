"""Regression tests for PR check recovery scripts."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dispatch_required_ci_runs_all_required_workflows() -> None:
    script = (ROOT / "scripts" / "dispatch_required_ci.sh").read_text(encoding="utf-8")

    assert 'gh workflow run ci.yml --repo "${REPO}" --ref "${head_ref}"' in script
    assert 'gh workflow run pr-security-gate.yml --repo "${REPO}" --ref "${head_ref}"' in script
    assert 'gh workflow run codeql.yml --repo "${REPO}" --ref "${head_ref}"' in script


def test_ci_runbook_documents_fallback_workflows() -> None:
    runbook = (ROOT / "docs" / "operations" / "CI_RUNBOOK.md").read_text(encoding="utf-8")

    assert "`ci.yml`" in runbook
    assert "`pr-security-gate.yml`" in runbook
    assert "`codeql.yml`" in runbook
