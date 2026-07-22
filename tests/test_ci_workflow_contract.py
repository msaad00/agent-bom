"""Regression guards for CI path gating and duplicate-work prevention."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _ci() -> dict[str, object]:
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))


def test_path_classifier_covers_main_pushes() -> None:
    workflow = _ci()
    on = workflow.get(True, workflow.get("on", {}))
    assert isinstance(on, dict)
    assert "push" in on

    changes = workflow["jobs"]["changes"]
    assert "github.event_name == 'pull_request' || github.event_name == 'push'" in changes["if"]
    classify = next(step for step in changes["steps"] if step.get("id") == "classify")
    script = classify["run"]
    assert "github.event.before" in script
    assert "git diff-tree --no-commit-id" in script


def test_path_gated_jobs_fail_closed_when_classifier_fails() -> None:
    jobs = _ci()["jobs"]
    for name in ("docs-strict", "ui", "endpoint-packaging", "postgres-integration", "test-alpine", "action-dogfood"):
        condition = jobs[name]["if"]
        assert "needs.changes.result != 'success'" in condition


def test_security_reuses_typescript_install_for_build() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    security = text.split("  # 2. Linting + Type Checking", 1)[0]
    assert security.count("npm ci --ignore-scripts") == 2
    assert "The preceding SDK audit step installed this exact lockfile" in security


def test_graph_guard_does_not_rerun_full_graph_tests() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    guard = text.split("      - name: Graph accuracy fixture guard", 1)[1].split(
        "      - name: DCM scanner self-check", 1
    )[0]
    assert "pytest" not in guard
    assert "rebaseline_graph_edges.py --dry-run" in guard


def test_stranded_ci_recovery_runs_on_pr_synchronize() -> None:
    workflow = (ROOT / ".github" / "workflows" / "auto-retrigger-stranded.yml").read_text(
        encoding="utf-8"
    )
    assert "  pull_request:" in workflow
    assert "    types: [synchronize]" in workflow
    assert "scripts/dispatch_required_ci.sh" in workflow
    assert "scripts/retrigger_stranded_pr.sh" in workflow
    assert "github.event.pull_request.number" in workflow
    assert "github.event_name == 'pull_request' && '0' || '3'" in workflow
