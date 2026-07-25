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


def test_main_ui_smoke_covers_every_ui_classifier_surface() -> None:
    """The main-push smoke must mirror paths that make PR UI validation run."""
    workflow = (ROOT / ".github" / "workflows" / "main-ui-smoke.yml").read_text(
        encoding="utf-8"
    )
    for path in (
        '"ui/**"',
        '"action.yml"',
        '"contracts/**"',
        '"src/agent_bom/api/**"',
        '"src/agent_bom/graph/**"',
        '"src/agent_bom/context_graph.py"',
        '"src/agent_bom/graph_schema.py"',
        '"src/agent_bom/models.py"',
    ):
        assert path in workflow


def test_path_gated_jobs_fail_closed_when_classifier_fails() -> None:
    jobs = _ci()["jobs"]
    for name in ("docs-strict", "ui", "endpoint-packaging", "postgres-integration", "test-alpine", "action-dogfood"):
        condition = jobs[name]["if"]
        assert "needs.changes.result != 'success'" in condition


def test_path_gated_jobs_remain_cancellable() -> None:
    jobs = _ci()["jobs"]
    for name in (
        "docs-strict",
        "ui",
        "endpoint-packaging",
        "test",
        "sdk-import-smoke",
        "postgres-integration",
        "test-alpine",
        "action-dogfood",
    ):
        condition = jobs[name]["if"]
        assert "!cancelled()" in condition
        assert "always()" not in condition


def test_test_job_timeout_leaves_margin_over_observed_worst_case() -> None:
    """25 minutes keeps ~40% headroom over the ~17.6 min worst case seen on main.

    A 35-minute ceiling let a hung suite burn a runner for another quarter hour
    before anyone saw it.
    """
    assert _ci()["jobs"]["test"]["timeout-minutes"] == 25


def test_alpine_full_suite_timeout_leaves_musl_headroom() -> None:
    """Full-suite Alpine runs must outlive the observed 25-minute ceiling."""
    assert _ci()["jobs"]["test-alpine"]["timeout-minutes"] == 35


def test_pull_request_pytest_reports_slowest_tests() -> None:
    """PR runs surface the slowest tests so timeout regressions have evidence."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    run_tests = text.split("      - name: Run tests", 1)[1].split(
        "      - name: Graph accuracy fixture guard", 1
    )[0]

    pytest_lines = [line.strip() for line in run_tests.splitlines() if "uv run pytest tests/" in line]
    assert len(pytest_lines) == 2
    assert all("--durations=25" in line for line in pytest_lines)
    coverage_line = next(line for line in pytest_lines if "--cov=agent_bom" in line)
    assert "--cov-fail-under=75" in coverage_line


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


def test_self_scan_upload_filters_first_party_informational_skill_rows() -> None:
    pr_gate = (ROOT / ".github" / "workflows" / "pr-security-gate.yml").read_text(encoding="utf-8")
    post_merge = (ROOT / ".github" / "workflows" / "post-merge-self-scan.yml").read_text(encoding="utf-8")
    assert "filter_first_party_skill_sarif.py" in pr_gate
    assert "filter_first_party_skill_sarif.py" in post_merge
