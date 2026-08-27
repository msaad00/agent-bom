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


def test_required_ci_contexts_use_docs_only_fast_paths_without_disappearing() -> None:
    """Branch-protection contexts must report success instead of being path-skipped."""
    jobs = _ci()["jobs"]
    assert "docs_only" in jobs["changes"]["outputs"]

    for name in ("security", "lint", "test", "build"):
        job = jobs[name]
        assert "changes" in job["needs"]
        assert "!cancelled()" in job["if"]

    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "scripts/classify_ci_changes.py" in workflow_text
    assert "Documentation-only safety checks" in workflow_text
    assert "Documentation-only test skip" in workflow_text
    assert "Documentation-only package skip" in workflow_text


def test_non_required_heavy_jobs_are_path_gated() -> None:
    jobs = _ci()["jobs"]
    assert "needs.changes.outputs.helm == 'true'" in jobs["helm-profiles"]["if"]
    assert "needs.changes.result != 'success'" in jobs["helm-profiles"]["if"]


def test_enterprise_demo_contract_is_gated_and_packaged() -> None:
    workflow_text = CI_WORKFLOW.read_text(encoding="utf-8")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    deploy_workflow = (ROOT / ".github" / "workflows" / "demo-deploy-cloudrun.yml").read_text(encoding="utf-8")

    assert "scripts/check_enterprise_demo_surfaces.py" in workflow_text
    assert "scripts/check_enterprise_demo_surfaces.py" in makefile
    assert "agent_bom/demo_estate/data/enterprise_observations.jsonl" in workflow_text
    assert "/v1/demo-estate/story" in deploy_workflow
    assert "/v1/demo-estate/status" in deploy_workflow
    assert 'payload["graph_alignment"] == "aligned"' in deploy_workflow
    assert "rate_limited_after_page_2" in deploy_workflow


def test_dependency_security_skips_only_proven_docs_only_changes() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "pr-security-gate.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    assert "scripts/classify_ci_changes.py" in workflow_path.read_text(encoding="utf-8")
    for name in ("code-scanning-config-pr", "pip-audit-pr", "self-scan-pr"):
        condition = jobs[name]["if"]
        assert "needs.changes.result != 'success'" in condition
        assert "needs.changes.outputs.docs_only != 'true'" in condition


def test_gitleaks_remains_unconditional_for_documentation_changes() -> None:
    workflow = (ROOT / ".github" / "workflows" / "gitleaks.yml").read_text(encoding="utf-8")
    assert "classify_ci_changes.py" not in workflow
    assert "paths-ignore" not in workflow


def test_main_ui_smoke_covers_every_ui_classifier_surface() -> None:
    """The main-push smoke must mirror paths that make PR UI validation run."""
    workflow = (ROOT / ".github" / "workflows" / "main-ui-smoke.yml").read_text(encoding="utf-8")
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


def test_postgres_integration_uses_a_persistent_audit_signing_key() -> None:
    """A durable shared audit ledger must never use a process-local key."""
    postgres_env = _ci()["jobs"]["postgres-integration"]["env"]

    assert postgres_env["AGENT_BOM_POSTGRES_URL"]
    assert postgres_env["AGENT_BOM_AUDIT_HMAC_KEY"] == "ci-postgres-audit-signing-key"


def test_test_job_timeout_leaves_margin_over_observed_worst_case() -> None:
    """Keep bounded headroom over the Python 3.11 coverage lane on main.

    The coverage lane exhausted the former 35-minute ceiling twice on exact
    main while the Python 3.13 and 3.14 lanes completed successfully. A
    45-minute ceiling preserves a hard bound and ten minutes of measured
    headroom for the coverage-only lane.
    """
    assert _ci()["jobs"]["test-main"]["timeout-minutes"] == 45


def test_version_alignment_fails_fast_when_uv_lock_is_stale() -> None:
    """Reject dependency drift before Docker and full-suite jobs consume runners."""
    steps = _ci()["jobs"]["version-check"]["steps"]
    lock_check_index = next(index for index, step in enumerate(steps) if step.get("name") == "Verify uv lockfile freshness")
    dependency_install_index = next(
        index for index, step in enumerate(steps) if step.get("name") == "Install dependencies for CLI smoke checks"
    )

    assert steps[lock_check_index]["run"] == "uv lock --check"
    assert lock_check_index < dependency_install_index


def test_alpine_full_suite_timeout_leaves_musl_headroom() -> None:
    """Full-suite Alpine runs must leave cleanup margin over the 34m51s baseline."""
    assert _ci()["jobs"]["test-alpine"]["timeout-minutes"] == 45


def test_alpine_full_suite_uses_bounded_parallelism() -> None:
    """The musl full suite must finish without overcommitting the hosted runner."""
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    alpine = text.split("      - name: Run tests (musl)", 1)[1].split("  # 3c. PR Base Branch Guard", 1)[0]
    full_suite = next(line.strip() for line in alpine.splitlines() if "uv run pytest tests/" in line)

    assert "-n 2" in full_suite
    assert "--dist worksteal" in full_suite


def test_pull_request_pytest_reports_slowest_tests() -> None:
    """PR runs surface the slowest tests so timeout regressions have evidence."""
    jobs = _ci()["jobs"]
    shard_run = next(step["run"] for step in jobs["test-pr-shard"]["steps"] if step.get("name") == "Run deterministic test shard")
    main_run = next(step["run"] for step in jobs["test-main"]["steps"] if step.get("name") == "Run full correctness suite")

    assert "--durations=25" in shard_run
    assert "--durations=25" in main_run
    coverage_line = next(line.strip() for line in main_run.splitlines() if "--cov=agent_bom" in line)
    assert "--cov-fail-under=75" in coverage_line


def test_pull_request_correctness_is_sharded_behind_required_aggregator() -> None:
    """PR correctness stays exhaustive without one serial 17-minute job."""
    jobs = _ci()["jobs"]

    shards = jobs["test-pr-shard"]
    assert shards["strategy"]["matrix"]["shard"] == [0, 1, 2, 3]
    shard_run = next(step["run"] for step in shards["steps"] if step.get("name") == "Run deterministic test shard")
    assert "scripts/pytest_ci_plan.py shard" in shard_run
    assert "not graph_performance" in shard_run

    required = jobs["test"]
    assert required["name"] == "Test (Python 3.13)"
    assert "test-pr-shard" in required["needs"]
    assert "graph-performance" in required["needs"]


def test_python_smoke_gate_combines_changed_domain_and_cross_surface_contracts() -> None:
    """Every Python PR gets quick relevant and product-boundary feedback."""
    smoke = _ci()["jobs"]["test-smoke"]
    run = next(step["run"] for step in smoke["steps"] if step.get("name") == "Run changed-domain and cross-surface smoke")

    assert "scripts/pytest_ci_plan.py targeted" in run
    assert "tests/test_cli_entry_points.py" in run
    assert "tests/test_product_surface_contract.py" in run
    assert "tests/api/test_api_scan_findings_wiring.py" in run


def test_package_build_waits_for_smoke_not_long_correctness_shards() -> None:
    """Wheel proof starts after fast correctness while shards continue in parallel."""
    needs = _ci()["jobs"]["build"]["needs"]
    assert "test-smoke" in needs
    assert "test" not in needs


def test_measured_graph_heap_assertion_has_dedicated_conditional_job() -> None:
    """The six-minute scale assertion is required only on relevant PRs and main."""
    workflow = _ci()
    assert "graph_performance" in workflow["jobs"]["changes"]["outputs"]
    graph_job = workflow["jobs"]["graph-performance"]
    run = next(step["run"] for step in graph_job["steps"] if step.get("name") == "Run measured graph scale assertion")
    assert "-m graph_performance" in run

    graph_test = (ROOT / "tests" / "graph" / "test_store_backed_build_wiring.py").read_text(encoding="utf-8")
    assert "@pytest.mark.graph_performance" in graph_test

    nightly = (ROOT / ".github" / "workflows" / "perf-scale-evidence.yml").read_text(encoding="utf-8")
    assert "-m graph_performance" in nightly


def test_output_scale_budgets_run_in_a_dedicated_uninstrumented_lane() -> None:
    """Wall-clock budgets must not share coverage/xdist CPU with the full suite."""

    jobs = _ci()["jobs"]
    scale_job = jobs["output-scale-performance"]
    run = next(step["run"] for step in scale_job["steps"] if step.get("name") == "Run measured output scale assertions")
    setup = next(step for step in scale_job["steps"] if step.get("uses") == "./.github/actions/setup-python")

    assert setup["with"]["python-version"] == "3.11"
    assert scale_job["needs"] == "changes"
    assert "github.event_name != 'pull_request'" in scale_job["if"]
    assert "needs.changes.outputs.python == 'true'" in scale_job["if"]
    assert "tests/test_release_output_scale_contract.py" in run
    assert "-m output_performance" in run
    assert "--cov" not in run
    assert " -n " not in run

    main_run = next(step["run"] for step in jobs["test-main"]["steps"] if step.get("name") == "Run full correctness suite")
    assert "not slow" in main_run

    required = jobs["test"]
    assert "output-scale-performance" in required["needs"]
    required_run = next(step["run"] for step in required["steps"] if step.get("name") == "Require every applicable correctness lane")
    assert "OUTPUT_SCALE_RESULT" in required_run
    assert '"$OUTPUT_SCALE_RESULT"' in required_run

    scale_test = (ROOT / "tests" / "test_release_output_scale_contract.py").read_text(encoding="utf-8")
    assert "pytest.mark.slow" in scale_test
    assert "pytest.mark.output_performance" in scale_test


def test_security_reuses_typescript_install_for_build() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    security = text.split("  # 2. Linting + Type Checking", 1)[0]
    assert security.count("npm ci --ignore-scripts") == 2
    assert "The preceding SDK audit step installed this exact lockfile" in security


def test_graph_guard_does_not_rerun_full_graph_tests() -> None:
    text = CI_WORKFLOW.read_text(encoding="utf-8")
    guard = text.split("      - name: Graph accuracy fixture guard", 1)[1].split("      - name: DCM scanner self-check", 1)[0]
    assert "pytest" not in guard
    assert "rebaseline_graph_edges.py --dry-run" in guard


def test_stranded_ci_recovery_runs_on_pr_synchronize() -> None:
    workflow = (ROOT / ".github" / "workflows" / "auto-retrigger-stranded.yml").read_text(encoding="utf-8")
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


def test_ci_lint_scope_is_defined_once_in_the_makefile() -> None:
    """CI and ``make lint`` must not hold separate opinions about what is linted.

    They did: CI ran ``ruff check src/`` while the Makefile ran ``src/ tests/``,
    and neither covered ``scripts/`` — where the release gates, drift checks and
    documentation generators live. A dead local in
    ``scripts/generate_doc_architecture_svgs.py`` sat on ``main`` because no gate
    could see it.
    """
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    lint_paths = next(line.split(":=", 1)[1].split() for line in makefile.splitlines() if line.startswith("LINT_PATHS"))
    for required in ("src/", "tests/", "scripts/"):
        assert required in lint_paths, f"{required} is outside the linted scope"

    lint_steps = _ci()["jobs"]["lint"]["steps"]
    ruff = next(step for step in lint_steps if step.get("name") == "Ruff")
    assert "make lint-ruff" in ruff["run"], "CI must call the Makefile target, not restate the paths"
    assert "ruff check" not in ruff["run"], "CI restated the lint paths instead of reusing LINT_PATHS"


def test_dependency_review_keeps_mmh3_license_exception_package_scoped() -> None:
    """A metadata false positive must not globally allow CC-BY software."""
    workflow = (ROOT / ".github" / "workflows" / "dependency-review.yml").read_text(encoding="utf-8")
    global_allowlist = workflow.split("allow-licenses:", 1)[1].split("# Packages whitelisted by PURL:", 1)[0]

    assert "pkg:pypi/mmh3" in workflow
    assert "CC-BY-4.0" not in global_allowlist
    assert "bibliography metadata" in workflow
    assert "sdist declare MIT" in workflow
