"""Regression guards for CI path gating and duplicate-work prevention."""

from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def _ci() -> dict[str, object]:
    return yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))


def test_main_docker_pulls_authenticate_before_setup_and_build() -> None:
    job = _ci()["jobs"]["docker"]
    assert "github.event_name != 'pull_request'" in job["if"]
    steps = job["steps"]
    login = next(step for step in steps if step.get("uses", "").startswith("docker/login-action@"))
    assert login["with"] == {
        "registry": "docker.io",
        "username": "${{ secrets.DOCKERHUB_USERNAME }}",
        "password": "${{ secrets.DOCKERHUB_TOKEN }}",
    }
    assert "if" not in login
    assert not login.get("continue-on-error", False)
    for step in steps:
        if step.get("uses", "").startswith(
            ("docker/setup-qemu-action@", "docker/setup-buildx-action@")
        ) or "docker buildx build" in step.get("run", ""):
            assert steps.index(login) < steps.index(step)


def test_dependency_updates_share_one_scheduled_owner() -> None:
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    groups = config["multi-ecosystem-groups"]
    assert set(groups) == {"weekly-maintenance"}
    assert groups["weekly-maintenance"]["schedule"]["interval"] == "weekly"
    assert groups["weekly-maintenance"]["open-pull-requests-limit"] == 1
    for update in config["updates"]:
        assert update["multi-ecosystem-group"] == "weekly-maintenance"
        assert update["patterns"] == ["*"]
        assert update["groups"]["security-updates"]["applies-to"] == "security-updates"

    lock_refresh = yaml.safe_load((ROOT / ".github" / "workflows" / "uv-lock-upgrade.yml").read_text())
    triggers = lock_refresh.get("on", lock_refresh.get(True))
    assert set(triggers) == {"workflow_dispatch"}


def test_timeout_policy_uses_the_locked_security_environment() -> None:
    steps = _ci()["jobs"]["security"]["steps"]
    install = next(step for step in steps if step.get("name") == "Install dependencies")
    timeout = next(step for step in steps if step.get("name") == "Workflow job timeout policy")
    assert steps.index(install) < steps.index(timeout)
    assert "--frozen" in install["run"]
    assert "pip install" not in timeout["run"]
    assert "uv run --no-sync python scripts/check_workflow_timeouts.py" in timeout["run"]


def test_cloud_sdk_drift_uses_checkout_lockfile() -> None:
    path = ROOT / ".github/workflows/cloud-sdk-drift.yml"
    workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["drift"]["steps"]
    scripts = "\n".join(step.get("run", "") for step in steps)
    assert any(step.get("uses") == "./.github/actions/setup-python" for step in steps)
    assert "uv sync --frozen" in scripts
    assert "pip install" not in scripts
    assert "uv run --no-sync python scripts/check_cloud_sdk_drift.py" in scripts


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
    assert "Documentation-only test skip" not in workflow_text
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


def test_demo_deploy_new_release_supersedes_stale_approval_wait() -> None:
    """An obsolete protected-environment wait must not block a newer release."""
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "demo-deploy-cloudrun.yml").read_text(encoding="utf-8"))

    assert workflow["concurrency"] == {
        "group": "demo-deploy-cloudrun",
        "cancel-in-progress": True,
    }


def test_dependency_security_skips_only_proven_docs_only_changes() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "pr-security-gate.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]
    assert "scripts/classify_ci_changes.py" in workflow_path.read_text(encoding="utf-8")
    for name in ("code-scanning-config-pr", "pip-audit-pr", "self-scan-pr"):
        condition = jobs[name]["if"]
        assert "needs.changes.result != 'success'" in condition
        assert "needs.changes.outputs.docs_only != 'true'" in condition


def test_npm_audits_use_committed_lockfiles() -> None:
    """Advisory checks must use the bulk API without npm's retired fallback."""
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert ci.count("check_npm_advisories.py package-lock.json") == 2
    assert release.count("check_npm_advisories.py package-lock.json") == 1
    assert "--npm-install-report" not in ci
    assert "--npm-install-report" not in release
    assert ci.count("npm ci --ignore-scripts --no-audit") == 2
    assert release.count("npm ci --ignore-scripts --no-audit") == 1
    assert "npm audit" not in ci
    assert "npm audit" not in release


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
    for name in ("docs-strict", "ui", "ui-e2e", "endpoint-packaging", "test-alpine"):
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
        "ui-e2e",
        "graph-performance",
        "output-scale-performance",
    ):
        condition = jobs[name]["if"]
        assert "!cancelled()" in condition
        assert "always()" not in condition


def test_postgres_integration_uses_a_persistent_audit_signing_key() -> None:
    """A durable shared audit ledger must never use a process-local key."""
    postgres_env = _ci()["jobs"]["postgres-integration"]["env"]

    assert postgres_env["AGENT_BOM_POSTGRES_URL"]
    assert postgres_env["AGENT_BOM_AUDIT_HMAC_KEY"] == "ci-postgres-audit-signing-key"


def test_postgres_storage_contract_passes_every_listed_suite_to_one_pytest_command() -> None:
    """A missing line continuation would run a suite path as its own shell command."""
    steps = _ci()["jobs"]["postgres-integration"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Run real Postgres storage contract")
    lines = [line.strip() for line in script.strip().splitlines() if line.strip()]

    assert lines[0].startswith("uv run pytest")
    assert all(line.endswith("\\") for line in lines[:-1]), [line for line in lines[:-1] if not line.endswith("\\")]
    listed = {line.rstrip("\\ ").strip() for line in lines[1:]}
    for suite in ("tests/test_tenant_quota_store.py", "tests/test_tenant_graph_retention_store.py", "tests/test_storage_sql.py"):
        assert suite in listed
        assert (ROOT / suite).is_file()


def test_test_job_timeout_leaves_margin_over_observed_worst_case() -> None:
    """Keep bounded headroom over the Python 3.11 coverage lane on main.

    The coverage lane exhausted the former 35-minute ceiling twice on exact
    main while the Python 3.13 and 3.14 lanes completed successfully. A
    45-minute ceiling preserves a hard bound and ten minutes of measured
    headroom for the coverage-only lane.
    """
    assert _ci()["jobs"]["test-main"]["timeout-minutes"] == 45


def test_changed_domain_timeout_covers_broad_selections() -> None:
    """A security change can select nearly the full suite, plus setup time."""
    assert 30 <= _ci()["jobs"]["test-smoke"]["timeout-minutes"] <= 45


def test_full_correctness_matrix_covers_every_supported_python_minor() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    supported = {
        classifier.rsplit(" :: ", 1)[-1]
        for classifier in project["classifiers"]
        if classifier.startswith("Programming Language :: Python :: 3.")
    }
    matrix = set(_ci()["jobs"]["test-main"]["strategy"]["matrix"]["python-version"])

    assert matrix == supported


def test_local_test_target_enforces_the_ci_coverage_floor() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    test_target = makefile.split("test:  ## Run unit tests", 1)[1].split("\n\n", 1)[0]

    assert "--cov-fail-under=75" in test_target


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
    alpine = text.split("      - name: Run tests (musl)", 1)[1].split("  # 3c. Release Surface Consistency Check", 1)[0]
    full_suite = next(line.strip() for line in alpine.splitlines() if "uv run pytest tests/" in line)

    assert "-n 2" in full_suite
    assert "--dist worksteal" in full_suite


def test_pull_request_pytest_reports_slowest_tests() -> None:
    """PR runs surface the slowest tests so timeout regressions have evidence."""
    jobs = _ci()["jobs"]
    smoke_run = next(
        step["run"] for step in jobs["test-smoke"]["steps"] if step.get("name") == "Run changed-domain and cross-surface smoke"
    )
    main_run = next(step["run"] for step in jobs["test-main"]["steps"] if step.get("name") == "Run full correctness suite")

    assert "--durations=" in smoke_run
    assert "--durations=25" in main_run
    coverage_line = next(line.strip() for line in main_run.splitlines() if "--cov=agent_bom" in line)
    assert "--cov-fail-under=75" in coverage_line


PR_EXCLUDED_POST_MERGE_JOBS = (
    "graph-performance",
    "output-scale-performance",
    "sdk-import-smoke",
    "test-alpine",
    "action-dogfood",
    "docker",
    "ui-e2e",
)


REQUIRED_CI_JOBS = ("security", "lint", "build", "test")
SHARD_STEP = "Run full correctness shard"


def _marker_filter(run: str) -> str:
    return run.split(' -m "', 1)[1].split('"', 1)[0]


def test_pull_requests_run_the_full_suite_sharded_instead_of_the_matrix() -> None:
    """PRs prove the merge result with the sharded 3.13 suite; main runs the matrix."""
    jobs = _ci()["jobs"]
    assert jobs["test-main"]["if"] == ("${{ !cancelled() && github.event_name != 'pull_request' && github.event_name != 'merge_group' }}")
    assert jobs["test-shard"]["if"] == (
        "${{ !cancelled() && (github.event_name == 'pull_request' || github.event_name == 'merge_group') }}"
    )
    assert "test-queue-shard" not in jobs
    assert jobs["postgres-integration"]["if"] == "${{ !cancelled() }}"
    assert jobs["test-smoke"]["if"] == "${{ !cancelled() }}"
    assert "test-pr-shard" not in jobs
    for name in PR_EXCLUDED_POST_MERGE_JOBS:
        condition = jobs[name]["if"]
        assert "github.event_name != 'pull_request'" in condition, name
        assert "!cancelled()" in condition, name


def test_shards_run_the_whole_suite_on_the_merge_result() -> None:
    jobs = _ci()["jobs"]
    shard = jobs["test-shard"]
    assert shard["name"] == "Full correctness shard (${{ matrix.shard }}, Python 3.13)"
    assert "needs" not in shard
    assert "ref" not in shard["steps"][0].get("with", {})
    setup = next(step for step in shard["steps"] if step.get("uses") == "./.github/actions/setup-python")
    assert setup["with"]["python-version"] == "3.13"
    assert shard["strategy"]["fail-fast"] is False
    indexes = shard["strategy"]["matrix"]["shard"]
    assert indexes == list(range(len(indexes))) and len(indexes) >= 2
    assert shard["timeout-minutes"] <= 20
    assert "cancel-in-progress" not in shard.get("concurrency", {})

    run = next(step["run"] for step in shard["steps"] if step.get("name") == SHARD_STEP)
    assert f"--total {len(indexes)}" in run
    assert '--index "${{ matrix.shard }}"' in run
    assert "--durations=" in run
    main_run = next(step["run"] for step in jobs["test-main"]["steps"] if step.get("name") == "Run full correctness suite")
    main_filters = {_marker_filter(line) for line in main_run.splitlines() if "uv run pytest tests/" in line}
    assert main_filters == {_marker_filter(run)}


def test_shards_partition_every_test_module_exactly_once() -> None:
    import subprocess
    import sys

    shard = _ci()["jobs"]["test-shard"]
    total = len(shard["strategy"]["matrix"]["shard"])
    selected: list[str] = []
    for index in range(total):
        result = subprocess.run(
            [sys.executable, "scripts/pytest_ci_plan.py", "shard", "--index", str(index), "--total", str(total)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        lines = result.stdout.split()
        assert lines, index
        selected.extend(lines)
    every = sorted(path.relative_to(ROOT).as_posix() for path in (ROOT / "tests").rglob("test_*.py") if path.is_file())
    assert len(selected) == len(set(selected))
    assert sorted(selected) == every


def test_required_contexts_report_on_pull_request_and_merge_group() -> None:
    """Required contexts report on every event that can gate a merge."""
    workflow = _ci()
    triggers = workflow.get(True, workflow.get("on", {}))
    assert triggers["merge_group"] == {"types": ["checks_requested"]}
    for name in REQUIRED_CI_JOBS:
        assert workflow["jobs"][name]["if"] == "${{ !cancelled() }}", name
    assert workflow["jobs"]["test"]["name"] == "Test (Python 3.13)"
    for name in ("codeql.yml", "pr-security-gate.yml"):
        other = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
        assert other.get(True, other.get("on", {}))["merge_group"] == {"types": ["checks_requested"]}, name


def test_runbook_keeps_strict_protection_and_documents_pr_shards() -> None:
    """No merge queue is available for this repository, so strict protection stays."""
    runbook = " ".join((ROOT / "docs" / "operations" / "CI_RUNBOOK.md").read_text(encoding="utf-8").split())
    total = len(_ci()["jobs"]["test-shard"]["strategy"]["matrix"]["shard"])
    assert f"split into {total} parallel shards" in runbook
    assert "-F strict=false" not in runbook
    assert "rulesets" not in runbook
    assert "| Merge queue |" not in runbook


def test_main_push_aggregator_requires_the_full_suite() -> None:
    """A green main run must mean every post-merge lane actually passed.

    The release gate (scripts/check_release_main_ci.py) accepts the tag only
    when the exact main SHA has a successful ``ci.yml`` push run, so skipping
    the full suite on main would silently weaken the release proof.
    """
    jobs = _ci()["jobs"]
    core = jobs["test-core"]
    lanes = (
        "test-smoke",
        "test-main",
        "test-shard",
        "graph-performance",
        "output-scale-performance",
        "sdk-import-smoke",
        "postgres-integration",
    )
    for lane in lanes:
        assert lane in core["needs"], lane
    run = next(step["run"] for step in core["steps"] if step.get("name") == "Require every applicable correctness lane")
    assert 'if [ "$EVENT_NAME" != "pull_request" ]' in run
    for variable in ("MAIN_RESULT", "SHARD_RESULT", "GRAPH_RESULT", "OUTPUT_SCALE_RESULT", "SDK_SMOKE_RESULT", "POSTGRES_RESULT"):
        assert f'"${variable}"' in run
    assert core["steps"][0]["env"]["EVENT_NAME"] == "${{ github.event_name }}"

    required = jobs["test"]
    assert required["name"] == "Test (Python 3.13)"
    assert "test-core" in required["needs"]
    assert "docker" in required["needs"]
    docker_required = required["steps"][0]["env"]["DOCKER_REQUIRED"]
    assert "pull_request" not in docker_required
    assert "refs/heads/main" in docker_required


def test_ci_runs_nightly_with_full_musl_suite() -> None:
    workflow = _ci()
    on = workflow.get(True, workflow.get("on", {}))
    assert on["schedule"]
    alpine = workflow["jobs"]["test-alpine"]
    run_step = next(step for step in alpine["steps"] if step.get("name") == "Run tests (musl)")
    assert "github.event_name == 'schedule'" in run_step["env"]["ALPINE_FULL"]


def test_pull_request_classifiers_diff_from_the_merge_base() -> None:
    """A two-dot diff against a newer base pulls main's own commits into the PR.

    ``base.sha`` is main's tip when the PR event fired, not the branch point.
    ``git diff base head`` then lists every file main changed since the branch
    point, so unrelated lanes run and the changed-domain selector over-selects.
    """
    two_dot = 'git diff --name-only "${{ github.event.pull_request.base.sha }}" "${{ github.event.pull_request.head.sha }}"'
    three_dot = 'git diff --name-only "${{ github.event.pull_request.base.sha }}...${{ github.event.pull_request.head.sha }}"'
    for name in ("ci.yml", "pr-security-gate.yml"):
        text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
        assert two_dot not in text, name
        assert three_dot in text, name
    assert CI_WORKFLOW.read_text(encoding="utf-8").count(three_dot) == 2


def test_only_pull_request_runs_cancel_superseded_runs() -> None:
    concurrency = _ci()["concurrency"]
    assert "github.event.pull_request.number" in concurrency["group"]
    assert "github.event_name" in concurrency["group"]
    assert "github.ref == 'refs/heads/main' && github.sha" in concurrency["group"]
    assert concurrency["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}"
    for name in ("codeql.yml", "pr-security-gate.yml"):
        other = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
        assert other["concurrency"]["cancel-in-progress"] == "${{ github.event_name == 'pull_request' }}", name


# Lanes each event must prove; every other lane must be skipped or succeed.
# PRs (and merge groups, if a queue is ever enabled) prove the merge result
# with the sharded 3.13 suite; main, nightly and manual runs prove the matrix.
_EVENT_PROOF = {
    "pull_request": ("SMOKE_RESULT", "POSTGRES_RESULT", "SHARD_RESULT"),
    "merge_group": (
        "SMOKE_RESULT",
        "POSTGRES_RESULT",
        "SHARD_RESULT",
        "GRAPH_RESULT",
        "OUTPUT_SCALE_RESULT",
        "SDK_SMOKE_RESULT",
    ),
    "push": ("SMOKE_RESULT", "POSTGRES_RESULT", "MAIN_RESULT", "GRAPH_RESULT", "OUTPUT_SCALE_RESULT", "SDK_SMOKE_RESULT"),
    "schedule": ("SMOKE_RESULT", "POSTGRES_RESULT", "MAIN_RESULT", "GRAPH_RESULT", "OUTPUT_SCALE_RESULT", "SDK_SMOKE_RESULT"),
    "workflow_dispatch": ("SMOKE_RESULT", "POSTGRES_RESULT", "MAIN_RESULT", "GRAPH_RESULT", "OUTPUT_SCALE_RESULT", "SDK_SMOKE_RESULT"),
}


def _run_correctness_gate(event: str, results: dict[str, str]) -> bool:
    import os
    import subprocess

    step = _ci()["jobs"]["test-core"]["steps"][0]
    env = {**os.environ, **dict.fromkeys(step["env"], "skipped"), "EVENT_NAME": event, **results}
    return subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True, text=True).returncode == 0


def test_correctness_gate_requires_exactly_the_lanes_each_event_proves() -> None:
    for event, proof in _EVENT_PROOF.items():
        assert _run_correctness_gate(event, dict.fromkeys(proof, "success")), event
        for lane in proof:
            for outcome in ("failure", "skipped", "cancelled"):
                results = {**dict.fromkeys(proof, "success"), lane: outcome}
                assert not _run_correctness_gate(event, results), (event, lane, outcome)


def test_correctness_gate_rejects_a_failed_lane_that_the_event_does_not_require() -> None:
    for event, proof in _EVENT_PROOF.items():
        for lane in ("MAIN_RESULT", "SHARD_RESULT", "GRAPH_RESULT"):
            if lane in proof:
                continue
            results = {**dict.fromkeys(proof, "success"), lane: "failure"}
            assert not _run_correctness_gate(event, results), (event, lane)


def test_ui_pr_lane_is_fast_and_e2e_runs_after_merge() -> None:
    jobs = _ci()["jobs"]
    fast = {step.get("name") for step in jobs["ui"]["steps"]}
    assert {"UI lint", "UI tests", "Graph schema codegen — Python ↔ TypeScript drift gate"} <= fast
    assert "UI E2E" not in fast
    assert "UI container smoke test" not in fast

    export = jobs["ui-export"]
    assert "UI static-export build (release parity)" in {step.get("name") for step in export["steps"]}
    assert export["if"] == jobs["ui"]["if"]
    assert "NEXT_EXPORT=1 npm run build" in CI_WORKFLOW.read_text(encoding="utf-8")

    full = {step.get("name") for step in jobs["ui-e2e"]["steps"]}
    assert {"UI production build", "UI container smoke test", "UI bundle budget", "UI E2E"} <= full
    assert "needs.changes.outputs.ui == 'true'" in jobs["ui-e2e"]["if"]


def test_mypy_cache_is_restored_on_prs_and_saved_only_from_main() -> None:
    steps = _ci()["jobs"]["lint"]["steps"]
    restore = next(step for step in steps if str(step.get("uses", "")).startswith("actions/cache/restore@"))
    save = next(step for step in steps if str(step.get("uses", "")).startswith("actions/cache/save@"))
    mypy = next(step for step in steps if step.get("name") == "MyPy")
    assert steps.index(restore) < steps.index(mypy) < steps.index(save)
    assert restore["with"]["path"] == save["with"]["path"] == ".mypy_cache"
    assert "hashFiles('uv.lock')" in restore["with"]["key"]
    assert "github.event_name == 'push'" in save["if"]
    assert "refs/heads/main" in save["if"]


def test_fuzzing_runs_after_merge_not_on_pull_requests() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/cflite-pr.yml").read_text())
    triggers = workflow.get(True, workflow.get("on", {}))
    assert "pull_request" not in triggers
    assert "push" in triggers and "schedule" in triggers
    main_fuzz = workflow["jobs"]["Main-Fuzzing"]
    assert "github.event_name == 'push'" in main_fuzz["if"]
    run = next(step for step in main_fuzz["steps"] if "run_fuzzers" in str(step.get("uses", "")))
    assert run["with"]["mode"] == "batch"


def test_codeql_pr_analysis_skips_test_code_only() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/codeql.yml").read_text())
    init = next(step for step in workflow["jobs"]["analyze-python"]["steps"] if "codeql-action/init" in str(step.get("uses", "")))
    config = yaml.safe_load(init["with"]["config"])
    assert config["paths-ignore"] == ["tests/**"]
    assert init["with"]["queries"] == "security-extended"


def test_runtime_acceptance_is_post_merge_for_broad_api_changes() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/runtime-acceptance.yml").read_text())
    triggers = workflow.get(True, workflow.get("on", {}))
    assert "src/agent_bom/api/**" not in triggers["pull_request"]["paths"]
    assert "src/agent_bom/api/**" in triggers["push"]["paths"]
    assert ".github/workflows/runtime-acceptance.yml" in triggers["pull_request"]["paths"]

    alert = yaml.safe_load((ROOT / ".github/workflows/main-failure-alert.yml").read_text())
    watched = alert.get(True, alert.get("on", {}))["workflow_run"]["workflows"]
    assert {"CI/CD Pipeline", "Runtime Helm Acceptance", "ClusterFuzzLite"} <= set(watched)


def test_python_smoke_gate_combines_changed_domain_and_cross_surface_contracts() -> None:
    """Every Python PR gets quick relevant and product-boundary feedback."""
    smoke = _ci()["jobs"]["test-smoke"]
    run = next(step["run"] for step in smoke["steps"] if step.get("name") == "Run changed-domain and cross-surface smoke")

    assert "scripts/pytest_ci_plan.py targeted" in run
    assert "tests/test_cli_entry_points.py" in run
    assert "tests/test_product_surface_contract.py" in run
    assert "tests/api/test_api_scan_findings_wiring.py" in run
    assert "tests/api/test_live_export_contracts.py" in run


def test_readme_contracts_run_for_ui_and_documentation_only_changes() -> None:
    """Public presentation edits must fail PR CI before the full main suite."""
    smoke = _ci()["jobs"]["test-smoke"]
    steps = smoke["steps"]
    for step in steps:
        if "uses" in step or step.get("name") in {"Install dependencies", "Run changed-domain and cross-surface smoke"}:
            assert step.get("if") is None
    run = next(step["run"] for step in steps if step.get("name") == "Run changed-domain and cross-surface smoke")
    for contract in (
        "test_doc_architecture_svgs.py",
        "test_public_frontdoor_contract.py",
        "test_public_docs_cli_alignment.py",
        "test_readme_demo_excerpt.py",
    ):
        assert f"tests/{contract}" in run


def test_required_package_build_starts_immediately() -> None:
    """Build Package is a required context; it must not queue behind other lanes."""
    assert _ci()["jobs"]["build"]["needs"] == ["changes"]


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
    assert "tests/test_release_output_scale_contract.py" in run
    assert "-m output_performance" in run
    assert "--cov" not in run
    assert " -n " not in run

    main_run = next(step["run"] for step in jobs["test-main"]["steps"] if step.get("name") == "Run full correctness suite")
    assert "not slow" in main_run

    core = jobs["test-core"]
    assert "output-scale-performance" in core["needs"]
    core_run = next(step["run"] for step in core["steps"] if step.get("name") == "Require every applicable correctness lane")
    assert "OUTPUT_SCALE_RESULT" in core_run
    assert '"$OUTPUT_SCALE_RESULT"' in core_run

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


def test_dependency_review_keeps_caniuse_license_exception_package_scoped() -> None:
    """Browser compatibility data must not globally allow CC-BY software."""
    workflow = (ROOT / ".github" / "workflows" / "dependency-review.yml").read_text(encoding="utf-8")
    global_allowlist = workflow.split("allow-licenses:", 1)[1].split("# Packages whitelisted by PURL:", 1)[0]

    assert "pkg:npm/caniuse-lite" in workflow
    assert "CC-BY-4.0" not in global_allowlist
    assert "browser compatibility data" in workflow
    assert "build tooling" in workflow


def test_dependency_review_accepts_regex_declared_dual_license() -> None:
    """The regex wheel accurately declares its inherited CPython license."""
    workflow = (ROOT / ".github" / "workflows" / "dependency-review.yml").read_text(encoding="utf-8")
    global_allowlist = workflow.split("allow-licenses:", 1)[1].split("# Packages whitelisted by PURL:", 1)[0]

    assert "Apache-2.0" in global_allowlist
    assert "CNRI-Python" in global_allowlist
    assert "derived from CPython 2.6/3.1" in workflow


def test_alpine_installs_jq_for_registry_selector_contracts() -> None:
    """The full musl suite executes jq, including after bootstrap retries."""
    steps = _ci()["jobs"]["test-alpine"]["steps"]
    install = next(step for step in steps if step.get("name") == "Install build deps (Alpine)")
    commands = [line for line in install["run"].splitlines() if "apk add --no-cache" in line]
    assert commands
    assert all("jq" in command.replace(";", " ").split() for command in commands)


def test_pip_audit_reuses_only_proven_identical_dependency_inputs() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/pr-security-gate.yml").read_text())
    jobs = workflow["jobs"]
    assert "python_dependencies" in jobs["changes"]["outputs"]
    steps = jobs["pip-audit-pr"]["steps"]
    reuse = next(step for step in steps if step.get("name") == "Reuse audit for unchanged Python dependency inputs")
    base = next(step for step in steps if step.get("name") == "Run pip-audit on PR base for delta comparison")
    assert "github.event_name == 'pull_request'" in reuse["if"]
    assert "needs.changes.result == 'success'" in reuse["if"]
    assert "needs.changes.outputs.python_dependencies == 'false'" in reuse["if"]
    assert reuse["run"] == "cp audit.json base-audit.json"
    assert "needs.changes.result != 'success'" in base["if"]
    assert "needs.changes.outputs.python_dependencies != 'false'" in base["if"]
    assert "github.event.pull_request.base.sha" in base["run"]
    assert "github.base_ref" not in base["run"]
    evaluate = next(step for step in steps if step.get("name") == "Evaluate pip-audit gate")
    assert "--mode delta" in evaluate["run"] and "--mode strict" in evaluate["run"]


def test_codeql_skips_only_prose_image_pushes_and_preserves_required_pr_checks() -> None:
    from fnmatch import fnmatch

    workflow = yaml.safe_load((ROOT / ".github/workflows/codeql.yml").read_text())
    triggers = workflow.get(True, workflow.get("on", {}))
    ignores = triggers["push"]["paths-ignore"]
    for path in ("README.md", "docs/operator.md", "docs/images/dashboard.png"):
        assert any(fnmatch(path, pattern) for pattern in ignores)
    # Mixed changes still trigger: code, dependency inputs and unknown files
    # must never match the prose/image-only exclusion list.
    for path in ("src/agent_bom/proxy.py", "docs/example.py", ".github/workflows/ci.yml", "uv.lock", "pyproject.toml", "new-input"):
        assert not any(fnmatch(path, pattern) for pattern in ignores)
    for event in ("pull_request", "merge_group"):
        assert "paths" not in triggers[event]
        assert "paths-ignore" not in triggers[event]
    assert "schedule" in triggers and "workflow_dispatch" in triggers
    assert set(workflow["jobs"]) == {"analyze-python", "analyze-actions"}


def test_keycloak_image_participates_in_dependency_maintenance() -> None:
    config = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    assert any(update["package-ecosystem"] == "docker" and update.get("directory") == "/deploy/keycloak" for update in config["updates"])


def test_postgres_contract_suites_are_arguments_to_one_pytest_invocation() -> None:
    import shlex

    steps = _ci()["jobs"]["postgres-integration"]["steps"]
    script = next(step["run"] for step in steps if step.get("name") == "Run real Postgres storage contract")
    commands = [line.strip() for line in script.replace("\\\n", " ").splitlines() if line.strip()]
    assert len(commands) == 1, "A missing shell continuation runs a test file as a command"
    arguments = shlex.split(commands[0])
    assert arguments[:3] == ["uv", "run", "pytest"]
    assert "tests/test_tenant_quota_store.py" in arguments
    assert "tests/test_jit_grant_tenant_boundary.py" in arguments
    assert "tests/test_identity_policy_tenant_boundary.py" in arguments
    assert "tests/test_findings_sql_read_contract.py" in arguments
    assert "tests/test_findings_sql_backfill.py" in arguments
    assert "tests/test_findings_current_sql_contract.py" in arguments
    assert "tests/test_jobs_tenant_key_contract.py" in arguments
    assert "tests/test_jobs_dispatch_postgres.py" in arguments


def test_ui_first_failure_diagnostics_survive_without_retries() -> None:
    job = _ci()["jobs"]["ui-e2e"]
    steps = job["steps"]
    uploads = [step for step in steps if str(step.get("uses", "")).startswith("actions/upload-artifact@")]
    assert len(uploads) == 1, "Retain first-attempt browser failures before the runner disappears"
    upload = uploads[0]
    assert "failure()" in upload["if"] and "cancelled()" in upload["if"]
    assert steps.index(upload) > next(index for index, step in enumerate(steps) if step.get("name") == "UI E2E")
    assert upload["with"]["retention-days"] <= 3
    assert set(upload["with"]["path"].splitlines()) == {
        "ui/test-results/**/trace.zip",
        "ui/test-results/**/test-failed-*.png",
        "ui/test-results/**/error-context.md",
    }
    # Uploaded traces must stay within the public synthetic-fixture CI lane.
    e2e = next(step for step in steps if step.get("name") == "UI E2E")
    assert e2e["env"]["GRAPH_SCAN_ARTIFACT"] == ""
    assert "${{ secrets." not in yaml.safe_dump(job)
    config = (ROOT / "ui" / "playwright.config.ts").read_text()
    assert 'trace: "retain-on-failure"' in config
    assert 'screenshot: "only-on-failure"' in config


def test_action_classifier_includes_the_cyclonedx_dogfood_fixture() -> None:
    import re

    steps = _ci()["jobs"]["changes"]["steps"]
    script = next(step["run"] for step in steps if step.get("id") == "classify")
    pattern = re.search(r"grep -Eq '([^']+)'; then\n\s+action=true", script)
    assert pattern is not None
    for path in ("action.yml", "tests/fixtures/test-sbom.cdx.json", "tests/fixtures/test-policy.json"):
        assert re.search(pattern[1], path), path
    assert not re.search(pattern[1], "docs/readme.md")


def test_every_main_push_runs_all_release_ui_lanes():
    for name in ("ui", "ui-export", "ui-e2e"):
        condition = _ci()["jobs"][name]["if"]
        assert "github.event_name == 'push'" in condition
        assert "github.ref == 'refs/heads/main'" in condition
