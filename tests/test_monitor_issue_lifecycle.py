"""Execute monitor scripts against a fake GitHub API to verify quiet issue reuse."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node is required to execute GitHub Actions scripts")


def run_monitor(
    workflow,
    job,
    issues,
    *,
    fresh=False,
    latest_id=99,
    latest_attempt=1,
    main_sha="a" * 40,
    workflow_name="Publish to Registries",
    step_name=None,
    probe_env=None,
):
    data = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())
    script = next(
        step["with"]["script"]
        for step in data["jobs"][job]["steps"]
        if "github-script@" in step.get("uses", "") and (step_name is None or step.get("name") == step_name)
    )
    harness = """
    const fs = require('node:fs');
    const {script, issues, fresh, latest_id, latest_attempt, main_sha, workflow_name, probe_env} = JSON.parse(fs.readFileSync(0, 'utf8'));
    const events = [];
    const github = {paginate: async () => issues, rest: {
      actions: {listWorkflowRuns: async () => ({data: {workflow_runs: [{id: latest_id, run_attempt: latest_attempt}]}})},
      repos: {getBranch: async () => ({data: {commit: {sha: main_sha}}})},
      issues: {
      listForRepo: () => {}, createLabel: async () => {},
      create: async value => events.push({kind: 'create', ...value}),
      update: async value => events.push({kind: 'update', ...value}),
      createComment: async value => events.push({kind: 'comment', ...value}),
    }}};
    const context = {repo: {owner: 'owner', repo: 'repo'}, serverUrl: 'https://github.com', runId: 99,
      payload: {workflow_run: {id: 99, run_attempt: 1, workflow_id: 42, name: workflow_name, html_url: 'https://github.com/run/99',
        head_sha: 'a'.repeat(40), actor: {login: 'owner'}}}};
    process.env.REPORT = JSON.stringify({expected: '0.103.2', all_fresh: fresh, all_required_fresh: fresh, surfaces: []});
    Object.assign(process.env, probe_env || {});
    const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
    new AsyncFunction('github', 'context', script)(github, context)
      .then(() => console.log(JSON.stringify(events))).catch(e => {console.error(e); process.exit(1)});
    """
    result = subprocess.run(
        [NODE, "-e", harness],
        input=json.dumps(
            {
                "script": script,
                "issues": issues,
                "fresh": fresh,
                "latest_id": latest_id,
                "latest_attempt": latest_attempt,
                "main_sha": main_sha,
                "workflow_name": workflow_name,
                "probe_env": probe_env,
            }
        ),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize(
    "workflow,job,title",
    [
        ("main-failure-alert.yml", "alert", "ci-regression: Publish to Registries failing on main"),
        ("surface-freshness.yml", "freshness", "supply-chain-drift: distribution surfaces out of sync"),
    ],
)
@pytest.mark.parametrize("state", ["open", "closed"])
def test_failure_reuses_tracker_without_repeat_comments(workflow, job, title, state):
    events = run_monitor(workflow, job, [{"number": 123, "title": title, "state": state}])
    assert len(events) == 1
    assert events[0]["kind"] == "update"
    assert events[0]["issue_number"] == 123
    assert events[0]["state"] == "open"


@pytest.mark.parametrize(
    "workflow,job,title",
    [
        ("main-failure-alert.yml", "resolve", "ci-regression: Publish to Registries failing on main"),
        ("surface-freshness.yml", "freshness", "supply-chain-drift: distribution surfaces out of sync"),
    ],
)
def test_recovery_closes_tracker_without_extra_comment(workflow, job, title):
    events = run_monitor(workflow, job, [{"number": 123, "title": title, "state": "open"}], fresh=True)
    assert len(events) == 1
    assert events[0]["kind"] == "update"
    assert events[0]["state"] == "closed"


def test_surface_verification_on_pr_branch_cannot_close_main_incident():
    data = yaml.safe_load((ROOT / ".github/workflows/surface-freshness.yml").read_text())
    step = next(s for s in data["jobs"]["freshness"]["steps"] if "github-script@" in s.get("uses", ""))
    assert "github.ref" in step["if"] and "github.event.repository.default_branch" in step["if"]


@pytest.mark.parametrize(
    "workflow,job,title",
    [
        ("main-failure-alert.yml", "alert", "ci-regression: Publish to Registries failing on main"),
        ("surface-freshness.yml", "freshness", "supply-chain-drift: distribution surfaces out of sync"),
    ],
)
def test_new_failures_still_alert_and_identical_reruns_are_noops(workflow, job, title):
    created = run_monitor(workflow, job, [])
    assert len(created) == 1 and created[0]["kind"] == "create"
    assert created[0]["title"] == title
    assert run_monitor(workflow, job, [{"number": 123, "title": title, "state": "open", "body": created[0]["body"]}]) == []


def test_surface_recovery_does_not_notify_again_after_closure():
    assert (
        run_monitor(
            "surface-freshness.yml",
            "freshness",
            [{"number": 123, "title": "supply-chain-drift: distribution surfaces out of sync", "state": "closed"}],
            fresh=True,
        )
        == []
    )


@pytest.mark.parametrize(
    "filename,job,upstream",
    [
        ("deployment-freshness.yml", "check", "Deploy MCP SSE"),
        ("surface-freshness.yml", "freshness", "Publish to Registries"),
    ],
)
def test_freshness_reconciles_after_success_and_failure(filename, job, upstream):
    data = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
    trigger = data.get("on", data.get(True))
    assert upstream in trigger["workflow_run"]["workflows"]
    assert trigger["workflow_run"]["types"] == ["completed"]
    condition = data["jobs"][job]["if"]
    assert '["success","failure"]' in condition


@pytest.mark.parametrize("job", ["alert", "resolve"])
@pytest.mark.parametrize("latest", [{"latest_id": 100}, {"latest_attempt": 2}])
def test_obsolete_completion_cannot_change_regression_tracker(job, latest):
    issues = [{"number": 123, "title": "ci-regression: Publish to Registries failing on main", "state": "open"}]
    assert run_monitor("main-failure-alert.yml", job, issues, **latest) == []


@pytest.mark.parametrize("job", ["alert", "resolve"])
def test_ci_completion_for_old_main_sha_cannot_change_tracker(job):
    issues = [{"number": 123, "title": "ci-regression: CI/CD Pipeline failing on main", "state": "open"}]
    assert run_monitor("main-failure-alert.yml", job, issues, workflow_name="CI/CD Pipeline", main_sha="b" * 40) == []


DEPLOYMENT_STEP = "Reconcile deployment monitoring issues"
DEPLOYMENT_TITLE = "supply-chain-drift: deployment surfaces out of sync"
UNMONITORED_TITLE = "deployment-monitoring: a deployment surface is UNMONITORED (missing config)"


def run_deployment(issues, **overrides):
    env = {
        "EXPECTED_VERSION": "0.105.0",
        "RAILWAY_VERSION": "unreachable",
        "RAILWAY_OUTCOME": "success",
        "RAILWAY_PROBE_FAILED": "true",
        "PUBLIC_VERSION": "fresh",
        "PUBLIC_OUTCOME": "success",
        "PUBLIC_NOT_CONFIGURED": "false",
        "RAILWAY_TOOLS": "unknown",
        "PUBLIC_TOOLS": "8",
    }
    env.update(overrides)
    return run_monitor("deployment-freshness.yml", "check", issues, step_name=DEPLOYMENT_STEP, probe_env=env)


@pytest.mark.parametrize("title", [DEPLOYMENT_TITLE, UNMONITORED_TITLE])
def test_deployment_reopens_completed_tracker_and_never_comments(title):
    issue = {"number": 5270, "title": title, "state": "closed", "state_reason": "completed"}
    env = {"PUBLIC_NOT_CONFIGURED": "true"} if title == UNMONITORED_TITLE else {}
    if title == UNMONITORED_TITLE:
        env.update(RAILWAY_VERSION="0.105.0", RAILWAY_PROBE_FAILED="false")
    events = run_deployment([issue], **env)
    assert len(events) == 1 and events[0]["kind"] == "update"
    assert events[0]["issue_number"] == 5270 and events[0]["state"] == "open"
    assert run_deployment([{**issue, "state": "open", "body": events[0]["body"]}], **env) == []


def test_deployment_ignores_closed_duplicate_and_pull_requests():
    issues = [
        {"number": 5339, "title": DEPLOYMENT_TITLE, "state": "closed", "state_reason": "not_planned"},
        {"number": 5340, "title": DEPLOYMENT_TITLE, "state": "open", "pull_request": {}},
        {"number": 5270, "title": DEPLOYMENT_TITLE, "state": "closed", "state_reason": "completed"},
    ]
    assert run_deployment(issues)[0]["issue_number"] == 5270


@pytest.mark.parametrize(
    "field,value", [("EXPECTED_VERSION", ""), ("RAILWAY_OUTCOME", "failure"), ("RAILWAY_PROBE_FAILED", ""), ("RAILWAY_VERSION", "0.104.0")]
)
def test_deployment_never_closes_without_verified_success(field, value):
    issue = {"number": 5270, "title": DEPLOYMENT_TITLE, "state": "open"}
    env = {"RAILWAY_VERSION": "0.105.0", "RAILWAY_PROBE_FAILED": "false", field: value}
    assert not any(e.get("state") == "closed" for e in run_deployment([issue], **env))


def test_deployment_recovery_is_quiet_and_preserves_distribution_tracker():
    issues = [
        {"number": 5270, "title": DEPLOYMENT_TITLE + " with 0.104.0", "state": "open"},
        {"number": 5184, "title": "supply-chain-drift: distribution surfaces out of sync", "state": "open"},
        {"number": 12, "title": UNMONITORED_TITLE, "state": "open"},
    ]
    events = run_deployment(issues, RAILWAY_VERSION="0.105.0", RAILWAY_PROBE_FAILED="false")
    assert {e["issue_number"] for e in events} == {5270, 12}
    assert all(e["kind"] == "update" and e["state"] == "closed" for e in events)


def test_deployment_missing_public_probe_cannot_close_unmonitored_tracker():
    issue = {"number": 12, "title": UNMONITORED_TITLE, "state": "open"}
    events = run_deployment([issue], RAILWAY_VERSION="0.105.0", RAILWAY_PROBE_FAILED="false", PUBLIC_VERSION="", PUBLIC_OUTCOME="skipped")
    assert events == []


def test_deployment_issue_mutation_is_default_branch_only():
    data = yaml.safe_load((ROOT / ".github/workflows/deployment-freshness.yml").read_text())
    steps = [s for s in data["jobs"]["check"]["steps"] if "github-script@" in s.get("uses", "")]
    assert steps
    for step in steps:
        assert "github.ref" in step["if"] and "github.event.repository.default_branch" in step["if"]
