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
    workflow, job, issues, *, fresh=False, latest_id=99, latest_attempt=1, main_sha="a" * 40, workflow_name="Publish to Registries"
):
    data = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())
    script = next(step["with"]["script"] for step in data["jobs"][job]["steps"] if "github-script@" in step.get("uses", ""))
    harness = """
    const fs = require('node:fs');
    const {script, issues, fresh, latest_id, latest_attempt, main_sha, workflow_name} = JSON.parse(fs.readFileSync(0, 'utf8'));
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
