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


def run_monitor(workflow, job, issues, *, fresh=False):
    data = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text())
    script = next(step["with"]["script"] for step in data["jobs"][job]["steps"] if "github-script@" in step.get("uses", ""))
    harness = """
    const fs = require('node:fs');
    const {script, issues, fresh} = JSON.parse(fs.readFileSync(0, 'utf8'));
    const events = [];
    const github = {paginate: async () => issues, rest: {issues: {
      listForRepo: () => {}, createLabel: async () => {},
      create: async value => events.push({kind: 'create', ...value}),
      update: async value => events.push({kind: 'update', ...value}),
      createComment: async value => events.push({kind: 'comment', ...value}),
    }}};
    const context = {repo: {owner: 'owner', repo: 'repo'}, serverUrl: 'https://github.com', runId: 99,
      payload: {workflow_run: {name: 'Publish to Registries', html_url: 'https://github.com/run/99',
        head_sha: 'a'.repeat(40), actor: {login: 'owner'}}}};
    process.env.REPORT = JSON.stringify({expected: '0.103.2', all_fresh: fresh, surfaces: []});
    const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
    new AsyncFunction('github', 'context', script)(github, context)
      .then(() => console.log(JSON.stringify(events))).catch(e => {console.error(e); process.exit(1)});
    """
    result = subprocess.run(
        [NODE, "-e", harness],
        input=json.dumps({"script": script, "issues": issues, "fresh": fresh}),
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
