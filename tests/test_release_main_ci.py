from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_release_main_ci.py"
SHA = "d" * 40


def _load_script():
    spec = importlib.util.spec_from_file_location("check_release_main_ci", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fetcher(*, branch_sha: str = SHA, runs: list[dict[str, Any]] | None = None):
    run_rows = runs if runs is not None else [_run()]

    def fetch(endpoint: str) -> dict[str, Any]:
        if "/git/ref/heads/" in endpoint:
            return {"object": {"sha": branch_sha}}
        assert "/actions/workflows/ci.yml/runs?" in endpoint
        return {"workflow_runs": run_rows}

    return fetch


def _run(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 123,
        "name": "CI/CD Pipeline",
        "path": ".github/workflows/ci.yml",
        "head_sha": SHA,
        "head_branch": "main",
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "html_url": "https://github.com/msaad00/agent-bom/actions/runs/123",
    }
    row.update(overrides)
    return row


def test_exact_main_completed_success_is_accepted() -> None:
    checker = _load_script()

    proof = checker.verify_release_candidate(
        repo="msaad00/agent-bom",
        sha=SHA,
        branch="main",
        workflow="ci.yml",
        fetch_json=_fetcher(),
    )

    assert proof == {
        "sha": SHA,
        "run_id": 123,
        "run_url": "https://github.com/msaad00/agent-bom/actions/runs/123",
    }


def test_stale_candidate_sha_is_rejected_before_ci_lookup() -> None:
    checker = _load_script()

    with pytest.raises(checker.ReleaseProofError, match="does not equal current main"):
        checker.verify_release_candidate(
            repo="msaad00/agent-bom",
            sha=SHA,
            branch="main",
            workflow="ci.yml",
            fetch_json=_fetcher(branch_sha="e" * 40),
        )


@pytest.mark.parametrize(
    "run",
    [
        _run(status="in_progress", conclusion=None),
        _run(status="completed", conclusion="cancelled"),
        _run(event="pull_request"),
        _run(head_sha="e" * 40),
        _run(head_branch="feature/release"),
        _run(path=".github/workflows/other.yml"),
    ],
)
def test_only_exact_completed_successful_main_push_proves_release(run: dict[str, Any]) -> None:
    checker = _load_script()

    with pytest.raises(checker.ReleaseProofError, match="completed successful main push"):
        checker.verify_release_candidate(
            repo="msaad00/agent-bom",
            sha=SHA,
            branch="main",
            workflow="ci.yml",
            fetch_json=_fetcher(runs=[run]),
        )


def test_lookup_failures_do_not_expose_raw_remote_details() -> None:
    checker = _load_script()

    def fail(_endpoint: str) -> dict[str, Any]:
        raise RuntimeError("Authorization: Bearer secret-token database.internal")

    with pytest.raises(checker.ReleaseProofError) as caught:
        checker.verify_release_candidate(
            repo="msaad00/agent-bom",
            sha=SHA,
            branch="main",
            workflow="ci.yml",
            fetch_json=fail,
        )

    message = str(caught.value)
    assert "release proof lookup failed" in message
    assert "secret-token" not in message
    assert "database.internal" not in message


def test_release_workflow_requires_exact_main_ci_proof() -> None:
    workflow_path = ROOT / ".github" / "workflows" / "release.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    guard = workflow["jobs"]["version-guard"]

    assert guard["permissions"]["actions"] == "read"
    step = next(step for step in guard["steps"] if step.get("name") == "Verify tag commit is exact green main")
    assert step["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "scripts/check_release_main_ci.py" in step["run"]
    assert '--sha "${{ github.sha }}"' in step["run"]
