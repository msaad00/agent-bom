"""API scan repo_url contract and pipeline integration tests."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.pipeline import _run_scan_sync


def test_scan_request_repo_url_rejects_local_path_mix() -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        ScanRequest(repo_url="https://github.com/org/repo", agent_projects=["/tmp/proj"])


def test_scan_request_accepts_repo_url_only() -> None:
    req = ScanRequest(repo_url="https://github.com/org/repo", no_scan=True)
    assert req.repo_url == "https://github.com/org/repo"


def test_scan_request_repo_url_rejects_offline() -> None:
    """offline cannot clone a remote repo — reject up front with a clear message
    instead of failing deep in the pipeline with an opaque subpath error."""
    with pytest.raises(ValueError, match="offline mode cannot clone a remote repo_url"):
        ScanRequest(repo_url="https://github.com/org/repo", offline=True)


def test_run_scan_sync_clones_repo_url_and_cleans_up(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cloned = tmp_path / "cloned-repo"
    cloned.mkdir()
    (cloned / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    workflow_dir = cloned / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow_dir.joinpath("ci.yml").write_text(
        """name: CI
on: push
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
""",
        encoding="utf-8",
    )
    clone_calls: list[str] = []
    cleanup_calls: list[str] = []

    @contextmanager
    def fake_clone(repo_url: str, *, token_env: str = "", branch: str | None = None):
        clone_calls.append(repo_url)
        yield cloned
        cleanup_calls.append(repo_url)

    monkeypatch.setattr("agent_bom.repo_scan.clone_repository", fake_clone)

    py_calls: list[str] = []

    def fake_scan_python_agents(path: str):
        py_calls.append(path)
        return [], []

    monkeypatch.setattr("agent_bom.python_agents.scan_python_agents", fake_scan_python_agents)
    monkeypatch.setattr("agent_bom.terraform.scan_terraform_dir", lambda _path: ([], []))
    monkeypatch.setattr("agent_bom.github_actions.scan_github_actions", lambda _path: ([], []))
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda **_kwargs: [])

    tree_calls: list[str] = []

    from agent_bom.api.repo_tree_scan import RepoTreeScanResult

    def fake_repo_tree(path: str, *, agents, warnings, update_progress=None, offline=False):
        tree_calls.append(path)
        assert offline is False
        return RepoTreeScanResult(
            iac_findings_data={"total": 1, "findings": [{"rule_id": "TF001", "severity": "high", "title": "test"}]},
            sast_data={"scanner_driver_id": "sast-semgrep", "execution_status": "clean", "findings": []},
        )

    monkeypatch.setattr("agent_bom.api.repo_tree_scan.scan_cloned_repo_tree", fake_repo_tree)
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda *_a, **_k: [])

    job = ScanJob(
        job_id="repo-scan-job",
        created_at="2026-01-01T00:00:00Z",
        request=ScanRequest(repo_url="https://github.com/org/repo", no_scan=True),
    )

    _run_scan_sync(job)

    assert clone_calls == ["https://github.com/org/repo"]
    assert py_calls == [str(cloned)]
    assert tree_calls == [str(cloned)]
    assert cleanup_calls == ["https://github.com/org/repo"]
    assert job.status == JobStatus.DONE
    assert job.result is not None
    assert job.result.get("iac_findings", {}).get("total") == 1
    assert job.result.get("sast", {}).get("execution_status") == "clean"
    assert job.result.get("status") == "findings_only"
    action_packages = [
        package
        for agent in job.result["agents"]
        for server in agent["mcp_servers"]
        for package in server["packages"]
        if package["ecosystem"] == "github-action"
    ]
    assert [(package["name"], package["version"]) for package in action_packages] == [
        ("actions/checkout", "0123456789abcdef0123456789abcdef01234567")
    ]


@pytest.mark.parametrize("with_packages", [False, True])
@pytest.mark.parametrize("pruned", [False, True])
@pytest.mark.parametrize("visible_secret", [False, True])
def test_repo_secret_coverage_survives_report_assembly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, with_packages: bool, pruned: bool, visible_secret: bool
) -> None:
    """Finding-only and dependency reports must retain secret discovery gaps."""
    from agent_bom.sast import SASTExecutionStatus, SASTResult

    root = tmp_path / "repo"
    root.mkdir()
    if pruned:
        (root / "build").mkdir()
        (root / "build" / ".env").write_text('PASSWORD="regression-fixture-password"\n')
    if visible_secret:
        (root / ".env").write_text('PASSWORD="regression-fixture-password"\n')
    if with_packages:
        (root / "requirements.txt").write_text("requests==2.31.0\n")

    @contextmanager
    def clone(*_args, **_kwargs):
        yield root

    monkeypatch.setattr("agent_bom.repo_scan.clone_repository", clone)
    monkeypatch.setattr("agent_bom.repo_scan.fetch_repo_trust", lambda *_a, **_k: {})
    monkeypatch.setattr("agent_bom.sast.scan_code", lambda *_a, **_k: ([], SASTResult(execution_status=SASTExecutionStatus.CLEAN)))
    monkeypatch.setattr("agent_bom.python_agents.scan_python_agents", lambda *_a, **_k: ([], []))
    monkeypatch.setattr("agent_bom.terraform.scan_terraform_dir", lambda *_a, **_k: ([], []))
    monkeypatch.setattr("agent_bom.github_actions.scan_github_actions", lambda *_a, **_k: ([], []))
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda **_kwargs: [])

    job = ScanJob(
        job_id=f"repo-coverage-{with_packages}-{pruned}-{visible_secret}",
        created_at="2026-09-11T00:00:00Z",
        request=ScanRequest(repo_url="https://github.com/org/repo", no_scan=True),
    )
    _run_scan_sync(job)

    assert job.status == JobStatus.DONE
    assert job.result is not None
    secret_scan = job.result["ai_inventory"]["secrets"]
    assert secret_scan["complete"] is (not pruned)
    assert secret_scan["pruned_directories"] == int(pruned)
    assert (secret_scan["total"] > 0) is visible_secret
    assert job.result["scan_run"]["outcome"] == ("partial" if pruned else "complete")
    issues = [issue for issue in job.result["scan_run"]["issues"] if issue["source"] == "secret-scan"]
    assert len(issues) == int(pruned)
    if pruned:
        assert issues[0]["code"] == "scanner_coverage_gap"
        assert issues[0]["affects_coverage"] is True
        assert issues[0]["message"] in job.result["warnings"]
    assert "regression-fixture-password" not in str(job.result)
