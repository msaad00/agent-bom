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


def test_run_scan_sync_clones_repo_url_and_cleans_up(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cloned = tmp_path / "cloned-repo"
    cloned.mkdir()
    (cloned / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
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

    def fake_repo_tree(path: str, *, agents, warnings, update_progress=None):
        tree_calls.append(path)
        return None, {"total": 1, "findings": [{"rule_id": "TF001", "severity": "high", "title": "test"}]}

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
    assert job.result.get("status") == "findings_only"
