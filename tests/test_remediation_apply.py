"""Tests for guarded remediation apply workflow."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from agent_bom.remediation_apply import RemediationApplyError, apply_remediation_plan


def _run(args: list[str], cwd: Path) -> None:
    subprocess.run(args, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def _init_repo(path: Path) -> None:
    _run(["git", "init"], path)
    _run(["git", "config", "user.email", "test@example.com"], path)
    _run(["git", "config", "user.name", "agent-bom test"], path)


def _npm_plan_item() -> dict:
    return {
        "package": "express",
        "ecosystem": "npm",
        "current": "4.17.1",
        "fix": "4.21.0",
        "priority": "P1",
        "vulns": ["GHSA-test-0001"],
        "agents": ["claude-desktop"],
        "references": ["https://github.com/advisories/GHSA-test-0001"],
        "blast_radius_score": 8.5,
        "has_kev": False,
    }


def _pip_plan_item(package: str = "flask", current: str = "2.0.0", fixed: str = "3.0.0") -> dict:
    return {
        "package": package,
        "ecosystem": "pypi",
        "current": current,
        "fix": fixed,
        "priority": "P1",
        "vulns": ["CVE-test-0001"],
        "agents": ["cursor"],
        "references": ["https://example.invalid/CVE-test-0001"],
        "blast_radius_score": 7.0,
        "has_kev": False,
    }


def test_apply_remediation_plan_updates_clean_repo_and_writes_audit(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    package_json = tmp_path / "package.json"
    package_json.write_text(json.dumps({"dependencies": {"express": "^4.17.1"}}, indent=2) + "\n")
    _run(["git", "add", "package.json"], tmp_path)
    _run(["git", "commit", "-m", "fixture"], tmp_path)

    audit_log = tmp_path / "audit.jsonl"
    outcome = apply_remediation_plan([_npm_plan_item()], project_dir=tmp_path, backup=False, audit_log_path=audit_log)

    assert outcome.apply_result.applied[0].package == "express"
    assert outcome.changed_files == ["package.json"]
    assert json.loads(package_json.read_text())["dependencies"]["express"] == "^4.21.0"
    audit = [json.loads(line) for line in audit_log.read_text().splitlines()]
    assert audit[-1]["status"] == "success"
    assert audit[-1]["packages"][0]["package"] == "express"


def test_apply_remediation_plan_refuses_dirty_worktree_and_audits(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.17.1"}}))
    _run(["git", "add", "package.json"], tmp_path)
    _run(["git", "commit", "-m", "fixture"], tmp_path)
    (tmp_path / "untracked.txt").write_text("dirty")

    audit_log = tmp_path / "audit.jsonl"
    with pytest.raises(RemediationApplyError, match="dirty worktree"):
        apply_remediation_plan([_npm_plan_item()], project_dir=tmp_path, audit_log_path=audit_log)

    audit = [json.loads(line) for line in audit_log.read_text().splitlines()]
    assert audit[-1]["status"] == "refused"
    assert audit[-1]["reason"] == "dirty_worktree"


def test_apply_remediation_plan_discovers_nested_tracked_pyproject(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    nested = tmp_path / "services" / "api"
    nested.mkdir(parents=True)
    pyproject = nested / "pyproject.toml"
    pyproject.write_text('[project]\nname = "api"\ndependencies = [\n    "flask==2.0.0",\n]\n')
    _run(["git", "add", "services/api/pyproject.toml"], tmp_path)
    _run(["git", "commit", "-m", "fixture"], tmp_path)

    outcome = apply_remediation_plan([_pip_plan_item()], project_dir=tmp_path, backup=False)

    assert [fix.package for fix in outcome.apply_result.applied] == ["flask"]
    assert outcome.changed_files == ["services/api/pyproject.toml"]
    assert '"flask>=3.0.0"' in pyproject.read_text()


def test_apply_remediation_plan_fails_when_no_advertised_fix_is_applicable(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "fixture"\ndependencies = ["requests==2.31.0"]\n')
    _run(["git", "add", "pyproject.toml"], tmp_path)
    _run(["git", "commit", "-m", "fixture"], tmp_path)

    audit_log = tmp_path / "audit.jsonl"
    with pytest.raises(RemediationApplyError, match="flask.*not a direct dependency"):
        apply_remediation_plan([_pip_plan_item()], project_dir=tmp_path, backup=False, audit_log_path=audit_log)

    audit = [json.loads(line) for line in audit_log.read_text().splitlines()]
    assert audit[-1]["status"] == "no_applicable_dependency_updates"
