"""Tests for shallow-clone repo tree discovery passes."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent_bom.api.repo_tree_scan import RepoTreeScanResult, _scan_weak_crypto, scan_cloned_repo_tree
from agent_bom.sast import SASTExecutionStatus, SASTScanError


def test_scan_cloned_repo_tree_discovers_skills_and_iac(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "# Skill\n\n```bash\nnpx -y @modelcontextprotocol/server-filesystem /tmp\n```\n",
        encoding="utf-8",
    )
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n  bucket = "open-bucket"\n  acl    = "public-read"\n}\n',
        encoding="utf-8",
    )

    agents: list = []
    warnings: list[str] = []
    progress: list[str] = []

    result = scan_cloned_repo_tree(
        str(tmp_path),
        agents=agents,
        warnings=warnings,
        update_progress=progress.append,
    )

    assert isinstance(result, RepoTreeScanResult)
    assert progress
    assert result.skill_audit_data is not None
    assert result.iac_findings_data is not None
    assert result.iac_findings_data["total"] >= 1
    assert agents


def test_scan_cloned_repo_tree_parses_uv_lock_and_requirements(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "httpx"\nversion = "0.27.0"\n',
        encoding="utf-8",
    )

    agents: list = []
    result = scan_cloned_repo_tree(str(tmp_path), agents=agents, warnings=[])

    assert result.ai_inventory_data is not None
    inventory = result.ai_inventory_data["dependency_inventory"]
    assert inventory["package_count"] >= 1
    assert agents
    assert any(agent.name.startswith("repo-deps:") for agent in agents)


def test_scan_cloned_repo_tree_finds_secrets_and_weak_crypto(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        'API_KEY = "sk-test-abcdefghijklmnopqrstuvwxyz123456"\nimport hashlib\ndigest = hashlib.md5(data).hexdigest()\n',
        encoding="utf-8",
    )

    result = scan_cloned_repo_tree(str(tmp_path), agents=[], warnings=[])

    assert result.ai_inventory_data is not None
    assert result.ai_inventory_data.get("secrets", {}).get("total", 0) >= 1
    assert result.ai_inventory_data.get("weak_crypto", {}).get("total", 0) >= 1


def test_scan_cloned_repo_tree_discovers_jupyter_notebooks(tmp_path: Path) -> None:
    notebook = {
        "cells": [
            {
                "cell_type": "code",
                "metadata": {},
                "source": ["import openai\n", "client = openai.OpenAI()\n"],
                "outputs": [],
                "execution_count": None,
            }
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    import json

    (tmp_path / "analysis.ipynb").write_text(json.dumps(notebook), encoding="utf-8")

    agents: list = []
    scan_cloned_repo_tree(str(tmp_path), agents=agents, warnings=[])

    assert any(agent.source == "jupyter" or "jupyter" in agent.name.lower() for agent in agents)


def test_scan_weak_crypto_skips_test_files(tmp_path: Path) -> None:
    (tmp_path / "test_app.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    (tmp_path / "service.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")

    result = _scan_weak_crypto(tmp_path)

    assert result.total == 1
    assert result.findings[0].file_path == "service.py"


def test_repo_tree_persists_clean_sast_execution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from agent_bom.sast import SASTResult

    monkeypatch.setattr("agent_bom.sast.scan_code", lambda *_args, **_kwargs: ([], SASTResult()))

    result = scan_cloned_repo_tree(str(tmp_path), agents=[], warnings=[])

    assert result.sast_data is not None
    assert result.sast_data["execution_status"] == "clean"
    assert result.sast_data["scanner_driver_id"] == "sast-semgrep"


def test_repo_tree_persists_skipped_sast_execution_without_invoking_remote_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    run_mock = MagicMock()
    monkeypatch.setattr("agent_bom.sast.subprocess.run", run_mock)
    monkeypatch.setattr("agent_bom.sast.shutil.which", lambda _: "/usr/bin/semgrep")

    result = scan_cloned_repo_tree(str(tmp_path), agents=[], warnings=[], offline=True)

    assert result.sast_data is not None
    assert result.sast_data["execution_status"] == "skipped"
    assert result.sast_data["status_reason"] == "offline_remote_config"
    assert result.sast_data["status_detail"] == "SAST skipped because offline mode disallows registry-backed rules."
    run_mock.assert_not_called()


def test_repo_tree_persists_sanitized_failed_sast_execution(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret = "token=super-secret-value"

    def fail_scan(*_args, **_kwargs):
        raise SASTScanError(f"semgrep crashed with {secret}", reason_code="semgrep_failed")

    monkeypatch.setattr("agent_bom.sast.scan_code", fail_scan)
    warnings: list[str] = []

    result = scan_cloned_repo_tree(str(tmp_path), agents=[], warnings=warnings)

    assert result.sast_data is not None
    assert result.sast_data["execution_status"] == "failed"
    assert result.sast_data["status_reason"] == "semgrep_failed"
    assert secret not in result.sast_data["status_detail"]
    assert secret not in "\n".join(warnings)
    assert result.sast_data["status_detail"] == "An internal error occurred. Please contact support."


def test_repo_tree_preserves_explicit_skip_classification(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def skip_scan(*_args, **_kwargs):
        raise SASTScanError(
            "semgrep unavailable",
            execution_status=SASTExecutionStatus.SKIPPED,
            reason_code="semgrep_unavailable",
        )

    monkeypatch.setattr("agent_bom.sast.scan_code", skip_scan)

    result = scan_cloned_repo_tree(str(tmp_path), agents=[], warnings=[])

    assert result.sast_data is not None
    assert result.sast_data["execution_status"] == "skipped"
    assert result.sast_data["status_reason"] == "semgrep_unavailable"
