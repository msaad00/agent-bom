"""Tests for shallow-clone repo tree discovery passes."""

from __future__ import annotations

from pathlib import Path

from agent_bom.api.repo_tree_scan import RepoTreeScanResult, _scan_weak_crypto, scan_cloned_repo_tree


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
        'API_KEY = "sk-test-abcdefghijklmnopqrstuvwxyz123456"\n'
        "import hashlib\n"
        "digest = hashlib.md5(data).hexdigest()\n",
        encoding="utf-8",
    )

    result = scan_cloned_repo_tree(str(tmp_path), agents=[], warnings=[])

    assert result.ai_inventory_data is not None
    assert result.ai_inventory_data.get("secrets", {}).get("total", 0) >= 1
    assert result.ai_inventory_data.get("weak_crypto", {}).get("total", 0) >= 1


def test_scan_weak_crypto_skips_test_files(tmp_path: Path) -> None:
    (tmp_path / "test_app.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    (tmp_path / "service.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")

    result = _scan_weak_crypto(tmp_path)

    assert result.total == 1
    assert result.findings[0].file_path == "service.py"
