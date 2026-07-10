"""Tests for shallow-clone repo tree discovery passes."""

from __future__ import annotations

from pathlib import Path

from agent_bom.api.repo_tree_scan import scan_cloned_repo_tree


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

    skill_audit, iac_findings = scan_cloned_repo_tree(
        str(tmp_path),
        agents=agents,
        warnings=warnings,
        update_progress=progress.append,
    )

    assert progress
    assert skill_audit is not None
    assert iac_findings is not None
    assert iac_findings["total"] >= 1
    assert agents
