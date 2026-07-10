"""Tests for project/repo auto-detect scan target expansion."""

from __future__ import annotations

from pathlib import Path

from agent_bom.repo_auto_detect import expand_project_scan_targets, project_has_notebooks


def test_expand_project_scan_targets_auto_jupyter_and_terraform(tmp_path: Path) -> None:
    (tmp_path / "notebooks" / "analysis.ipynb").parent.mkdir(parents=True)
    (tmp_path / "notebooks" / "analysis.ipynb").write_text("{}", encoding="utf-8")
    (tmp_path / "infra.tf").write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("langchain==0.2.0\n", encoding="utf-8")
    (tmp_path / ".github" / "workflows" / "ci.yml").parent.mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")

    targets = expand_project_scan_targets(str(tmp_path))

    assert "jupyter" in targets.auto_enabled
    assert "terraform" in targets.auto_enabled
    assert "github_actions" in targets.auto_enabled
    assert "python_agents" in targets.auto_enabled
    assert "ai_inventory" in targets.auto_enabled
    assert targets.jupyter_dirs == (str(tmp_path),)
    assert targets.tf_dirs == (str(tmp_path),)
    assert targets.gha_path == str(tmp_path)
    assert targets.ai_inventory_paths == (str(tmp_path),)


def test_expand_project_scan_targets_respects_explicit_jupyter(tmp_path: Path) -> None:
    (tmp_path / "analysis.ipynb").write_text("{}", encoding="utf-8")
    custom = tmp_path / "custom"
    custom.mkdir()

    targets = expand_project_scan_targets(str(tmp_path), jupyter_dirs=(str(custom),))

    assert targets.jupyter_dirs == (str(custom),)
    assert "jupyter" not in targets.auto_enabled


def test_project_has_notebooks_skips_checkpoints(tmp_path: Path) -> None:
    checkpoints = tmp_path / ".ipynb_checkpoints" / "draft-checkpoint.ipynb"
    checkpoints.parent.mkdir(parents=True)
    checkpoints.write_text("{}", encoding="utf-8")
    assert project_has_notebooks(tmp_path) is False

    (tmp_path / "live.ipynb").write_text("{}", encoding="utf-8")
    assert project_has_notebooks(tmp_path) is True


def test_expand_project_scan_targets_auto_sast_when_semgrep_available(
    tmp_path: Path, monkeypatch
) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    monkeypatch.setattr("agent_bom.repo_auto_detect.semgrep_available", lambda: True)

    targets = expand_project_scan_targets(str(tmp_path))

    assert "sast" in targets.auto_enabled
    assert targets.code_paths == (str(tmp_path),)


def test_expand_project_scan_targets_auto_prompts_in_subdir(tmp_path: Path) -> None:
    prompts_dir = tmp_path / "prompts" / "support"
    prompts_dir.mkdir(parents=True)
    (prompts_dir / "system_prompt.txt").write_text("You are a helpful assistant.\n", encoding="utf-8")

    targets = expand_project_scan_targets(str(tmp_path))

    assert "prompts" in targets.auto_enabled
    assert targets.scan_prompts is True


def test_repo_static_surface_catalog_lists_api_surfaces() -> None:
    from agent_bom.repo_auto_detect import repo_static_surface_catalog

    catalog = repo_static_surface_catalog()
    ids = {entry["id"] for entry in catalog}
    assert "secrets" in ids
    assert "jupyter" in ids
    assert "ai_inventory" in ids
    assert any(entry["api_repo_tree"] for entry in catalog)


def test_expand_project_scan_targets_respects_explicit_ai_inventory(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langchain==0.2.0\n", encoding="utf-8")
    custom = tmp_path / "custom"
    custom.mkdir()

    targets = expand_project_scan_targets(str(tmp_path), ai_inventory_paths=(str(custom),))

    assert targets.ai_inventory_paths == (str(custom),)
    assert "ai_inventory" not in targets.auto_enabled
    assert "python_agents" in targets.auto_enabled
