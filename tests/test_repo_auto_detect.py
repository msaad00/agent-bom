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


def test_expand_project_scan_targets_auto_sast_when_semgrep_available(tmp_path: Path, monkeypatch) -> None:
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


def test_expand_project_scan_targets_auto_iac_in_subdir(tmp_path: Path) -> None:
    """IaC nested below the project root must be auto-detected.

    ``tf_dirs`` detection has always been recursive, so a repo with
    ``infra/main.tf`` reported ``terraform`` as a completed scan source while
    the IaC rules — gated behind a top-level-only glob — never ran.
    """
    (tmp_path / "infra").mkdir()
    (tmp_path / "infra" / "main.tf").write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")

    targets = expand_project_scan_targets(str(tmp_path))

    assert "iac" in targets.auto_enabled
    assert targets.iac_paths == (str(tmp_path),)
    # The recursive terraform surface and the IaC surface must agree.
    assert "terraform" in targets.auto_enabled


def test_expand_project_scan_targets_auto_iac_covers_non_terraform_formats(tmp_path: Path) -> None:
    """Dockerfile / K8s / Helm nested anywhere count as IaC, not just ``*.tf``."""
    for relative, body in (
        ("deploy/Dockerfile.prod", "FROM python:3.13\nUSER root\n"),
        ("charts/app/values.yaml", "image:\n  tag: latest\n"),
        ("k8s/deployment.yaml", "apiVersion: apps/v1\nkind: Deployment\n"),
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
        targets = expand_project_scan_targets(str(tmp_path))
        assert "iac" in targets.auto_enabled, f"{relative} was not detected as IaC"
        target.unlink()


def test_expand_project_scan_targets_no_iac_when_tree_has_none(tmp_path: Path) -> None:
    """Detection must not fire on a plain source tree (no false scan source)."""
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# hi\n", encoding="utf-8")

    targets = expand_project_scan_targets(str(tmp_path))

    assert "iac" not in targets.auto_enabled
    assert targets.iac_paths == ()


def test_expand_project_scan_targets_respects_explicit_iac(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "x" {}\n', encoding="utf-8")
    custom = tmp_path / "custom"
    custom.mkdir()

    targets = expand_project_scan_targets(str(tmp_path), iac_paths=(str(custom),))

    assert targets.iac_paths == (str(custom),)
    assert "iac" not in targets.auto_enabled


def test_iac_detection_agrees_with_the_scanner_dispatch(tmp_path: Path) -> None:
    """Auto-detect and the scanner must share one definition of "is IaC".

    If they drift, the CLI can again report a scan source whose rules never
    ran. ``is_iac_file`` is that single source of truth.
    """
    from agent_bom.iac import is_iac_file, scan_iac_with_context

    tf = tmp_path / "infra" / "main.tf"
    tf.parent.mkdir()
    tf.write_text('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n', encoding="utf-8")

    assert is_iac_file(tf, tmp_path) is True
    assert is_iac_file(tmp_path / "notes.md", tmp_path) is False
    # The scanner really dispatches terraform for this tree.
    verdicts = {v.scanner_id: v.status for v in scan_iac_with_context(tmp_path).verdicts}
    assert verdicts["terraform"] == "ran"


def test_repo_static_surface_catalog_marks_iac_as_cli_auto() -> None:
    """The published catalog must not claim IaC is API-only once the CLI runs it."""
    from agent_bom.repo_auto_detect import repo_static_surface_catalog

    iac = next(entry for entry in repo_static_surface_catalog() if entry["id"] == "iac")
    assert iac["cli_auto_key"] == "iac"
    assert iac["api_repo_tree"] is True


def test_expand_project_scan_targets_respects_explicit_ai_inventory(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("langchain==0.2.0\n", encoding="utf-8")
    custom = tmp_path / "custom"
    custom.mkdir()

    targets = expand_project_scan_targets(str(tmp_path), ai_inventory_paths=(str(custom),))

    assert targets.ai_inventory_paths == (str(custom),)
    assert "ai_inventory" not in targets.auto_enabled
    assert "python_agents" in targets.auto_enabled
