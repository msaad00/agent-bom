from __future__ import annotations

import subprocess
from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.deploy_teardown import (
    build_reference_teardown_plan,
    format_teardown_plan,
    validate_teardown_plan,
)


def test_build_reference_teardown_plan_formats_expected_steps(tmp_path: Path):
    plan = build_reference_teardown_plan(
        cluster_name="corp-ai",
        region="us-east-1",
        namespace="agent-bom",
        release_name="agent-bom",
        state_dir=tmp_path,
        delete_namespace=True,
        delete_local_state=True,
        terraform_bin="terraform",
    )

    rendered = format_teardown_plan(plan)
    assert "helm uninstall agent-bom --namespace agent-bom" in rendered
    assert "kubectl delete namespace agent-bom --ignore-not-found=true" in rendered
    assert f"terraform -chdir={tmp_path / 'corp-ai' / 'terraform'} destroy -auto-approve" in rendered
    assert "Platform-owned surfaces left untouched:" in rendered
    assert "EKS cluster and node groups" in rendered


def test_validate_teardown_plan_reports_missing_binaries_and_state(tmp_path: Path, monkeypatch):
    plan = build_reference_teardown_plan(
        cluster_name="corp-ai",
        region="us-east-1",
        namespace="agent-bom",
        release_name="agent-bom",
        state_dir=tmp_path,
        terraform_bin="terraform",
    )

    monkeypatch.setattr("shutil.which", lambda _name: None)
    errors = validate_teardown_plan(plan, dry_run=False)

    assert "helm is required to uninstall the release" in errors
    assert "kubectl is required for namespace wait/delete operations" in errors
    assert "terraform is required to destroy the AWS baseline" in errors
    assert f"terraform root does not exist: {tmp_path / 'corp-ai' / 'terraform'}" in errors


def test_cli_teardown_dry_run_writes_summary(tmp_path: Path):
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "teardown",
            "--cluster-name",
            "corp-ai",
            "--region",
            "us-east-1",
            "--state-dir",
            str(tmp_path),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "agent-bom teardown plan" in result.output
    assert "+ helm uninstall agent-bom --namespace agent-bom" in result.output
    assert "+ terraform" in result.output
    assert (tmp_path / "corp-ai" / "generated" / "teardown-summary.txt").exists()


def test_cli_teardown_runs_expected_commands(tmp_path: Path, monkeypatch):
    terraform_root = tmp_path / "corp-ai" / "terraform"
    terraform_root.mkdir(parents=True)

    commands: list[tuple[str, ...]] = []

    def fake_run(cmd: tuple[str, ...] | list[str], check: bool = True, timeout: int | None = None):
        assert timeout is not None
        commands.append(tuple(cmd))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr("shutil.which", lambda name: name)
    monkeypatch.setattr("subprocess.run", fake_run)

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "teardown",
            "--cluster-name",
            "corp-ai",
            "--region",
            "us-east-1",
            "--state-dir",
            str(tmp_path),
            "--yes",
        ],
    )

    assert result.exit_code == 0
    assert ("helm", "uninstall", "agent-bom", "--namespace", "agent-bom") in commands
    assert (
        "kubectl",
        "wait",
        "--for=delete",
        "pod,job",
        "--all",
        "--namespace",
        "agent-bom",
        "--timeout=180s",
    ) in commands
    assert ("terraform", f"-chdir={terraform_root}", "destroy", "-auto-approve") in commands


def test_teardown_wrapper_script_exists():
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "deploy" / "teardown-eks-reference.sh"
    assert script_path.exists()
