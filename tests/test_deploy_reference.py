from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _write_fake_command(bin_dir: Path, name: str, body: str) -> None:
    path = bin_dir / name
    path.write_text("#!/bin/sh\nset -eu\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def test_legacy_eks_reference_installer_fails_closed_without_aws_access(tmp_path: Path):
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "scripts" / "deploy" / "install-eks-reference.sh"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "legacy EKS reference installer has been retired" in result.stderr
    assert "scripts/deploy/install.sh eks" in result.stderr
    assert "RDS-managed master credential" in result.stderr
    assert not any(tmp_path.iterdir())


def test_unified_eks_installer_fails_before_apply_without_operator_config() -> None:
    result = subprocess.run(
        ["bash", str(ROOT / "scripts" / "deploy" / "install.sh"), "eks", "--dry-run"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "terraform.tfvars.example" in result.stderr
    assert "configure it first" in result.stderr
    assert "terraform apply" not in result.stdout


def test_public_docs_do_not_advertise_retired_eks_cli_flags() -> None:
    public_roots = (
        ROOT / "README.md",
        ROOT / "docs",
        ROOT / "site-docs",
        ROOT / "deploy" / "RUNBOOK.md",
        ROOT / "deploy" / "terraform",
    )
    stale = []
    for root in public_roots:
        paths = (root,) if root.is_file() else tuple(root.rglob("*.md"))
        for path in paths:
            text = path.read_text(encoding="utf-8")
            stale_contracts = (
                "install.sh eks --create-cluster",
                "install-eks-reference.sh",
                "~/.agent-bom/eks-reference",
                "controlPlane.api.envFrom` | loads Postgres",
                "teardown-eks-reference.sh",
            )
            if any(contract in text for contract in stale_contracts):
                stale.append(str(path.relative_to(ROOT)))
    assert stale == []


def test_verify_wrapper_script_exists_and_parses():
    script_path = ROOT / "scripts" / "deploy" / "verify-eks-reference.sh"
    result = subprocess.run(
        ["bash", "-n", str(script_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert script_path.exists()
    assert result.returncode == 0, result.stderr


def test_verify_reference_writes_evidence_artifacts(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_fake_command(fake_bin, "aws", "exit 0\n")
    _write_fake_command(fake_bin, "helm", "exit 0\n")
    _write_fake_command(fake_bin, "kubectl", "exit 0\n")
    _write_fake_command(
        fake_bin,
        "curl",
        r"""
out=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) shift 2 ;;
    -sS) shift ;;
    -H) shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
case "$url" in
  */healthz) printf '{"status":"ok"}' > "$out" ;;
  */v1/auth/debug) printf '{"method":"api_key"}' > "$out" ;;
  *) printf '<html>agent-bom dashboard</html>' > "$out" ;;
esac
printf "200"
""",
    )

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    evidence_dir = tmp_path / "evidence"

    result = subprocess.run(
        [
            "bash",
            str(ROOT / "scripts" / "deploy" / "verify-eks-reference.sh"),
            "--cluster-name",
            "corp-ai",
            "--region",
            "us-east-1",
            "--base-url",
            "https://agent-bom.example.com",
            "--api-key",
            "test-key",
            "--evidence-dir",
            str(evidence_dir),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode == 0, result.stderr
    assert (evidence_dir / "verify-eks-reference.log").exists()
    assert (evidence_dir / "healthz.json").read_text() == '{"status":"ok"}'
    assert "agent-bom dashboard" in (evidence_dir / "ui-root.html").read_text()
    assert (evidence_dir / "auth-debug.json").read_text() == '{"method":"api_key"}'
    summary = (evidence_dir / "summary.md").read_text()
    assert "status: passed" in summary
    assert "base_url: https://agent-bom.example.com" in summary
    assert "- auth-debug.json" in summary
