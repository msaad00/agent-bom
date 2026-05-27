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


def test_install_reference_dry_run_writes_verify_hint(tmp_path: Path):
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "scripts" / "deploy" / "install-eks-reference.sh"),
            "--cluster-name",
            "corp-ai",
            "--region",
            "us-east-1",
            "--state-dir",
            str(tmp_path),
            "--dry-run",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = tmp_path / "corp-ai" / "generated" / "operator-summary.txt"
    assert summary.exists()
    rendered = summary.read_text()
    assert "verify-eks-reference.sh" in rendered
    assert "--base-url http://localhost:8080" in rendered


def test_install_reference_rejects_oidc_without_hostname(tmp_path: Path):
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "scripts" / "deploy" / "install-eks-reference.sh"),
            "--cluster-name",
            "corp-ai",
            "--region",
            "us-east-1",
            "--state-dir",
            str(tmp_path),
            "--dry-run",
            "--oidc-issuer",
            "https://idp.example.com",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode != 0
    assert "--hostname is required when --oidc-issuer is set" in result.stderr


def test_install_reference_preflight_rejects_old_aws_version(tmp_path: Path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_fake_command(fake_bin, "aws", 'echo "aws-cli/2.10.0 Python/3.12.0 Linux/6.0 exe/x86_64"\n')
    _write_fake_command(fake_bin, "kubectl", 'echo "Client Version: v1.30.1"\n')
    _write_fake_command(fake_bin, "helm", 'echo "v3.15.0"\n')
    _write_fake_command(fake_bin, "eksctl", 'echo "0.180.0"\n')
    _write_fake_command(fake_bin, "terraform", 'echo "Terraform v1.6.0"\n')

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"

    result = subprocess.run(
        [
            "bash",
            str(ROOT / "scripts" / "deploy" / "install-eks-reference.sh"),
            "--cluster-name",
            "corp-ai",
            "--region",
            "us-east-1",
            "--state-dir",
            str(tmp_path / "state"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )

    assert result.returncode != 0
    assert "aws 2.15.0+ is required" in result.stderr


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


def test_install_reference_dry_run_gateway_summary_includes_gateway_verify(tmp_path: Path):
    result = subprocess.run(
        [
            "bash",
            str(ROOT / "scripts" / "deploy" / "install-eks-reference.sh"),
            "--cluster-name",
            "corp-ai",
            "--region",
            "us-east-1",
            "--state-dir",
            str(tmp_path),
            "--dry-run",
            "--enable-gateway",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = tmp_path / "corp-ai" / "generated" / "operator-summary.txt"
    rendered = summary.read_text()
    assert "--check-gateway" in rendered
