"""Regression tests for the PR gate, action, and focused SARIF contracts."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import AIBOMReport
from agent_bom.output.sarif import to_sarif

ROOT = Path(__file__).resolve().parents[1]


def test_pr_security_gate_uses_real_self_scan_sarif_not_fixture() -> None:
    workflow = (ROOT / ".github/workflows/pr-security-gate.yml").read_text(encoding="utf-8")

    assert "tests/fixtures/test-sbom.cdx.json" not in workflow
    assert "|| true" not in workflow
    assert "agent-bom scan --self-scan" in workflow
    assert "--format sarif" in workflow
    assert "--fail-on-severity high" in workflow
    assert yaml.safe_load(workflow)["jobs"]["self-scan-pr"]


def test_action_rejects_secrets_and_code_sarif_or_gate_contracts() -> None:
    action_text = (ROOT / "action.yml").read_text(encoding="utf-8")
    action = yaml.safe_load(action_text)
    scan_step = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    run_script = scan_step["run"]

    assert "INPUT_UPLOAD_SARIF" in scan_step["env"]
    assert "fail_unsupported_focused_mode" in run_script
    assert "scan-type=$INPUT_SCAN_TYPE does not support SARIF upload or vulnerability gates" in run_script
    assert '[ "$INPUT_SCAN_TYPE" = "secrets" ] || [ "$INPUT_SCAN_TYPE" = "code" ]' in run_script
    assert '[ "$INPUT_SCAN_TYPE" != "secrets" ] && [ "$INPUT_SCAN_TYPE" != "code" ]' in run_script


def test_focused_secrets_and_code_reject_sarif_format(tmp_path: Path) -> None:
    runner = CliRunner()

    secrets = runner.invoke(main, ["secrets", str(tmp_path), "-f", "sarif", "-o", str(tmp_path / "secrets.sarif")])
    assert secrets.exit_code != 0
    assert "SARIF output and vulnerability gates are not supported" in secrets.output
    assert not (tmp_path / "secrets.sarif").exists()

    code = runner.invoke(main, ["code", str(tmp_path), "-f", "sarif", "-o", str(tmp_path / "code.sarif")])
    assert code.exit_code != 0
    assert "SARIF output and vulnerability gates are not supported" in code.output
    assert not (tmp_path / "code.sarif").exists()


def test_iac_sarif_output_path_writes_valid_sarif(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM python:latest\nUSER root\n", encoding="utf-8")
    output = tmp_path / "iac-results.sarif"

    result = CliRunner().invoke(main, ["iac", str(tmp_path), "-f", "sarif", "-o", str(output), "--quiet"])

    assert result.exit_code == 0, result.output
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "agent-bom"
    assert data["runs"][0]["results"]
    assert data["runs"][0]["results"][0]["ruleId"].startswith("iac/")


def test_sarif_sanitizes_unified_finding_evidence_at_sink() -> None:
    token = "sk-" + "live-" + "1234567890" + "abcdef"
    report = AIBOMReport(
        findings=[
            Finding(
                finding_type=FindingType.SAST,
                source=FindingSource.SAST,
                asset=Asset(name="app", asset_type="source", location="/Users/alice/prod-secrets/app.py"),
                severity="high",
                title="Unsafe credential flow",
                evidence={
                    "api_key": token,
                    "path": "/Users/alice/prod-secrets/app.py",
                    "url": "https://alice:secret@example.com/hook?token=secret",
                },
                remediation_guidance=f"Rotate {token}",
            )
        ]
    )

    encoded = json.dumps(to_sarif(report), sort_keys=True)

    assert token not in encoded
    assert "/Users/alice/prod-secrets" not in encoded
    assert "alice:secret" not in encoded
    assert "***REDACTED***" in encoded
    assert "<path:app.py>" in encoded
