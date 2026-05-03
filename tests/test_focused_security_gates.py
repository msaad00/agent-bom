from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.iac.models import IaCFinding, ScannerVerdict, ScanResult
from agent_bom.secret_scanner import SecretFinding, SecretScanResult


def test_secrets_command_exits_one_for_high_confidence_findings(tmp_path: Path):
    result_payload = SecretScanResult(
        findings=[
            SecretFinding(
                file_path=".env",
                line_number=1,
                secret_type="AWS Access Key",
                severity="critical",
                matched_preview="AWS Access Key",
                category="credential",
            )
        ],
        files_scanned=1,
    )

    with patch("agent_bom.secret_scanner.scan_secrets", return_value=result_payload):
        result = CliRunner().invoke(main, ["secrets", str(tmp_path)])

    assert result.exit_code == 1
    assert "AWS Access Key" in result.output


def test_secrets_command_json_writes_report_before_failing_gate(tmp_path: Path):
    result_payload = SecretScanResult(
        findings=[
            SecretFinding(
                file_path=".env",
                line_number=1,
                secret_type="GitHub Token",
                severity="critical",
                matched_preview="GitHub Token",
                category="credential",
            )
        ],
        files_scanned=1,
    )
    output = tmp_path / "secrets.json"

    with patch("agent_bom.secret_scanner.scan_secrets", return_value=result_payload):
        result = CliRunner().invoke(main, ["secrets", str(tmp_path), "--format", "json", "--output", str(output)])

    assert result.exit_code == 1
    assert output.exists()
    assert "Secrets report written" in result.output


def test_secrets_command_exits_zero_when_clean(tmp_path: Path):
    (tmp_path / "README.md").write_text("No credentials here.\n", encoding="utf-8")

    result = CliRunner().invoke(main, ["secrets", str(tmp_path)])

    assert result.exit_code == 0
    assert "No secrets or PII found" in result.output


def test_iac_command_exits_one_for_high_findings_by_default(tmp_path: Path):
    finding = IaCFinding(
        rule_id="TF-TEST",
        severity="high",
        title="Open storage",
        message="Bucket is public",
        file_path="main.tf",
        line_number=1,
        category="terraform",
    )

    _scan_result = ScanResult(findings=[finding], verdicts=[ScannerVerdict("terraform", "ran", 1)])
    with patch("agent_bom.iac.scan_iac_with_context", return_value=_scan_result):
        result = CliRunner().invoke(main, ["iac", str(tmp_path)])

    assert result.exit_code == 1
    assert "1 finding" in " ".join(result.output.split())


def test_iac_command_json_exits_one_for_high_findings_by_default(tmp_path: Path):
    finding = IaCFinding(
        rule_id="TF-TEST",
        severity="high",
        title="Open storage",
        message="Bucket is public",
        file_path="main.tf",
        line_number=1,
        category="terraform",
    )

    _scan_result = ScanResult(findings=[finding], verdicts=[ScannerVerdict("terraform", "ran", 1)])
    with patch("agent_bom.iac.scan_iac_with_context", return_value=_scan_result):
        result = CliRunner().invoke(main, ["iac", str(tmp_path), "--format", "json"])

    assert result.exit_code == 1
    assert '"rule_id": "TF-TEST"' in result.output


def test_iac_command_exits_zero_when_clean(tmp_path: Path):
    _scan_result = ScanResult(findings=[], verdicts=[])
    with patch("agent_bom.iac.scan_iac_with_context", return_value=_scan_result):
        result = CliRunner().invoke(main, ["iac", str(tmp_path)])

    assert result.exit_code == 0
    assert "no misconfigurations" in " ".join(result.output.split())
