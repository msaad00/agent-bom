from __future__ import annotations

from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from agent_bom.cli import main
from agent_bom.cli._focused_commands import _has_finding_at_or_above
from agent_bom.cli.agents._preflight import run_iac_only_scan
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


def test_secrets_command_accepts_offline_flag_as_noop(tmp_path: Path):
    # `--offline` is accepted for parity with scan; secret scanning is always
    # local so it neither errors (exit 2 usage error) nor changes the result.
    (tmp_path / "README.md").write_text("No credentials here.\n", encoding="utf-8")

    result = CliRunner().invoke(main, ["secrets", str(tmp_path), "--offline"])

    assert result.exit_code == 0
    assert "No secrets or PII found" in result.output


def test_secrets_offline_flag_listed_in_help():
    result = CliRunner().invoke(main, ["secrets", "--help"])

    assert result.exit_code == 0
    assert "--offline" in result.output


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


def test_iac_command_json_exits_one_for_high_findings_by_default(monkeypatch, tmp_path: Path):
    profile_config = tmp_path / "config.toml"
    profile_output = tmp_path / "profile-report.json"
    profile_config.write_text(
        f"""
current_profile = "prod"

[profiles.prod]
format = "json"
output = "{profile_output}"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(profile_config))

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
    assert not profile_output.exists()


def test_iac_command_exits_zero_when_clean(tmp_path: Path):
    _scan_result = ScanResult(findings=[], verdicts=[])
    with patch("agent_bom.iac.scan_iac_with_context", return_value=_scan_result):
        result = CliRunner().invoke(main, ["iac", str(tmp_path)])

    assert result.exit_code == 0
    assert "no misconfigurations" in " ".join(result.output.split())


def test_focused_gate_uses_canonical_severity_order():
    findings = [SimpleNamespace(severity="medium"), SimpleNamespace(severity="unknown")]

    assert _has_finding_at_or_above(findings, "medium") is True
    assert _has_finding_at_or_above(findings, "high") is False


def test_iac_preflight_gate_uses_canonical_severity_order(tmp_path: Path):
    finding = IaCFinding(
        rule_id="TF-TEST",
        severity="medium",
        title="Open storage",
        message="Bucket is public",
        file_path="main.tf",
        line_number=1,
        category="terraform",
    )
    scan_result = ScanResult(findings=[finding], verdicts=[ScannerVerdict("terraform", "ran", 1)])

    with patch("agent_bom.iac.scan_iac_with_context", return_value=scan_result):
        run_iac_only_scan(
            con=Console(file=StringIO(), force_terminal=False),
            iac_paths=(str(tmp_path),),
            k8s_live=False,
            k8s_live_namespace="default",
            k8s_live_all_namespaces=False,
            k8s_live_context=None,
            output=None,
            output_format="console",
            no_tree=False,
            quiet=True,
            no_color=True,
            open_report=False,
            compliance_export=None,
            mermaid_mode="auto",
            push_gateway=None,
            otel_endpoint=None,
            baseline=None,
            delta_mode=False,
            verbose=False,
            exclude_unfixable=False,
            fixable_only=False,
            fail_on_severity="high",
        )

    with patch("agent_bom.iac.scan_iac_with_context", return_value=scan_result):
        with pytest.raises(SystemExit):
            run_iac_only_scan(
                con=Console(file=StringIO(), force_terminal=False),
                iac_paths=(str(tmp_path),),
                k8s_live=False,
                k8s_live_namespace="default",
                k8s_live_all_namespaces=False,
                k8s_live_context=None,
                output=None,
                output_format="console",
                no_tree=False,
                quiet=True,
                no_color=True,
                open_report=False,
                compliance_export=None,
                mermaid_mode="auto",
                push_gateway=None,
                otel_endpoint=None,
                baseline=None,
                delta_mode=False,
                verbose=False,
                exclude_unfixable=False,
                fixable_only=False,
                fail_on_severity="medium",
            )


def test_drop_unfixable_drops_findings_without_fix():
    """--exclude-unfixable removes findings with no available fix (gate parity)."""
    from unittest.mock import MagicMock

    from agent_bom.ignores import drop_unfixable

    fixable = MagicMock()
    fixable.vulnerability.fixed_version = "2.0.0"
    unfixable = MagicMock()
    unfixable.vulnerability.fixed_version = None
    empty_fix = MagicMock()
    empty_fix.vulnerability.fixed_version = "  "

    kept, dropped = drop_unfixable([fixable, unfixable, empty_fix])
    assert kept == [fixable]
    assert dropped == 2


def test_image_and_fs_expose_ignore_and_exclude_unfixable():
    """Both focused gates expose --ignore and --exclude-unfixable (wiring guard)."""
    for cmd in ("image", "fs"):
        result = CliRunner().invoke(main, [cmd, "--help"])
        assert result.exit_code == 0
        assert "--ignore" in result.output
        assert "--exclude-unfixable" in result.output


# ── Focused-command --format validation (CI-gate bypass guard) ───────────────


@pytest.mark.parametrize("command", ["fs", "iac", "sbom", "image"])
def test_focused_bad_format_is_rejected_rc2(command: str, tmp_path: Path):
    """A bogus -f must be rejected (rc=2) like `scan`, not accepted as a free
    string that silently disables the default fail-on-severity gate."""
    target = tmp_path / "target"
    if command == "sbom":
        target.write_text("{}", encoding="utf-8")
        args = [command, str(target), "-f", "bogus"]
    elif command == "image":
        args = [command, "nginx:latest", "-f", "bogus"]
    elif command == "iac":
        target.write_text("FROM ubuntu:latest\n", encoding="utf-8")
        args = [command, str(target), "-f", "bogus"]
    else:  # fs
        target.mkdir()
        args = [command, str(target), "-f", "bogus"]

    result = CliRunner().invoke(main, args)

    assert result.exit_code == 2, result.output
    assert "bogus" in result.output


@pytest.mark.parametrize("command", ["fs", "iac", "sbom", "image"])
def test_focused_valid_format_is_accepted(command: str):
    """The now-restricted choice must still advertise the shared scan formats."""
    result = CliRunner().invoke(main, [command, "--help"])
    assert result.exit_code == 0
    for fmt in ("console", "json", "sarif"):
        assert fmt in result.output


def test_iac_missing_path_errors_nonzero(tmp_path: Path):
    """A missing/typo'd IaC path must error, never report a clean pass."""
    missing = tmp_path / "does-not-exist.tf"
    result = CliRunner().invoke(main, ["iac", str(missing)])
    assert result.exit_code != 0
    assert "no misconfigurations" not in result.output


def test_image_missing_tar_errors_nonzero(tmp_path: Path):
    """A missing --tar image path must be rejected, not silently scanned."""
    missing = tmp_path / "nope.tar"
    result = CliRunner().invoke(main, ["image", "--tar", str(missing)])
    assert result.exit_code == 2
