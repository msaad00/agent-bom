"""Tests for agent_bom.cli._policy to improve coverage."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._policy import apply_command, policy_template

# ---------------------------------------------------------------------------
# policy_template
# ---------------------------------------------------------------------------


def test_policy_template_default(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(policy_template, [])
        assert result.exit_code == 0
        assert Path("policy.json").exists()
        data = json.loads(Path("policy.json").read_text())
        assert "rules" in data


def test_policy_template_custom_path(tmp_path):
    runner = CliRunner()
    out = tmp_path / "custom.json"
    result = runner.invoke(policy_template, ["-o", str(out)])
    assert result.exit_code == 0
    assert out.exists()


def test_policy_templates_aliases(tmp_path):
    runner = CliRunner()
    top_level = tmp_path / "top.json"
    grouped = tmp_path / "grouped.json"

    result = runner.invoke(main, ["policy-templates", "-o", str(top_level)])
    assert result.exit_code == 0
    assert top_level.exists()

    result = runner.invoke(main, ["policy", "templates", "-o", str(grouped)])
    assert result.exit_code == 0
    assert grouped.exists()


# ---------------------------------------------------------------------------
# apply_command
# ---------------------------------------------------------------------------


def test_apply_no_fixes(tmp_path):
    runner = CliRunner()
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps({"blast_radius": []}))

    mock_result = MagicMock()
    mock_result.applied = []
    mock_result.skipped = []
    mock_result.dry_run = False
    mock_result.backed_up = []

    with patch("agent_bom.remediate.apply_fixes_from_json", return_value=mock_result):
        result = runner.invoke(apply_command, [str(scan), "-d", str(tmp_path), "-y"])
        assert result.exit_code == 0
        assert "No fixable" in result.output


def test_apply_dry_run(tmp_path):
    runner = CliRunner()
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps({"blast_radius": []}))

    mock_fix = MagicMock()
    mock_fix.package = "lodash"
    mock_fix.current_version = "4.17.20"
    mock_fix.fixed_version = "4.17.22"
    mock_fix.ecosystem = "npm"

    mock_result = MagicMock()
    mock_result.applied = [mock_fix]
    mock_result.skipped = []
    mock_result.dry_run = True
    mock_result.backed_up = []

    with patch("agent_bom.remediate.apply_fixes_from_json", return_value=mock_result):
        result = runner.invoke(apply_command, [str(scan), "-d", str(tmp_path), "--dry-run"])
        assert result.exit_code == 0
        assert "Dry run" in result.output


def test_apply_with_skipped(tmp_path):
    runner = CliRunner()
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps({"blast_radius": []}))

    mock_fix = MagicMock()
    mock_fix.package = "missing-pkg"
    mock_fix.ecosystem = "npm"

    mock_result = MagicMock()
    mock_result.applied = []
    mock_result.skipped = [mock_fix]
    mock_result.dry_run = False
    mock_result.backed_up = []

    with patch("agent_bom.remediate.apply_fixes_from_json", return_value=mock_result):
        result = runner.invoke(apply_command, [str(scan), "-d", str(tmp_path), "-y"])
        assert result.exit_code == 0
        assert "Skipped" in result.output
