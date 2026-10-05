"""Unreadable project trees retain collected evidence and report coverage gaps."""

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.parsers import scan_project_directory
from agent_bom.scanners.state import peek_coverage_warnings, reset_scan_warnings


@pytest.fixture(autouse=True)
def isolated_coverage_state():
    reset_scan_warnings()
    yield
    reset_scan_warnings()


@pytest.mark.parametrize("operation", ["exists", "iterdir", "resolve"])
def test_manifest_probe_failure_keeps_accessible_sibling(tmp_path, monkeypatch, operation):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    good = tmp_path / "good"
    good.mkdir()
    (good / "requirements.txt").write_text("requests==2.32.3\n")
    original = getattr(Path, operation)

    def denied(path, *args, **kwargs):
        if path.parent == blocked if operation == "exists" else path == blocked:
            raise PermissionError("private detail must not appear in receipt")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, operation, denied)
    reset_scan_warnings()
    warnings = []
    result = scan_project_directory(tmp_path, warnings=warnings)
    assert [p.name for p in result[good]] == ["requests"]
    assert warnings and "private detail" not in str(warnings)
    assert any(w["reason"] == "read_error" for w in peek_coverage_warnings())


def test_cli_manifest_probe_failure_writes_partial_report(tmp_path, monkeypatch):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")
    original = Path.exists

    def exists(path):
        if path.parent == blocked:
            raise PermissionError("private detail must not appear in receipt")
        return original(path)

    monkeypatch.setattr(Path, "exists", exists)
    output = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--no-discover", "--offline", "-f", "json", "-o", str(output)])
    assert output.exists(), result.output
    report = json.loads(output.read_text())
    assert report["scan_run"]["outcome"] == "partial"
    assert any("Project package discovery incomplete" in issue["message"] for issue in report["scan_run"]["issues"])
    assert result.exit_code == 1
    assert "private detail" not in output.read_text()


def test_actual_unreadable_directory_retains_accessible_inventory(tmp_path):
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n")
    blocked.chmod(0)
    try:
        if os.access(blocked, os.R_OK | os.X_OK):
            pytest.skip("execution identity bypasses directory permissions")
        result = scan_project_directory(tmp_path)
        assert [p.name for p in result[tmp_path]] == ["requests"]
        assert any(w["reason"] == "read_error" for w in peek_coverage_warnings())
    finally:
        blocked.chmod(0o700)
