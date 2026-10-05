"""Declared scope exclusions are visible without masquerading as failures."""

import json

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.models import AIBOMReport
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings
from agent_bom.secret_scanner import scan_secrets
from agent_bom.traversal import iter_discovery_files


@pytest.mark.parametrize("exclusion", [".git", "node_modules", "ignored", "worktree"])
def test_expected_exclusion_is_complete_with_a_scope_receipt(tmp_path, exclusion):
    reset_scan_warnings()
    (tmp_path / "app.py").write_text("print('hello')\n")
    excluded = tmp_path / exclusion
    excluded.mkdir()
    if exclusion == "ignored":
        (tmp_path / ".gitignore").write_text("ignored/\n")
    if exclusion == "worktree":
        (excluded / ".git").write_text("gitdir: ../.git/worktrees/duplicate\n")
    result = scan_secrets(tmp_path)
    assert result.to_dict()["complete"] is True
    assert result.to_dict()["exclusions"]
    assert not result.warnings
    receipts = consume_coverage_warnings()
    assert receipts and all(w["kind"] == "scope_exclusion" for w in receipts)
    run = effective_scan_run(AIBOMReport(coverage_warnings=receipts))
    assert run.outcome is ScanOutcome.COMPLETE
    assert run.issues and all(not i.affects_coverage for i in run.issues)


def test_symlink_gap_and_file_budget_still_make_evidence_partial(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    reset_scan_warnings()
    result = scan_secrets(root)
    assert result.to_dict()["complete"] is False
    assert result.warnings
    run = effective_scan_run(AIBOMReport(coverage_warnings=consume_coverage_warnings()))
    assert run.outcome is ScanOutcome.PARTIAL
    (root / "one.py").write_text("pass")
    (root / "two.py").write_text("pass")
    list(iter_discovery_files(root, max_files=1))
    assert any(w["reason"] == "discovery_file_limit" for w in consume_coverage_warnings())


@pytest.mark.parametrize("format", ["console", "json"])
def test_secrets_cli_git_metadata_does_not_force_error_exit(tmp_path, format):
    (tmp_path / ".git").mkdir()
    (tmp_path / "app.py").write_text("print('hello')\n")
    result = CliRunner().invoke(main, ["secrets", str(tmp_path), "--format", format])
    assert result.exit_code == 0, result.output
    if format == "json":
        report = json.loads(result.stdout)
        assert report["complete"] and report["exclusions"]
    else:
        assert "scope" in result.output.lower()
        assert "Coverage incomplete" not in result.output


def test_repository_scan_git_metadata_is_a_non_failing_scope_receipt(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    (root / "package.json").write_text('{"name":"empty-project","version":"1.0.0"}')
    result = CliRunner().invoke(
        main, ["scan", "--project", str(root), "--no-discover", "--offline", "--no-auto-update-db", "--format", "json"]
    )
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["scan_run"]["outcome"] == "complete"
    receipts = [issue for issue in report["scan_run"]["issues"] if issue["code"] == "scope_exclusion"]
    assert receipts and all(not issue["affects_coverage"] for issue in receipts)
