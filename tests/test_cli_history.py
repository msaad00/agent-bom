"""Tests for agent_bom.cli._history to improve coverage."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agent_bom.cli._history import compliance_narrative_cmd, diff_cmd, history_cmd, rescan_command

# ---------------------------------------------------------------------------
# history_cmd
# ---------------------------------------------------------------------------


def test_history_no_reports():
    runner = CliRunner()
    with patch("agent_bom.history.list_reports", return_value=[]):
        result = runner.invoke(history_cmd, [])
        assert result.exit_code == 0
        assert "No saved scans" in result.output


def test_history_with_reports(tmp_path):
    runner = CliRunner()
    report_path = tmp_path / "scan_20250101.json"
    report_data = {
        "generated_at": "2025-01-01T00:00:00Z",
        "summary": {
            "total_agents": 2,
            "total_packages": 10,
            "total_vulnerabilities": 3,
            "critical_findings": 1,
        },
    }
    report_path.write_text(json.dumps(report_data))

    with (
        patch("agent_bom.history.list_reports", return_value=[report_path]),
        patch("agent_bom.history.load_report", return_value=report_data),
    ):
        result = runner.invoke(history_cmd, [])
        assert result.exit_code == 0
        assert "Scan History" in result.output


def test_history_with_corrupt_report(tmp_path):
    runner = CliRunner()
    report_path = tmp_path / "bad.json"
    report_path.write_text("corrupt")

    with (
        patch("agent_bom.history.list_reports", return_value=[report_path]),
        patch("agent_bom.history.load_report", side_effect=Exception("corrupt")),
    ):
        result = runner.invoke(history_cmd, [])
        assert result.exit_code == 0


def test_history_json_output(tmp_path):
    runner = CliRunner()
    report_path = tmp_path / "scan_20250101.json"
    report_data = {
        "generated_at": "2025-01-01T00:00:00Z",
        "summary": {
            "total_agents": 2,
            "total_packages": 10,
            "total_vulnerabilities": 3,
            "critical_findings": 1,
        },
    }
    report_path.write_text(json.dumps(report_data))

    with (
        patch("agent_bom.history.list_reports", return_value=[report_path]),
        patch("agent_bom.history.load_report", return_value=report_data),
    ):
        result = runner.invoke(history_cmd, ["--format", "json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["total_reports"] == 1
        assert payload["reports"][0]["file"] == "scan_20250101.json"
        assert payload["reports"][0]["total_vulnerabilities"] == 3


# ---------------------------------------------------------------------------
# diff_cmd
# ---------------------------------------------------------------------------


def _make_report_data():
    return {
        "generated_at": "2025-01-01T00:00:00Z",
        "summary": {"total_agents": 1, "total_packages": 2},
        "agents": [],
        "blast_radius": [],
    }


def test_diff_two_files(tmp_path):
    runner = CliRunner()
    base = tmp_path / "base.json"
    curr = tmp_path / "curr.json"
    base.write_text(json.dumps(_make_report_data()))
    curr.write_text(json.dumps(_make_report_data()))

    diff_result = {"summary": {"new_findings": 0, "resolved_findings": 0}}
    with patch("agent_bom.history.diff_reports", return_value=diff_result), patch("agent_bom.cli._history.print_diff"):
        result = runner.invoke(diff_cmd, [str(base), str(curr)])
        assert result.exit_code == 0


def test_diff_with_new_findings(tmp_path):
    runner = CliRunner()
    base = tmp_path / "base.json"
    curr = tmp_path / "curr.json"
    base.write_text(json.dumps(_make_report_data()))
    curr.write_text(json.dumps(_make_report_data()))

    diff_result = {"summary": {"new_findings": 3, "resolved_findings": 1}}
    with patch("agent_bom.history.diff_reports", return_value=diff_result), patch("agent_bom.cli._history.print_diff"):
        result = runner.invoke(diff_cmd, [str(base), str(curr)])
        assert result.exit_code == 1  # new findings


def test_diff_baseline_only_no_history(tmp_path):
    runner = CliRunner()
    base = tmp_path / "base.json"
    base.write_text(json.dumps(_make_report_data()))

    with patch("agent_bom.history.latest_report", return_value=None):
        result = runner.invoke(diff_cmd, [str(base)])
        assert result.exit_code == 1  # "No saved scans"


def test_diff_baseline_with_latest(tmp_path):
    runner = CliRunner()
    base = tmp_path / "base.json"
    base.write_text(json.dumps(_make_report_data()))
    latest = tmp_path / "latest.json"
    latest.write_text(json.dumps(_make_report_data()))

    diff_result = {"summary": {"new_findings": 0}}
    with (
        patch("agent_bom.history.latest_report", return_value=latest),
        patch("agent_bom.history.diff_reports", return_value=diff_result),
        patch("agent_bom.cli._history.print_diff"),
    ):
        result = runner.invoke(diff_cmd, [str(base)])
        assert result.exit_code == 0


def test_diff_accepts_sbom_baseline_and_latest_report(tmp_path):
    runner = CliRunner()
    baseline = tmp_path / "baseline.cdx.json"
    latest = tmp_path / "latest.json"
    baseline.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "metadata": {"component": {"name": "vendor-api"}},
                "components": [{"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}],
            }
        )
    )
    latest.write_text(
        json.dumps(
            {
                "generated_at": "2025-01-02T00:00:00Z",
                "summary": {"total_agents": 1, "total_packages": 1},
                "agents": [
                    {
                        "name": "scan",
                        "mcp_servers": [
                            {
                                "name": "scan",
                                "packages": [{"name": "requests", "version": "2.31.0", "ecosystem": "pypi"}],
                            }
                        ],
                    }
                ],
                "blast_radius": [],
            }
        )
    )

    with patch("agent_bom.history.latest_report", return_value=latest), patch("agent_bom.cli._history.print_diff") as mock_print:
        result = runner.invoke(diff_cmd, [str(baseline)])
        assert result.exit_code == 0
        mock_print.assert_called_once()


def test_diff_accepts_two_sboms(tmp_path):
    runner = CliRunner()
    baseline = tmp_path / "baseline.cdx.json"
    current = tmp_path / "current.spdx.json"
    baseline.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "components": [{"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"}],
            }
        )
    )
    current.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {
                        "name": "requests",
                        "versionInfo": "2.31.0",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/requests@2.31.0",
                            }
                        ],
                    },
                    {
                        "name": "urllib3",
                        "versionInfo": "2.2.0",
                        "externalRefs": [
                            {
                                "referenceCategory": "PACKAGE-MANAGER",
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/urllib3@2.2.0",
                            }
                        ],
                    },
                ],
            }
        )
    )

    with patch("agent_bom.cli._history.print_diff") as mock_print:
        result = runner.invoke(diff_cmd, [str(baseline), str(current)])
        assert result.exit_code == 0
        diff_payload = mock_print.call_args.args[0]
        assert diff_payload["summary"]["new_packages"] == 1


def test_diff_json_output(tmp_path):
    runner = CliRunner()
    base = tmp_path / "base.json"
    curr = tmp_path / "curr.json"
    base.write_text(json.dumps(_make_report_data()))
    curr.write_text(json.dumps(_make_report_data()))

    diff_result = {
        "baseline_generated_at": "2025-01-01T00:00:00Z",
        "current_generated_at": "2025-01-02T00:00:00Z",
        "new": [],
        "resolved": [],
        "unchanged": [],
        "new_packages": [],
        "removed_packages": [],
        "inventory_diff": {},
        "summary": {"new_findings": 0, "resolved_findings": 0, "unchanged_findings": 0, "new_packages": 0, "removed_packages": 0},
    }
    with patch("agent_bom.history.diff_reports", return_value=diff_result):
        result = runner.invoke(diff_cmd, [str(base), str(curr), "--format", "json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["baseline_path"].endswith("base.json")
        assert payload["current_path"].endswith("curr.json")
        assert payload["summary"]["new_findings"] == 0


# ---------------------------------------------------------------------------
# rescan_command
# ---------------------------------------------------------------------------


def test_rescan_no_vulns(tmp_path):
    runner = CliRunner()
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"blast_radius": []}))

    result = runner.invoke(rescan_command, [str(base)])
    assert result.exit_code == 0
    assert "nothing to verify" in result.output.lower() or "no vulnerabilities" in result.output.lower()


def test_rescan_invalid_baseline(tmp_path):
    runner = CliRunner()
    base = tmp_path / "bad.json"
    base.write_text("not json")

    result = runner.invoke(rescan_command, [str(base)])
    assert result.exit_code == 2


def test_rescan_with_vulns(tmp_path):
    runner = CliRunner()
    base = tmp_path / "base.json"
    baseline_data = {
        "blast_radius": [
            {
                "package": "lodash@4.17.20",
                "ecosystem": "npm",
                "vulnerability_id": "CVE-2025-0001",
            }
        ]
    }
    base.write_text(json.dumps(baseline_data))

    # Mock OSV query returning empty (vuln resolved)
    with patch("agent_bom.scan_cache.ScanCache") as mock_cache_cls, patch("agent_bom.scanners.query_osv_batch", return_value={}):
        mock_cache = MagicMock()
        mock_cache.evict_many.return_value = 1
        mock_cache_cls.return_value = mock_cache
        result = runner.invoke(rescan_command, [str(base)])
        assert result.exit_code == 0
        assert "Resolved" in result.output


def test_rescan_with_remaining_vulns(tmp_path):
    runner = CliRunner()
    base = tmp_path / "base.json"
    baseline_data = {
        "blast_radius": [
            {
                "package": "lodash@4.17.20",
                "ecosystem": "npm",
                "vulnerability_id": "CVE-2025-0001",
            }
        ]
    }
    base.write_text(json.dumps(baseline_data))

    from agent_bom.models import Severity, Vulnerability

    mock_vuln = Vulnerability(
        id="CVE-2025-0001",
        severity=Severity.HIGH,
        summary="test",
        fixed_version="4.17.22",
    )

    with (
        patch("agent_bom.scan_cache.ScanCache") as mock_cache_cls,
        patch("agent_bom.scanners.query_osv_batch", return_value={"npm:lodash@4.17.20": [{}]}),
        patch("agent_bom.scanners.build_vulnerabilities", return_value=[mock_vuln]),
    ):
        mock_cache = MagicMock()
        mock_cache.evict_many.return_value = 1
        mock_cache_cls.return_value = mock_cache
        result = runner.invoke(rescan_command, [str(base)])
        assert result.exit_code == 1  # vulnerabilities remain


def test_rescan_with_output_and_md(tmp_path):
    runner = CliRunner()
    base = tmp_path / "base.json"
    out_file = tmp_path / "verify.json"
    md_file = tmp_path / "verify.md"
    baseline_data = {
        "blast_radius": [
            {
                "package": "lodash@4.17.20",
                "ecosystem": "npm",
                "vulnerability_id": "CVE-2025-0001",
            }
        ]
    }
    base.write_text(json.dumps(baseline_data))

    with patch("agent_bom.scan_cache.ScanCache") as mock_cache_cls, patch("agent_bom.scanners.query_osv_batch", return_value={}):
        mock_cache = MagicMock()
        mock_cache.evict_many.return_value = 0
        mock_cache_cls.return_value = mock_cache
        result = runner.invoke(rescan_command, [str(base), "--output", str(out_file), "--md", str(md_file)])
        assert result.exit_code == 0
        assert out_file.exists()
        assert md_file.exists()


def test_rescan_osv_failure(tmp_path):
    runner = CliRunner()
    base = tmp_path / "base.json"
    baseline_data = {"blast_radius": [{"package": "x@1.0", "ecosystem": "pypi", "vulnerability_id": "CVE-1"}]}
    base.write_text(json.dumps(baseline_data))

    with (
        patch("agent_bom.scan_cache.ScanCache") as mock_cache_cls,
        patch("agent_bom.scanners.query_osv_batch", side_effect=RuntimeError("timeout")),
    ):
        mock_cache = MagicMock()
        mock_cache.evict_many.return_value = 0
        mock_cache_cls.return_value = mock_cache
        result = runner.invoke(rescan_command, [str(base)])
        assert result.exit_code == 2


def test_compliance_narrative_command_json(tmp_path):
    runner = CliRunner()
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "summary": {"total_packages": 1, "total_vulnerabilities": 1},
                "blast_radius": [
                    {
                        "vulnerability_id": "CVE-2025-1234",
                        "severity": "high",
                        "package": "requests@1.0.0",
                        "ecosystem": "pypi",
                        "affected_agents": ["claude"],
                        "affected_servers": ["filesystem"],
                        "owasp_tags": ["LLM05"],
                    }
                ],
            }
        )
    )

    result = runner.invoke(compliance_narrative_cmd, [str(report), "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "executive_summary" in payload
    assert payload["framework_narratives"]


def test_compliance_narrative_uses_saved_summary_totals(tmp_path):
    runner = CliRunner()
    report = tmp_path / "report.json"
    report.write_text(
        json.dumps(
            {
                "summary": {"total_agents": 4, "total_packages": 12, "total_vulnerabilities": 1},
                "blast_radius": [
                    {
                        "vulnerability_id": "CVE-2025-1234",
                        "severity": "high",
                        "package": "requests@1.0.0",
                        "ecosystem": "pypi",
                        "affected_agents": ["claude"],
                        "affected_servers": ["filesystem"],
                        "owasp_tags": ["LLM05"],
                    }
                ],
            }
        )
    )

    result = runner.invoke(compliance_narrative_cmd, [str(report), "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert "covers 4 AI agents and 12 packages" in payload["executive_summary"]
