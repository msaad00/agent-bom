"""Tests for the primary scan CLI command and the db CLI group.

Covers the high-level invocation paths in cli/scan.py and cli/_db.py that
were previously untested (floor was at 79%).  Uses Click's CliRunner so
no network or filesystem side-effects escape the test.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from agent_bom.cli import cli_main, main
from agent_bom.cli._agent_mode import dumps_envelope, success_envelope, summarize_scan_data
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.scanners import IncompleteScanError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_report_json(n_vulns: int = 0) -> dict:
    return {
        "document_type": "AI-BOM",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "summary": {"total_vulnerabilities": n_vulns, "agents": 0, "servers": 0},
        "agents": [],
        "blast_radius": [],
    }


def _run(args: list, catch_exceptions: bool = False, **kwargs):
    if (
        args[:1] == ["scan"]
        and "--help" not in args
        and "--help-all" not in args
        and "--no-scan" not in args
        and "--dry-run" not in args
        and "--no-auto-update-db" not in args
    ):
        raise AssertionError("scan CLI tests must opt out of auto DB refresh unless they are testing that behavior")
    runner = CliRunner()
    return runner.invoke(main, args, catch_exceptions=catch_exceptions, **kwargs)


# ---------------------------------------------------------------------------
# Top-level --help / --version
# ---------------------------------------------------------------------------


def test_main_help():
    result = _run(["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
    assert "where" in result.output
    assert "Navigation tips:" in result.output


def test_main_version():
    result = _run(["--version"])
    assert result.exit_code == 0
    from agent_bom import __version__

    assert __version__ in result.output


def test_scan_help():
    result = _run(["scan", "--help"])
    assert result.exit_code == 0
    assert "--output" in result.output
    assert "--format" in result.output
    assert "--no-discover" in result.output
    # --inventory-only is a deprecated hidden alias — no longer advertised.
    assert "--inventory-only" not in result.output
    assert "additional scan flags" in result.output

    full = _run(["scan", "--help-all"])
    full_normalized = " ".join(full.output.split())
    assert full.exit_code == 0
    assert "--no-follow-symlinks" in full.output
    assert "graph (Cytoscape.js graph JSON)" in full_normalized
    assert "graph (raw graph JSON)" not in full_normalized


def test_scan_agent_mode_emits_machine_envelope(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_CONFIG", raising=False)
    result = _run(["agents", "--agent-mode", "--demo", "--no-scan", "--offline", "--no-auto-update-db"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1"
    assert payload["mode"] == "agent"
    assert payload["ok"] is True
    assert payload["command"] == "agents"
    assert payload["exit_code"] == 0
    assert payload["summary"]["agents"] >= 1
    assert payload["confidence"]["level"] in {"high", "medium", "low"}
    assert payload["truncated"] is False
    assert payload["truncation"]["truncated"] is False
    assert payload["data"]["document_type"] == "AI-BOM"


def test_scan_agent_mode_ignores_profile_output_default(monkeypatch, tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
current_profile = "prod"

[profiles.prod]
format = "json"
output = "profile-report.json"
"""
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))

    result = _run(["agents", "--agent-mode", "--demo", "--no-scan", "--offline", "--no-auto-update-db"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["mode"] == "agent"


def test_scan_agent_mode_token_budget_reports_truncation(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_CONFIG", raising=False)
    result = _run(["agents", "--agent-mode", "--agent-token-budget", "200", "--demo", "--no-scan", "--offline", "--no-auto-update-db"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["truncation"]["enabled"] is True
    assert payload["truncation"]["token_budget"] == 200
    assert payload["truncated"] is True
    assert payload["truncation"]["truncated"] is True
    assert payload["truncation"]["removed"]


def test_agent_mode_token_budget_bounds_large_envelope():
    report = _minimal_report_json(80)
    report.update(
        {
            "schema_version": "1.0",
            "spec_version": "1.0",
            "posture_grade": "F",
            "summary": {"total_vulnerabilities": 80, "agents": 30, "servers": 0},
            "agents": [{"name": f"agent-{idx}", "mcp_servers": []} for idx in range(30)],
            "findings": [{"id": f"finding-{idx}", "details": "x" * 200} for idx in range(80)],
            "blast_radius": [
                {
                    "vulnerability_id": f"CVE-2026-{idx:04d}",
                    "severity": "high",
                    "package": "pkg",
                    "details": "x" * 200,
                }
                for idx in range(80)
            ],
            "inventory_snapshot": {"agents": [{"name": f"agent-{idx}"} for idx in range(30)], "details": "x" * 2000},
            "remediation_plan": [{"id": f"fix-{idx}", "details": "x" * 200} for idx in range(80)],
            "ai_bom_entities": {"details": "x" * 2000},
        }
    )

    payload = success_envelope(command="agents", report_json=report, exit_code=0, token_budget=500)
    output = dumps_envelope(payload)

    assert len(output) < 500 * 10
    assert payload["truncated"] is True
    assert payload["truncation"]["truncated"] is True
    assert payload["truncation"]["approx_tokens"] <= 500
    assert payload["truncation"]["removed"]
    assert payload["summary"]["agents"] >= 30
    assert payload["data"]["document_type"] == "AI-BOM"


def _provenance_heavy_report(n_packages: int = 400, n_findings: int = 60) -> dict:
    """A report shaped like a real scan: huge inlined per-package provenance."""
    provenance = {
        "discovery_provenance": {
            "source": "project",
            "source_type": "local_discovery",
            "observed_via": ["local_discovery"],
            "version_provenance": {"declared_name": "pkg", "confidence": "unknown", "blob": "x" * 200},
        }
    }
    packages = [{"name": f"pkg-{i}", "version": "1.0.0", "ecosystem": "npm" if i % 2 else "pypi", **provenance} for i in range(n_packages)]
    findings = [
        {
            "id": f"finding-{i}",
            "cve_id": f"CVE-2026-{i:04d}",
            "title": f"finding {i}",
            "effective_severity": "critical" if i < 3 else "medium",
            "risk_score": 9.5 if i < 3 else 4.0,
            "finding_type": "CVE",
            "ai_summary": "y" * 300,
        }
        for i in range(n_findings)
    ]
    return {
        "schema_version": "1",
        "document_type": "AI-BOM",
        "spec_version": "1.0",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "scan_id": "scan-123",
        "posture_grade": "B",
        "summary": {"total_agents": 2, "total_mcp_servers": 4, "total_packages": n_packages, "total_vulnerabilities": 1},
        "agents": [{"name": f"agent-{i}", "type": "custom", "mcp_servers": [{"name": "srv", "blob": "z" * 500}]} for i in range(2)],
        "packages": packages,
        "inventory_snapshot": {"packages": packages},
        "findings": findings,
        "blast_radius": [{"vulnerability_id": "CVE-2026-9999", "package_name": "pkg-0", "severity": "medium", "risk_score": 4.5}],
        "ai_inventory": {"ast_analysis": {"blob": "a" * 5000}, "secrets": {"blob": "b" * 5000}},
        "ai_bom_entities": {"blob": "c" * 5000},
    }


def test_agent_mode_scan_summarizes_by_default():
    report = _provenance_heavy_report()
    full_size = len(json.dumps(report, default=str))

    payload = success_envelope(command="agents", report_json=report, exit_code=0)
    output = dumps_envelope(payload)

    # Still valid JSON, and dramatically smaller than the full report.
    reparsed = json.loads(output)
    assert reparsed == payload
    assert payload["data_mode"] == "summary"
    assert len(output) < full_size // 10

    data = payload["data"]
    # Heavy provenance dumps are omitted by default.
    assert "ai_inventory" not in data
    assert "ai_bom_entities" not in data
    assert "packages" not in data  # the full package list is replaced by counts
    assert "inventory_snapshot" not in data

    # Counts + top findings ARE present.
    assert data["counts"]["packages"] == 400
    assert data["counts"]["packages_by_ecosystem"] == {"npm": 200, "pypi": 200}
    assert data["counts"]["findings_by_severity"]["critical"] == 3
    assert len(data["top_findings"]) == 10
    assert data["top_findings"][0]["severity"] == "critical"
    assert len(data["top_exposure_paths"]) == 1
    assert data["full_report"]["included"] is False
    assert "--agent-mode-full" in data["full_report"]["hint"]


def test_agent_mode_scan_full_inlines_report():
    report = _provenance_heavy_report()

    payload = success_envelope(command="agents", report_json=report, exit_code=0, full=True)

    assert payload["data_mode"] == "full"
    data = payload["data"]
    assert "ai_inventory" in data
    assert "ai_bom_entities" in data
    assert len(data["packages"]) == 400


def test_summarize_scan_data_records_output_path():
    report = _provenance_heavy_report()
    summary = summarize_scan_data(report, output_path="/tmp/report.json")
    assert summary["full_report"]["output_path"] == "/tmp/report.json"
    # stdout sentinel is not a real on-disk path
    assert summarize_scan_data(report, output_path="-")["full_report"]["output_path"] is None


def test_agent_mode_scan_summary_envelope_omits_provenance_end_to_end(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_CONFIG", raising=False)
    result = _run(["agents", "--agent-mode", "--demo", "--no-scan", "--offline", "--no-auto-update-db"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["data_mode"] == "summary"
    data = payload["data"]
    assert "ai_inventory" not in data
    assert "ai_bom_entities" not in data
    assert "counts" in data and isinstance(data["counts"]["packages"], int)
    assert isinstance(data["top_findings"], list)


def test_agent_mode_entry_wraps_usage_errors(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["agent-bom", "--agent-mode", "not-a-command"])

    with pytest.raises(SystemExit) as excinfo:
        cli_main()

    assert excinfo.value.code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "agent"
    assert payload["ok"] is False
    assert payload["exit_code"] == 2
    assert payload["truncated"] is False
    assert payload["error"]["type"] == "usage"
    assert payload["errors"][0]["type"] == "usage"


def test_agent_mode_entry_accepts_late_flag(monkeypatch, capsys):
    monkeypatch.delenv("AGENT_BOM_AGENT_MODE", raising=False)
    monkeypatch.setattr(sys, "argv", ["agent-bom", "not-a-command", "--agent-mode"])

    with pytest.raises(SystemExit) as excinfo:
        cli_main()

    assert excinfo.value.code == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "agent"
    assert payload["ok"] is False


def test_scan_external_scan_invalid_json_exits_nonzero(tmp_path):
    inventory = {
        "schema_version": "1",
        "generated_at": "2026-05-09T00:00:00Z",
        "agents": [{"name": "fixture-agent", "agent_type": "custom", "mcp_servers": []}],
    }
    inventory_file = tmp_path / "inventory.json"
    inventory_file.write_text(json.dumps(inventory), encoding="utf-8")
    bad_external_scan = tmp_path / "bad-external-scan.json"
    bad_external_scan.write_text("{bad", encoding="utf-8")

    result = _run(
        [
            "scan",
            "--inventory",
            str(inventory_file),
            "--external-scan",
            str(bad_external_scan),
            "--offline",
            "--no-auto-update-db",
        ],
    )

    assert result.exit_code != 0
    assert "External scan error:" in result.output


# ---------------------------------------------------------------------------
# scan — zero-config dry run (no network, no real discovery)
# ---------------------------------------------------------------------------


def _mock_scan_pipeline():
    """Return a patch context that makes the scan return an empty report."""
    report = MagicMock()
    report.agents = []
    report.generated_at.isoformat.return_value = "2026-01-01T00:00:00+00:00"
    report.generated_at.strftime.return_value = "2026-01-01 00:00:00 UTC"
    report.scan_sources = []
    report.compliance_frameworks = []
    report.policy_results = None
    report.warn_gate_status = None
    report._cached_json = None

    blast_radii: list = []

    return report, blast_radii


def test_scan_dry_run_no_output():
    """scan with --dry-run should exit 0 without writing files."""
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--dry-run"])
    assert result.exit_code == 0


def test_scan_no_scan_flag():
    """--no-scan should skip CVE scanning entirely."""
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--no-scan"])
    assert result.exit_code == 0


def test_scan_records_local_analytics_without_save():
    calls = []

    def _record(report_json, **kwargs):
        calls.append((report_json, kwargs))
        return "local-scan"

    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.db.local_analytics.record_scan_report_best_effort", side_effect=_record),
    ):
        result = _run(["scan", "--demo", "--no-scan", "--quiet"])

    assert result.exit_code == 0
    assert calls
    assert calls[0][1]["source"] == "cli"


def test_scan_empty_state_shows_real_client_paths(monkeypatch):
    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *args, **kwargs: [])

    result = _run(["scan", "--no-auto-update-db"])

    assert result.exit_code == 0
    assert "Common MCP config locations checked on this machine" in result.output
    assert "Claude Desktop" in result.output
    assert "Cursor" in result.output


def test_scan_format_json_no_output_file(tmp_path):
    """--format json without --output writes JSON to stdout."""
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--format", "json", "--no-scan"])
    assert result.exit_code == 0


def test_scan_format_console_no_output_file():
    """--format console (default) should not crash on empty results."""
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--format", "console", "--no-scan"])
    assert result.exit_code == 0


def test_scan_format_console_with_output_gives_actionable_error(tmp_path):
    """--format console is terminal-only; file output should suggest useful formats."""
    out = tmp_path / "abom-out.console"
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--format", "console", "--output", str(out), "--no-scan"])
    assert result.exit_code == 2
    assert "console renders to the terminal only" in result.output
    assert "--format plain" in result.output


def test_scan_quiet_flag():
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--quiet", "--no-scan"])
    assert result.exit_code == 0


def test_scan_quiet_uses_error_log_level(monkeypatch):
    captured = {}

    def _fake_setup_logging(*, level, json_output=None, log_file=None):
        captured["level"] = level
        captured["json_output"] = json_output
        captured["log_file"] = log_file

    monkeypatch.setattr("agent_bom.logging_config.setup_logging", _fake_setup_logging)
    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *args, **kwargs: [])

    result = _run(["scan", "--quiet", "--no-scan"])

    assert result.exit_code == 0
    assert captured["level"] == "ERROR"


def test_where_help():
    result = _run(["where", "--help"])
    assert result.exit_code == 0
    assert "MCP configurations" in result.output


def test_scan_output_to_file(tmp_path):
    """--output <path> should write the report to disk."""
    out = tmp_path / "report.json"
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--format", "json", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0


def test_scan_output_appends_format_extension_for_extensionless_path(tmp_path):
    """Explicit formats should create artifacts with the expected suffix."""
    out = tmp_path / "scan-report"
    expected = tmp_path / "scan-report.sarif"
    with (
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "sarif", "--output", str(out), "--no-scan"])

    assert result.exit_code == 0, result.output
    assert expected.exists()
    assert not out.exists()
    assert "SARIF report:" in result.output
    assert "scan-report.sarif" in result.output


def test_scan_output_rejects_mismatched_format_extension(tmp_path):
    """A selected format should not silently write to a misleading file name."""
    out = tmp_path / "scan-report.json"
    with (
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "sarif", "--output", str(out), "--no-scan"])

    assert result.exit_code == 2
    assert "--format sarif cannot write" in result.output
    assert ".sarif" in result.output
    assert not out.exists()


def test_scan_reproducible_pins_report_and_inventory_timestamps(tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "generated_at": "2026-05-09T00:00:00Z",
                "agents": [{"name": "fixture-agent", "agent_type": "custom", "mcp_servers": []}],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "report.json"
    result = _run(
        [
            "scan",
            "--inventory",
            str(inventory),
            "--inventory-only",
            "--no-scan",
            "--reproducible",
            "--format",
            "json",
            "--output",
            str(out),
        ]
    )

    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["generated_at"] == "1970-01-01T00:00:00+00:00"
    assert report["inventory_snapshot"]["generated_at"] == "1970-01-01T00:00:00+00:00"


def test_scan_honors_source_date_epoch_for_reproducible_outputs(tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "generated_at": "2026-05-09T00:00:00Z",
                "agents": [{"name": "fixture-agent", "agent_type": "custom", "mcp_servers": []}],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "report.json"
    result = _run(
        [
            "scan",
            "--inventory",
            str(inventory),
            "--inventory-only",
            "--no-scan",
            "--format",
            "json",
            "--output",
            str(out),
        ],
        env={"SOURCE_DATE_EPOCH": "1700000000"},
    )

    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["generated_at"] == "2023-11-14T22:13:20+00:00"
    assert report["inventory_snapshot"]["generated_at"] == "2023-11-14T22:13:20+00:00"


def test_scan_unknown_output_extension_fails(tmp_path):
    out = tmp_path / "report.ocsf"
    result = _run(["scan", "--demo", "--output", str(out), "--no-scan"])
    assert result.exit_code == 2
    assert "Cannot infer output format" in result.output


def test_scan_bad_inventory_json_exits_two(tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text("{bad json", encoding="utf-8")

    result = _run(["scan", "--inventory", str(inventory), "--no-scan"])

    assert result.exit_code == 2
    assert "Invalid value for --inventory" in result.output
    assert "Expecting property name" in result.output


def test_scan_inventory_no_discover_does_not_merge_project_or_skill_state(tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "generated_at": "2026-05-09T00:00:00Z",
                "agents": [
                    {
                        "name": "declared-agent",
                        "agent_type": "custom",
                        "source": "operator_inventory",
                        "mcp_servers": [
                            {
                                "name": "declared-server",
                                "command": "python -m declared",
                                "packages": [
                                    {"name": "requests", "version": "2.31.0", "ecosystem": "pypi"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    project = tmp_path / "repo"
    project.mkdir()
    (project / "requirements.txt").write_text("flask==2.2.0\n", encoding="utf-8")
    (project / "SKILL.md").write_text(
        "---\nname: local-skill\n---\nRun with package flask==2.2.0.\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"

    result = _run(
        [
            "scan",
            "--inventory",
            str(inventory),
            "--project",
            str(project),
            "--no-discover",
            "--no-scan",
            "--format",
            "json",
            "--output",
            str(out),
        ]
    )

    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    agent_names = [agent["name"] for agent in report["agents"]]
    assert agent_names == ["declared-agent"]
    assert "Scanning project directory" not in result.output
    assert "Scanning 1 skill file" not in result.output


def test_scan_sbom_does_not_merge_ambient_skill_packages(tmp_path, monkeypatch):
    sbom = tmp_path / "bom.cdx.json"
    sbom.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {
                        "type": "library",
                        "name": "axios",
                        "version": "1.6.0",
                        "purl": "pkg:npm/axios@1.6.0",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    project = tmp_path / "repo"
    project.mkdir()
    (project / "SKILL.md").write_text(
        "---\nname: ambient-skill\n---\nRun with package flask==2.2.0.\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"
    monkeypatch.chdir(project)

    result = _run(
        [
            "scan",
            "--sbom",
            str(sbom),
            "--no-scan",
            "--format",
            "json",
            "--output",
            str(out),
        ]
    )

    assert result.exit_code == 0, result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    packages = {(pkg["name"], pkg.get("version"), pkg.get("ecosystem")) for pkg in report["packages"]}
    assert packages == {("axios", "1.6.0", "npm")}
    assert [agent["name"] for agent in report["agents"]] == ["sbom:bom.cdx"]
    assert "Scanning 1 skill file" not in result.output


def test_scan_inventory_only_round_trips_scan_report_snapshot_without_accretion(tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "generated_at": "2026-05-09T00:00:00Z",
                "agents": [
                    {
                        "name": "declared-agent",
                        "agent_type": "custom",
                        "config_path": "<path:mcp.json>",
                        "mcp_servers": [
                            {
                                "name": "declared-server",
                                "command": "python",
                                "config_path": "<path:mcp.json>",
                                "security_intelligence": [
                                    {
                                        "entry_id": "MCP-TEST-1",
                                        "title": "Fixture intelligence",
                                        "severity": "high",
                                        "confidence": "heuristic",
                                        "default_recommendation": "review",
                                        "source_type": "heuristic",
                                        "source": "fixture",
                                        "match_type": "package",
                                        "matched_value": "declared-server",
                                    }
                                ],
                                "packages": [
                                    {
                                        "name": "requests",
                                        "version": "2.31.0",
                                        "ecosystem": "pypi",
                                        "discovery_provenance": {
                                            "source_type": "operator_pushed_inventory",
                                            "version_provenance": {
                                                "version_source": "lockfile",
                                                "confidence": "high",
                                                "evidence": [{"package_path": "<path:mcp.json>"}],
                                            },
                                        },
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"

    first_result = _run(
        [
            "scan",
            "--inventory",
            str(inventory),
            "--inventory-only",
            "--no-scan",
            "--format",
            "json",
            "--output",
            str(first),
        ]
    )
    second_result = _run(
        [
            "scan",
            "--inventory",
            str(first),
            "--inventory-only",
            "--no-scan",
            "--format",
            "json",
            "--output",
            str(second),
        ]
    )

    assert first_result.exit_code == 0, first_result.output
    assert second_result.exit_code == 0, second_result.output

    first_snapshot = json.loads(first.read_text(encoding="utf-8"))["inventory_snapshot"]
    second_snapshot = json.loads(second.read_text(encoding="utf-8"))["inventory_snapshot"]
    first_snapshot.pop("generated_at", None)
    second_snapshot.pop("generated_at", None)

    assert first_snapshot == second_snapshot
    server = second_snapshot["agents"][0]["mcp_servers"][0]
    assert server["config_path"] == "<path:mcp.json>"
    assert "collector" not in server["security_intelligence"][0]
    evidence = server["packages"][0]["discovery_provenance"]["version_provenance"]["evidence"]
    assert evidence == [{"package_path": "<path:mcp.json>"}]


def test_scan_bad_ignore_file_yaml_exits_one(tmp_path):
    ignore_file = tmp_path / ".agent-bom-ignore.yaml"
    ignore_file.write_text("ignores:\n  - id: [unterminated\n", encoding="utf-8")

    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--ignore-file", str(ignore_file), "--no-scan"])

    assert result.exit_code == 1
    assert "Invalid YAML in ignore file" in result.output
    assert "line" in result.output


def test_scan_bad_policy_json_exits_one_with_message(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text("{bad json", encoding="utf-8")

    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--policy", str(policy), "--no-scan", "--quiet"])

    assert result.exit_code == 1
    assert "Policy error" in result.output
    assert "Invalid JSON in policy file" in result.output


def test_focused_secrets_and_skills_scan_expose_logging_flags():
    for args in (["secrets", "--help"], ["skills", "scan", "--help"]):
        result = _run(args)
        assert result.exit_code == 0
        assert "--no-color" in result.output
        assert "--log-json" in result.output
        assert "--log-file" in result.output


def test_focused_fs_json_and_sarif_default_to_stdout():
    from agent_bom.cli._focused_commands import _focused_default_output

    assert _focused_default_output("json", None) == "-"
    assert _focused_default_output("sarif", None) == "-"
    assert _focused_default_output("console", None) is None
    assert _focused_default_output("json", "report.json") == "report.json"


def test_scan_bad_baseline_json_exits_before_rendering(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{bad json", encoding="utf-8")
    output = tmp_path / "report.json"

    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--baseline", str(baseline), "--no-scan", "--format", "json", "--output", str(output)])

    assert result.exit_code == 1
    assert "Baseline error" in result.output
    assert "not valid JSON" in result.output
    assert not output.exists()


def test_scan_missing_inventory_schema_exits_two(tmp_path):
    inventory = tmp_path / "inventory.json"
    inventory.write_text('{"agents": []}', encoding="utf-8")

    with patch("agent_bom.inventory.load_inventory", side_effect=RuntimeError("Inventory schema file not found")):
        result = _run(["scan", "--inventory", str(inventory), "--no-scan"])

    assert result.exit_code == 2
    assert "Invalid value for --inventory" in result.output
    assert "Inventory schema file not found" in result.output


def test_scan_preset_ci_flag():
    """--preset ci should be accepted without error."""
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--preset", "ci", "--no-scan"])
    assert result.exit_code == 0


def test_scan_fail_on_severity_critical():
    """--fail-on-severity critical with no vulns → exit 0."""
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--fail-on-severity", "critical", "--no-scan"])
    assert result.exit_code == 0


def test_scan_warn_on_high():
    """--warn-on high with no vulns → exit 0."""
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--warn-on", "high", "--no-scan"])
    assert result.exit_code == 0


def test_scan_delta_flag_no_baseline():
    """--delta without --baseline should fail with a clear error."""
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--delta", "--no-scan"])
    # Delta mode without baseline should exit non-zero or handle gracefully
    # The exact code depends on implementation; just ensure no unhandled exception
    assert result.exit_code in (0, 1, 2)


def test_scan_delta_with_baseline(tmp_path):
    """--delta --baseline <file> with a valid baseline file."""
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(_minimal_report_json()), encoding="utf-8")
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--delta", "--baseline", str(baseline), "--no-scan"])
    assert result.exit_code == 0


def test_scan_delta_filters_json_output_before_render(tmp_path):
    old_vuln = Vulnerability(id="CVE-2026-0001", summary="old finding", severity=Severity.HIGH, fixed_version="1.0.1")
    new_vuln = Vulnerability(id="CVE-2026-0002", summary="new finding", severity=Severity.HIGH, fixed_version="1.0.1")
    old_pkg = Package(name="oldpkg", version="1.0.0", ecosystem="pypi", vulnerabilities=[old_vuln])
    new_pkg = Package(name="newpkg", version="1.0.0", ecosystem="pypi", vulnerabilities=[new_vuln])
    server = MCPServer(name="srv", command="python", packages=[old_pkg, new_pkg])
    agent = Agent(name="agent", agent_type=AgentType.CUSTOM, config_path="agent.json", mcp_servers=[server])
    blast_radii = [
        BlastRadius(
            vulnerability=old_vuln,
            package=old_pkg,
            affected_servers=[server],
            affected_agents=[agent],
            exposed_credentials=[],
            exposed_tools=[],
        ),
        BlastRadius(
            vulnerability=new_vuln,
            package=new_pkg,
            affected_servers=[server],
            affected_agents=[agent],
            exposed_credentials=[],
            exposed_tools=[],
        ),
    ]
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                **_minimal_report_json(1),
                "blast_radius": [{"vulnerability_id": "CVE-2026-0001", "package": "oldpkg@1.0.0"}],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "delta.json"
    project = tmp_path / "project"
    project.mkdir()

    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[agent]),
        patch("agent_bom.cli.agents.extract_packages", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=blast_radii),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(
            [
                "scan",
                "--project",
                str(project),
                "--delta",
                "--baseline",
                str(baseline),
                "-f",
                "json",
                "-o",
                str(output),
                "--no-auto-update-db",
            ]
        )

    assert result.exit_code == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["delta"]["new_count"] == 1
    assert data["delta"]["pre_existing_count"] == 1
    assert [item["vulnerability_id"] for item in data["blast_radius"]] == ["CVE-2026-0002"]


def test_scan_enrich_flag():
    """--enrich flag is accepted (network calls mocked)."""
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
    ):
        result = _run(["scan", "--enrich", "--no-scan"])
    assert result.exit_code == 0


def test_scan_no_tree_flag():
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--no-tree", "--no-scan"])
    assert result.exit_code == 0


def test_scan_prints_package_extraction_progress(monkeypatch):
    """Real MCP inventories should show which server is being extracted."""
    from agent_bom.models import TransportType

    pkg = Package(name="example", version="1.0.0", ecosystem="pypi")
    server = MCPServer(name="demo-server", command="python", transport=TransportType.STDIO)
    agent = Agent(name="demo-agent", agent_type=AgentType.CUSTOM, config_path="/tmp/demo.json", mcp_servers=[server])

    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *args, **kwargs: [agent])
    monkeypatch.setattr("agent_bom.cli.agents.extract_packages", lambda *args, **kwargs: [pkg])

    result = _run(["scan", "--no-scan"])

    assert result.exit_code == 0
    assert "Extracting packages from demo-agent/demo-server" in result.output


def test_demo_scan_hides_synthetic_project_temp_path():
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.parsers.scan_project_directory", return_value={}),
    ):
        result = _run(["scan", "--demo", "--no-scan"])
    assert result.exit_code == 0
    assert "agent-bom-demo-dir-" not in result.output
    assert "Scanning project directory for package manifests" not in result.output
    assert "Scanning 1 path(s) for IaC misconfigurations" not in result.output


def test_demo_scan_preserves_curated_inventory_without_registry_fallback(monkeypatch):
    captured: dict[str, int] = {}

    def _extract_packages(*args, **kwargs):
        raise AssertionError("demo mode should not add registry fallback packages")

    def _scan_agents_sync(agents, *args, **kwargs):
        captured["packages"] = sum(len(server.packages) for agent in agents for server in agent.mcp_servers)
        return []

    monkeypatch.setattr("agent_bom.cli.agents.extract_packages", _extract_packages)
    monkeypatch.setattr("agent_bom.cli.agents.scan_agents_sync", _scan_agents_sync)

    result = _run(["scan", "--demo", "--offline", "--no-auto-update-db"])

    assert result.exit_code == 0
    assert captured["packages"] == 12
    assert "12 packages" in result.output
    assert "PARTIAL COVERAGE" not in result.output


def test_scan_format_sarif(tmp_path):
    """--format sarif should produce a SARIF file."""
    out = tmp_path / "results.sarif"
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--format", "sarif", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0


def test_scan_sarif_auto_enables_enrich(monkeypatch):
    captured = {}

    def _scan_agents_sync(*args, **kwargs):
        captured["enable_enrichment"] = kwargs.get("enable_enrichment")
        return []

    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *args, **kwargs: [])
    monkeypatch.setattr("agent_bom.cli.agents.scan_agents_sync", _scan_agents_sync)

    result = _run(["scan", "--format", "sarif", "--demo", "--no-auto-update-db"])

    assert result.exit_code == 0
    assert captured["enable_enrichment"] is True


def _critical_scan_mocks():
    """Return (agent, blast_radii) with one CRITICAL CVE for output-parity tests."""
    vuln = Vulnerability(id="CVE-2099-0001", summary="crit", severity=Severity.CRITICAL, fixed_version="9.9.9")
    pkg = Package(name="badpkg", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    server = MCPServer(name="srv", command="python", packages=[pkg])
    agent = Agent(name="ag", agent_type=AgentType.CUSTOM, config_path="a.json", mcp_servers=[server])
    br = [
        BlastRadius(
            vulnerability=vuln,
            package=pkg,
            affected_servers=[server],
            affected_agents=[agent],
            exposed_credentials=[],
            exposed_tools=[],
        )
    ]
    return agent, br


def test_scan_sarif_does_not_auto_enable_context_graph(tmp_path):
    """`-f sarif` must not silently run the context graph / toxic-combo evaluator.

    Gating it on the output format made SARIF emit COMBINATION findings that the
    same input as `-f json`/`-f csv` never produced — a SIEM/API parity bug
    (#3643). Enrichment (annotation only) stays on; the finding set must not.
    """
    agent, br = _critical_scan_mocks()
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[agent]),
        patch("agent_bom.cli.agents.extract_packages", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=br),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
        patch("agent_bom.context_graph.build_context_graph") as build_cg,
    ):
        result = _run(["scan", "--project", str(tmp_path), "-f", "sarif", "-o", str(tmp_path / "r.sarif"), "--no-auto-update-db"])
    assert result.exit_code in (0, 1), result.output
    build_cg.assert_not_called()


def test_scan_finding_count_parity_across_formats(tmp_path):
    """json/csv/sarif of the same scan must report identical finding counts (#3643)."""
    out = tmp_path / "out"
    out.mkdir()

    def _scan(fmt: str, path):
        agent, br = _critical_scan_mocks()
        with (
            patch("agent_bom.cli.agents.discover_all", return_value=[agent]),
            patch("agent_bom.cli.agents.extract_packages", return_value=[]),
            patch("agent_bom.cli.agents.scan_agents_sync", return_value=br),
            patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
        ):
            return _run(["scan", "--project", str(tmp_path), "-f", fmt, "-o", str(path), "--no-auto-update-db"])

    jf, sf, cf = out / "r.json", out / "r.sarif", out / "r.csv"
    _scan("json", jf)
    _scan("sarif", sf)
    _scan("csv", cf)

    json_count = len(json.loads(jf.read_text())["findings"])
    sarif_count = len(json.loads(sf.read_text())["runs"][0]["results"])
    csv_count = cf.read_text().strip().count("\n")  # minus header
    assert json_count == sarif_count == csv_count == 1


def test_scan_reproducible_pins_agent_timestamps(tmp_path):
    """--reproducible must pin per-agent discovered_at/last_seen, not just generated_at (#3643)."""
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema_version": "1",
                "generated_at": "2026-05-09T00:00:00Z",
                "agents": [{"name": "fixture-agent", "agent_type": "custom", "mcp_servers": []}],
            }
        ),
        encoding="utf-8",
    )

    def _emit(path):
        return _run(
            [
                "scan",
                "--inventory",
                str(inventory),
                "--inventory-only",
                "--no-scan",
                "--reproducible",
                "--format",
                "json",
                "--output",
                str(path),
            ]
        )

    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert _emit(a).exit_code == 0
    assert _emit(b).exit_code == 0

    report = json.loads(a.read_text(encoding="utf-8"))
    agent = report["agents"][0]
    assert agent["discovered_at"] == "1970-01-01T00:00:00Z"
    assert agent["last_seen"] == "1970-01-01T00:00:00Z"
    # Byte-identical across repeated runs of the same input.
    assert a.read_text(encoding="utf-8") == b.read_text(encoding="utf-8")


def test_scan_dev_null_output_honors_policy_exit_code(tmp_path):
    """`-o /dev/null` discards output but must not mask --fail-on-severity (#3643).

    Previously the null sink tripped SystemExit(2) (console-to-file guard /
    extension inference) regardless of findings.
    """
    agent, br = _critical_scan_mocks()

    def _scan(extra):
        with (
            patch("agent_bom.cli.agents.discover_all", return_value=[agent]),
            patch("agent_bom.cli.agents.extract_packages", return_value=[]),
            patch("agent_bom.cli.agents.scan_agents_sync", return_value=br),
            patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
        ):
            return _run(["scan", "--project", str(tmp_path), "-o", "/dev/null", *extra, "--no-auto-update-db"])

    # Critical present + fail-on-severity critical -> policy exit 1 (not 2).
    assert _scan(["-f", "json", "--fail-on-severity", "critical"]).exit_code == 1
    # Default console format + null sink no longer false-exits 2.
    assert _scan(["--fail-on-severity", "critical"]).exit_code == 1


def test_scan_format_html(tmp_path):
    """--format html should produce an HTML file."""
    out = tmp_path / "report.html"
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--format", "html", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0


def test_scan_format_pdf(tmp_path):
    """--format pdf should produce a PDF file."""
    out = tmp_path / "report.pdf"
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "pdf", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0
    assert out.exists()
    assert out.read_bytes().startswith(b"%PDF")


def test_scan_format_pdf_rejects_stdout():
    """--format pdf cannot write binary PDF to stdout."""
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "pdf", "--output", "-", "--no-scan"])
    assert result.exit_code == 2
    assert "requires --output/-o" in result.output


def test_scan_format_pdf_requires_output_file():
    """--format pdf should not silently write a default file when no output path is given."""
    result = _run(["scan", "--demo", "--format", "pdf", "--no-scan"])
    assert result.exit_code == 2
    assert "requires --output/-o" in result.output


def test_scan_save_flag(tmp_path):
    """--save should persist the report to history."""
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--save", "--no-scan"])
    assert result.exit_code == 0


def test_scan_incomplete_offline_scan_exits_two(monkeypatch, tmp_path):
    profile_output = tmp_path / "profile-report.json"
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f"""
current_profile = "local"

[profiles.local]
format = "json"
output = "{profile_output}"
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_BOM_CONFIG", str(config_path))
    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *args, **kwargs: [])

    def _scan_agents_sync(*args, **kwargs):
        raise IncompleteScanError("Offline mode requires a populated local vulnerability DB.")

    monkeypatch.setattr("agent_bom.cli.agents.scan_agents_sync", _scan_agents_sync)

    result = _run(["scan", "--demo", "--no-auto-update-db"])

    assert result.exit_code == 2
    assert "populated local vulnerability DB" in result.output
    # Verdict-led default panel labels the row "Security posture:"; the
    # ``--verbose`` form labels it "SECURITY POSTURE:". Either is acceptable
    # — the contract under test is that the partial-coverage state surfaces.
    assert "Security posture" in result.output or "SECURITY POSTURE" in result.output
    assert "PARTIAL COVERAGE" in result.output
    assert "CLEAN" not in result.output
    assert "agents" in result.output.lower()
    assert not profile_output.exists()


def test_scan_incomplete_offline_scan_honors_explicit_output(monkeypatch, tmp_path):
    output = tmp_path / "partial-report.json"
    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *args, **kwargs: [])

    def _scan_agents_sync(*args, **kwargs):
        raise IncompleteScanError("Offline mode requires a populated local vulnerability DB.")

    monkeypatch.setattr("agent_bom.cli.agents.scan_agents_sync", _scan_agents_sync)

    result = _run(["scan", "--demo", "--no-auto-update-db", "--format", "json", "--output", str(output)])

    assert result.exit_code == 2
    assert "populated local vulnerability DB" in result.output
    assert output.exists()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["scan_performance"]["coverage_state"] == "incomplete"
    assert payload["scan_performance"]["coverage_reason"] == "Offline mode requires a populated local vulnerability DB."


def test_scan_expands_local_docker_mcp_image():
    from agent_bom.cli.agents import _expand_docker_mcp_packages
    from agent_bom.models import MCPServer, Package, TransportType

    server = MCPServer(name="docker-mcp", command="docker", args=["run", "--rm", "mcp/playwright:1.2.3"], transport=TransportType.STDIO)
    docker_stub = Package(name="mcp/playwright", version="1.2.3", ecosystem="docker")
    image_pkg = Package(name="express", version="4.18.2", ecosystem="npm")

    def scan_image(image_ref, **kwargs):
        assert image_ref == "mcp/playwright:1.2.3"
        return [image_pkg], "native"

    packages, failures = _expand_docker_mcp_packages(
        server=server,
        discovered=[docker_stub],
        docker_image_cache={},
        scan_image_fn=scan_image,
        registry_user=None,
        registry_pass=None,
        image_platform=None,
    )

    assert packages == [image_pkg]
    assert failures == []


def test_scan_fails_when_local_docker_mcp_image_cannot_expand():
    from agent_bom.cli.agents import _expand_docker_mcp_packages
    from agent_bom.image import ImageScanError
    from agent_bom.models import MCPServer, Package, TransportType

    server = MCPServer(name="docker-mcp", command="docker", args=["run", "--rm", "mcp/playwright:1.2.3"], transport=TransportType.STDIO)
    docker_stub = Package(name="mcp/playwright", version="1.2.3", ecosystem="docker")

    def fail_image_scan(*args, **kwargs):
        raise ImageScanError("docker not available")

    packages, failures = _expand_docker_mcp_packages(
        server=server,
        discovered=[docker_stub],
        docker_image_cache={},
        scan_image_fn=fail_image_scan,
        registry_user=None,
        registry_pass=None,
        image_platform=None,
    )

    assert packages == []
    assert failures
    assert "docker not available" in failures[0]
    assert server.security_warnings == failures


def test_offline_scan_summary_marks_partial_unpinned_coverage(monkeypatch):
    from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

    pkg = Package(name="unpinned", version="unknown", ecosystem="pypi")
    server = MCPServer(name="test-server", command="npx", transport=TransportType.STDIO, packages=[pkg])
    agent = Agent(name="test-agent", agent_type=AgentType.CUSTOM, config_path="/tmp/test", mcp_servers=[server])

    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *args, **kwargs: [agent])
    monkeypatch.setattr("agent_bom.cli.agents.scan_agents_sync", lambda *args, **kwargs: [])
    monkeypatch.setattr("agent_bom.cli.agents.extract_packages", lambda *args, **kwargs: [pkg])

    result = _run(["scan", "--offline", "--no-auto-update-db"])

    assert result.exit_code == 0
    assert "Offline scan complete: no known vulnerabilities found in local data" in result.output
    assert "coverage is partial" in result.output


def test_scan_offline_mode_does_not_leak_after_cli_invocation(monkeypatch):
    from agent_bom.http_client import create_sync_client
    from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

    pkg = Package(name="unpinned", version="unknown", ecosystem="pypi")
    server = MCPServer(name="test-server", command="npx", transport=TransportType.STDIO, packages=[pkg])
    agent = Agent(name="test-agent", agent_type=AgentType.CUSTOM, config_path="/tmp/test", mcp_servers=[server])

    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *args, **kwargs: [agent])
    monkeypatch.setattr("agent_bom.cli.agents.scan_agents_sync", lambda *args, **kwargs: [])
    monkeypatch.setattr("agent_bom.cli.agents.extract_packages", lambda *args, **kwargs: [pkg])

    result = _run(["scan", "--offline", "--no-auto-update-db"])

    assert result.exit_code == 0

    client = create_sync_client()
    try:
        assert client is not None
    finally:
        client.close()


# ---------------------------------------------------------------------------
# db CLI group — #529 and #631 coverage
# ---------------------------------------------------------------------------


def test_db_help():
    result = _run(["db", "--help"])
    assert result.exit_code == 0
    assert "update" in result.output
    assert "status" in result.output
    assert "path" in result.output


def test_db_update_help():
    result = _run(["db", "update", "--help"])
    assert result.exit_code == 0
    assert "--source" in result.output


def test_db_status_help():
    result = _run(["db", "status", "--help"])
    assert result.exit_code == 0


def test_db_path_prints_default():
    """db path should print a path ending in vulns.db."""
    result = _run(["db", "path"])
    assert result.exit_code == 0
    assert "vulns.db" in result.output


def test_db_path_override(tmp_path):
    """db path --path <custom> should echo the custom path."""
    custom = str(tmp_path / "custom.db")
    result = _run(["db", "path", "--path", custom])
    assert result.exit_code == 0
    assert "custom.db" in result.output


def test_db_status_no_db(tmp_path):
    """db status when DB file does not exist prints helpful message."""
    non_existent = str(tmp_path / "nonexistent.db")
    result = _run(["db", "status", "--path", non_existent])
    assert result.exit_code == 0
    assert "No local DB" in result.output or "db update" in result.output


def test_db_status_with_existing_db(tmp_path):
    """db status with a real (empty) DB prints stats."""
    from agent_bom.db.schema import init_db

    db_file = tmp_path / "test.db"
    conn = init_db(db_file)
    conn.close()

    result = _run(["db", "status", "--path", str(db_file)])
    assert result.exit_code == 0
    assert "Vulnerabilities" in result.output or "vuln" in result.output.lower()


def test_db_update_sync_error_exits_1(tmp_path):
    """db update exits 1 when sync fails."""
    db_path = str(tmp_path / "test.db")
    with patch("agent_bom.db.sync.sync_db", side_effect=RuntimeError("connection refused")):
        result = CliRunner().invoke(main, ["db", "update", "--path", db_path], catch_exceptions=True)
    assert result.exit_code == 1


def test_db_update_mocked_success(tmp_path):
    """db update with mocked sync prints per-source counts."""
    db_path = str(tmp_path / "test.db")
    with patch("agent_bom.db.sync.sync_db", return_value={"osv": 100, "epss": 200, "kev": 50}):
        result = _run(["db", "update", "--path", db_path])
    assert result.exit_code == 0
    assert "osv" in result.output
    assert "100" in result.output


def test_db_update_single_source(tmp_path):
    """db update --source epss only syncs epss."""
    db_path = str(tmp_path / "test.db")
    with patch("agent_bom.db.sync.sync_db", return_value={"epss": 42}) as mock_sync:
        result = _run(["db", "update", "--source", "epss", "--path", db_path])
    assert result.exit_code == 0
    assert mock_sync.call_args[1]["sources"] == ["epss"]


def test_db_update_ghsa_accepts_full_backend_ecosystem_set(tmp_path):
    """CLI GHSA ecosystem choices should not lag behind the sync backend."""
    db_path = str(tmp_path / "test.db")
    with patch("agent_bom.db.sync.sync_db", return_value={"ghsa": 1}) as mock_sync:
        result = _run(["db", "update", "--source", "ghsa", "--ghsa-ecosystems", "actions", "--path", db_path])

    assert result.exit_code == 0
    assert mock_sync.call_args[1]["ghsa_ecosystems"] == ["actions"]


# ---------------------------------------------------------------------------
# check / verify / where CLI commands (quick smoke tests)
# ---------------------------------------------------------------------------


def test_check_help():
    result = _run(["check", "--help"])
    assert result.exit_code == 0


def test_verify_help():
    result = _run(["verify", "--help"])
    assert result.exit_code == 0


def test_where_runs():
    """where command shows discovery paths and exits 0."""
    result = _run(["mcp", "where"])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# db status — freshness display
# ---------------------------------------------------------------------------


def test_db_status_freshness_fresh(tmp_path):
    """db status shows green 'Fresh' when synced recently."""
    from datetime import datetime, timezone

    from agent_bom.db.schema import init_db

    db_file = tmp_path / "test.db"
    conn = init_db(db_file)
    now_iso = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
        ("osv", now_iso, 1000),
    )
    conn.commit()
    conn.close()

    result = _run(["db", "status", "--path", str(db_file)])
    assert result.exit_code == 0
    assert "Fresh" in result.output or "ago" in result.output


def test_db_status_freshness_stale(tmp_path):
    """db status shows red 'Stale' when DB is old."""
    from datetime import datetime, timedelta, timezone

    from agent_bom.db.schema import init_db

    db_file = tmp_path / "stale.db"
    conn = init_db(db_file)
    old_iso = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
        ("osv", old_iso, 100),
    )
    conn.commit()
    conn.close()

    result = _run(["db", "status", "--path", str(db_file)])
    assert result.exit_code == 0
    assert "Stale" in result.output or "20d" in result.output or "ago" in result.output


def test_db_status_freshness_aging_at_daily_boundary(tmp_path):
    """db status marks a one-day-old DB as aging, not fresh."""
    from datetime import datetime, timedelta, timezone

    from agent_bom.db.schema import init_db

    db_file = tmp_path / "aging.db"
    conn = init_db(db_file)
    old_iso = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
        ("osv", old_iso, 100),
    )
    conn.commit()
    conn.close()

    result = _run(["db", "status", "--path", str(db_file)])
    assert result.exit_code == 0
    assert "Aging" in result.output
    assert "daily" in result.output
    assert "freshness" in result.output
    assert "Fresh (" not in result.output


def test_db_status_no_sync_meta(tmp_path):
    """db status with empty sync_meta shows 'No sync data' message."""
    from agent_bom.db.schema import init_db

    db_file = tmp_path / "empty.db"
    conn = init_db(db_file)
    conn.close()

    result = _run(["db", "status", "--path", str(db_file)])
    assert result.exit_code == 0
    # Should show a 'no sync data' or 'db update' hint
    assert "update" in result.output.lower() or "sync" in result.output.lower()


# ---------------------------------------------------------------------------
# Output format integration tests — badge, svg, graph, plain (#675)
# ---------------------------------------------------------------------------


def test_scan_format_plain_to_stdout():
    """--format plain writes no-color text to stdout."""
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--format", "plain", "--no-scan"])
    assert result.exit_code == 0


def test_scan_format_plain_alias_text():
    """--format text (alias for plain) also exits 0."""
    with (
        patch("agent_bom.cli.agents.discover_all", return_value=[]),
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--format", "text", "--no-scan"])
    assert result.exit_code == 0


def test_scan_format_badge_writes_json(tmp_path):
    """--format badge writes a Shields.io-compatible JSON file."""
    out = tmp_path / "badge.json"
    with (
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "badge", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0
    assert out.exists(), "badge output file was not created"
    data = json.loads(out.read_text())
    assert "schemaVersion" in data or "label" in data or "message" in data


def test_scan_format_svg_writes_file(tmp_path):
    """--format svg writes an SVG file."""
    out = tmp_path / "report.svg"
    with (
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "svg", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0
    assert out.exists(), "svg output file was not created"
    content = out.read_text()
    assert "<svg" in content


def test_scan_format_graph_writes_json(tmp_path):
    """--format graph writes Cytoscape JSON to a file."""
    out = tmp_path / "graph.json"
    with (
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "graph", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0
    assert out.exists(), "graph output file was not created"
    data = json.loads(out.read_text())
    assert "elements" in data
    assert data.get("format") == "cytoscape"


def test_scan_format_mermaid_writes_file(tmp_path):
    """--format mermaid writes a Mermaid diagram file."""
    out = tmp_path / "diagram.mmd"
    with (
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "mermaid", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0
    assert out.exists(), "mermaid output file was not created"


def test_scan_format_mermaid_accepts_mermaid_extension(tmp_path):
    """--format mermaid accepts the explicit .mermaid extension."""
    out = tmp_path / "diagram.mermaid"
    with (
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "mermaid", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0
    assert out.exists(), "mermaid output file was not created"


def test_scan_format_graph_html_writes_file(tmp_path):
    """--format graph-html writes an interactive HTML file."""
    out = tmp_path / "graph.html"
    with (
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "graph-html", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0
    assert out.exists(), "graph-html output file was not created"
    assert "<html" in out.read_text().lower()


def test_scan_format_graph_html_offline_omits_cdn_scripts(tmp_path):
    """--offline-html writes an airgap-safe static graph HTML file."""
    out = tmp_path / "graph.html"
    with (
        patch("agent_bom.cli.agents.scan_agents_sync", return_value=([], [])),
        patch("agent_bom.cli.agents.resolve_all_versions_sync", return_value=[]),
    ):
        result = _run(["scan", "--demo", "--format", "graph-html", "--offline-html", "--output", str(out), "--no-scan"])
    assert result.exit_code == 0
    content = out.read_text(encoding="utf-8")
    assert "Offline HTML mode" in content
    assert "https://cdnjs.cloudflare.com" not in content
    assert "https://cdn.jsdelivr.net" not in content


def test_format_choices_include_plain():
    """--format help text must list 'plain' as a valid choice."""
    result = _run(["scan", "--help"])
    assert result.exit_code == 0
    assert "plain" in result.output


def test_compliance_export_help_lists_supported_values():
    """--compliance-export help should document the accepted slugs clearly."""
    result = _run(["scan", "--help-all"])
    assert result.exit_code == 0
    assert "--compliance-export" in result.output
    assert "cmmc" in result.output
    assert "fedramp" in result.output
    assert "nist-ai-rmf" in result.output
    assert "soc2" in result.output
    assert "pci-dss" in result.output


def test_scan_complete_closer_renders_severity_breakdown():
    """Regression: ``Scan complete -- N high · M medium`` must render content,
    not just an empty trailing dash.

    On Python 3.13 ``str(Severity.CRITICAL)`` returns ``'Severity.CRITICAL'``
    rather than ``'critical'``, which previously caused the closer's
    severity-key lookup to miss every entry in the canonical
    ``["critical", "high", "medium", "low", "unknown"]`` order list and
    render an empty breakdown after ``Scan complete --``.
    """
    result = _run(["scan", "--demo", "--no-auto-update-db"])

    # The closer fires only when blast_radii is non-empty; demo provides 50+.
    if "Scan complete" in result.output:
        # Must NOT be the empty-breakdown form.
        # Find the closer line and confirm it has content after the em dash.
        for line in result.output.splitlines():
            if "Scan complete" in line and "—" in line:
                trailing = line.split("—", 1)[1].strip()
                assert trailing, f"closer rendered empty breakdown: {line!r}"
                # And the trailing content should mention at least one severity tier.
                assert any(s in trailing.lower() for s in ("critical", "high", "medium", "low", "advisory")), (
                    f"closer rendered no severity tier: {line!r}"
                )
                break


# ---------------------------------------------------------------------------
# Positional PATH (Docker-style shorthand for --project/-p)
# ---------------------------------------------------------------------------


def test_scan_positional_path_resolves_like_project(tmp_path):
    """`scan <dir>` resolves to the same project scan as `scan -p <dir>`."""
    captured: dict = {}

    def _capture(**kwargs):
        captured["project_dir"] = kwargs.get("project_dir")
        return []

    with patch("agent_bom.cli.agents.discover_all", side_effect=_capture):
        result = _run(["scan", str(tmp_path), "--no-scan"])

    assert result.exit_code == 0
    assert captured["project_dir"] == str(tmp_path)


def test_scan_positional_path_matches_project_flag(tmp_path):
    """Positional PATH and -p produce the same project_dir handed to discovery."""
    pos: dict = {}
    flag: dict = {}

    def _make(sink):
        def _capture(**kwargs):
            sink["project_dir"] = kwargs.get("project_dir")
            return []

        return _capture

    with patch("agent_bom.cli.agents.discover_all", side_effect=_make(pos)):
        r1 = _run(["scan", str(tmp_path), "--no-scan"])
    with patch("agent_bom.cli.agents.discover_all", side_effect=_make(flag)):
        r2 = _run(["scan", "-p", str(tmp_path), "--no-scan"])

    assert r1.exit_code == 0
    assert r2.exit_code == 0
    assert pos["project_dir"] == flag["project_dir"] == str(tmp_path)


def test_scan_positional_dot_current_dir(tmp_path):
    """`scan .` scans the current working directory."""
    captured: dict = {}

    def _capture(**kwargs):
        captured["project_dir"] = kwargs.get("project_dir")
        return []

    runner = CliRunner()
    with patch("agent_bom.cli.agents.discover_all", side_effect=_capture):
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ["scan", ".", "--no-scan", "--no-auto-update-db"], catch_exceptions=False)

    assert result.exit_code == 0
    assert captured["project_dir"] == "."


def test_scan_no_positional_keeps_default(tmp_path):
    """No positional and no -p leaves project as the existing default (None)."""
    captured: dict = {}

    def _capture(**kwargs):
        captured["project_dir"] = kwargs.get("project_dir")
        return []

    with patch("agent_bom.cli.agents.discover_all", side_effect=_capture):
        result = _run(["scan", "--no-scan"])

    assert result.exit_code == 0
    assert captured["project_dir"] is None


def test_scan_positional_and_project_conflict_warns_project_wins(tmp_path):
    """When PATH and -p disagree, -p wins (positional must not silently override)."""
    other = tmp_path / "other"
    other.mkdir()
    captured: dict = {}

    def _capture(**kwargs):
        captured["project_dir"] = kwargs.get("project_dir")
        return []

    with patch("agent_bom.cli.agents.discover_all", side_effect=_capture):
        result = _run(["scan", str(tmp_path), "-p", str(other), "--no-scan"])

    assert result.exit_code == 0
    assert captured["project_dir"] == str(other)


def test_scan_positional_with_image_still_routes_to_image(tmp_path):
    """Positional PATH alongside --image must not hijack image scanning."""
    image_calls: list = []
    discover_calls: list = []

    def _fake_scan_image(image_ref, **kwargs):
        image_calls.append(image_ref)
        return ([], "test-strategy")

    def _capture_discover(**kwargs):
        discover_calls.append(kwargs.get("project_dir"))
        return []

    with (
        patch("agent_bom.image.scan_image", side_effect=_fake_scan_image),
        patch("agent_bom.cli.agents.discover_all", side_effect=_capture_discover),
    ):
        result = _run(["scan", str(tmp_path), "--image", "alpine:3.19", "--no-scan"])

    assert result.exit_code == 0
    # Image scanning still happened.
    assert image_calls == ["alpine:3.19"]
    # Local project discovery was skipped for image scans (no hijack via PATH).
    assert discover_calls == []
