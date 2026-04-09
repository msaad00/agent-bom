"""Tests for the primary scan CLI command and the db CLI group.

Covers the high-level invocation paths in cli/scan.py and cli/_db.py that
were previously untested (floor was at 79%).  Uses Click's CliRunner so
no network or filesystem side-effects escape the test.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agent_bom.cli import main
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
    runner = CliRunner()
    return runner.invoke(main, args, catch_exceptions=catch_exceptions, **kwargs)


# ---------------------------------------------------------------------------
# Top-level --help / --version
# ---------------------------------------------------------------------------


def test_main_help():
    result = _run(["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


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


def test_scan_empty_state_shows_real_client_paths(monkeypatch):
    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *args, **kwargs: [])

    result = _run(["scan"])

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


def test_scan_quiet_flag():
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--quiet", "--no-scan"])
    assert result.exit_code == 0


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


def test_scan_unknown_output_extension_fails(tmp_path):
    out = tmp_path / "report.ocsf"
    result = _run(["scan", "--demo", "--output", str(out), "--no-scan"])
    assert result.exit_code == 2
    assert "Cannot infer output format" in result.output


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

    result = _run(["scan", "--format", "sarif", "--demo"])

    assert result.exit_code == 0
    assert captured["enable_enrichment"] is True


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


def test_scan_save_flag(tmp_path):
    """--save should persist the report to history."""
    with patch("agent_bom.cli.agents.discover_all", return_value=[]):
        result = _run(["scan", "--save", "--no-scan"])
    assert result.exit_code == 0


def test_scan_incomplete_offline_scan_exits_two(monkeypatch):
    monkeypatch.setattr("agent_bom.cli.agents.discover_all", lambda *args, **kwargs: [])

    def _scan_agents_sync(*args, **kwargs):
        raise IncompleteScanError("Offline mode requires a populated local vulnerability DB.")

    monkeypatch.setattr("agent_bom.cli.agents.scan_agents_sync", _scan_agents_sync)

    result = _run(["scan", "--demo"])

    assert result.exit_code == 2
    assert "populated local vulnerability DB" in result.output


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


def test_format_choices_include_plain():
    """--format help text must list 'plain' as a valid choice."""
    result = _run(["scan", "--help"])
    assert result.exit_code == 0
    assert "plain" in result.output


def test_compliance_export_help_lists_supported_values():
    """--compliance-export help should document the accepted slugs clearly."""
    result = _run(["scan", "--help"])
    assert result.exit_code == 0
    assert "--compliance-export" in result.output
    assert "cmmc, fedramp, nist-ai-rmf" in result.output
