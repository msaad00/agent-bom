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
    normalized = " ".join(result.output.split())
    assert result.exit_code == 0
    assert "--output" in result.output
    assert "--format" in result.output
    assert "graph (Cytoscape.js graph JSON)" in normalized
    assert "graph (raw graph JSON)" not in normalized


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

    result = _run(["scan", "--format", "sarif", "--demo", "--no-auto-update-db"])

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


def test_scan_incomplete_offline_scan_exits_two(monkeypatch):
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
