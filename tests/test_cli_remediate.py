"""Tests for the ``agent-bom remediate`` CLI command."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agent_bom.cli._remediate import remediate_cmd

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_blast_radius(
    pkg_name="flask",
    pkg_version="2.0.0",
    ecosystem="pypi",
    vuln_id="CVE-2023-0001",
    severity_val=None,
    fix_version="2.0.3",
    risk_score=7.5,
    is_kev=False,
    agents=None,
    servers=None,
):
    """Build a mock BlastRadius for testing."""
    from agent_bom.models import Severity

    sev = severity_val or Severity.HIGH

    vuln = MagicMock()
    vuln.id = vuln_id
    vuln.severity = sev
    vuln.fixed_version = fix_version
    vuln.is_kev = is_kev
    vuln.references = [f"https://nvd.nist.gov/vuln/detail/{vuln_id}"]

    pkg = MagicMock()
    pkg.name = pkg_name
    pkg.version = pkg_version
    pkg.ecosystem = ecosystem

    agent = MagicMock()
    agent.name = "test-agent"

    server = MagicMock()
    server.name = "test-server"

    br = MagicMock()
    br.vulnerability = vuln
    br.package = pkg
    br.affected_agents = agents or [agent]
    br.affected_servers = servers or [server]
    br.exposed_credentials = []
    br.exposed_tools = []
    br.risk_score = risk_score
    br.ai_risk_context = None
    br.owasp_tags = []
    br.atlas_tags = []
    br.nist_ai_rmf_tags = []
    br.owasp_mcp_tags = []
    br.owasp_agentic_tags = []
    br.eu_ai_act_tags = []
    br.nist_csf_tags = []
    br.iso_27001_tags = []
    br.soc2_tags = []
    br.cis_tags = []
    return br


def _patch_scan(blast_radii=None):
    """Return a patch context that replaces run_default_scan with a mock."""
    from agent_bom.cli._scan_runner import ScanResult
    from agent_bom.models import AIBOMReport

    if blast_radii is None:
        blast_radii = [_make_mock_blast_radius()]

    agents = [MagicMock()]
    report = AIBOMReport(agents=agents, blast_radii=blast_radii, findings=[])

    return patch(
        "agent_bom.cli._remediate.run_default_scan",
        return_value=ScanResult(agents=agents, blast_radii=blast_radii, report=report, total_packages=1),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_remediate_demo_offline_runs():
    """``remediate --demo --offline`` should complete without error."""
    runner = CliRunner()
    with _patch_scan():
        result = runner.invoke(remediate_cmd, ["--demo", "--offline"])
    assert result.exit_code == 0, result.output


def test_remediate_json_contains_plan_key():
    """JSON output should contain ``remediation_plan`` key with items."""
    runner = CliRunner()
    with _patch_scan():
        result = runner.invoke(remediate_cmd, ["--demo", "--offline", "-f", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert "remediation_plan" in data
    assert "version" in data
    assert "generated_at" in data
    assert len(data["remediation_plan"]) > 0
    # Check item structure
    item = data["remediation_plan"][0]
    assert "package" in item
    assert "blast_radius_score" in item
    assert "references" in item
    assert "ranking_rationale" in item
    assert "ranking_reasons" in item


def test_remediate_fixable_only_filters():
    """``--fixable-only`` should exclude items without a fix version."""
    from agent_bom.models import Severity

    fixable_br = _make_mock_blast_radius(pkg_name="flask", fix_version="2.0.3")
    unfixable_br = _make_mock_blast_radius(
        pkg_name="requests",
        fix_version=None,
        vuln_id="CVE-2023-9999",
        severity_val=Severity.MEDIUM,
    )

    runner = CliRunner()
    with _patch_scan(blast_radii=[fixable_br, unfixable_br]):
        result = runner.invoke(remediate_cmd, ["--demo", "--offline", "-f", "json", "--fixable-only"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    for item in data["remediation_plan"]:
        assert item["fixed_version"] is not None, f"Unfixable item leaked through: {item['package']}"


def test_remediate_server_group_changes_output():
    """``--server-group`` should produce grouped console output."""
    runner = CliRunner()
    with _patch_scan():
        runner.invoke(remediate_cmd, ["--demo", "--offline"])
        result_grouped = runner.invoke(remediate_cmd, ["--demo", "--offline", "--server-group"])
    assert result_grouped.exit_code == 0, result_grouped.output
    # Grouped output should mention "grouped by MCP server"
    assert "MCP server" in result_grouped.output or "test-server" in result_grouped.output


def test_remediate_server_group_json():
    """``--server-group`` with JSON should include ``server_groups``."""
    runner = CliRunner()
    with _patch_scan():
        result = runner.invoke(remediate_cmd, ["--demo", "--offline", "-f", "json", "--server-group"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert "server_groups" in data


def test_remediate_priority_filter():
    """``--priority P1`` should exclude P2+ items."""
    from agent_bom.models import Severity

    # KEV = P1
    p1_br = _make_mock_blast_radius(pkg_name="critical-pkg", is_kev=True, severity_val=Severity.CRITICAL)
    # Non-KEV high = P3
    p3_br = _make_mock_blast_radius(pkg_name="minor-pkg", severity_val=Severity.HIGH, vuln_id="CVE-2023-0002")

    runner = CliRunner()
    with _patch_scan(blast_radii=[p1_br, p3_br]):
        result = runner.invoke(remediate_cmd, ["--demo", "--offline", "-f", "json", "--priority", "P1"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    for item in data["remediation_plan"]:
        assert item["priority"] == "P1", f"Non-P1 item leaked: {item['package']} ({item['priority']})"


def test_remediate_orders_same_priority_items_by_credential_aware_rank():
    from agent_bom.models import Severity

    cred_br = _make_mock_blast_radius(
        pkg_name="cred-first",
        severity_val=Severity.CRITICAL,
        vuln_id="CVE-2023-1111",
        risk_score=7.0,
    )
    cred_br.exposed_credentials = ["OPENAI_API_KEY", "DB_TOKEN"]

    plain_br = _make_mock_blast_radius(
        pkg_name="plain-second",
        severity_val=Severity.CRITICAL,
        vuln_id="CVE-2023-2222",
        risk_score=7.0,
    )

    runner = CliRunner()
    with _patch_scan(blast_radii=[plain_br, cred_br]):
        result = runner.invoke(remediate_cmd, ["--demo", "--offline", "-f", "json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["remediation_plan"][0]["package"] == "cred-first"
    assert "exposed credentials" in data["remediation_plan"][0]["ranking_rationale"]


def test_remediate_markdown_output():
    """Markdown format should produce readable report."""
    runner = CliRunner()
    with _patch_scan():
        result = runner.invoke(remediate_cmd, ["--demo", "--offline", "-f", "markdown"])
    assert result.exit_code == 0, result.output
    assert "# Remediation Plan" in result.output
    assert "flask" in result.output


def test_remediate_no_vulns():
    """When no vulns found, should print clean message."""
    runner = CliRunner()
    with _patch_scan(blast_radii=[]):
        result = runner.invoke(remediate_cmd, ["--demo", "--offline"])
    assert result.exit_code == 0
    assert "no remediation" in result.output.lower() or "No vulnerabilities" in result.output


def test_remediate_output_file(tmp_path):
    """``-o`` should write output to a file."""
    out_file = tmp_path / "plan.json"
    runner = CliRunner()
    with _patch_scan():
        result = runner.invoke(remediate_cmd, ["--demo", "--offline", "-f", "json", "-o", str(out_file)])
    assert result.exit_code == 0, result.output
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert "remediation_plan" in data


def test_remediate_quiet_suppresses_scan_chatter():
    from agent_bom.cli._scan_runner import ScanResult
    from agent_bom.models import AIBOMReport

    blast_radii = [_make_mock_blast_radius()]
    report = AIBOMReport(agents=[MagicMock()], blast_radii=blast_radii, findings=[])

    def _fake_run_default_scan(config, con):  # noqa: ARG001
        con.print("scan chatter that should stay hidden")
        return ScanResult(agents=[MagicMock()], blast_radii=blast_radii, report=report, total_packages=1)

    runner = CliRunner()
    with patch("agent_bom.cli._remediate.run_default_scan", side_effect=_fake_run_default_scan):
        result = runner.invoke(remediate_cmd, ["--demo", "--offline", "--quiet"])

    assert result.exit_code == 0, result.output
    assert "scan chatter" not in result.output
    assert "flask" in result.output
