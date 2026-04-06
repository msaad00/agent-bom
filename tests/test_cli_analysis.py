"""Tests for agent_bom.cli._analysis to improve coverage."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from agent_bom.cli._analysis import (
    analytics_cmd,
    dashboard_cmd,
    graph_cmd,
    introspect_cmd,
    mesh_cmd,
)

# ---------------------------------------------------------------------------
# analytics_cmd
# ---------------------------------------------------------------------------


def test_analytics_no_url():
    runner = CliRunner()
    result = runner.invoke(analytics_cmd, ["trends"])
    assert result.exit_code == 1
    assert "ClickHouse URL required" in result.output


def test_analytics_trends():
    runner = CliRunner()
    mock_store = MagicMock()
    mock_store.query_vuln_trends.return_value = [{"day": "2025-01-01", "severity": "high", "cnt": 5}]
    with patch("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", return_value=mock_store):
        result = runner.invoke(analytics_cmd, ["trends", "--clickhouse-url", "http://localhost:8123"])
        assert result.exit_code == 0


def test_analytics_posture():
    runner = CliRunner()
    mock_store = MagicMock()
    mock_store.query_posture_history.return_value = [
        {"day": "2025-01-01", "agent_name": "test", "posture_grade": "B", "risk_score": 3.5, "compliance_score": 85}
    ]
    with patch("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", return_value=mock_store):
        result = runner.invoke(analytics_cmd, ["posture", "--clickhouse-url", "http://localhost:8123"])
        assert result.exit_code == 0


def test_analytics_events():
    runner = CliRunner()
    mock_store = MagicMock()
    mock_store.query_event_summary.return_value = [{"event_type": "tool_call", "severity": "medium", "cnt": 10}]
    with patch("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", return_value=mock_store):
        result = runner.invoke(analytics_cmd, ["events", "--clickhouse-url", "http://localhost:8123"])
        assert result.exit_code == 0


def test_analytics_top_cves():
    runner = CliRunner()
    mock_store = MagicMock()
    mock_store.query_top_cves.return_value = [{"cve_id": "CVE-2025-0001", "cnt": 5, "max_cvss": 9.8}]
    with patch("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", return_value=mock_store):
        result = runner.invoke(analytics_cmd, ["top-cves", "--clickhouse-url", "http://localhost:8123"])
        assert result.exit_code == 0


def test_analytics_fleet():
    runner = CliRunner()
    mock_store = MagicMock()
    mock_store.query_top_riskiest_agents.return_value = [
        {
            "agent_name": "alpha",
            "lifecycle_state": "discovered",
            "trust_score": 42.0,
            "vuln_count": 3,
            "credential_count": 1,
            "tenant_id": "default",
        }
    ]
    with patch("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", return_value=mock_store):
        result = runner.invoke(analytics_cmd, ["fleet", "--clickhouse-url", "http://localhost:8123"])
        assert result.exit_code == 0


def test_analytics_compliance():
    runner = CliRunner()
    mock_store = MagicMock()
    mock_store.query_compliance_heatmap.return_value = [{"framework": "owasp-llm-top10", "status": "fail", "cnt": 2, "avg_score": 40.0}]
    with patch("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", return_value=mock_store):
        result = runner.invoke(analytics_cmd, ["compliance", "--clickhouse-url", "http://localhost:8123"])
        assert result.exit_code == 0


def test_analytics_empty_results():
    runner = CliRunner()
    mock_store = MagicMock()
    mock_store.query_vuln_trends.return_value = []
    with patch("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", return_value=mock_store):
        result = runner.invoke(analytics_cmd, ["trends", "--clickhouse-url", "http://localhost:8123"])
        assert result.exit_code == 0
        assert "No data found" in result.output


def test_analytics_connection_error():
    runner = CliRunner()
    with patch("agent_bom.api.clickhouse_store.ClickHouseAnalyticsStore", side_effect=RuntimeError("connection refused")):
        result = runner.invoke(analytics_cmd, ["trends", "--clickhouse-url", "http://bad:1234"])
        assert result.exit_code == 1
        assert "connection error" in result.output.lower()


# ---------------------------------------------------------------------------
# graph_cmd
# ---------------------------------------------------------------------------


def test_graph_cmd_json(tmp_path):
    runner = CliRunner()
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(
        json.dumps(
            {"agents": [{"name": "a", "mcp_servers": [{"name": "s", "packages": [{"name": "p", "version": "1.0", "ecosystem": "npm"}]}]}]}
        )
    )

    mock_graph = MagicMock()
    mock_graph.node_count.return_value = 2
    mock_graph.edge_count.return_value = 1

    with (
        patch("agent_bom.output.graph_export.load_graph_from_scan", return_value=mock_graph),
        patch("agent_bom.output.graph_export.to_json", return_value={"nodes": [], "edges": []}),
    ):
        result = runner.invoke(graph_cmd, [str(scan_file)])
        assert result.exit_code == 0


def test_graph_cmd_dot_with_output(tmp_path):
    runner = CliRunner()
    scan_file = tmp_path / "scan.json"
    scan_file.write_text("{}")
    out_file = tmp_path / "graph.dot"

    mock_graph = MagicMock()
    mock_graph.node_count.return_value = 2
    mock_graph.edge_count.return_value = 1

    with (
        patch("agent_bom.output.graph_export.load_graph_from_scan", return_value=mock_graph),
        patch("agent_bom.output.graph_export.to_dot", return_value="digraph {}"),
    ):
        result = runner.invoke(graph_cmd, [str(scan_file), "-f", "dot", "-o", str(out_file)])
        assert result.exit_code == 0
        assert out_file.exists()


def test_graph_cmd_mermaid(tmp_path):
    runner = CliRunner()
    scan_file = tmp_path / "scan.json"
    scan_file.write_text("{}")

    mock_graph = MagicMock()
    with (
        patch("agent_bom.output.graph_export.load_graph_from_scan", return_value=mock_graph),
        patch("agent_bom.output.graph_export.to_mermaid", return_value="graph TD"),
    ):
        result = runner.invoke(graph_cmd, [str(scan_file), "-f", "mermaid"])
        assert result.exit_code == 0


def test_graph_cmd_load_error(tmp_path):
    runner = CliRunner()
    scan_file = tmp_path / "scan.json"
    scan_file.write_text("{}")

    with patch("agent_bom.output.graph_export.load_graph_from_scan", side_effect=ValueError("bad scan")):
        result = runner.invoke(graph_cmd, [str(scan_file)])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# mesh_cmd
# ---------------------------------------------------------------------------


def test_mesh_cmd_from_scan_file_json(tmp_path):
    runner = CliRunner()
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(
        json.dumps(
            {
                "agents": [
                    {
                        "name": "claude",
                        "mcp_servers": [
                            {
                                "name": "filesystem",
                                "packages": [{"name": "pkg", "version": "1.0.0", "vulnerabilities": []}],
                                "tools": [{"name": "read_file"}],
                                "env": {"OPENAI_API_KEY": "x"},
                            }
                        ],
                    }
                ],
                "blast_radius": [],
            }
        )
    )

    result = runner.invoke(mesh_cmd, [str(scan_file), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["stats"]["total_agents"] == 1
    assert data["stats"]["total_tools"] == 1


def test_mesh_cmd_live_summary():
    runner = CliRunner()
    server = MagicMock()
    server.name = "filesystem"
    server.packages = []
    server.tools = [{"name": "read_file"}, {"name": "write_file"}]
    server.env = {"GITHUB_TOKEN": "x"}
    agent = MagicMock()
    agent.mcp_servers = [server]

    with (
        patch("agent_bom.discovery.discover_all", return_value=[agent]),
        patch("agent_bom.parsers.extract_packages", return_value=[{"name": "pkg", "version": "1.0.0", "vulnerabilities": []}]),
        patch(
            "dataclasses.asdict",
            return_value={
                "name": "claude",
                "mcp_servers": [
                    {
                        "name": "filesystem",
                        "packages": [{"name": "pkg", "version": "1.0.0", "vulnerabilities": []}],
                        "tools": [{"name": "read_file"}, {"name": "write_file"}],
                        "env": {"GITHUB_TOKEN": "x"},
                    }
                ],
            },
        ),
    ):
        result = runner.invoke(mesh_cmd, [])
        assert result.exit_code == 0
        assert "Mesh" in result.output
        assert "claude" in result.output
        assert "filesystem" in result.output


def test_mesh_cmd_summary_rejects_output_path(tmp_path):
    runner = CliRunner()
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps({"agents": [{"name": "a", "mcp_servers": []}], "blast_radius": []}))
    result = runner.invoke(mesh_cmd, [str(scan_file), "--output", str(tmp_path / "mesh.txt")])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# dashboard_cmd
# ---------------------------------------------------------------------------


def test_dashboard_no_streamlit():
    runner = CliRunner()
    with patch("shutil.which", return_value=None):
        result = runner.invoke(dashboard_cmd, [])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# introspect_cmd
# ---------------------------------------------------------------------------


def test_introspect_no_args():
    runner = CliRunner()
    result = runner.invoke(introspect_cmd, [])
    assert result.exit_code == 1
    assert "Provide" in result.output


def test_introspect_all_no_servers():
    runner = CliRunner()
    with patch("agent_bom.discovery.discover_all", return_value=[]):
        result = runner.invoke(introspect_cmd, ["--all"])
        assert result.exit_code == 0
        assert "No MCP servers" in result.output


def test_introspect_with_command():
    runner = CliRunner()
    mock_result = MagicMock()
    mock_result.server_name = "echo"
    mock_result.success = True
    mock_result.runtime_tools = []
    mock_result.runtime_resources = []
    mock_result.error = None
    mock_result.protocol_version = "1.0"

    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[mock_result]):
        result = runner.invoke(introspect_cmd, ["--command", "echo hello"])
        assert result.exit_code == 0


def test_introspect_with_command_tolerates_missing_capability_risk_fields():
    runner = CliRunner()
    mock_result = MagicMock()
    mock_result.server_name = "echo"
    mock_result.success = True
    mock_result.runtime_tools = []
    mock_result.runtime_resources = []
    mock_result.error = None
    mock_result.protocol_version = "1.0"
    mock_result.capability_risk_score = MagicMock()
    mock_result.capability_risk_level = MagicMock()
    mock_result.dangerous_combinations = MagicMock()
    mock_result.tool_risk_profiles = MagicMock()

    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[mock_result]):
        result = runner.invoke(introspect_cmd, ["--command", "echo hello"])
        assert result.exit_code == 0
        assert "Capability Risk:" in result.output


def test_introspect_json_output():
    runner = CliRunner()
    mock_result = MagicMock()
    mock_result.server_name = "test"
    mock_result.success = True
    mock_result.runtime_tools = []
    mock_result.runtime_resources = []
    mock_result.error = None

    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[mock_result]):
        result = runner.invoke(introspect_cmd, ["--command", "echo", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)


def test_introspect_failed_server():
    runner = CliRunner()
    mock_result = MagicMock()
    mock_result.server_name = "test"
    mock_result.success = False
    mock_result.runtime_tools = []
    mock_result.runtime_resources = []
    mock_result.error = "connection failed"
    mock_result.protocol_version = None

    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[mock_result]):
        result = runner.invoke(introspect_cmd, ["--url", "http://localhost:9999"])
        assert result.exit_code == 0


def test_introspect_with_baseline_drift(tmp_path):
    runner = CliRunner()
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"test": ["tool_a", "tool_b"]}))

    mock_tool_c = MagicMock()
    mock_tool_c.name = "tool_c"
    mock_tool_c.description = "new tool"

    mock_result = MagicMock()
    mock_result.server_name = "test"
    mock_result.success = True
    mock_result.runtime_tools = [mock_tool_c]
    mock_result.runtime_resources = []
    mock_result.error = None
    mock_result.protocol_version = "1.0"

    with patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=[mock_result]):
        result = runner.invoke(introspect_cmd, ["--command", "echo", "--baseline", str(baseline)])
        assert result.exit_code == 1  # drift detected
        assert "Drift" in result.output or "Removed" in result.output


def test_introspect_import_error():
    runner = CliRunner()
    with patch("agent_bom.mcp_introspect.introspect_servers_sync", side_effect=ImportError("no mcp")):
        result = runner.invoke(introspect_cmd, ["--command", "echo"])
        assert result.exit_code == 1
        assert "MCP SDK" in result.output
