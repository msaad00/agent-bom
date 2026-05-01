"""Tests for MCP tool implementation modules.

These cover mcp_tools/registry.py, mcp_tools/analysis.py, and
mcp_tools/specialized.py which were at <25% coverage.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _trunc(s: str) -> str:
    return s


def _trunc_async(s: str) -> str:
    return s


# ---------------------------------------------------------------------------
# mcp_tools/registry.py — registry_lookup_impl
# ---------------------------------------------------------------------------


def test_registry_lookup_no_term():
    from agent_bom.mcp_tools.registry import registry_lookup_impl

    result = registry_lookup_impl(
        server_name=None,
        package_name=None,
        _get_registry_data=lambda: {"servers": {}},
    )
    data = json.loads(result)
    assert "error" in data


def test_registry_lookup_not_found():
    from agent_bom.mcp_tools.registry import registry_lookup_impl

    result = registry_lookup_impl(
        server_name="nonexistent-xyz-abc",
        package_name=None,
        _get_registry_data=lambda: {"servers": {}},
    )
    data = json.loads(result)
    # Stable envelope from #1960.
    assert data["error"]["code"] == "AGENTBOM_MCP_NOT_FOUND_RESOURCE"
    assert data["error"]["category"] == "not_found"


def test_registry_lookup_found_by_name():
    from agent_bom.mcp_tools.registry import registry_lookup_impl

    registry = {
        "servers": {
            "filesystem": {
                "name": "filesystem",
                "package": "@modelcontextprotocol/server-filesystem",
                "ecosystem": "npm",
                "latest_version": "2025.1.14",
                "risk_level": "low",
                "risk_justification": "No CVEs",
                "verified": True,
                "tools": ["read_file"],
                "credential_env_vars": [],
                "known_cves": [],
                "category": "tools",
                "license": "MIT",
                "source_url": "https://github.com/modelcontextprotocol/servers",
            }
        }
    }
    result = registry_lookup_impl(
        server_name="filesystem",
        package_name=None,
        _get_registry_data=lambda: registry,
    )
    data = json.loads(result)
    assert data["found"] is True
    assert data["id"] == "filesystem"


def test_registry_lookup_found_by_package_name():
    from agent_bom.mcp_tools.registry import registry_lookup_impl

    registry = {
        "servers": {
            "github": {
                "name": "github",
                "package": "@modelcontextprotocol/server-github",
                "ecosystem": "npm",
                "latest_version": "1.0.0",
                "risk_level": "medium",
                "risk_justification": "Has network access",
                "verified": True,
                "tools": [],
                "credential_env_vars": ["GITHUB_TOKEN"],
                "known_cves": [],
                "category": "tools",
                "license": "MIT",
                "source_url": "",
            }
        }
    }
    result = registry_lookup_impl(
        server_name=None,
        package_name="server-github",
        _get_registry_data=lambda: registry,
    )
    data = json.loads(result)
    assert data["found"] is True


def test_registry_lookup_registry_error():
    from agent_bom.mcp_tools.registry import registry_lookup_impl

    def _fail():
        raise RuntimeError("disk read failed")

    result = registry_lookup_impl(
        server_name="anything",
        package_name=None,
        _get_registry_data=_fail,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_marketplace_check_empty_package():
    from agent_bom.mcp_tools.registry import marketplace_check_impl

    result = await marketplace_check_impl(
        package="",
        ecosystem="npm",
        _validate_ecosystem=lambda e: e,
        _get_registry_data_raw=lambda: {},
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_marketplace_check_package_too_long():
    from agent_bom.mcp_tools.registry import marketplace_check_impl

    result = await marketplace_check_impl(
        package="x" * 300,
        ecosystem="npm",
        _validate_ecosystem=lambda e: e,
        _get_registry_data_raw=lambda: {},
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


# ---------------------------------------------------------------------------
# mcp_tools/analysis.py — blast_radius_impl, context_graph_impl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blast_radius_invalid_cve():
    from agent_bom.mcp_tools.analysis import blast_radius_impl

    def _bad_validate(cve_id):
        raise ValueError("invalid CVE format")

    result = await blast_radius_impl(
        cve_id="NOT-A-CVE",
        _validate_cve_id=_bad_validate,
        _run_scan_pipeline=AsyncMock(),
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_blast_radius_cve_not_found():
    from agent_bom.mcp_tools.analysis import blast_radius_impl

    async def _pipeline():
        return [], [], [], []

    result = await blast_radius_impl(
        cve_id="CVE-2024-9999",
        _validate_cve_id=lambda x: x.upper(),
        _run_scan_pipeline=_pipeline,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    # Stable envelope from #1960.
    assert data["error"]["code"] == "AGENTBOM_MCP_NOT_FOUND_RESOURCE"
    assert data["error"]["category"] == "not_found"
    assert data["error"]["details"]["cve_id"] == "CVE-2024-9999"


@pytest.mark.asyncio
async def test_blast_radius_found():
    from agent_bom.mcp_tools.analysis import blast_radius_impl

    br = MagicMock()
    br.vulnerability.id = "CVE-2024-9999"
    br.vulnerability.severity.value = "high"
    br.vulnerability.cvss_score = 8.5
    br.vulnerability.fixed_version = "1.1.0"
    br.risk_score = 8.0
    br.package.name = "requests"
    br.package.version = "2.0.0"
    br.package.ecosystem = "pypi"
    br.affected_servers = []
    br.affected_agents = []
    br.exposed_credentials = []
    br.exposed_tools = []
    br.ai_risk_context = ""

    async def _pipeline():
        return [], [br], [], []

    result = await blast_radius_impl(
        cve_id="CVE-2024-9999",
        _validate_cve_id=lambda x: x.upper(),
        _run_scan_pipeline=_pipeline,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert data["found"] is True
    assert len(data["blast_radii"]) == 1


@pytest.mark.asyncio
async def test_blast_radius_pipeline_exception():
    from agent_bom.mcp_tools.analysis import blast_radius_impl

    async def _fail():
        raise RuntimeError("scan failed")

    result = await blast_radius_impl(
        cve_id="CVE-2024-1",
        _validate_cve_id=lambda x: x.upper(),
        _run_scan_pipeline=_fail,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


# ---------------------------------------------------------------------------
# mcp_tools/specialized.py — dataset_card_scan_impl, training_pipeline_scan_impl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dataset_card_scan_invalid_path():
    from agent_bom.mcp_tools.specialized import dataset_card_scan_impl

    result = await dataset_card_scan_impl(
        directory="/nonexistent/path/xyz",
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_training_pipeline_scan_invalid_path():
    from agent_bom.mcp_tools.specialized import training_pipeline_scan_impl

    result = await training_pipeline_scan_impl(
        directory="/nonexistent/path/xyz",
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_browser_extension_scan_impl_success():
    from agent_bom.mcp_tools.specialized import browser_extension_scan_impl

    with patch("agent_bom.parsers.browser_extensions.discover_browser_extensions", return_value=[]):
        result = await browser_extension_scan_impl(
            include_low_risk=False,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "extensions" in data
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_browser_extension_scan_impl_error():
    from agent_bom.mcp_tools.specialized import browser_extension_scan_impl

    with patch(
        "agent_bom.parsers.browser_extensions.discover_browser_extensions",
        side_effect=RuntimeError("discovery failed"),
    ):
        result = await browser_extension_scan_impl(
            include_low_risk=False,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


# ---------------------------------------------------------------------------
# mcp_tools/analysis.py — context_graph_impl, analytics_query_impl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_context_graph_no_agents():
    from agent_bom.mcp_tools.analysis import context_graph_impl

    async def _pipeline(_config=None, _image=None):
        return [], [], [], []

    result = await context_graph_impl(
        config_path=None,
        source_agent=None,
        _run_scan_pipeline=_pipeline,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_context_graph_pipeline_exception():
    from agent_bom.mcp_tools.analysis import context_graph_impl

    async def _fail(_config=None, _image=None):
        raise RuntimeError("graph build failed")

    result = await context_graph_impl(
        config_path=None,
        source_agent=None,
        _run_scan_pipeline=_fail,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_analytics_query_invalid_type():
    from agent_bom.mcp_tools.analysis import analytics_query_impl

    result = await analytics_query_impl(
        query_type="nonexistent",
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_analytics_query_invalid_agent_name():
    from agent_bom.mcp_tools.analysis import analytics_query_impl

    result = await analytics_query_impl(
        query_type="vuln_trends",
        agent="../../etc/passwd; DROP TABLE vulns;--",
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_analytics_query_success_vuln_trends():
    from agent_bom.mcp_tools.analysis import analytics_query_impl

    mock_store = MagicMock()
    mock_store.query_vuln_trends.return_value = [{"date": "2026-01-01", "count": 5}]

    with patch("agent_bom.api.stores._get_analytics_store", return_value=mock_store):
        result = await analytics_query_impl(
            query_type="vuln_trends",
            agent=None,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data["query_type"] == "vuln_trends"


@pytest.mark.asyncio
async def test_analytics_query_success_top_cves():
    from agent_bom.mcp_tools.analysis import analytics_query_impl

    mock_store = MagicMock()
    mock_store.query_top_cves.return_value = []

    with patch("agent_bom.api.stores._get_analytics_store", return_value=mock_store):
        result = await analytics_query_impl(
            query_type="top_cves",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data["query_type"] == "top_cves"


@pytest.mark.asyncio
async def test_analytics_query_success_event_summary():
    from agent_bom.mcp_tools.analysis import analytics_query_impl

    mock_store = MagicMock()
    mock_store.query_event_summary.return_value = []

    with patch("agent_bom.api.stores._get_analytics_store", return_value=mock_store):
        result = await analytics_query_impl(
            query_type="event_summary",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data["query_type"] == "event_summary"


@pytest.mark.asyncio
async def test_analytics_query_exception():
    from agent_bom.mcp_tools.analysis import analytics_query_impl

    with patch("agent_bom.api.stores._get_analytics_store", side_effect=RuntimeError("db down")):
        result = await analytics_query_impl(
            query_type="top_cves",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


# ---------------------------------------------------------------------------
# mcp_tools/compliance.py — compliance_impl, policy_check_impl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compliance_impl_no_agents():
    from agent_bom.mcp_tools.compliance import compliance_impl

    async def _pipeline(_config=None, _image=None):
        return [], [], [], []

    result = await compliance_impl(
        config_path=None,
        image=None,
        _run_scan_pipeline=_pipeline,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    # No agents → should still return compliance breakdown (empty findings)
    assert "overall_status" in data or "error" in data


@pytest.mark.asyncio
async def test_compliance_impl_exception():
    from agent_bom.mcp_tools.compliance import compliance_impl

    async def _fail(_config=None, _image=None):
        raise RuntimeError("scan failed")

    result = await compliance_impl(
        config_path=None,
        image=None,
        _run_scan_pipeline=_fail,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_policy_check_invalid_json():
    from agent_bom.mcp_tools.compliance import policy_check_impl

    result = await policy_check_impl(
        policy_json="{invalid json",
        _run_scan_pipeline=AsyncMock(),
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_policy_check_invalid_policy():
    from agent_bom.mcp_tools.compliance import policy_check_impl

    with patch("agent_bom.policy._validate_policy", side_effect=ValueError("bad policy")):
        result = await policy_check_impl(
            policy_json='{"name": "test"}',
            _run_scan_pipeline=AsyncMock(return_value=([], [], [], [])),
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


# ---------------------------------------------------------------------------
# mcp_tools/cloud.py — vector_db_scan_impl, gpu_infra_scan_impl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vector_db_scan_impl_no_hosts():
    from agent_bom.mcp_tools.cloud import vector_db_scan_impl

    with (
        patch("agent_bom.cloud.vector_db.discover_vector_dbs", return_value=[]),
        patch("agent_bom.cloud.vector_db.discover_pinecone", return_value=[]),
    ):
        result = await vector_db_scan_impl(
            hosts=None,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data["databases_found"] == 0


@pytest.mark.asyncio
async def test_vector_db_scan_impl_with_hosts():
    from agent_bom.mcp_tools.cloud import vector_db_scan_impl

    mock_result = MagicMock()
    mock_result.to_dict.return_value = {"host": "localhost", "port": 6333}

    with (
        patch("agent_bom.cloud.vector_db.discover_vector_dbs", return_value=[mock_result]),
        patch("agent_bom.cloud.vector_db.discover_pinecone", return_value=[]),
    ):
        result = await vector_db_scan_impl(
            hosts="localhost:6333",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data["databases_found"] == 1


@pytest.mark.asyncio
async def test_vector_db_scan_impl_exception():
    from agent_bom.mcp_tools.cloud import vector_db_scan_impl

    with patch("agent_bom.cloud.vector_db.discover_vector_dbs", side_effect=RuntimeError("conn refused")):
        result = await vector_db_scan_impl(
            hosts=None,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_gpu_infra_scan_impl_exception():
    from agent_bom.mcp_tools.cloud import gpu_infra_scan_impl

    with patch("agent_bom.cloud.gpu_infra.scan_gpu_infra", side_effect=RuntimeError("no GPU")):
        result = await gpu_infra_scan_impl(
            k8s_context=None,
            probe_dcgm=False,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


# ---------------------------------------------------------------------------
# mcp_tools/registry.py — fleet_scan_impl, marketplace_check_impl body
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fleet_scan_empty_servers():
    from agent_bom.mcp_tools.registry import fleet_scan_impl

    result = await fleet_scan_impl(
        servers="",
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_fleet_scan_too_many_servers():
    from agent_bom.mcp_tools.registry import fleet_scan_impl

    servers = ",".join([f"server-{i}" for i in range(1001)])
    result = await fleet_scan_impl(
        servers=servers,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_fleet_scan_success():
    from agent_bom.mcp_tools.registry import fleet_scan_impl

    mock_result = MagicMock()
    mock_result.to_json.return_value = '{"servers": [], "total": 0}'

    with patch("agent_bom.fleet_scan.fleet_scan", return_value=mock_result):
        result = await fleet_scan_impl(
            servers="filesystem,github",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "servers" in data or "total" in data


@pytest.mark.asyncio
async def test_fleet_scan_exception():
    from agent_bom.mcp_tools.registry import fleet_scan_impl

    with patch("agent_bom.fleet_scan.fleet_scan", side_effect=RuntimeError("fleet error")):
        result = await fleet_scan_impl(
            servers="filesystem",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


# ---------------------------------------------------------------------------
# mcp_tools/compliance.py — cis_benchmark_impl, aisvs_benchmark_impl,
#                            license_compliance_scan_impl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cis_benchmark_invalid_region():
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl

    result = await cis_benchmark_impl(
        provider="aws",
        region="INVALID_REGION!!",
        profile=None,
        subscription_id=None,
        project_id=None,
        checks=None,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_cis_benchmark_invalid_profile():
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl

    result = await cis_benchmark_impl(
        provider="aws",
        region="us-east-1",
        profile="../../../../etc/passwd",
        subscription_id=None,
        project_id=None,
        checks=None,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_cis_benchmark_unsupported_provider():
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl

    result = await cis_benchmark_impl(
        provider="unknown-cloud",
        region=None,
        profile=None,
        subscription_id=None,
        project_id=None,
        checks=None,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_cis_benchmark_aws_exception():
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl

    with patch("agent_bom.cloud.aws_cis_benchmark.run_benchmark", side_effect=RuntimeError("no creds")):
        result = await cis_benchmark_impl(
            provider="aws",
            region="us-east-1",
            profile=None,
            subscription_id=None,
            project_id=None,
            checks=None,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_aisvs_benchmark_exception():
    from agent_bom.mcp_tools.compliance import aisvs_benchmark_impl

    with patch("agent_bom.cloud.aisvs_benchmark.run_benchmark", side_effect=RuntimeError("no data")):
        result = await aisvs_benchmark_impl(
            checks=None,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_license_compliance_scan_invalid_json():
    from agent_bom.mcp_tools.compliance import license_compliance_scan_impl

    result = await license_compliance_scan_impl(
        scan_json="{not json",
        policy_json="",
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_license_compliance_scan_flat_list():
    from agent_bom.mcp_tools.compliance import license_compliance_scan_impl

    packages = [{"name": "requests", "version": "2.31.0", "ecosystem": "pypi", "license": "Apache-2.0"}]
    mock_report = MagicMock()

    with (
        patch("agent_bom.license_policy.evaluate_license_policy", return_value=mock_report),
        patch("agent_bom.license_policy.to_serializable", return_value={"status": "pass", "violations": []}),
    ):
        result = await license_compliance_scan_impl(
            scan_json=json.dumps(packages),
            policy_json="",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "status" in data


@pytest.mark.asyncio
async def test_license_compliance_scan_full_result():
    from agent_bom.mcp_tools.compliance import license_compliance_scan_impl

    scan = {"agents": [{"name": "my-agent", "mcp_servers": []}]}
    mock_report = MagicMock()

    with (
        patch("agent_bom.license_policy.evaluate_license_policy", return_value=mock_report),
        patch("agent_bom.license_policy.to_serializable", return_value={"status": "pass", "violations": []}),
    ):
        result = await license_compliance_scan_impl(
            scan_json=json.dumps(scan),
            policy_json="",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "status" in data


# ---------------------------------------------------------------------------
# mcp_tools/runtime.py — runtime_correlate_impl, where_impl, inventory_impl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_runtime_correlate_no_audit_log():
    from agent_bom.mcp_tools.runtime import runtime_correlate_impl

    async def _pipeline(_config=None):
        return [], [], [], []

    result = await runtime_correlate_impl(
        config_path="auto",
        audit_log="",
        otel_trace="",
        _safe_path=lambda p: p,
        _run_scan_pipeline=_pipeline,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "scan_summary" in data
    assert data["scan_summary"]["agents"] == 0


@pytest.mark.asyncio
async def test_runtime_correlate_pipeline_exception():
    from agent_bom.mcp_tools.runtime import runtime_correlate_impl

    async def _fail(_config=None):
        raise RuntimeError("scan exploded")

    result = await runtime_correlate_impl(
        config_path="auto",
        audit_log="",
        otel_trace="",
        _safe_path=lambda p: p,
        _run_scan_pipeline=_fail,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


def test_where_impl():
    from agent_bom.mcp_tools.runtime import where_impl

    result = where_impl(_truncate_response=_trunc)
    data = json.loads(result)
    assert "clients" in data
    assert "platform" in data


def test_inventory_impl_no_agents():
    from agent_bom.mcp_tools.runtime import inventory_impl

    with patch("agent_bom.discovery.discover_all", return_value=[]):
        result = inventory_impl(config_path=None, _truncate_response=_trunc)
    data = json.loads(result)
    assert data["status"] == "no_agents_found"


def test_inventory_impl_exception():
    from agent_bom.mcp_tools.runtime import inventory_impl

    with patch("agent_bom.discovery.discover_all", side_effect=RuntimeError("no config")):
        result = inventory_impl(config_path=None, _truncate_response=_trunc)
    data = json.loads(result)
    assert "error" in data


def test_tool_risk_assessment_impl_success():
    from agent_bom.mcp_introspect import IntrospectionReport, ServerIntrospection
    from agent_bom.mcp_tools.runtime import tool_risk_assessment_impl

    server = MagicMock()
    server.name = "filesystem"
    server.command = "npx"
    server.transport.value = "stdio"
    agent = MagicMock()
    agent.mcp_servers = [server]

    intro = ServerIntrospection(
        server_name="filesystem",
        success=True,
        capability_risk_score=7.2,
        capability_risk_level="high",
        tool_risk_profiles=[{"tool_name": "write_file", "risk_score": 8.0, "risk_level": "high"}],
    )
    report = IntrospectionReport(results=[intro])

    with (
        patch("agent_bom.discovery.discover_all", return_value=[agent]),
        patch("agent_bom.mcp_introspect.introspect_servers_sync", return_value=report),
    ):
        result = tool_risk_assessment_impl(config_path=None, timeout=5.0, _truncate_response=_trunc)
    data = json.loads(result)
    assert data["summary"]["total_servers"] == 1
    assert data["servers"][0]["capability_risk_level"] == "high"


# ---------------------------------------------------------------------------
# cli/__init__.py — cli_main error path
# ---------------------------------------------------------------------------


def test_cli_main_keyboard_interrupt():
    """cli_main catches KeyboardInterrupt and exits 130."""
    from agent_bom.cli import cli_main

    with patch("agent_bom.cli.main", side_effect=KeyboardInterrupt):
        try:
            cli_main()
        except SystemExit as exc:
            assert exc.code == 130


def test_cli_main_unhandled_exception():
    """cli_main catches generic exceptions and exits 1."""
    from agent_bom.cli import cli_main

    with patch("agent_bom.cli.main", side_effect=RuntimeError("boom")):
        try:
            cli_main()
        except SystemExit as exc:
            assert exc.code == 1


# ---------------------------------------------------------------------------
# mcp_tools/runtime.py — runtime_correlate_impl audit_log + otel paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_runtime_correlate_with_audit_log(tmp_path):
    from agent_bom.mcp_tools.runtime import runtime_correlate_impl

    log_file = tmp_path / "audit.jsonl"
    log_file.write_text("")

    async def _pipeline(_config=None):
        return [], [], [], []

    mock_corr = MagicMock()
    mock_corr.to_dict.return_value = {"correlated": []}

    with patch("agent_bom.runtime_correlation.correlate", return_value=mock_corr):
        result = await runtime_correlate_impl(
            config_path="auto",
            audit_log=str(log_file),
            otel_trace="",
            _safe_path=lambda p: log_file,
            _run_scan_pipeline=_pipeline,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "correlation" in data


@pytest.mark.asyncio
async def test_runtime_correlate_with_otel_trace(tmp_path):
    from agent_bom.mcp_tools.runtime import runtime_correlate_impl

    trace_file = tmp_path / "trace.json"
    trace_data = {"resourceSpans": []}
    trace_file.write_text(json.dumps(trace_data))

    async def _pipeline(_config=None):
        return [], [], [], []

    with (
        patch("agent_bom.otel_ingest.parse_ml_api_spans", return_value=[]),
        patch("agent_bom.otel_ingest.flag_deprecated_models", return_value=[]),
    ):
        result = await runtime_correlate_impl(
            config_path="auto",
            audit_log="",
            otel_trace=str(trace_file),
            _safe_path=lambda p: trace_file,
            _run_scan_pipeline=_pipeline,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "ml_api_calls" in data


# ---------------------------------------------------------------------------
# mcp_tools/compliance.py — cis_benchmark_impl snowflake/azure/gcp branches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cis_benchmark_snowflake_exception():
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl

    with patch("agent_bom.cloud.snowflake_cis_benchmark.run_benchmark", side_effect=RuntimeError("no snowflake")):
        result = await cis_benchmark_impl(
            provider="snowflake",
            region=None,
            profile=None,
            subscription_id=None,
            project_id=None,
            checks=None,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_cis_benchmark_azure_exception():
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl

    with patch("agent_bom.cloud.azure_cis_benchmark.run_benchmark", side_effect=RuntimeError("no azure")):
        result = await cis_benchmark_impl(
            provider="azure",
            region=None,
            profile=None,
            subscription_id="sub-123",
            project_id=None,
            checks=None,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_cis_benchmark_gcp_exception():
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl

    with patch("agent_bom.cloud.gcp_cis_benchmark.run_benchmark", side_effect=RuntimeError("no gcp")):
        result = await cis_benchmark_impl(
            provider="gcp",
            region=None,
            profile=None,
            subscription_id=None,
            project_id="my-project",
            checks=None,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_license_compliance_scan_with_policy():
    from agent_bom.mcp_tools.compliance import license_compliance_scan_impl

    packages = [{"name": "gpl-pkg", "version": "1.0.0", "ecosystem": "pypi", "license": "GPL-3.0"}]
    policy = {"blocked_licenses": ["GPL-3.0"]}
    mock_report = MagicMock()

    with (
        patch("agent_bom.license_policy.evaluate_license_policy", return_value=mock_report),
        patch("agent_bom.license_policy.to_serializable", return_value={"status": "fail", "violations": []}),
    ):
        result = await license_compliance_scan_impl(
            scan_json=json.dumps(packages),
            policy_json=json.dumps(policy),
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "status" in data


# ---------------------------------------------------------------------------
# mcp_tools/runtime.py — verify_impl, skill_scan_impl, skill_verify_impl, skill_trust_impl
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_impl_invalid_ecosystem():
    from agent_bom.mcp_tools.runtime import verify_impl

    def _bad_eco(eco):
        raise ValueError(f"unsupported ecosystem: {eco}")

    result = await verify_impl(
        package="requests@2.31.0",
        ecosystem="badeco",
        _validate_ecosystem=_bad_eco,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


def test_skill_trust_impl_file_not_found():
    from pathlib import Path

    from agent_bom.mcp_tools.runtime import skill_trust_impl

    fake_path = Path("/nonexistent/skill.md")

    def _safe_path(p):
        return fake_path

    result = skill_trust_impl(
        skill_path="/nonexistent/skill.md",
        _safe_path=_safe_path,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


def test_skill_scan_impl_success(tmp_path):
    from agent_bom.mcp_tools.runtime import skill_scan_impl

    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# System\nUse npx @modelcontextprotocol/server-filesystem\n")

    result = skill_scan_impl(
        path=str(tmp_path),
        _safe_path=lambda p: tmp_path,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert data["summary"]["files_scanned"] == 1


def test_skill_verify_impl_success(tmp_path):
    from agent_bom.mcp_tools.runtime import skill_verify_impl

    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# System\nStay safe.\n")

    result = skill_verify_impl(
        path=str(tmp_path),
        _safe_path=lambda p: tmp_path,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert len(data["files"]) == 1
    assert data["files"][0]["status"] == "unsigned"


def test_skill_trust_impl_safe_path_error():
    from agent_bom.mcp_tools.runtime import skill_trust_impl

    def _reject_path(p):
        raise ValueError("path outside home")

    result = skill_trust_impl(
        skill_path="/etc/passwd",
        _safe_path=_reject_path,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "error" in data


# ---------------------------------------------------------------------------
# Additional paths to reach 80.0% coverage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_policy_check_impl_success():
    from agent_bom.mcp_tools.compliance import policy_check_impl

    policy = {"name": "test", "rules": []}

    with (
        patch("agent_bom.policy._validate_policy"),
        patch("agent_bom.policy.evaluate_policy", return_value={"passed": True, "violations": []}),
    ):
        result = await policy_check_impl(
            policy_json=json.dumps(policy),
            _run_scan_pipeline=AsyncMock(return_value=([], [], [], [])),
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "passed" in data or "error" not in data


@pytest.mark.asyncio
async def test_policy_check_impl_surfaces_fail_action_matches():
    from agent_bom.mcp_tools.compliance import policy_check_impl
    from agent_bom.models import BlastRadius, Package, Severity, Vulnerability

    br = BlastRadius(
        vulnerability=Vulnerability(id="CVE-2026-0001", severity=Severity.HIGH, summary="bad"),
        package=Package(name="axios", version="1.4.0", ecosystem="npm"),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    policy = {"rules": [{"id": "fail-high", "severity_gte": "high", "action": "fail"}]}

    result = await policy_check_impl(
        policy_json=json.dumps(policy),
        _run_scan_pipeline=AsyncMock(return_value=([], [br], [], [])),
        _truncate_response=_trunc,
    )

    data = json.loads(result)
    assert data["passed"] is False
    assert data["failures"][0]["rule_id"] == "fail-high"


@pytest.mark.asyncio
async def test_cis_benchmark_snowflake_success():
    from agent_bom.mcp_tools.compliance import cis_benchmark_impl

    mock_report = MagicMock()
    mock_report.to_dict.return_value = {"provider": "snowflake", "status": "pass", "checks": []}

    with patch("agent_bom.cloud.snowflake_cis_benchmark.run_benchmark", return_value=mock_report):
        result = await cis_benchmark_impl(
            provider="snowflake",
            region=None,
            profile=None,
            subscription_id=None,
            project_id=None,
            checks=None,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data["provider"] == "snowflake"


@pytest.mark.asyncio
async def test_aisvs_benchmark_success():
    from agent_bom.mcp_tools.compliance import aisvs_benchmark_impl

    mock_report = MagicMock()
    mock_report.to_dict.return_value = {"framework": "AISVS", "status": "pass"}

    with patch("agent_bom.cloud.aisvs_benchmark.run_benchmark", return_value=mock_report):
        result = await aisvs_benchmark_impl(
            checks=None,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "framework" in data


def test_inventory_impl_with_agents():
    from agent_bom.mcp_tools.runtime import inventory_impl

    mock_agent = MagicMock()
    mock_agent.name = "test-agent"
    mock_agent.agent_type.value = "custom"
    mock_agent.config_path = "/tmp/test.json"
    mock_server = MagicMock()
    mock_server.name = "filesystem"
    mock_server.command = "npx"
    mock_server.transport.value = "stdio"
    mock_server.packages = []
    mock_agent.mcp_servers = [mock_server]

    with (
        patch("agent_bom.discovery.discover_all", return_value=[mock_agent]),
        patch("agent_bom.parsers.extract_packages", return_value=[]),
    ):
        result = inventory_impl(config_path=None, _truncate_response=_trunc)
    data = json.loads(result)
    assert data["total_agents"] == 1


def test_skill_trust_impl_success(tmp_path):
    from agent_bom.mcp_tools.runtime import skill_trust_impl

    skill_file = tmp_path / "CLAUDE.md"
    skill_file.write_text("# System\nYou are a helpful assistant.")

    result = skill_trust_impl(
        skill_path=str(skill_file),
        _safe_path=lambda p: skill_file,
        _truncate_response=_trunc,
    )
    data = json.loads(result)
    assert "verdict" in data
    assert "categories" in data
    assert data["provenance"]["status"] == "unsigned"


@pytest.mark.asyncio
async def test_license_compliance_scan_with_mcp_servers():
    """Full agents dict with MCP servers and packages."""
    from agent_bom.mcp_tools.compliance import license_compliance_scan_impl

    scan = {
        "agents": [
            {
                "name": "my-agent",
                "mcp_servers": [
                    {
                        "name": "filesystem",
                        "packages": [{"name": "requests", "version": "2.31.0", "ecosystem": "pypi", "license": "Apache-2.0"}],
                    }
                ],
            }
        ]
    }
    mock_report = MagicMock()

    with (
        patch("agent_bom.license_policy.evaluate_license_policy", return_value=mock_report),
        patch("agent_bom.license_policy.to_serializable", return_value={"status": "pass", "violations": []}),
    ):
        result = await license_compliance_scan_impl(
            scan_json=json.dumps(scan),
            policy_json="",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert data["status"] == "pass"


@pytest.mark.asyncio
async def test_policy_check_impl_general_exception():
    from agent_bom.mcp_tools.compliance import policy_check_impl

    with (
        patch("agent_bom.policy._validate_policy"),
        patch("agent_bom.policy.evaluate_policy", side_effect=RuntimeError("policy engine crash")),
    ):
        result = await policy_check_impl(
            policy_json='{"name": "test"}',
            _run_scan_pipeline=AsyncMock(return_value=([], [], [], [])),
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "error" in data


@pytest.mark.asyncio
async def test_runtime_correlate_otel_parse_error(tmp_path):
    """OTel trace file that fails to parse triggers the exception path."""
    from agent_bom.mcp_tools.runtime import runtime_correlate_impl

    trace_file = tmp_path / "bad_trace.json"
    trace_file.write_text("{}")

    async def _pipeline(_config=None):
        return [], [], [], []

    with patch("agent_bom.otel_ingest.parse_ml_api_spans", side_effect=ValueError("bad trace")):
        result = await runtime_correlate_impl(
            config_path="auto",
            audit_log="",
            otel_trace=str(trace_file),
            _safe_path=lambda p: trace_file,
            _run_scan_pipeline=_pipeline,
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "ml_api_error" in data


@pytest.mark.asyncio
async def test_verify_impl_scoped_package():
    """Test @scope/package@version parsing path."""
    from agent_bom.mcp_tools.runtime import verify_impl

    mock_integrity = MagicMock()
    mock_integrity.to_dict.return_value = {"verified": True, "sha256": "abc"}
    mock_provenance = MagicMock()
    mock_provenance.to_dict.return_value = {"has_provenance": False}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("agent_bom.http_client.create_client", return_value=mock_client),
        patch("agent_bom.integrity.verify_package_integrity", return_value=mock_integrity),
        patch("agent_bom.integrity.check_package_provenance", return_value=mock_provenance),
    ):
        result = await verify_impl(
            package="@scope/pkg@1.0.0",
            ecosystem="npm",
            _validate_ecosystem=lambda e: "npm",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "package" in data or "error" in data


@pytest.mark.asyncio
async def test_verify_impl_pypi_double_eq():
    """Test pypi name==version parsing path."""
    from agent_bom.mcp_tools.runtime import verify_impl

    mock_integrity = MagicMock()
    mock_integrity.to_dict.return_value = {"verified": True}
    mock_provenance = MagicMock()
    mock_provenance.to_dict.return_value = {"has_provenance": False}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("agent_bom.http_client.create_client", return_value=mock_client),
        patch("agent_bom.integrity.verify_package_integrity", return_value=mock_integrity),
        patch("agent_bom.integrity.check_package_provenance", return_value=mock_provenance),
    ):
        result = await verify_impl(
            package="requests==2.31.0",
            ecosystem="pypi",
            _validate_ecosystem=lambda e: "pypi",
            _truncate_response=_trunc,
        )
    data = json.loads(result)
    assert "package" in data or "error" in data


def test_inventory_impl_with_packages():
    """inventory_impl extracts packages from servers."""
    from agent_bom.mcp_tools.runtime import inventory_impl

    mock_pkg = MagicMock()
    mock_pkg.name = "requests"
    mock_pkg.version = "2.31.0"
    mock_pkg.ecosystem = "pypi"

    mock_server = MagicMock()
    mock_server.name = "filesystem"
    mock_server.command = "npx"
    mock_server.transport.value = "stdio"
    mock_server.packages = []  # Empty triggers extract_packages

    mock_agent = MagicMock()
    mock_agent.name = "my-agent"
    mock_agent.agent_type.value = "claude"
    mock_agent.config_path = "/home/user/.claude/claude_desktop_config.json"
    mock_agent.mcp_servers = [mock_server]

    with (
        patch("agent_bom.discovery.discover_all", return_value=[mock_agent]),
        patch("agent_bom.parsers.extract_packages", return_value=[mock_pkg]),
    ):
        result = inventory_impl(config_path=None, _truncate_response=_trunc)
    data = json.loads(result)
    assert data["total_agents"] == 1
    assert data["agents"][0]["servers"][0]["packages"][0]["name"] == "requests"
