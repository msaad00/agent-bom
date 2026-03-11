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
    assert data["found"] is False


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
    assert data["found"] is False


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
