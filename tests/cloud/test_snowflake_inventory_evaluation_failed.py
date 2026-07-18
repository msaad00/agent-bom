"""Snowflake inventory evaluation gaps must surface as warnings and coverage evidence."""

from __future__ import annotations

import importlib
import sys
import types
from unittest.mock import MagicMock

import pytest

from agent_bom.finding import FindingType, cloud_cis_check_to_finding
from agent_bom.models import AIBOMReport
from agent_bom.scanners.state import consume_coverage_warnings, reset_scan_warnings


def _install_mock_snowflake() -> types.ModuleType:
    snowflake = types.ModuleType("snowflake")
    snowflake_connector = types.ModuleType("snowflake.connector")
    snowflake_connector_errors = types.ModuleType("snowflake.connector.errors")

    class _DatabaseError(Exception):
        pass

    snowflake_connector_errors.DatabaseError = _DatabaseError
    snowflake_connector.connect = MagicMock
    snowflake_connector.errors = snowflake_connector_errors
    snowflake.connector = snowflake_connector

    sys.modules.setdefault("snowflake", snowflake)
    sys.modules.setdefault("snowflake.connector", snowflake_connector)
    sys.modules.setdefault("snowflake.connector.errors", snowflake_connector_errors)
    return snowflake_connector


@pytest.fixture(autouse=True)
def _clean_scan_state() -> None:
    reset_scan_warnings()
    yield
    reset_scan_warnings()


def test_cortex_agents_list_failure_is_not_silent() -> None:
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_cortex_agents

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.execute.side_effect = RuntimeError("SHOW AGENTS denied")

    agents, warnings = _discover_cortex_agents(mock_conn, "myorg")

    assert agents == []
    assert len(warnings) == 1
    assert "Cortex Agents" in warnings[0]
    coverage = consume_coverage_warnings()
    assert len(coverage) == 1
    assert coverage[0]["reason"] == "inventory_evaluation_failed"
    assert coverage[0]["ecosystem"] == "snowflake"
    assert "cortex" in coverage[0]["release"].lower()


def test_mcp_servers_list_failure_is_not_silent() -> None:
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_mcp_servers

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.execute.side_effect = RuntimeError("SHOW MCP SERVERS denied")

    agents, warnings = _discover_mcp_servers(mock_conn, "myorg")

    assert agents == []
    assert len(warnings) == 1
    assert "MCP Servers" in warnings[0]
    coverage = consume_coverage_warnings()
    assert len(coverage) == 1
    assert coverage[0]["reason"] == "inventory_evaluation_failed"
    assert "mcp" in coverage[0]["release"].lower()


def test_grants_to_roles_failure_is_not_silent() -> None:
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _mine_grants_to_roles

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.execute.side_effect = RuntimeError("GRANTS_TO_ROLES unavailable")

    grants, warnings = _mine_grants_to_roles(mock_conn)

    assert grants == []
    assert len(warnings) == 1
    assert "GRANTS_TO_ROLES" in warnings[0]
    coverage = consume_coverage_warnings()
    assert len(coverage) == 1
    assert coverage[0]["reason"] == "inventory_evaluation_failed"
    assert "grants" in coverage[0]["release"].lower()


def test_notebook_describe_failure_emits_warning_not_silent_pass() -> None:
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_snowflake_notebooks

    class _Cursor:
        def __init__(self) -> None:
            self.description: list[tuple[str]] = []
            self._rows: list[tuple[str, ...]] = []
            self.executed: list[str] = []

        def execute(self, sql: str) -> None:
            self.executed.append(sql)
            if sql == "SHOW NOTEBOOKS IN ACCOUNT":
                self.description = [
                    ("name",),
                    ("database_name",),
                    ("schema_name",),
                    ("owner",),
                    ("comment",),
                ]
                self._rows = [("nb1", "DB", "SCHEMA", "owner", "comment")]
            elif sql.startswith("DESCRIBE NOTEBOOK "):
                raise RuntimeError("DESCRIBE NOTEBOOK unavailable")

        def fetchall(self) -> list[tuple[str, ...]]:
            return self._rows

        def close(self) -> None:
            return None

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = _Cursor()

    agents, warnings = _discover_snowflake_notebooks(mock_conn, "myorg")

    assert len(agents) == 1
    assert any("notebook" in w.lower() and "nb1" in w.lower() for w in warnings)


def test_cloud_cis_error_converter_and_report_lift() -> None:
    check = {
        "check_id": "1.1",
        "title": "MFA coverage",
        "status": "ERROR",
        "severity": "high",
        "evidence": "ACCOUNT_USAGE stale",
        "recommendation": "Restore read-only evidence access and rerun.",
    }
    finding = cloud_cis_check_to_finding(check, "snowflake")
    assert finding.finding_type == FindingType.CIS_ERROR
    assert finding.evidence["status"] == "ERROR"

    report = AIBOMReport(scan_id="contract")
    report.snowflake_cis_benchmark_data = {"checks": [check]}
    lifted = report._cloud_cis_findings()
    assert len(lifted) == 1
    assert lifted[0].finding_type == FindingType.CIS_ERROR
    assert lifted[0].id == finding.id
