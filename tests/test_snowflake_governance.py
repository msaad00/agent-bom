"""Tests for Snowflake governance discovery.

Covers ACCESS_HISTORY, GRANTS_TO_ROLES, TAG_REFERENCES,
CORTEX_AGENT_USAGE_HISTORY mining and finding derivation.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.governance import (
    AccessRecord,
    AgentUsageRecord,
    DataClassification,
    GovernanceCategory,
    GovernanceFinding,
    GovernanceReport,
    GovernanceSeverity,
    PrivilegeGrant,
)

# ─── Model tests ─────────────────────────────────────────────────────────────


class TestGovernanceModels:
    def test_access_record_defaults(self):
        rec = AccessRecord(
            query_id="q1",
            user_name="alice",
            role_name="ANALYST",
            query_start="2026-02-20T00:00:00Z",
            object_name="DB.SCHEMA.TABLE",
            object_type="TABLE",
        )
        assert rec.columns == []
        assert rec.operation == ""
        assert rec.is_write is False

    def test_privilege_grant_elevated(self):
        grant = PrivilegeGrant(
            grantee="ADMIN_ROLE",
            grantee_type="ROLE",
            privilege="OWNERSHIP",
            granted_on="TABLE",
            object_name="DB.SCHEMA.TABLE",
            is_elevated=True,
        )
        assert grant.is_elevated is True

    def test_data_classification(self):
        tag = DataClassification(
            object_name="DB.SCHEMA.USERS",
            object_type="TABLE",
            column_name="EMAIL",
            tag_name="PII",
            tag_value="EMAIL_ADDRESS",
        )
        assert tag.tag_name == "PII"
        assert tag.column_name == "EMAIL"

    def test_agent_usage_record(self):
        rec = AgentUsageRecord(
            agent_name="my_agent",
            total_tokens=50000,
            credits_used=0.05,
            tool_calls=12,
            status="SUCCESS",
        )
        assert rec.total_tokens == 50000
        assert rec.status == "SUCCESS"

    def test_governance_finding_to_dict(self):
        finding = GovernanceFinding(
            category=GovernanceCategory.ACCESS,
            severity=GovernanceSeverity.HIGH,
            title="Write access detected",
            description="Role X wrote to table Y",
            agent_or_role="X",
        )
        d = finding.to_dict()
        assert d["category"] == "access"
        assert d["severity"] == "high"
        assert d["title"] == "Write access detected"

    def test_governance_report_to_dict(self):
        report = GovernanceReport(account="test_account")
        report.findings.append(
            GovernanceFinding(
                category=GovernanceCategory.PRIVILEGE,
                severity=GovernanceSeverity.CRITICAL,
                title="Test finding",
                description="Test desc",
            )
        )
        d = report.to_dict()
        assert d["account"] == "test_account"
        assert d["summary"]["findings"] == 1
        assert d["summary"]["critical_findings"] == 1
        assert len(d["findings"]) == 1

    def test_governance_report_summary_counts(self):
        report = GovernanceReport(account="acct")
        report.access_records = [
            AccessRecord(
                query_id="q1",
                user_name="u",
                role_name="r",
                query_start="t",
                object_name="o",
                object_type="TABLE",
            )
        ]
        report.privilege_grants = [
            PrivilegeGrant(
                grantee="r",
                grantee_type="ROLE",
                privilege="SELECT",
                granted_on="TABLE",
                object_name="o",
            )
        ]
        d = report.to_dict()
        assert d["summary"]["access_records"] == 1
        assert d["summary"]["privilege_grants"] == 1


# ─── Discovery function tests (mocked Snowflake) ────────────────────────────


def _make_mock_conn():
    """Create a mock Snowflake connection with cursor support."""
    conn = MagicMock()
    return conn


def _make_cursor(rows, columns):
    """Create a mock cursor that returns given rows and column descriptions."""
    cursor = MagicMock()
    cursor.fetchall.return_value = rows
    cursor.description = [(col,) for col in columns]
    return cursor


class TestAccessHistory:
    def test_mine_access_history(self):
        from agent_bom.cloud.snowflake import _mine_access_history

        conn = _make_mock_conn()
        direct_objects = json.dumps(
            [
                {
                    "objectName": "DB.SCHEMA.USERS",
                    "objectDomain": "TABLE",
                    "columns": [
                        {"columnName": "EMAIL", "directSources": [{"type": "SELECT"}]},
                        {"columnName": "NAME", "directSources": [{"type": "SELECT"}]},
                    ],
                }
            ]
        )
        base_objects = json.dumps([{"objectName": "DB.SCHEMA.USERS"}])

        cursor = _make_cursor(
            rows=[("q123", "alice", "ANALYST", "2026-02-20T00:00:00Z", direct_objects, base_objects)],
            columns=["query_id", "user_name", "role_name", "query_start_time", "direct_objects_accessed", "base_objects_accessed"],
        )
        conn.cursor.return_value = cursor

        records, warnings = _mine_access_history(conn, 30)
        assert len(records) == 1
        assert records[0].object_name == "DB.SCHEMA.USERS"
        assert records[0].role_name == "ANALYST"
        assert "EMAIL" in records[0].columns
        assert records[0].operation == "SELECT"
        assert records[0].is_write is False
        assert warnings == []

    def test_mine_access_history_write_operation(self):
        from agent_bom.cloud.snowflake import _mine_access_history

        conn = _make_mock_conn()
        direct_objects = json.dumps(
            [
                {
                    "objectName": "DB.SCHEMA.ORDERS",
                    "objectDomain": "TABLE",
                    "columns": [
                        {"columnName": "STATUS", "directSources": [{"type": "UPDATE"}]},
                    ],
                }
            ]
        )

        cursor = _make_cursor(
            rows=[("q456", "bot", "ETL_ROLE", "2026-02-20T00:00:00Z", direct_objects, "[]")],
            columns=["query_id", "user_name", "role_name", "query_start_time", "direct_objects_accessed", "base_objects_accessed"],
        )
        conn.cursor.return_value = cursor

        records, _ = _mine_access_history(conn, 30)
        assert len(records) == 1
        assert records[0].operation == "UPDATE"
        assert records[0].is_write is True

    def test_mine_access_history_enterprise_error(self):
        from agent_bom.cloud.snowflake import _mine_access_history

        conn = _make_mock_conn()
        cursor = MagicMock()
        cursor.execute.side_effect = Exception("access_history not available on Standard edition")
        conn.cursor.return_value = cursor

        records, warnings = _mine_access_history(conn, 30)
        assert len(records) == 0
        assert any("Enterprise edition" in w for w in warnings)


class TestGrantsToRoles:
    def test_mine_grants(self):
        from agent_bom.cloud.snowflake import _mine_grants_to_roles

        conn = _make_mock_conn()
        cursor = _make_cursor(
            rows=[
                ("ADMIN_ROLE", "OWNERSHIP", "TABLE", "DB.SCHEMA.TABLE", "SYSADMIN", True),
                ("ANALYST", "SELECT", "TABLE", "DB.SCHEMA.TABLE", "ADMIN_ROLE", False),
            ],
            columns=["grantee_name", "privilege", "granted_on", "name", "granted_by", "grant_option"],
        )
        conn.cursor.return_value = cursor

        grants, warnings = _mine_grants_to_roles(conn)
        assert len(grants) == 2
        assert grants[0].grantee == "ADMIN_ROLE"
        assert grants[0].privilege == "OWNERSHIP"
        assert grants[0].is_elevated is True
        assert grants[1].is_elevated is False
        assert warnings == []

    def test_mine_grants_error(self):
        from agent_bom.cloud.snowflake import _mine_grants_to_roles

        conn = _make_mock_conn()
        cursor = MagicMock()
        cursor.execute.side_effect = Exception("permission denied")
        conn.cursor.return_value = cursor

        grants, warnings = _mine_grants_to_roles(conn)
        assert len(grants) == 0
        assert len(warnings) == 1


class TestTagReferences:
    def test_mine_tag_references(self):
        from agent_bom.cloud.snowflake import _mine_tag_references

        conn = _make_mock_conn()
        cursor = _make_cursor(
            rows=[
                ("PII", "EMAIL_ADDRESS", "DB", "SCHEMA", "USERS", "EMAIL", "COLUMN"),
                ("SENSITIVE", "FINANCIAL", "DB", "SCHEMA", "TRANSACTIONS", None, "TABLE"),
            ],
            columns=["tag_name", "tag_value", "object_database", "object_schema", "object_name", "column_name", "domain"],
        )
        conn.cursor.return_value = cursor

        tags, warnings = _mine_tag_references(conn)
        assert len(tags) == 2
        assert tags[0].tag_name == "PII"
        assert tags[0].object_name == "DB.SCHEMA.USERS"
        assert tags[0].column_name == "EMAIL"
        assert tags[1].tag_name == "SENSITIVE"
        assert tags[1].column_name is None
        assert warnings == []


class TestCortexAgentUsage:
    def test_mine_cortex_agent_usage(self):
        from agent_bom.cloud.snowflake import _mine_cortex_agent_usage

        conn = _make_mock_conn()
        cursor = _make_cursor(
            rows=[
                (
                    "my_agent",
                    "DB",
                    "SCHEMA",
                    "alice",
                    "ANALYST",
                    "2026-02-20T00:00:00Z",
                    "2026-02-20T00:00:05Z",
                    1000,
                    500,
                    1500,
                    0.015,
                    "claude-3.5-sonnet",
                    5,
                    "SUCCESS",
                ),
            ],
            columns=[
                "agent_name",
                "database_name",
                "schema_name",
                "user_name",
                "role_name",
                "start_time",
                "end_time",
                "input_tokens",
                "output_tokens",
                "total_tokens",
                "credits_used",
                "model_name",
                "tool_calls",
                "status",
            ],
        )
        conn.cursor.return_value = cursor

        records, warnings = _mine_cortex_agent_usage(conn, 30)
        assert len(records) == 1
        assert records[0].agent_name == "my_agent"
        assert records[0].total_tokens == 1500
        assert records[0].credits_used == 0.015
        assert records[0].tool_calls == 5
        assert warnings == []

    def test_mine_cortex_agent_usage_not_available(self):
        from agent_bom.cloud.snowflake import _mine_cortex_agent_usage

        conn = _make_mock_conn()
        cursor = MagicMock()
        cursor.execute.side_effect = Exception("cortex_agent_usage_history does not exist")
        conn.cursor.return_value = cursor

        records, warnings = _mine_cortex_agent_usage(conn, 30)
        assert len(records) == 0
        assert any("CORTEX_AGENT_USAGE_HISTORY" in w for w in warnings)


# ─── Finding derivation tests ────────────────────────────────────────────────


class TestFindingDerivation:
    def test_write_access_findings_high(self):
        from agent_bom.cloud.snowflake import _find_write_access_risks

        report = GovernanceReport(account="test")
        report.access_records = [
            AccessRecord(
                query_id=f"q{i}",
                user_name="bot",
                role_name="ETL_ROLE",
                query_start="t",
                object_name=f"DB.SCHEMA.TABLE_{i}",
                object_type="TABLE",
                operation="INSERT",
                is_write=True,
            )
            for i in range(6)
        ]

        findings = _find_write_access_risks(report)
        assert len(findings) == 1
        assert findings[0].severity == GovernanceSeverity.HIGH
        assert "6" in findings[0].description

    def test_write_access_findings_medium(self):
        from agent_bom.cloud.snowflake import _find_write_access_risks

        report = GovernanceReport(account="test")
        report.access_records = [
            AccessRecord(
                query_id="q1",
                user_name="bot",
                role_name="ETL_ROLE",
                query_start="t",
                object_name="DB.SCHEMA.TABLE_1",
                object_type="TABLE",
                operation="DELETE",
                is_write=True,
            ),
        ]

        findings = _find_write_access_risks(report)
        assert len(findings) == 1
        assert findings[0].severity == GovernanceSeverity.MEDIUM

    def test_no_write_access_no_findings(self):
        from agent_bom.cloud.snowflake import _find_write_access_risks

        report = GovernanceReport(account="test")
        report.access_records = [
            AccessRecord(
                query_id="q1",
                user_name="alice",
                role_name="READER",
                query_start="t",
                object_name="DB.SCHEMA.TABLE",
                object_type="TABLE",
                operation="SELECT",
                is_write=False,
            ),
        ]

        findings = _find_write_access_risks(report)
        assert len(findings) == 0

    def test_elevated_privilege_critical(self):
        from agent_bom.cloud.snowflake import _find_elevated_privilege_risks

        report = GovernanceReport(account="test")
        report.privilege_grants = [
            PrivilegeGrant(
                grantee="ADMIN_ROLE",
                grantee_type="ROLE",
                privilege="OWNERSHIP",
                granted_on="TABLE",
                object_name="DB.SCHEMA.TABLE",
                is_elevated=True,
            ),
        ]

        findings = _find_elevated_privilege_risks(report)
        assert len(findings) == 1
        assert findings[0].severity == GovernanceSeverity.CRITICAL

    def test_elevated_privilege_high(self):
        from agent_bom.cloud.snowflake import _find_elevated_privilege_risks

        report = GovernanceReport(account="test")
        report.privilege_grants = [
            PrivilegeGrant(
                grantee="MANAGER",
                grantee_type="ROLE",
                privilege="MANAGE GRANTS",
                granted_on="ACCOUNT",
                object_name="ACCOUNT",
                is_elevated=True,
            ),
        ]

        findings = _find_elevated_privilege_risks(report)
        assert len(findings) == 1
        assert findings[0].severity == GovernanceSeverity.HIGH

    def test_sensitive_data_access_pii(self):
        from agent_bom.cloud.snowflake import _find_sensitive_data_access

        report = GovernanceReport(account="test")
        report.data_classifications = [
            DataClassification(
                object_name="DB.SCHEMA.USERS",
                object_type="TABLE",
                column_name="EMAIL",
                tag_name="PII",
                tag_value="EMAIL_ADDRESS",
            ),
        ]
        report.access_records = [
            AccessRecord(
                query_id="q1",
                user_name="agent",
                role_name="AGENT_ROLE",
                query_start="t",
                object_name="DB.SCHEMA.USERS",
                object_type="TABLE",
                columns=["EMAIL"],
            ),
        ]

        findings = _find_sensitive_data_access(report)
        assert len(findings) == 1
        assert findings[0].severity == GovernanceSeverity.CRITICAL
        assert "PII" in findings[0].title

    def test_sensitive_data_access_non_pii(self):
        from agent_bom.cloud.snowflake import _find_sensitive_data_access

        report = GovernanceReport(account="test")
        report.data_classifications = [
            DataClassification(
                object_name="DB.SCHEMA.FINANCIALS",
                object_type="TABLE",
                tag_name="FINANCIAL",
                tag_value="REVENUE",
            ),
        ]
        report.access_records = [
            AccessRecord(
                query_id="q1",
                user_name="agent",
                role_name="AGENT_ROLE",
                query_start="t",
                object_name="DB.SCHEMA.FINANCIALS",
                object_type="TABLE",
            ),
        ]

        findings = _find_sensitive_data_access(report)
        assert len(findings) == 1
        assert findings[0].severity == GovernanceSeverity.HIGH

    def test_no_tags_no_findings(self):
        from agent_bom.cloud.snowflake import _find_sensitive_data_access

        report = GovernanceReport(account="test")
        report.data_classifications = []
        report.access_records = [
            AccessRecord(
                query_id="q1",
                user_name="agent",
                role_name="AGENT_ROLE",
                query_start="t",
                object_name="DB.SCHEMA.TABLE",
                object_type="TABLE",
            ),
        ]

        findings = _find_sensitive_data_access(report)
        assert len(findings) == 0

    def test_agent_usage_multi_role(self):
        from agent_bom.cloud.snowflake import _find_agent_usage_anomalies

        report = GovernanceReport(account="test")
        report.agent_usage = [
            AgentUsageRecord(
                agent_name="my_agent",
                role_name="ROLE_A",
                total_tokens=100,
                status="SUCCESS",
            ),
            AgentUsageRecord(
                agent_name="my_agent",
                role_name="ROLE_B",
                total_tokens=200,
                status="SUCCESS",
            ),
        ]

        findings = _find_agent_usage_anomalies(report)
        multi_role = [f for f in findings if "Multi-role" in f.title]
        assert len(multi_role) == 1
        assert multi_role[0].severity == GovernanceSeverity.HIGH

    def test_agent_usage_high_tokens(self):
        from agent_bom.cloud.snowflake import _find_agent_usage_anomalies

        report = GovernanceReport(account="test")
        report.agent_usage = [
            AgentUsageRecord(
                agent_name="heavy_agent",
                role_name="ROLE_A",
                total_tokens=1_200_000,
                credits_used=12.0,
                status="SUCCESS",
            ),
        ]

        findings = _find_agent_usage_anomalies(report)
        high_token = [f for f in findings if "High token" in f.title]
        assert len(high_token) == 1

    def test_agent_usage_high_tool_calls(self):
        from agent_bom.cloud.snowflake import _find_agent_usage_anomalies

        report = GovernanceReport(account="test")
        report.agent_usage = [
            AgentUsageRecord(
                agent_name="tool_heavy",
                role_name="ROLE_A",
                total_tokens=100,
                tool_calls=600,
                status="SUCCESS",
            ),
        ]

        findings = _find_agent_usage_anomalies(report)
        tool_findings = [f for f in findings if "tool usage" in f.title]
        assert len(tool_findings) == 1

    def test_agent_usage_high_failure_rate(self):
        from agent_bom.cloud.snowflake import _find_agent_usage_anomalies

        report = GovernanceReport(account="test")
        report.agent_usage = [
            AgentUsageRecord(
                agent_name="flaky_agent",
                role_name="ROLE_A",
                total_tokens=100,
                status="FAILED",
            )
            for _ in range(4)
        ] + [
            AgentUsageRecord(
                agent_name="flaky_agent",
                role_name="ROLE_A",
                total_tokens=100,
                status="SUCCESS",
            )
            for _ in range(6)
        ]

        findings = _find_agent_usage_anomalies(report)
        failure_findings = [f for f in findings if "failure rate" in f.title]
        assert len(failure_findings) == 1

    def test_agent_usage_no_anomalies(self):
        from agent_bom.cloud.snowflake import _find_agent_usage_anomalies

        report = GovernanceReport(account="test")
        report.agent_usage = [
            AgentUsageRecord(
                agent_name="good_agent",
                role_name="ROLE_A",
                total_tokens=5000,
                tool_calls=10,
                status="SUCCESS",
            ),
        ]

        findings = _find_agent_usage_anomalies(report)
        assert len(findings) == 0


class TestDeriveFindings:
    def test_derive_findings_sorted_by_severity(self):
        from agent_bom.cloud.snowflake import _derive_findings

        report = GovernanceReport(account="test")
        # Add data that generates findings of different severities
        report.privilege_grants = [
            PrivilegeGrant(
                grantee="ADMIN",
                grantee_type="ROLE",
                privilege="OWNERSHIP",
                granted_on="TABLE",
                object_name="DB.T",
                is_elevated=True,
            ),
        ]
        report.access_records = [
            AccessRecord(
                query_id="q1",
                user_name="bot",
                role_name="ETL",
                query_start="t",
                object_name="DB.SCHEMA.T1",
                object_type="TABLE",
                operation="INSERT",
                is_write=True,
            ),
        ]

        findings = _derive_findings(report)
        assert len(findings) >= 2
        # Critical should come first
        severities = [f.severity for f in findings]
        assert severities[0] == GovernanceSeverity.CRITICAL


# ─── Full discover_governance integration test (mocked) ──────────────────────


class TestDiscoverGovernance:
    def _install_mock_sf(self):
        """Install mock snowflake modules into sys.modules."""
        import sys

        mock_sf = MagicMock()
        mock_connector = MagicMock()
        mock_sf.connector = mock_connector
        mock_connector.errors = MagicMock()
        mock_connector.errors.DatabaseError = Exception

        sys.modules["snowflake"] = mock_sf
        sys.modules["snowflake.connector"] = mock_connector
        sys.modules["snowflake.connector.errors"] = mock_connector.errors

        return mock_connector

    def _cleanup_mock_sf(self):
        import sys

        for mod in ["snowflake", "snowflake.connector", "snowflake.connector.errors"]:
            sys.modules.pop(mod, None)

    def test_discover_governance_no_account(self):
        from agent_bom.cloud.snowflake import discover_governance

        with patch.dict("os.environ", {}, clear=True):
            report = discover_governance(account="")
            assert len(report.warnings) >= 1

    def test_discover_governance_connection_failure(self):
        mock_connector = self._install_mock_sf()
        try:
            from agent_bom.cloud.snowflake import discover_governance

            mock_connector.connect.side_effect = Exception("connection refused")

            with patch.dict("os.environ", {"SNOWFLAKE_ACCOUNT": "test", "SNOWFLAKE_PASSWORD": "pw"}):
                report = discover_governance(account="test")
                assert any("Could not connect" in w for w in report.warnings)
        finally:
            self._cleanup_mock_sf()

    def test_discover_governance_success(self):
        mock_connector = self._install_mock_sf()
        try:
            from agent_bom.cloud.snowflake import discover_governance

            conn = _make_mock_conn()
            mock_connector.connect.return_value = conn

            # Each mining function gets its own cursor call
            cursors = []

            # ACCESS_HISTORY cursor
            access_cursor = _make_cursor(
                rows=[
                    (
                        "q1",
                        "alice",
                        "ANALYST",
                        "2026-02-20T00:00:00Z",
                        json.dumps([{"objectName": "DB.S.T", "objectDomain": "TABLE", "columns": []}]),
                        "[]",
                    )
                ],
                columns=["query_id", "user_name", "role_name", "query_start_time", "direct_objects_accessed", "base_objects_accessed"],
            )
            cursors.append(access_cursor)

            # GRANTS_TO_ROLES cursor
            grants_cursor = _make_cursor(
                rows=[("ANALYST", "SELECT", "TABLE", "DB.S.T", "ADMIN", False)],
                columns=["grantee_name", "privilege", "granted_on", "name", "granted_by", "grant_option"],
            )
            cursors.append(grants_cursor)

            # TAG_REFERENCES cursor
            tags_cursor = _make_cursor(rows=[], columns=[])
            cursors.append(tags_cursor)

            # CORTEX_AGENT_USAGE cursor
            usage_cursor = _make_cursor(rows=[], columns=[])
            cursors.append(usage_cursor)

            conn.cursor.side_effect = cursors

            with patch.dict("os.environ", {"SNOWFLAKE_ACCOUNT": "test", "SNOWFLAKE_PASSWORD": "pw"}):
                report = discover_governance(account="test")
                assert report.account == "test"
                assert len(report.access_records) == 1
                assert len(report.privilege_grants) == 1
        finally:
            self._cleanup_mock_sf()


# ─── Helper function tests ───────────────────────────────────────────────────


class TestHelpers:
    def test_parse_json_field_string(self):
        from agent_bom.cloud.snowflake import _parse_json_field

        result = _parse_json_field('[{"objectName": "T"}]')
        assert len(result) == 1
        assert result[0]["objectName"] == "T"

    def test_parse_json_field_list(self):
        from agent_bom.cloud.snowflake import _parse_json_field

        result = _parse_json_field([{"objectName": "T"}])
        assert len(result) == 1

    def test_parse_json_field_none(self):
        from agent_bom.cloud.snowflake import _parse_json_field

        assert _parse_json_field(None) == []

    def test_parse_json_field_invalid(self):
        from agent_bom.cloud.snowflake import _parse_json_field

        assert _parse_json_field("not json") == []

    def test_infer_operation_select(self):
        from agent_bom.cloud.snowflake import _infer_operation

        obj = {"columns": [{"columnName": "ID", "directSources": [{"type": "SELECT"}]}]}
        assert _infer_operation(obj) == "SELECT"

    def test_infer_operation_insert(self):
        from agent_bom.cloud.snowflake import _infer_operation

        obj = {"columns": [{"columnName": "ID", "directSources": [{"type": "INSERT"}]}]}
        assert _infer_operation(obj) == "INSERT"

    def test_infer_operation_no_columns(self):
        from agent_bom.cloud.snowflake import _infer_operation

        assert _infer_operation({}) == "SELECT"

    def test_is_write_operation(self):
        from agent_bom.cloud.snowflake import _is_write_operation

        write_obj = {"columns": [{"columnName": "X", "directSources": [{"type": "DELETE"}]}]}
        read_obj = {"columns": [{"columnName": "X", "directSources": [{"type": "SELECT"}]}]}

        assert _is_write_operation(write_obj) is True
        assert _is_write_operation(read_obj) is False


# ─── Governance edge-case tests ──────────────────────────────────────────────


class TestGovernanceEdgeCases:
    def test_tag_references_error(self):
        """_mine_tag_references returns empty list + warning on cursor error."""
        from agent_bom.cloud.snowflake import _mine_tag_references

        conn = _make_mock_conn()
        cursor = MagicMock()
        cursor.execute.side_effect = Exception("TAG_REFERENCES not available")
        conn.cursor.return_value = cursor
        tags, warnings = _mine_tag_references(conn)
        assert len(tags) == 0
        assert len(warnings) == 1

    def test_derive_findings_empty_report(self):
        """_derive_findings with empty GovernanceReport returns empty list."""
        from agent_bom.cloud.snowflake import _derive_findings

        report = GovernanceReport(account="empty")
        findings = _derive_findings(report)
        assert findings == []

    def test_governance_finding_severity_filter(self):
        """GovernanceReport.to_dict correctly counts findings by severity."""
        report = GovernanceReport(account="test")
        report.findings = [
            GovernanceFinding(
                category=GovernanceCategory.ACCESS,
                severity=GovernanceSeverity.HIGH,
                title="high",
                description="d",
            ),
            GovernanceFinding(
                category=GovernanceCategory.ACCESS,
                severity=GovernanceSeverity.LOW,
                title="low",
                description="d",
            ),
            GovernanceFinding(
                category=GovernanceCategory.ACCESS,
                severity=GovernanceSeverity.CRITICAL,
                title="crit",
                description="d",
            ),
        ]
        d = report.to_dict()
        assert d["summary"]["critical_findings"] == 1
        assert d["summary"]["findings"] == 3


# ─── Cloud __init__ integration test ─────────────────────────────────────────


class TestCloudInit:
    def test_discover_governance_unsupported_provider(self):
        from agent_bom.cloud import discover_governance

        with pytest.raises(ValueError, match="not supported"):
            discover_governance(provider="aws")

    @patch("agent_bom.cloud.snowflake.discover_governance")
    def test_discover_governance_delegates(self, mock_discover):
        from agent_bom.cloud import discover_governance

        mock_discover.return_value = GovernanceReport(account="test")
        result = discover_governance(provider="snowflake", days=7)
        mock_discover.assert_called_once_with(days=7)
        assert result.account == "test"
