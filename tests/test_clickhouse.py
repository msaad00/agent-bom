"""Tests for ClickHouse analytics backend.

All tests mock ``agent_bom.http_client.sync_request_with_retry`` —
no real ClickHouse instance needed.
"""

from __future__ import annotations

import json
import os
from unittest.mock import patch

import httpx
import pytest

# ─── Helpers ───────────────────────────────────────────────────────────────


def _mock_response(text: str = "", status_code: int = 200) -> httpx.Response:
    """Create a mock httpx.Response."""
    resp = httpx.Response(status_code=status_code, text=text)
    return resp


# ─── ClickHouseClient tests ─────────────────────────────────────────────────


class TestClickHouseClient:
    """Tests for the zero-dep HTTP client."""

    def test_init_from_args(self):
        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123", user="admin", password="pw", database="test_db")
        assert c.url == "http://localhost:8123"
        assert c.user == "admin"
        assert c.password == "pw"
        assert c.database == "test_db"

    def test_init_from_env(self):
        from agent_bom.cloud.clickhouse import ClickHouseClient

        env = {
            "AGENT_BOM_CLICKHOUSE_URL": "http://ch.example.com:8123",
            "AGENT_BOM_CLICKHOUSE_USER": "myuser",
            "AGENT_BOM_CLICKHOUSE_PASSWORD": "secret",
        }
        with patch.dict(os.environ, env, clear=False):
            c = ClickHouseClient()
            assert c.url == "http://ch.example.com:8123"
            assert c.user == "myuser"
            assert c.password == "secret"

    def test_init_no_url_raises(self):
        from agent_bom.cloud.clickhouse import ClickHouseClient, ClickHouseError

        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ClickHouseError, match="ClickHouse URL required"):
                ClickHouseClient()

    def test_init_strips_trailing_slash(self):
        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123/")
        assert c.url == "http://localhost:8123"

    def test_auth_headers(self):
        """Verify X-ClickHouse-User / X-ClickHouse-Key headers are set."""
        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123", user="admin", password="pw")

        with patch("agent_bom.http_client.sync_request_with_retry", return_value=_mock_response("OK")) as mock_req:
            c.execute("SELECT 1")
            _, kwargs = mock_req.call_args[0], mock_req.call_args[1]
            headers = kwargs.get("headers", {})
            assert headers["X-ClickHouse-User"] == "admin"
            assert headers["X-ClickHouse-Key"] == "pw"
            assert headers["X-ClickHouse-Database"] == "agent_bom"

    def test_execute_sends_post(self):
        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        with patch("agent_bom.http_client.sync_request_with_retry", return_value=_mock_response("result")) as mock_req:
            result = c.execute("SELECT 1")
            assert result == "result"
            # Verify POST method
            args = mock_req.call_args[0]
            assert args[1] == "POST"  # method arg

    def test_execute_http_error(self):
        from agent_bom.cloud.clickhouse import ClickHouseClient, ClickHouseError

        c = ClickHouseClient(url="http://localhost:8123")

        with patch(
            "agent_bom.http_client.sync_request_with_retry",
            return_value=_mock_response("DB error", status_code=500),
        ):
            with pytest.raises(ClickHouseError, match="HTTP 500"):
                c.execute("BAD QUERY")

    def test_execute_connection_error(self):
        from agent_bom.cloud.clickhouse import ClickHouseClient, ClickHouseError

        c = ClickHouseClient(url="http://localhost:8123")

        with patch("agent_bom.http_client.sync_request_with_retry", return_value=None):
            with pytest.raises(ClickHouseError, match="timed out after retries"):
                c.execute("SELECT 1")

    def test_execute_timeout(self):
        from agent_bom.cloud.clickhouse import ClickHouseClient, ClickHouseError

        c = ClickHouseClient(url="http://localhost:8123", timeout=5)

        with patch("agent_bom.http_client.sync_request_with_retry", return_value=None):
            with pytest.raises(ClickHouseError, match="timed out"):
                c.execute("SELECT 1")

    def test_insert_json_batching(self):
        """Verify JSONEachRow format is assembled correctly."""
        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        rows = [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]
        with patch("agent_bom.http_client.sync_request_with_retry", return_value=_mock_response("")) as mock_req:
            c.insert_json("test_table", rows)
            kwargs = mock_req.call_args[1]
            body = kwargs["content"].decode("utf-8")
            assert body.startswith("INSERT INTO test_table FORMAT JSONEachRow\n")
            lines = body.split("\n")
            assert len(lines) == 3  # header + 2 JSON rows
            assert json.loads(lines[1]) == {"a": 1, "b": "x"}
            assert json.loads(lines[2]) == {"a": 2, "b": "y"}

    def test_insert_json_empty(self):
        """Empty rows list should be a no-op."""
        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")
        # Should not raise or call execute
        c.insert_json("test_table", [])

    def test_query_json_parsing(self):
        """Verify response JSON is parsed to list[dict]."""
        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        response_data = {"data": [{"day": "2024-01-01", "cnt": 5}], "rows": 1}
        with patch(
            "agent_bom.http_client.sync_request_with_retry",
            return_value=_mock_response(json.dumps(response_data)),
        ):
            result = c.query_json("SELECT day, count() AS cnt FROM t GROUP BY day")
            assert result == [{"day": "2024-01-01", "cnt": 5}]

    def test_query_json_appends_format(self):
        """Verify FORMAT JSON is appended if missing."""
        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        with patch(
            "agent_bom.http_client.sync_request_with_retry",
            return_value=_mock_response(json.dumps({"data": []})),
        ) as mock_req:
            c.query_json("SELECT 1")
            kwargs = mock_req.call_args[1]
            body = kwargs["content"].decode("utf-8")
            assert body.endswith("FORMAT JSON")

    def test_ensure_tables_idempotent(self):
        """CREATE TABLE IF NOT EXISTS should not error on repeated calls."""
        from agent_bom.cloud.clickhouse import _TABLE_DDL, _TABLE_MIGRATIONS, ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        with patch("agent_bom.http_client.sync_request_with_retry", return_value=_mock_response("")) as mock_req:
            c.ensure_tables()
            # 1 CREATE DATABASE + N CREATE TABLE + M ALTER forward-compat migrations
            expected = 1 + len(_TABLE_DDL) + len(_TABLE_MIGRATIONS)
            assert mock_req.call_count == expected


# ─── NullAnalyticsStore tests ───────────────────────────────────────────────


class TestNullAnalyticsStore:
    """NullAnalyticsStore should be a silent no-op."""

    def test_all_methods_return_empty(self):
        from agent_bom.api.clickhouse_store import NullAnalyticsStore

        store = NullAnalyticsStore()
        # Writes should not raise
        store.record_scan("test-id", "test-agent", [])
        store.record_event({})
        store.record_posture("test-agent", {})
        # Reads should return empty
        assert store.query_vuln_trends() == []
        assert store.query_top_cves() == []
        assert store.query_posture_history() == []

    def test_no_side_effects(self):
        """NullAnalyticsStore methods should be safe to call repeatedly."""
        from agent_bom.api.clickhouse_store import NullAnalyticsStore

        store = NullAnalyticsStore()
        for _ in range(3):
            store.record_scan("id", "agent", [])
            store.record_event({})
        assert store.query_vuln_trends() == []


class TestClickHouseAnalyticsStore:
    def test_record_scan_splits_package_name_and_version(self):
        from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

        inserted = {}

        class _Client:
            def ensure_tables(self):
                return None

            def insert_json(self, table, rows):
                inserted["table"] = table
                inserted["rows"] = rows

        with patch("agent_bom.cloud.clickhouse.ClickHouseClient", return_value=_Client()):
            store = ClickHouseAnalyticsStore(url="http://localhost:8123")
            store.record_scan(
                "scan-1",
                "agent-1",
                [
                    {
                        "package": "requests@2.33.0",
                        "ecosystem": "pypi",
                        "vulnerability_id": "CVE-2026-0001",
                        "severity": "high",
                    }
                ],
            )

        assert inserted["table"] == "vulnerability_scans"
        assert inserted["rows"][0]["package_name"] == "requests"
        assert inserted["rows"][0]["package_version"] == "2.33.0"

    def test_buffered_store_flushes_on_close(self):
        from agent_bom.api.clickhouse_store import BufferedAnalyticsStore, ClickHouseAnalyticsStore

        inserted: list[tuple[str, list[dict]]] = []

        class _Client:
            def ensure_tables(self):
                return None

            def insert_json(self, table, rows):
                inserted.append((table, rows))

        with patch("agent_bom.cloud.clickhouse.ClickHouseClient", return_value=_Client()):
            store = ClickHouseAnalyticsStore(url="http://localhost:8123")
            buffered = BufferedAnalyticsStore(store, max_batch=10, flush_interval=60.0)
            buffered.record_event({"event_type": "tool_blocked", "severity": "high"})
            buffered.record_scan_metadata({"scan_id": "scan-1", "vuln_count": 4})
            buffered.record_fleet_snapshot({"agent_name": "agent-1", "trust_score": 42.0})
            buffered.record_compliance_control({"framework": "owasp-llm-top10", "control_id": "LLM01"})
            buffered.record_cis_benchmark_checks([{"scan_id": "scan-1", "cloud": "aws", "check_id": "1.5", "priority": 1}])
            buffered.record_audit_event({"action": "auth.key_created", "actor": "system"})
            buffered.close()

        assert any(table == "runtime_events" for table, _rows in inserted)
        assert any(table == "scan_metadata" for table, _rows in inserted)
        assert any(table == "fleet_agents" for table, _rows in inserted)
        assert any(table == "compliance_controls" for table, _rows in inserted)
        assert any(table == "cis_benchmark_checks" for table, _rows in inserted)
        assert any(table == "audit_events" for table, _rows in inserted)

    def test_record_cis_benchmark_checks_normalizes_remediation(self):
        from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

        inserted = {}

        class _Client:
            def ensure_tables(self):
                return None

            def insert_json(self, table, rows):
                inserted["table"] = table
                inserted["rows"] = rows

        with patch("agent_bom.cloud.clickhouse.ClickHouseClient", return_value=_Client()):
            store = ClickHouseAnalyticsStore(url="http://localhost:8123")
            store.record_cis_benchmark_checks(
                [
                    {
                        "scan_id": "scan-1",
                        "cloud": "aws",
                        "check_id": "1.5",
                        "status": "fail",
                        "priority": 1,
                        "remediation": {"fix_console": "AWS Console", "priority": 1},
                        "requires_human_review": True,
                    }
                ],
                tenant_id="tenant-alpha",
            )

        assert inserted["table"] == "cis_benchmark_checks"
        row = inserted["rows"][0]
        assert row["tenant_id"] == "tenant-alpha"
        assert row["priority"] == 1
        assert json.loads(row["remediation"])["priority"] == 1
        assert row["requires_human_review"] == 1

    def test_buffered_store_flushes_before_query(self):
        from agent_bom.api.clickhouse_store import BufferedAnalyticsStore, ClickHouseAnalyticsStore

        inserted: list[tuple[str, list[dict]]] = []

        class _Client:
            def ensure_tables(self):
                return None

            def insert_json(self, table, rows):
                inserted.append((table, rows))

            def query_json(self, _query):
                return [{"day": "2026-04-05", "severity": "high", "cnt": 1}]

        with patch("agent_bom.cloud.clickhouse.ClickHouseClient", return_value=_Client()):
            store = ClickHouseAnalyticsStore(url="http://localhost:8123")
            buffered = BufferedAnalyticsStore(store, max_batch=10, flush_interval=60.0)
            buffered.record_scan("scan-1", "agent-1", [{"package": "requests@2.33.0", "severity": "high"}])
            result = buffered.query_vuln_trends()
            buffered.close()

        assert result == [{"day": "2026-04-05", "severity": "high", "cnt": 1}]
        assert any(table == "vulnerability_scans" for table, _rows in inserted)

    def test_record_events_batches_runtime_rows(self):
        from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

        inserted = {}

        class _Client:
            def ensure_tables(self):
                return None

            def insert_json(self, table, rows):
                inserted["table"] = table
                inserted["rows"] = rows

        with patch("agent_bom.cloud.clickhouse.ClickHouseClient", return_value=_Client()):
            store = ClickHouseAnalyticsStore(url="http://localhost:8123")
            store.record_events(
                [
                    {"event_type": "vulnerable_tool_call", "severity": "high", "tool_name": "read_file", "message": "flagged"},
                    {"event_type": "vulnerable_tool_call", "severity": "medium", "tool_name": "exec_sql", "message": "flagged"},
                ]
            )

        assert inserted["table"] == "runtime_events"
        assert len(inserted["rows"]) == 2
        assert inserted["rows"][0]["event_type"] == "vulnerable_tool_call"

    def test_audit_and_runtime_rows_preserve_correlation_fields(self):
        from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

        inserted: list[tuple[str, list[dict]]] = []

        class _Client:
            def ensure_tables(self):
                return None

            def insert_json(self, table, rows):
                inserted.append((table, rows))

        with patch("agent_bom.cloud.clickhouse.ClickHouseClient", return_value=_Client()):
            store = ClickHouseAnalyticsStore(url="http://localhost:8123")
            store.record_event(
                {
                    "event_type": "runtime_alert",
                    "session_id": "sess-1",
                    "trace_id": "trace-1",
                    "request_id": "req-1",
                    "source_id": "proxy-a",
                    "timestamp": "2026-04-20T12:00:01Z",
                },
                tenant_id="tenant-alpha",
            )
            store.record_audit_event(
                {
                    "action": "proxy.audit_ingested",
                    "tenant_id": "tenant-alpha",
                    "session_id": "sess-1",
                    "trace_id": "trace-1",
                    "request_id": "req-1",
                    "timestamp": "2026-04-20T12:00:02Z",
                }
            )

        runtime_row = next(rows[0] for table, rows in inserted if table == "runtime_events")
        audit_row = next(rows[0] for table, rows in inserted if table == "audit_events")
        assert runtime_row["session_id"] == "sess-1"
        assert runtime_row["trace_id"] == "trace-1"
        assert runtime_row["request_id"] == "req-1"
        assert runtime_row["source_id"] == "proxy-a"
        assert audit_row["session_id"] == "sess-1"
        assert audit_row["trace_id"] == "trace-1"
        assert audit_row["request_id"] == "req-1"


def test_clickhouse_escape_strips_control_chars_and_quotes():
    from agent_bom.api.clickhouse_store import _escape

    escaped = _escape("bad\x00name'\n\t\u2028\\test")

    assert "\x00" not in escaped
    assert "\u2028" not in escaped
    assert "\\'" in escaped
    assert "\\\\" in escaped


def test_build_scan_analytics_payload_splits_findings_by_agent():
    from agent_bom.analytics_contract import build_scan_analytics_payload
    from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability

    shared_pkg = Package(name="requests", version="2.33.0", ecosystem="pypi")
    vuln = Vulnerability(
        id="CVE-2026-9999",
        summary="shared vuln",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        advisory_sources=["osv", "ghsa", "nvd"],
    )
    shared_pkg.vulnerabilities = [vuln]
    server = MCPServer(name="filesystem", packages=[shared_pkg])
    agent_a = Agent(name="alpha", agent_type=AgentType.CUSTOM, config_path="alpha.json", mcp_servers=[server])
    agent_b = Agent(name="beta", agent_type=AgentType.CUSTOM, config_path="beta.json", mcp_servers=[server])
    br = BlastRadius(
        vulnerability=vuln,
        package=shared_pkg,
        affected_servers=[server],
        affected_agents=[agent_a, agent_b],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br.calculate_risk_score()
    report = AIBOMReport(agents=[agent_a, agent_b], blast_radii=[br], scan_id="scan-xyz")

    payload = build_scan_analytics_payload(report, source="api")

    assert payload.scan_id == "scan-xyz"
    assert payload.scan_metadata["source"] == "api"
    assert payload.scan_metadata["vuln_count"] == 2
    assert payload.agent_findings["alpha"][0]["source"] == "osv"
    assert payload.agent_findings["beta"][0]["cve_id"] == "CVE-2026-9999"
    assert payload.posture_snapshots["alpha"]["critical"] == 1
    assert payload.posture_snapshots["beta"]["critical"] == 1
    assert payload.fleet_snapshots[0]["lifecycle_state"] == "discovered"
    assert any(row["framework"] == "owasp-llm-top10" for row in payload.compliance_controls)


def test_build_scan_analytics_payload_extracts_cis_checks():
    from agent_bom.analytics_contract import build_scan_analytics_payload
    from agent_bom.models import AIBOMReport

    report = AIBOMReport(scan_id="scan-cis")
    report.cis_benchmark_data = {
        "checks": [
            {
                "check_id": "1.5",
                "title": "Root MFA",
                "status": "fail",
                "severity": "high",
                "remediation": {"priority": 1, "guardrails": ["identity"]},
            }
        ]
    }

    payload = build_scan_analytics_payload(report, source="api")

    assert payload.cis_benchmark_checks[0]["cloud"] == "aws"
    assert payload.cis_benchmark_checks[0]["priority"] == 1
    assert payload.cis_benchmark_checks[0]["guardrails"] == ["identity"]


def test_clickhouse_store_queries_fleet_and_compliance():
    from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

    queries: list[str] = []

    class _Client:
        def ensure_tables(self):
            return None

        def query_json(self, query):
            queries.append(query)
            return [{"ok": True}]

    with patch("agent_bom.cloud.clickhouse.ClickHouseClient", return_value=_Client()):
        store = ClickHouseAnalyticsStore(url="http://localhost:8123")
        assert store.query_top_riskiest_agents(limit=5) == [{"ok": True}]
        assert store.query_compliance_heatmap(days=7) == [{"ok": True}]
        assert store.query_cis_benchmark_checks(cloud="aws", status="fail", priority=1, tenant_id="tenant-a") == [{"ok": True}]

    assert "FROM fleet_agents" in queries[0]
    assert "LIMIT 5" in queries[0]
    assert "FROM compliance_controls" in queries[1]
    assert "FROM cis_benchmark_checks" in queries[2]
    assert "tenant_id = 'tenant-a'" in queries[2]
    assert "INTERVAL 7 DAY" in queries[1]
