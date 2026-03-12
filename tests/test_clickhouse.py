"""Tests for ClickHouse analytics backend.

All tests mock ``urllib.request.urlopen`` — no real ClickHouse instance needed.
"""

from __future__ import annotations

import io
import json
import os
from unittest.mock import MagicMock, patch

import pytest

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
        import urllib.request

        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123", user="admin", password="pw")

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"OK"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            c.execute("SELECT 1")
            req = mock_open.call_args[0][0]
            assert req.get_header("X-clickhouse-user") == "admin"
            assert req.get_header("X-clickhouse-key") == "pw"
            assert req.get_header("X-clickhouse-database") == "agent_bom"

    def test_execute_sends_post(self):
        import urllib.request

        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        mock_resp = MagicMock()
        mock_resp.read.return_value = b"result"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            result = c.execute("SELECT 1")
            assert result == "result"
            req = mock_open.call_args[0][0]
            assert req.method == "POST"
            assert req.data == b"SELECT 1"

    def test_execute_http_error(self):
        import urllib.error
        import urllib.request

        from agent_bom.cloud.clickhouse import ClickHouseClient, ClickHouseError

        c = ClickHouseClient(url="http://localhost:8123")

        err = urllib.error.HTTPError("http://localhost:8123", 500, "Internal Server Error", {}, io.BytesIO(b"DB error"))
        with patch.object(urllib.request, "urlopen", side_effect=err):
            with pytest.raises(ClickHouseError, match="HTTP 500"):
                c.execute("BAD QUERY")

    def test_execute_connection_error(self):
        import urllib.error
        import urllib.request

        from agent_bom.cloud.clickhouse import ClickHouseClient, ClickHouseError

        c = ClickHouseClient(url="http://localhost:8123")

        err = urllib.error.URLError("Connection refused")
        with patch.object(urllib.request, "urlopen", side_effect=err):
            with pytest.raises(ClickHouseError, match="connection error"):
                c.execute("SELECT 1")

    def test_execute_timeout(self):
        import urllib.request

        from agent_bom.cloud.clickhouse import ClickHouseClient, ClickHouseError

        c = ClickHouseClient(url="http://localhost:8123", timeout=5)

        with patch.object(urllib.request, "urlopen", side_effect=TimeoutError):
            with pytest.raises(ClickHouseError, match="timed out"):
                c.execute("SELECT 1")

    def test_insert_json_batching(self):
        """Verify JSONEachRow format is assembled correctly."""
        import urllib.request

        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        rows = [{"a": 1, "b": "x"}, {"a": 2, "b": "y"}]
        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            c.insert_json("test_table", rows)
            req = mock_open.call_args[0][0]
            body = req.data.decode("utf-8")
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
        import urllib.request

        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        response_data = {"data": [{"day": "2024-01-01", "cnt": 5}], "rows": 1}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp):
            result = c.query_json("SELECT day, count() AS cnt FROM t GROUP BY day")
            assert result == [{"day": "2024-01-01", "cnt": 5}]

    def test_query_json_appends_format(self):
        """Verify FORMAT JSON is appended if missing."""
        import urllib.request

        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"data": []}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            c.query_json("SELECT 1")
            req = mock_open.call_args[0][0]
            body = req.data.decode("utf-8")
            assert body.endswith("FORMAT JSON")

    def test_ensure_tables_idempotent(self):
        """CREATE TABLE IF NOT EXISTS should not error on repeated calls."""
        import urllib.request

        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            c.ensure_tables()
            # 1 CREATE DATABASE + 4 CREATE TABLE = 5 calls
            assert mock_open.call_count == 5


# ─── NullAnalyticsStore tests ───────────────────────────────────────────────


class TestNullAnalyticsStore:
    """NullAnalyticsStore should be a silent no-op."""

    def test_all_methods_return_empty(self):
        from agent_bom.api.clickhouse_store import NullAnalyticsStore

        store = NullAnalyticsStore()
        # Writes should not raise
        store.record_scan("id", "agent", [{"cve_id": "CVE-2024-0001"}])
        store.record_event({"type": "test"})
        store.record_posture("agent", {"grade": "A"})
        # Reads should return empty lists
        assert store.query_vuln_trends() == []
        assert store.query_top_cves() == []
        assert store.query_posture_history() == []
        assert store.query_event_summary() == []

    def test_implements_protocol(self):
        from agent_bom.api.clickhouse_store import AnalyticsStore, NullAnalyticsStore

        store = NullAnalyticsStore()
        assert isinstance(store, AnalyticsStore)


# ─── ClickHouseAnalyticsStore tests ─────────────────────────────────────────


class TestClickHouseAnalyticsStore:
    """Tests for the real ClickHouse-backed store (all HTTP mocked)."""

    def _mock_urlopen(self):
        """Return a mock that simulates successful ClickHouse responses."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        return mock_resp

    def _make_store(self, mock_resp=None):
        import urllib.request

        from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

        if mock_resp is None:
            mock_resp = self._mock_urlopen()

        with patch.object(urllib.request, "urlopen", return_value=mock_resp):
            return ClickHouseAnalyticsStore(url="http://localhost:8123")

    def test_record_scan_formatting(self):
        """Vulns should be converted to insert rows."""
        import urllib.request

        store = self._make_store()
        mock_resp = self._mock_urlopen()

        vulns = [
            {
                "package": "requests",
                "version": "2.28.0",
                "ecosystem": "PyPI",
                "cve_id": "CVE-2024-0001",
                "cvss_score": 9.8,
                "epss_score": 0.5,
                "severity": "CRITICAL",
                "source": "osv",
            }
        ]
        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            store.record_scan("scan-1", "test-agent", vulns)
            req = mock_open.call_args[0][0]
            body = req.data.decode("utf-8")
            assert "INSERT INTO vulnerability_scans" in body
            assert "requests" in body
            assert "CVE-2024-0001" in body

    def test_record_scan_empty(self):
        """Empty vuln list should be a no-op."""
        import urllib.request

        store = self._make_store()
        with patch.object(urllib.request, "urlopen") as mock_open:
            store.record_scan("scan-1", "agent", [])
            mock_open.assert_not_called()

    def test_record_event_formatting(self):
        import urllib.request

        store = self._make_store()
        mock_resp = self._mock_urlopen()

        event = {
            "event_type": "tool_blocked",
            "detector": "injection",
            "severity": "HIGH",
            "tool_name": "exec",
            "message": "Blocked command injection attempt",
            "agent_name": "test-agent",
        }
        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            store.record_event(event)
            req = mock_open.call_args[0][0]
            body = req.data.decode("utf-8")
            assert "INSERT INTO runtime_events" in body
            assert "tool_blocked" in body

    def test_record_posture_snapshot(self):
        import urllib.request

        store = self._make_store()
        mock_resp = self._mock_urlopen()

        snapshot = {
            "total_packages": 50,
            "critical": 2,
            "high": 5,
            "medium": 10,
            "grade": "C",
            "risk_score": 7.5,
            "compliance_score": 0.65,
        }
        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            store.record_posture("test-agent", snapshot)
            req = mock_open.call_args[0][0]
            body = req.data.decode("utf-8")
            assert "INSERT INTO posture_scores" in body
            assert '"posture_grade": "C"' in body

    def test_query_vuln_trends_sql(self):
        """Verify correct GROUP BY day, severity."""
        import urllib.request

        store = self._make_store()
        response_data = {"data": [{"day": "2024-01-01", "severity": "HIGH", "cnt": 3}]}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            result = store.query_vuln_trends(days=7)
            req = mock_open.call_args[0][0]
            body = req.data.decode("utf-8")
            assert "GROUP BY day, severity" in body
            assert "INTERVAL 7 DAY" in body
            assert result == [{"day": "2024-01-01", "severity": "HIGH", "cnt": 3}]

    def test_query_vuln_trends_with_agent(self):
        import urllib.request

        store = self._make_store()
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"data": []}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            store.query_vuln_trends(days=30, agent="my-agent")
            req = mock_open.call_args[0][0]
            body = req.data.decode("utf-8")
            assert "agent_name = 'my-agent'" in body

    def test_query_top_cves_sql(self):
        import urllib.request

        store = self._make_store()
        response_data = {"data": [{"cve_id": "CVE-2024-0001", "cnt": 10, "max_cvss": 9.8}]}
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(response_data).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            result = store.query_top_cves(limit=10)
            req = mock_open.call_args[0][0]
            body = req.data.decode("utf-8")
            assert "ORDER BY cnt DESC LIMIT 10" in body
            assert result[0]["cve_id"] == "CVE-2024-0001"

    def test_query_posture_history_sql(self):
        import urllib.request

        store = self._make_store()
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"data": []}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            store.query_posture_history(days=90)
            req = mock_open.call_args[0][0]
            body = req.data.decode("utf-8")
            assert "posture_scores" in body
            assert "INTERVAL 90 DAY" in body

    def test_query_event_summary_sql(self):
        import urllib.request

        store = self._make_store()
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"data": []}).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            store.query_event_summary(hours=12)
            req = mock_open.call_args[0][0]
            body = req.data.decode("utf-8")
            assert "runtime_events" in body
            assert "INTERVAL 12 HOUR" in body


# ─── Auto-detection tests ──────────────────────────────────────────────────


class TestAutoDetection:
    """Test analytics store auto-detection from env vars."""

    def test_env_var_creates_clickhouse_store(self):
        """AGENT_BOM_CLICKHOUSE_URL should create ClickHouseAnalyticsStore."""
        import urllib.request

        from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.dict(os.environ, {"AGENT_BOM_CLICKHOUSE_URL": "http://localhost:8123"}):
            with patch.object(urllib.request, "urlopen", return_value=mock_resp):
                store = ClickHouseAnalyticsStore()
                assert isinstance(store, ClickHouseAnalyticsStore)

    def test_no_env_var_uses_null(self):
        """No env var should use NullAnalyticsStore."""
        from agent_bom.api.clickhouse_store import NullAnalyticsStore

        store = NullAnalyticsStore()
        assert store.query_vuln_trends() == []


# ─── CLI tests ──────────────────────────────────────────────────────────────


class TestAnalyticsCLI:
    """Test the analytics CLI command."""

    def test_analytics_help(self):
        from click.testing import CliRunner

        from agent_bom.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["analytics", "--help"])
        assert result.exit_code == 0
        assert "trends" in result.output
        assert "posture" in result.output
        assert "events" in result.output
        assert "top-cves" in result.output

    def test_analytics_no_url_exits(self):
        from click.testing import CliRunner

        from agent_bom.cli import main

        runner = CliRunner()
        with patch.dict(os.environ, {}, clear=False):
            # Ensure env var is not set
            env = os.environ.copy()
            env.pop("AGENT_BOM_CLICKHOUSE_URL", None)
            result = runner.invoke(main, ["analytics", "trends"], env=env)
            assert result.exit_code != 0

    def test_scan_clickhouse_url_option(self):
        """--clickhouse-url should appear in scan help."""
        from click.testing import CliRunner

        from agent_bom.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["scan", "--help"])
        assert "--clickhouse-url" in result.output


# ─── ClickHouseChannel tests ───────────────────────────────────────────────


class TestClickHouseChannel:
    """Test the alert dispatcher ClickHouse channel."""

    def test_channel_send_records_event(self):
        import asyncio

        from agent_bom.alerts.dispatcher import ClickHouseChannel

        channel = ClickHouseChannel(url="http://localhost:8123")

        mock_store = MagicMock()
        channel._store = mock_store

        alert = {"event_type": "tool_blocked", "severity": "HIGH", "message": "test"}
        result = asyncio.run(channel.send(alert))
        assert result is True
        mock_store.record_event.assert_called_once_with(alert)

    def test_channel_send_failure(self):
        import asyncio

        from agent_bom.alerts.dispatcher import ClickHouseChannel

        channel = ClickHouseChannel(url="http://localhost:8123")

        mock_store = MagicMock()
        mock_store.record_event.side_effect = Exception("connection failed")
        channel._store = mock_store

        alert = {"event_type": "test", "severity": "LOW"}
        result = asyncio.run(channel.send(alert))
        assert result is False


# ─── Escape function tests ──────────────────────────────────────────────────


class TestEscape:
    """Test SQL injection prevention."""

    def test_escape_single_quote(self):
        from agent_bom.api.clickhouse_store import _escape

        assert _escape("it's") == "it\\'s"

    def test_escape_backslash(self):
        from agent_bom.api.clickhouse_store import _escape

        assert _escape("a\\b") == "a\\\\b"

    def test_escape_clean_string(self):
        from agent_bom.api.clickhouse_store import _escape

        assert _escape("my-agent") == "my-agent"


# ─── Scan metadata tests ──────────────────────────────────────────────────


class TestScanMetadata:
    """Test scan_metadata table and recording."""

    def test_scan_metadata_table_in_ddl(self):
        from agent_bom.cloud.clickhouse import _TABLE_DDL

        ddl_text = " ".join(_TABLE_DDL)
        assert "scan_metadata" in ddl_text
        assert "agent_count" in ddl_text
        assert "posture_grade" in ddl_text

    def test_null_store_record_scan_metadata(self):
        from agent_bom.api.clickhouse_store import NullAnalyticsStore

        store = NullAnalyticsStore()
        store.record_scan_metadata({"scan_id": "test", "agent_count": 5})
        # Should not raise

    def test_clickhouse_store_record_scan_metadata(self):
        import urllib.request

        from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

        mock_resp = MagicMock()
        mock_resp.read.return_value = b""
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
            store = ClickHouseAnalyticsStore(url="http://localhost:8123")
            store.record_scan_metadata(
                {
                    "scan_id": "abc-123",
                    "agent_count": 10,
                    "package_count": 50,
                    "vuln_count": 3,
                    "critical_count": 1,
                    "high_count": 2,
                    "posture_grade": "B",
                    "scan_duration_ms": 1500,
                    "source": "cli",
                }
            )
            # Find the insert call (contains INSERT INTO scan_metadata)
            insert_calls = [c for c in mock_open.call_args_list if b"INSERT INTO scan_metadata" in c[0][0].data]
            assert len(insert_calls) == 1
            body = insert_calls[0][0][0].data.decode("utf-8")
            assert "abc-123" in body


# ─── Grafana infrastructure tests ──────────────────────────────────────────


class TestGrafanaInfra:
    """Verify ClickHouse + Grafana infra files exist and are valid."""

    def test_docker_compose_exists(self):
        from pathlib import Path

        p = Path(__file__).parent.parent / "deploy" / "supabase" / "clickhouse" / "docker-compose.yml"
        assert p.exists()
        content = p.read_text()
        assert "clickhouse" in content
        assert "grafana" in content

    def test_init_sql_has_all_tables(self):
        from pathlib import Path

        p = Path(__file__).parent.parent / "deploy" / "supabase" / "clickhouse" / "init.sql"
        assert p.exists()
        content = p.read_text()
        assert "vulnerability_scans" in content
        assert "runtime_events" in content
        assert "posture_scores" in content
        assert "scan_metadata" in content

    def test_grafana_dashboard_valid_json(self):
        from pathlib import Path

        p = Path(__file__).parent.parent / "deploy" / "supabase" / "clickhouse" / "grafana-dashboard.json"
        assert p.exists()
        data = json.loads(p.read_text())
        assert data["title"] == "agent-bom Security Analytics"
        assert len(data["panels"]) >= 10

    def test_grafana_datasource_provisioning(self):
        from pathlib import Path

        p = Path(__file__).parent.parent / "deploy" / "supabase" / "clickhouse" / "grafana-provisioning" / "datasources" / "clickhouse.yml"
        assert p.exists()
        assert "grafana-clickhouse-datasource" in p.read_text()
