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
        from agent_bom.cloud.clickhouse import ClickHouseClient

        c = ClickHouseClient(url="http://localhost:8123")

        with patch("agent_bom.http_client.sync_request_with_retry", return_value=_mock_response("")) as mock_req:
            c.ensure_tables()
            # 1 CREATE DATABASE + 4 CREATE TABLE = 5 calls
            assert mock_req.call_count == 5


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
