"""Tests for Snowflake agent activity timeline discovery.

Covers QUERY_HISTORY 365-day mining, AI_OBSERVABILITY_EVENTS,
and query classification.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.governance import (
    ActivityTimeline,
    ObservabilityEvent,
    QueryHistoryRecord,
)

# ─── Model tests ─────────────────────────────────────────────────────────────


class TestActivityModels:
    def test_query_history_record_defaults(self):
        rec = QueryHistoryRecord(
            query_id="q1",
            query_text="SELECT 1",
            user_name="alice",
            role_name="ANALYST",
            start_time="2026-02-20T00:00:00Z",
        )
        assert rec.is_agent_query is False
        assert rec.agent_pattern == ""
        assert rec.execution_time_ms == 0

    def test_observability_event_defaults(self):
        ev = ObservabilityEvent(
            event_id="e1",
            event_type="TOOL_CALL",
            agent_name="my_agent",
            timestamp="2026-02-20T00:00:00Z",
        )
        assert ev.tool_name == ""
        assert ev.trace_id == ""
        assert ev.duration_ms == 0

    def test_activity_timeline_to_dict(self):
        timeline = ActivityTimeline(account="test_account")
        timeline.query_history = [
            QueryHistoryRecord(
                query_id="q1",
                query_text="CREATE AGENT my_agent",
                user_name="alice",
                role_name="ADMIN",
                start_time="2026-02-20T00:00:00Z",
                is_agent_query=True,
                agent_pattern="CREATE AGENT",
            ),
        ]
        timeline.observability_events = [
            ObservabilityEvent(
                event_id="e1",
                event_type="TOOL_CALL",
                agent_name="my_agent",
                timestamp="2026-02-20T00:00:01Z",
                tool_name="search_docs",
            ),
        ]

        d = timeline.to_dict()
        assert d["account"] == "test_account"
        assert d["summary"]["total_queries"] == 1
        assert d["summary"]["agent_queries"] == 1
        assert d["summary"]["observability_events"] == 1
        assert d["summary"]["unique_agents"] == 1
        assert d["summary"]["tool_calls"] == 1
        assert len(d["query_history"]) == 1
        assert d["query_history"][0]["is_agent_query"] is True
        assert len(d["observability_events"]) == 1

    def test_activity_timeline_empty(self):
        timeline = ActivityTimeline(account="test")
        d = timeline.to_dict()
        assert d["summary"]["total_queries"] == 0
        assert d["summary"]["agent_queries"] == 0
        assert d["summary"]["observability_events"] == 0

    def test_query_text_truncated_in_dict(self):
        long_query = "SELECT " + "x" * 500
        timeline = ActivityTimeline(account="test")
        timeline.query_history = [
            QueryHistoryRecord(
                query_id="q1",
                query_text=long_query,
                user_name="u",
                role_name="r",
                start_time="t",
            ),
        ]
        d = timeline.to_dict()
        assert len(d["query_history"][0]["query_text"]) == 200


# ─── Helper function tests ───────────────────────────────────────────────────


def _make_mock_conn():
    conn = MagicMock()
    return conn


def _make_cursor(rows, columns):
    cursor = MagicMock()
    cursor.fetchall.return_value = rows
    cursor.description = [(col,) for col in columns]
    return cursor


class TestQueryClassification:
    def test_classify_create_agent(self):
        from agent_bom.cloud.snowflake import _classify_agent_query

        is_agent, label = _classify_agent_query("CREATE AGENT my_agent ...")
        assert is_agent is True
        assert label == "CREATE AGENT"

    def test_classify_create_or_replace_agent(self):
        from agent_bom.cloud.snowflake import _classify_agent_query

        is_agent, label = _classify_agent_query("CREATE OR REPLACE AGENT my_agent")
        assert is_agent is True
        assert label == "CREATE AGENT"

    def test_classify_create_mcp_server(self):
        from agent_bom.cloud.snowflake import _classify_agent_query

        is_agent, label = _classify_agent_query("CREATE MCP SERVER my_server ...")
        assert is_agent is True
        assert label == "CREATE MCP SERVER"

    def test_classify_show_agents(self):
        from agent_bom.cloud.snowflake import _classify_agent_query

        is_agent, label = _classify_agent_query("SHOW AGENTS IN ACCOUNT")
        assert is_agent is True
        assert label == "SHOW AGENTS"

    def test_classify_cortex_function(self):
        from agent_bom.cloud.snowflake import _classify_agent_query

        is_agent, label = _classify_agent_query("SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3', 'hello')")
        assert is_agent is True
        assert "CORTEX" in label

    def test_classify_describe_mcp_server(self):
        from agent_bom.cloud.snowflake import _classify_agent_query

        is_agent, label = _classify_agent_query("DESCRIBE MCP SERVER db.schema.srv")
        assert is_agent is True
        assert label == "DESCRIBE MCP SERVER"

    def test_classify_system_execute_sql(self):
        from agent_bom.cloud.snowflake import _classify_agent_query

        is_agent, label = _classify_agent_query("CALL SYSTEM$EXECUTE_SQL('SELECT 1')")
        assert is_agent is True
        assert label == "SYSTEM_EXECUTE_SQL"

    def test_classify_ml_function(self):
        from agent_bom.cloud.snowflake import _classify_agent_query

        is_agent, label = _classify_agent_query("SELECT SNOWFLAKE.ML.FORECAST('model', ...)")
        assert is_agent is True
        assert label == "ML FUNCTION"

    def test_classify_normal_query(self):
        from agent_bom.cloud.snowflake import _classify_agent_query

        is_agent, label = _classify_agent_query("SELECT * FROM users")
        assert is_agent is False
        assert label == ""

    def test_classify_case_insensitive(self):
        from agent_bom.cloud.snowflake import _classify_agent_query

        is_agent, _ = _classify_agent_query("show agents in account")
        assert is_agent is True


# ─── Mining function tests ────────────────────────────────────────────────────


class TestQueryHistory365:
    def test_mine_query_history(self):
        from agent_bom.cloud.snowflake import _mine_query_history_365

        conn = _make_mock_conn()
        cursor = _make_cursor(
            rows=[
                (
                    "q1",
                    "CREATE AGENT my_agent SPEC=...",
                    "alice",
                    "ADMIN",
                    "2026-02-20T00:00:00Z",
                    "2026-02-20T00:00:01Z",
                    "SUCCESS",
                    "WH1",
                    "DB1",
                    "SCHEMA1",
                    "CREATE",
                    0,
                    0,
                    500,
                ),
                (
                    "q2",
                    "SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3', 'hi')",
                    "bot",
                    "ETL_ROLE",
                    "2026-02-20T00:01:00Z",
                    "2026-02-20T00:01:02Z",
                    "SUCCESS",
                    "WH1",
                    "DB1",
                    "SCHEMA1",
                    "SELECT",
                    1,
                    1024,
                    2000,
                ),
            ],
            columns=[
                "query_id",
                "query_text",
                "user_name",
                "role_name",
                "start_time",
                "end_time",
                "execution_status",
                "warehouse_name",
                "database_name",
                "schema_name",
                "query_type",
                "rows_produced",
                "bytes_scanned",
                "total_elapsed_time",
            ],
        )
        conn.cursor.return_value = cursor

        records, warnings = _mine_query_history_365(conn, 30)
        assert len(records) == 2
        assert records[0].is_agent_query is True
        assert records[0].agent_pattern == "CREATE AGENT"
        assert records[0].execution_time_ms == 500
        assert records[1].is_agent_query is True
        assert "CORTEX" in records[1].agent_pattern
        assert warnings == []

    def test_mine_query_history_error(self):
        from agent_bom.cloud.snowflake import _mine_query_history_365

        conn = _make_mock_conn()
        cursor = MagicMock()
        cursor.execute.side_effect = Exception("query_history access denied")
        conn.cursor.return_value = cursor

        records, warnings = _mine_query_history_365(conn, 30)
        assert len(records) == 0
        assert any("QUERY_HISTORY" in w for w in warnings)

    def test_mine_query_history_generic_error(self):
        from agent_bom.cloud.snowflake import _mine_query_history_365

        conn = _make_mock_conn()
        cursor = MagicMock()
        cursor.execute.side_effect = Exception("network timeout")
        conn.cursor.return_value = cursor

        records, warnings = _mine_query_history_365(conn, 30)
        assert len(records) == 0
        assert any("Could not query" in w for w in warnings)


class TestObservabilityEvents:
    def test_mine_observability_events(self):
        from agent_bom.cloud.snowflake import _mine_observability_events

        conn = _make_mock_conn()
        cursor = _make_cursor(
            rows=[
                (
                    "e1",
                    "TOOL_CALL",
                    "my_agent",
                    "2026-02-20T00:00:00Z",
                    150,
                    "SUCCESS",
                    "claude-3.5-sonnet",
                    100,
                    50,
                    "search_docs",
                    '{"query": "test"}',
                    "Found 3 results",
                    "",
                    "trace-123",
                    "",
                ),
                (
                    "e2",
                    "LLM_INFERENCE",
                    "my_agent",
                    "2026-02-20T00:00:01Z",
                    500,
                    "SUCCESS",
                    "claude-3.5-sonnet",
                    500,
                    200,
                    "",
                    "",
                    "",
                    "",
                    "trace-123",
                    "e1",
                ),
            ],
            columns=[
                "event_id",
                "event_type",
                "agent_name",
                "timestamp",
                "duration_ms",
                "status",
                "model_name",
                "input_tokens",
                "output_tokens",
                "tool_name",
                "tool_input",
                "tool_output_summary",
                "user_feedback",
                "trace_id",
                "parent_event_id",
            ],
        )
        conn.cursor.return_value = cursor

        events, warnings = _mine_observability_events(conn, 30)
        assert len(events) == 2
        assert events[0].event_type == "TOOL_CALL"
        assert events[0].tool_name == "search_docs"
        assert events[0].trace_id == "trace-123"
        assert events[1].event_type == "LLM_INFERENCE"
        assert events[1].parent_event_id == "e1"
        assert warnings == []

    def test_mine_observability_events_not_available(self):
        from agent_bom.cloud.snowflake import _mine_observability_events

        conn = _make_mock_conn()
        cursor = MagicMock()
        cursor.execute.side_effect = Exception("ai_observability_events does not exist")
        conn.cursor.return_value = cursor

        events, warnings = _mine_observability_events(conn, 30)
        assert len(events) == 0
        assert any("AI_OBSERVABILITY_EVENTS" in w for w in warnings)


# ─── Full discover_activity integration tests ─────────────────────────────────


class TestDiscoverActivity:
    def _install_mock_sf(self):
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

    def test_discover_activity_no_account(self):
        from agent_bom.cloud.snowflake import discover_activity

        with patch.dict("os.environ", {}, clear=True):
            timeline = discover_activity(account="")
            assert len(timeline.warnings) >= 1

    def test_discover_activity_connection_failure(self):
        mock_connector = self._install_mock_sf()
        try:
            from agent_bom.cloud.snowflake import discover_activity

            mock_connector.connect.side_effect = Exception("connection refused")

            with patch.dict("os.environ", {"SNOWFLAKE_ACCOUNT": "test", "SNOWFLAKE_PASSWORD": "pw"}):
                timeline = discover_activity(account="test")
                assert any("Could not connect" in w for w in timeline.warnings)
        finally:
            self._cleanup_mock_sf()

    def test_discover_activity_success(self):
        mock_connector = self._install_mock_sf()
        try:
            from agent_bom.cloud.snowflake import discover_activity

            conn = _make_mock_conn()
            mock_connector.connect.return_value = conn

            # QUERY_HISTORY cursor
            qh_cursor = _make_cursor(
                rows=[
                    (
                        "q1",
                        "SHOW AGENTS IN ACCOUNT",
                        "alice",
                        "ADMIN",
                        "2026-02-20T00:00:00Z",
                        "2026-02-20T00:00:01Z",
                        "SUCCESS",
                        "WH1",
                        "DB1",
                        "S1",
                        "SHOW",
                        0,
                        0,
                        100,
                    ),
                ],
                columns=[
                    "query_id",
                    "query_text",
                    "user_name",
                    "role_name",
                    "start_time",
                    "end_time",
                    "execution_status",
                    "warehouse_name",
                    "database_name",
                    "schema_name",
                    "query_type",
                    "rows_produced",
                    "bytes_scanned",
                    "total_elapsed_time",
                ],
            )

            # Observability cursor
            obs_cursor = _make_cursor(rows=[], columns=[])

            conn.cursor.side_effect = [qh_cursor, obs_cursor]

            with patch.dict("os.environ", {"SNOWFLAKE_ACCOUNT": "test", "SNOWFLAKE_PASSWORD": "pw"}):
                timeline = discover_activity(account="test")
                assert timeline.account == "test"
                assert len(timeline.query_history) == 1
                assert timeline.query_history[0].is_agent_query is True
        finally:
            self._cleanup_mock_sf()


# ─── Cloud __init__ integration test ─────────────────────────────────────────


class TestCloudInitActivity:
    def test_discover_activity_unsupported_provider(self):
        from agent_bom.cloud import discover_activity

        with pytest.raises(ValueError, match="not supported"):
            discover_activity(provider="aws")

    @patch("agent_bom.cloud.snowflake.discover_activity")
    def test_discover_activity_delegates(self, mock_discover):
        from agent_bom.cloud import discover_activity

        mock_discover.return_value = ActivityTimeline(account="test")
        result = discover_activity(provider="snowflake", days=7)
        mock_discover.assert_called_once_with(days=7)
        assert result.account == "test"
