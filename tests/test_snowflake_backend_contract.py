"""Contract tests for the advertised Snowflake control-plane slice.

These tests do not use a live Snowflake account. They prove the API wiring and
health contract against the mocked Snowflake store implementations that CI can
run deterministically.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.server import app


def _mock_cursor(fetchone_val=None, fetchall_val=None, rowcount=0):
    cur = MagicMock()
    cur.fetchone.return_value = fetchone_val
    cur.fetchall.return_value = fetchall_val or []
    cur.rowcount = rowcount
    cur.execute.return_value = cur
    return cur


def _mock_connection(cursor=None):
    conn = MagicMock()
    conn.cursor.return_value = cursor or _mock_cursor()
    conn.__enter__ = MagicMock(return_value=conn)
    conn.__exit__ = MagicMock(return_value=False)
    return conn


def _clear_store_globals() -> None:
    api_stores._store = None
    api_stores._fleet_store = None
    api_stores._policy_store = None
    api_stores._source_store = None
    api_stores._schedule_store = None
    api_stores._exception_store = None
    api_stores._trend_store = None
    api_stores._graph_store = None
    api_stores._analytics_store = None


@patch("agent_bom.api.snowflake_store._sf_connect")
def test_health_reports_supported_snowflake_control_plane_slice(mock_connect, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct")
    monkeypatch.setenv("SNOWFLAKE_USER", "user")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/test.p8")
    monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)
    mock_connect.return_value = _mock_connection()
    monkeypatch.setattr("agent_bom.api.server._cleanup_loop", lambda: _async_noop())
    monkeypatch.setattr("agent_bom.api.scheduler.scheduler_loop", lambda store, fn: _async_noop())

    _clear_store_globals()
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/health")
            assert resp.status_code == 200
            storage = resp.json()["storage"]
            assert storage["control_plane_backend"] == "snowflake"
            assert storage["job_store"] == "snowflake"
            assert storage["fleet_store"] == "snowflake"
            assert storage["policy_store"] == "snowflake"
            assert storage["schedule_store"] == "snowflake"
            assert storage["exception_store"] == "snowflake"
    finally:
        _clear_store_globals()


@patch("agent_bom.api.snowflake_store._sf_connect")
def test_supported_snowflake_routes_remain_wired(mock_connect, monkeypatch):
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct")
    monkeypatch.setenv("SNOWFLAKE_USER", "user")
    monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", "/keys/test.p8")
    monkeypatch.delenv("SNOWFLAKE_PASSWORD", raising=False)
    mock_connect.return_value = _mock_connection()
    monkeypatch.setattr("agent_bom.api.server._cleanup_loop", lambda: _async_noop())
    monkeypatch.setattr("agent_bom.api.scheduler.scheduler_loop", lambda store, fn: _async_noop())

    _clear_store_globals()
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            schedules = client.get("/v1/schedules")
            exceptions = client.get("/v1/exceptions")

            assert schedules.status_code == 200
            assert schedules.json() == []

            assert exceptions.status_code == 200
            assert exceptions.json() == {"exceptions": [], "total": 0}
    finally:
        _clear_store_globals()


async def _async_noop() -> None:
    return None
