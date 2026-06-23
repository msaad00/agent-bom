"""discover_snowflake_pipeline parses tasks/streams/pipes offline."""

from __future__ import annotations

import sys
import types

import pytest


@pytest.fixture(autouse=True)
def _stub_snowflake_connector(monkeypatch):
    sf_pkg = sys.modules.get("snowflake") or types.ModuleType("snowflake")
    connector = sys.modules.get("snowflake.connector") or types.ModuleType("snowflake.connector")
    monkeypatch.setitem(sys.modules, "snowflake", sf_pkg)
    monkeypatch.setitem(sys.modules, "snowflake.connector", connector)


class _FakeCursor:
    def __init__(self):
        self.description = None
        self._rows: list = []

    def execute(self, sql, *_a, **_k):
        s = " ".join(sql.split())
        if "SHOW TASKS" in s:
            self.description = [("name",), ("database_name",), ("schema_name",), ("warehouse",), ("schedule",), ("state",), ("owner",)]
            self._rows = [
                ("T_ETL", "DB", "PUBLIC", "WH_ETL", "5 MINUTE", "STARTED", "ETL_ROLE"),
                ("T_OLD", "DB", "PUBLIC", "WH_ETL", "1 DAY", "SUSPENDED", "ETL_ROLE"),
            ]
        elif "SHOW STREAMS" in s:
            self.description = [("name",), ("database_name",), ("schema_name",), ("table_name",), ("stale",), ("type",)]
            self._rows = [
                ("S_ORD", "DB", "PUBLIC", "DB.PUBLIC.ORDERS", "true", "DELTA"),
                ("S_FRESH", "DB", "PUBLIC", "DB.PUBLIC.LEADS", "false", "DELTA"),
            ]
        elif "SHOW PIPES" in s:
            self.description = [
                ("name",),
                ("database_name",),
                ("schema_name",),
                ("definition",),
                ("integration",),
                ("notification_channel",),
            ]
            self._rows = [
                ("P_LOAD", "DB", "PUBLIC", "COPY INTO t FROM @DB.PUBLIC.INGEST_STG FILE_FORMAT=(TYPE=CSV)", "NOTIF_INT", "arn:aws:sns:..."),
            ]
        else:
            self.description = []
            self._rows = []

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class _FakeConn:
    def cursor(self):
        return _FakeCursor()

    def close(self):
        pass


@pytest.fixture
def _pipe(monkeypatch):
    from agent_bom.cloud import snowflake as sf

    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _FakeConn())
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    return sf.discover_snowflake_pipeline()


def test_tasks_parsed_with_fqn_and_runtime(_pipe) -> None:
    by = {t["name"]: t for t in _pipe["tasks"]}
    assert by["T_ETL"]["fqn"] == "DB.PUBLIC.T_ETL"
    assert by["T_ETL"]["warehouse"] == "WH_ETL"
    assert by["T_ETL"]["owner"] == "ETL_ROLE"


def test_streams_parse_source_and_staleness(_pipe) -> None:
    by = {s["name"]: s for s in _pipe["streams"]}
    assert by["S_ORD"]["source_fqn"] == "DB.PUBLIC.ORDERS"
    assert by["S_ORD"]["stale"] is True
    assert by["S_FRESH"]["stale"] is False


def test_pipe_stage_extracted_from_copy_definition(_pipe) -> None:
    pipe = _pipe["pipes"][0]
    assert pipe["stage"] == "DB.PUBLIC.INGEST_STG"
    assert pipe["auto_ingest"] is True


def test_findings_flag_suspended_tasks_and_stale_streams(_pipe) -> None:
    titles = {f["title"] for f in _pipe["findings"]}
    assert "Suspended scheduled tasks" in titles
    assert "Stale change-data-capture streams" in titles
    assert _pipe["status"] == "ok"


def test_no_account_is_graceful(monkeypatch) -> None:
    from agent_bom.cloud import snowflake as sf

    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    assert sf.discover_snowflake_pipeline()["status"] == "no_account"
