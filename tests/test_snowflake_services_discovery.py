"""discover_snowflake_services parses warehouses/databases/schemas offline."""

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
        if "SHOW WAREHOUSES" in s:
            self.description = [("name",), ("size",), ("state",), ("auto_suspend",), ("type",)]
            self._rows = [
                ("WH_ETL", "X-SMALL", "STARTED", 0, "STANDARD"),  # no auto-suspend
                ("WH_BI", "SMALL", "SUSPENDED", 300, "STANDARD"),
            ]
        elif "SHOW DATABASES" in s:
            self.description = [("name",), ("owner",), ("retention_time",), ("is_default",)]
            self._rows = [
                ("DB", "SYSADMIN", 1, "N"),
                ("STAGING", "SYSADMIN", 0, "N"),  # zero retention
            ]
        elif "SHOW SCHEMAS" in s:
            self.description = [("name",), ("database_name",), ("owner",)]
            self._rows = [
                ("PUBLIC", "DB", "SYSADMIN"),
                ("SALES", "DB", "SYSADMIN"),
                ("INFORMATION_SCHEMA", "DB", "SYSADMIN"),  # filtered out
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
def _svc(monkeypatch):
    from agent_bom.cloud import snowflake as sf

    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _FakeConn())
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    return sf.discover_snowflake_services()


def test_warehouses_parsed(_svc) -> None:
    by = {w["name"]: w for w in _svc["warehouses"]}
    assert by["WH_ETL"]["auto_suspend"] == 0
    assert by["WH_BI"]["auto_suspend"] == 300
    assert by["WH_BI"]["state"] == "SUSPENDED"


def test_schemas_filter_information_schema(_svc) -> None:
    names = {s["name"] for s in _svc["schemas"]}
    assert names == {"PUBLIC", "SALES"}
    assert all(s["fqn"].startswith("DB.") for s in _svc["schemas"])


def test_findings_flag_no_autosuspend_and_zero_retention(_svc) -> None:
    titles = {f["title"] for f in _svc["findings"]}
    assert "Warehouse without auto-suspend" in titles
    assert "Database without time-travel retention" in titles
    assert _svc["status"] == "ok"


def test_no_account_is_graceful(monkeypatch) -> None:
    from agent_bom.cloud import snowflake as sf

    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    assert sf.discover_snowflake_services()["status"] == "no_account"
