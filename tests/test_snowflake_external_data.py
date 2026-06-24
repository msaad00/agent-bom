"""Snowflake iceberg + external tables: discovery + graph (cross-cloud stitch)."""

from __future__ import annotations

import sys
import types

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report


# ── Graph ────────────────────────────────────────────────────────────────
def _report() -> dict:
    return {
        "snowflake_external_data": {
            "status": "ok",
            "account": "acct1",
            "iceberg_tables": [
                {
                    "name": "EVENTS",
                    "fqn": "DB.PUBLIC.EVENTS",
                    "catalog": "MY_CAT",
                    "catalog_source": "SNOWFLAKE",
                    "base_location": "s3://lake-iceberg/events/",
                    "cloud_provider": "aws",
                    "bucket": "lake-iceberg",
                }
            ],
            "external_tables": [
                {
                    "name": "RAW",
                    "fqn": "DB.PUBLIC.RAW",
                    "location": "@DB.PUBLIC.RAW_STG/2026/",
                    "stage": "DB.PUBLIC.RAW_STG",
                    "file_format": "PARQUET",
                }
            ],
        }
    }


def _build():
    g = build_unified_graph_from_report(_report())
    return g, {(e.source, e.target, e.relationship.value) for e in g.edges}


def test_iceberg_table_exposed_to_cloud_bucket() -> None:
    g, edges = _build()
    assert g.nodes["data_store:snowflake:iceberg:DB.PUBLIC.EVENTS"].attributes["table_format"] == "iceberg"
    # cross-cloud stitch: same bucket-node id scheme an AWS scan emits
    assert ("data_store:snowflake:iceberg:DB.PUBLIC.EVENTS", "cloud_resource:aws:s3:bucket:lake-iceberg", "exposed_to") in edges


def test_external_table_depends_on_stage() -> None:
    g, edges = _build()
    assert "data_store:snowflake:external_table:DB.PUBLIC.RAW" in g.nodes
    assert ("data_store:snowflake:external_table:DB.PUBLIC.RAW", "cloud_resource:snowflake:stage:RAW_STG", "depends_on") in edges


def test_non_ok_payload_is_noop() -> None:
    g = build_unified_graph_from_report({"snowflake_external_data": {"status": "no_account"}})
    assert not [k for k in g.nodes if "snowflake" in k]


# ── Discovery ────────────────────────────────────────────────────────────
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
        if "SHOW ICEBERG TABLES" in s:
            self.description = [("name",), ("database_name",), ("schema_name",), ("catalog",), ("catalog_source",), ("base_location",)]
            self._rows = [
                ("EVENTS", "DB", "PUBLIC", "MY_CAT", "SNOWFLAKE", "s3://lake-iceberg/events/"),
                ("EXT_ICE", "DB", "PUBLIC", "POLARIS_CAT", "POLARIS", "azure://acct.blob.core.windows.net/c"),
            ]
        elif "SHOW EXTERNAL TABLES" in s:
            self.description = [("name",), ("database_name",), ("schema_name",), ("location",), ("file_format_type",)]
            self._rows = [("RAW", "DB", "PUBLIC", "@DB.PUBLIC.RAW_STG/2026/", "PARQUET")]
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
def _ext(monkeypatch):
    from agent_bom.cloud import snowflake as sf

    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _FakeConn())
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    return sf.discover_snowflake_external_data()


def test_iceberg_base_location_parsed(_ext) -> None:
    by = {t["name"]: t for t in _ext["iceberg_tables"]}
    assert by["EVENTS"]["cloud_provider"] == "aws" and by["EVENTS"]["bucket"] == "lake-iceberg"
    assert by["EXT_ICE"]["cloud_provider"] == "azure"
    assert by["EXT_ICE"]["catalog_source"] == "POLARIS"


def test_external_table_stage_parsed(_ext) -> None:
    t = _ext["external_tables"][0]
    assert t["stage"] == "DB.PUBLIC.RAW_STG"
    assert t["file_format"] == "PARQUET"


def test_findings_flag_external_catalog_and_external_tables(_ext) -> None:
    titles = {f["title"] for f in _ext["findings"]}
    assert "Iceberg tables on an external catalog" in titles
    assert "External tables query data in place" in titles
    assert _ext["status"] == "ok"


def test_no_account_is_graceful(monkeypatch) -> None:
    from agent_bom.cloud import snowflake as sf

    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    assert sf.discover_snowflake_external_data()["status"] == "no_account"
