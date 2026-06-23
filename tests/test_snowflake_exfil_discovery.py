"""discover_data_exfil parses shares/stages/sensitive objects without a live account."""

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
    def __init__(self, conn):
        self._conn = conn
        self.description = None
        self._rows: list = []

    def execute(self, sql, *_a, **_k):
        s = " ".join(sql.split())
        if "SHOW SHARES" in s:
            self.description = [("name",), ("kind",), ("database_name",), ("to",), ("listing_global_name",)]
            self._rows = [
                ("PARTNER_SHARE", "OUTBOUND", "DB", "ORG2.ACCT9", ""),
                ("PUBLIC_LISTING", "OUTBOUND", "DB", "", "GLOBAL.LISTING"),
                ("INBOUND_FROM_VENDOR", "INBOUND", "VDB", "", ""),
            ]
        elif "SHOW STAGES" in s:
            self.description = [("name",), ("database_name",), ("schema_name",), ("url",)]
            self._rows = [
                ("EXPORT_STAGE", "DB", "PUBLIC", "s3://acme-exports/dump/"),
                ("AZ_STAGE", "DB", "PUBLIC", "azure://acct.blob.core.windows.net/c"),
                ("INTERNAL_STAGE", "DB", "PUBLIC", ""),  # internal — no scheme, skipped
            ]
        elif "POLICY_REFERENCES" in s:
            self.description = [("ref_database_name",), ("ref_schema_name",), ("ref_entity_name",)]
            self._rows = [("DB", "PUBLIC", "PAYMENTS")]
        elif "TAG_REFERENCES" in s:
            self.description = [("object_database",), ("object_schema",), ("object_name",), ("tags",), ("cols",)]
            self._rows = [
                ("DB", "PUBLIC", "CUSTOMERS", 2, 3),
                ("DB", "PUBLIC", "PAYMENTS", 1, 1),
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
        return _FakeCursor(self)

    def close(self):
        pass


@pytest.fixture
def _exfil(monkeypatch):
    from agent_bom.cloud import snowflake as sf

    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _FakeConn())
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    return sf.discover_data_exfil()


def test_only_outbound_shares_returned(_exfil) -> None:
    names = {s["share_name"] for s in _exfil["outbound_shares"]}
    assert names == {"PARTNER_SHARE", "PUBLIC_LISTING"}  # inbound excluded
    by_name = {s["share_name"]: s for s in _exfil["outbound_shares"]}
    assert by_name["PARTNER_SHARE"]["consumers"] == ["ORG2.ACCT9"]
    assert by_name["PUBLIC_LISTING"]["is_marketplace"] is True


def test_external_stages_parse_cloud_and_bucket(_exfil) -> None:
    by_name = {s["stage_name"]: s for s in _exfil["external_stages"]}
    assert "INTERNAL_STAGE" not in by_name  # no scheme → skipped
    assert by_name["EXPORT_STAGE"]["cloud_provider"] == "aws"
    assert by_name["EXPORT_STAGE"]["bucket"] == "acme-exports"
    assert by_name["AZ_STAGE"]["cloud_provider"] == "azure"


def test_sensitive_objects_masking_coverage(_exfil) -> None:
    by_fqn = {o["fqn"]: o for o in _exfil["sensitive_objects"]}
    assert by_fqn["DB.PUBLIC.PAYMENTS"]["is_protected"] is True  # has masking policy
    assert by_fqn["DB.PUBLIC.CUSTOMERS"]["is_protected"] is False


def test_findings_flag_unprotected_and_marketplace(_exfil) -> None:
    titles = {f["title"] for f in _exfil["findings"]}
    assert "Outbound data share" in titles
    assert "External stage (exfil destination)" in titles
    assert "Unprotected sensitive data" in titles
    assert _exfil["status"] == "ok"


def test_no_account_is_graceful(monkeypatch) -> None:
    from agent_bom.cloud import snowflake as sf

    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    out = sf.discover_data_exfil()
    assert out["status"] == "no_account"
