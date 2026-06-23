"""Snowflake integrations: discovery parsing + graph external-trust nodes."""

from __future__ import annotations

import sys
import types

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report


# ── Graph ────────────────────────────────────────────────────────────────
def _report() -> dict:
    return {
        "snowflake_integrations": {
            "status": "ok",
            "account": "acct1",
            "integrations": [
                {"name": "S3_STORE", "type": "EXTERNAL_STAGE", "category": "STORAGE", "enabled": True, "comment": ""},
                {"name": "UDF_EGRESS", "type": "EXTERNAL_ACCESS", "category": "EXTERNAL_ACCESS", "enabled": True, "comment": ""},
                {"name": "OKTA_SSO", "type": "SAML2", "category": "SECURITY", "enabled": True, "comment": ""},
                {"name": "OLD_API", "type": "API", "category": "API", "enabled": False, "comment": ""},
            ],
        }
    }


def _build():
    g = build_unified_graph_from_report(_report())
    return g, {(e.source, e.target, e.relationship.value) for e in g.edges}


def test_integrations_become_account_owned_nodes() -> None:
    g, edges = _build()
    assert "cloud_resource:snowflake:integration:S3_STORE" in g.nodes
    assert ("account:snowflake:acct1", "cloud_resource:snowflake:integration:S3_STORE", "owns") in edges


def test_external_access_flagged() -> None:
    g, _ = _build()
    n = g.nodes["cloud_resource:snowflake:integration:UDF_EGRESS"]
    assert n.attributes["external_access"] is True
    assert n.attributes["internet_exposed"] is True


def test_security_integration_marks_federation() -> None:
    g, _ = _build()
    assert g.nodes["cloud_resource:snowflake:integration:OKTA_SSO"].attributes["identity_federation"] is True


def test_disabled_integration_not_internet_exposed() -> None:
    g, _ = _build()
    assert g.nodes["cloud_resource:snowflake:integration:OLD_API"].attributes["internet_exposed"] is False


def test_non_ok_payload_is_noop() -> None:
    g = build_unified_graph_from_report({"snowflake_integrations": {"status": "no_account"}})
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
        if "SHOW INTEGRATIONS" in " ".join(sql.split()):
            self.description = [("name",), ("type",), ("category",), ("enabled",), ("comment",)]
            self._rows = [
                ("S3_STORE", "EXTERNAL_STAGE", "STORAGE", "true", ""),
                ("UDF_EGRESS", "EXTERNAL_ACCESS", "EXTERNAL_ACCESS", "true", "outbound"),
                ("OKTA_SSO", "SAML2", "SECURITY", "true", ""),
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


def test_discovery_parses_and_flags(monkeypatch) -> None:
    from agent_bom.cloud import snowflake as sf

    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _FakeConn())
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    out = sf.discover_snowflake_integrations()
    assert {i["name"] for i in out["integrations"]} == {"S3_STORE", "UDF_EGRESS", "OKTA_SSO"}
    titles = {f["title"] for f in out["findings"]}
    assert "External-access integrations enabled" in titles
    assert "External identity federation configured" in titles
    assert out["status"] == "ok"


def test_no_account_is_graceful(monkeypatch) -> None:
    from agent_bom.cloud import snowflake as sf

    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    assert sf.discover_snowflake_integrations()["status"] == "no_account"
