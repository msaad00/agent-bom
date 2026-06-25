"""Snowflake Organization → Accounts roll-up + the graph CONTAINS backbone.

The Snowflake analogue of the GCP/AWS organization tests: multiple accounts roll
up under a parent ORG node via CONTAINS. Covers the discovery degradation paths
(disabled flag, missing ORGADMIN, standalone account) and the graph mapping,
plus the cross-cutting guarantees: deterministic ids, injected timestamps, and
idempotency.
"""

from __future__ import annotations

import sys
import types

import pytest

from agent_bom.cloud import snowflake as sf
from agent_bom.graph.builder import _add_snowflake_organization, build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType

# ── Discovery offline harness ───────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _stub_snowflake_connector(monkeypatch):
    sf_pkg = sys.modules.get("snowflake") or types.ModuleType("snowflake")
    connector = sys.modules.get("snowflake.connector") or types.ModuleType("snowflake.connector")
    monkeypatch.setitem(sys.modules, "snowflake", sf_pkg)
    monkeypatch.setitem(sys.modules, "snowflake.connector", connector)


class _OrgCursor:
    """Cursor that returns a two-account organization for SHOW ORGANIZATION ACCOUNTS."""

    def __init__(self, *, rows=None, raise_exc=None):
        self.description = None
        self._rows = rows if rows is not None else []
        self._raise = raise_exc

    def execute(self, sql, *_a, **_k):
        if "SHOW ORGANIZATION ACCOUNTS" in " ".join(sql.split()):
            if self._raise is not None:
                raise self._raise
            self.description = [
                ("organization_name",),
                ("account_name",),
                ("account_locator",),
                ("snowflake_region",),
                ("edition",),
                ("is_org_admin",),
            ]
        else:
            self.description = []
            self._rows = []

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class _OrgConn:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def close(self):
        pass


def _two_account_rows():
    return [
        ("ACME", "PROD", "ABC11111", "AWS_US_EAST_1", "ENTERPRISE", "Y"),
        ("ACME", "DEV", "ABC22222", "AWS_US_WEST_2", "STANDARD", "N"),
    ]


def _ok_payload() -> dict:
    return {
        "status": "ok",
        "org_name": "ACME",
        "accounts": [
            {"locator": "ABC11111", "name": "PROD", "region": "AWS_US_EAST_1", "edition": "ENTERPRISE", "is_org_admin": True},
            {"locator": "ABC22222", "name": "DEV", "region": "AWS_US_WEST_2", "edition": "STANDARD", "is_org_admin": False},
        ],
        "findings": [],
        "warnings": [],
        "discovered_at": "2026-06-25T00:00:00Z",
    }


# ── Discovery: gating + degradation ─────────────────────────────────────────


def test_disabled_when_flag_off(monkeypatch) -> None:
    monkeypatch.delenv(sf.ORG_ENV_FLAG, raising=False)
    out = sf.discover_organization()
    assert out["status"] == "disabled"
    assert out["accounts"] == []


def test_not_authorized_when_role_lacks_orgadmin_noops(monkeypatch) -> None:
    # SHOW ORGANIZATION ACCOUNTS raising an ORGADMIN privilege error must degrade
    # to a clear status with actionable guidance — never crash the scan.
    err = Exception("SQL access control error: Insufficient privileges to operate on ORGANIZATION (ORGADMIN required)")
    cur = _OrgCursor(raise_exc=err)
    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _OrgConn(cur))
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ABC11111")
    out = sf.discover_organization(force=True)
    assert out["status"] == "not_authorized"
    assert out["accounts"] == []
    assert any("ORGADMIN" in w for w in out["warnings"])
    assert out["discovery_envelope"] is None


def test_not_in_org_when_no_accounts(monkeypatch) -> None:
    cur = _OrgCursor(rows=[])
    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _OrgConn(cur))
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ABC11111")
    out = sf.discover_organization(force=True)
    assert out["status"] == "not_in_org"


def test_missing_account_degrades_not_in_org(monkeypatch) -> None:
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    out = sf.discover_organization(force=True)
    assert out["status"] == "not_in_org"


def test_ok_discovery_parses_accounts_and_findings(monkeypatch) -> None:
    cur = _OrgCursor(rows=_two_account_rows())
    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _OrgConn(cur))
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ABC11111")
    out = sf.discover_organization(force=True, now="2026-06-25T00:00:00Z")
    assert out["status"] == "ok"
    assert out["org_name"] == "ACME"
    locators = {a["locator"] for a in out["accounts"]}
    assert locators == {"ABC11111", "ABC22222"}
    assert out["discovered_at"] == "2026-06-25T00:00:00Z"
    assert out["discovery_envelope"] is not None
    titles = {f["title"] for f in out["findings"]}
    assert "Multi-account Snowflake organization" in titles


def test_injected_now_is_used_no_wallclock(monkeypatch) -> None:
    # The discoverer never reads wall-clock inline: the injected `now` flows
    # through verbatim, and absent `now` the stamp is empty (deterministic).
    cur = _OrgCursor(rows=_two_account_rows())
    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _OrgConn(cur))
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ABC11111")
    out = sf.discover_organization(force=True)
    assert out["discovered_at"] == ""


# ── Graph builder: CONTAINS hierarchy + idempotency ─────────────────────────


def test_builder_builds_org_contains_accounts() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    _add_snowflake_organization(g, _ok_payload(), "test")

    org = g.nodes.get("org:snowflake:ACME")
    assert org is not None and org.entity_type == EntityType.ORG

    # Accounts reuse the same account:snowflake:<locator> id the rest of the
    # Snowflake graph emits, so the org backbone stitches onto inventoried graphs.
    assert "account:snowflake:ABC11111" in g.nodes
    assert "account:snowflake:ABC22222" in g.nodes

    contains = {(e.source, e.target) for e in g.edges if e.relationship == RelationshipType.CONTAINS}
    assert ("org:snowflake:ACME", "account:snowflake:ABC11111") in contains
    assert ("org:snowflake:ACME", "account:snowflake:ABC22222") in contains


def test_builder_deterministic_ids() -> None:
    g1 = UnifiedGraph(scan_id="s", tenant_id="t")
    g2 = UnifiedGraph(scan_id="s2", tenant_id="t2")
    _add_snowflake_organization(g1, _ok_payload(), "test")
    _add_snowflake_organization(g2, _ok_payload(), "test")
    assert set(g1.nodes) == set(g2.nodes)


def test_builder_idempotent_double_apply() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    _add_snowflake_organization(g, _ok_payload(), "test")
    nodes_after_first = set(g.nodes)
    edges_after_first = {(e.source, e.target, e.relationship) for e in g.edges}
    _add_snowflake_organization(g, _ok_payload(), "test")
    assert set(g.nodes) == nodes_after_first
    assert {(e.source, e.target, e.relationship) for e in g.edges} == edges_after_first


def test_builder_non_ok_payload_is_noop() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    _add_snowflake_organization(g, {"status": "not_authorized"}, "test")
    _add_snowflake_organization(g, {"status": "ok", "accounts": []}, "test")
    _add_snowflake_organization(g, None, "test")
    assert len(g.nodes) == 0


def test_single_account_graph_unchanged_without_org() -> None:
    # A services-only report (no organization sub-key) graphs exactly as today:
    # the account stays the root with no ORG node and no CONTAINS-from-org edge.
    report = {
        "snowflake_services": {
            "status": "ok",
            "account": "ABC11111",
            "warehouses": [{"name": "WH", "size": "X-SMALL", "state": "STARTED", "auto_suspend": 60}],
            "databases": [{"name": "DB", "owner": "SYSADMIN", "retention_time": 1}],
            "schemas": [],
        }
    }
    g = build_unified_graph_from_report(report)
    assert not any(n.startswith("org:snowflake:") for n in g.nodes)
    assert "account:snowflake:ABC11111" in g.nodes
    org_contains = [e for e in g.edges if e.relationship == RelationshipType.CONTAINS and e.source.startswith("org:snowflake:")]
    assert org_contains == []


def test_builder_via_report_org_parents_account() -> None:
    # End-to-end: org payload carried on the services payload parents the account.
    report = {
        "snowflake_services": {
            "status": "ok",
            "account": "ABC11111",
            "warehouses": [],
            "databases": [{"name": "DB", "owner": "SYSADMIN", "retention_time": 1}],
            "schemas": [],
            "organization": _ok_payload(),
        }
    }
    g = build_unified_graph_from_report(report)
    assert "org:snowflake:ACME" in g.nodes
    contains = {(e.source, e.target) for e in g.edges if e.relationship == RelationshipType.CONTAINS}
    assert ("org:snowflake:ACME", "account:snowflake:ABC11111") in contains
