"""SHOW-based (zero-latency) Snowflake identity discovery + graph wiring.

``ACCOUNT_USAGE.GRANTS_TO_*`` lags 45min-2h; the SHOW path reflects current
state instantly. These tests drive a mock cursor through SHOW ROLES / SHOW
GRANTS TO ROLE / SHOW GRANTS OF ROLE / SHOW USERS and assert the discovery
payload + the USER/ROLE nodes, MEMBER_OF (user->role, role->role) and
HAS_PERMISSION (role->sensitive table) edges the graph builds.
"""

from __future__ import annotations

import sys
import types

import pytest

from agent_bom.graph.builder import build_unified_graph_from_report


@pytest.fixture(autouse=True)
def _stub_snowflake_connector(monkeypatch):
    sf_pkg = sys.modules.get("snowflake") or types.ModuleType("snowflake")
    connector = sys.modules.get("snowflake.connector") or types.ModuleType("snowflake.connector")
    monkeypatch.setitem(sys.modules, "snowflake", sf_pkg)
    monkeypatch.setitem(sys.modules, "snowflake.connector", connector)


# Live account state (the just-created hierarchy that ACCOUNT_USAGE can't see),
# mirroring the real ZV74085 fixture: ALICE_ANALYST / BOB_ENGINEER are *users*.
#   ALICE_ANALYST (user) -> ANALYST       -> PII_READ  -> SELECT CUSTOMERS
#   BOB_ENGINEER  (user) -> DATA_ENGINEER -> PII_WRITE -> INSERT/UPDATE CUSTOMERS
#   DATA_ENGINEER (role) -> ANALYST   (role->role; the engineer also reads)
_CUSTOMERS = "DB.PUBLIC.CUSTOMERS"
# privileges each role holds: object grants + role->role USAGE (parents)
_GRANTS_TO_ROLE: dict[str, list[tuple[str, str, str]]] = {
    # role: [(privilege, granted_on, name), ...]
    "PII_READ": [("SELECT", "TABLE", _CUSTOMERS)],
    "PII_WRITE": [("INSERT", "TABLE", _CUSTOMERS), ("UPDATE", "TABLE", _CUSTOMERS)],
    "ANALYST": [("USAGE", "ROLE", "PII_READ")],
    "DATA_ENGINEER": [("USAGE", "ROLE", "PII_WRITE"), ("USAGE", "ROLE", "ANALYST")],
}
# who each role is granted to: (granted_to, grantee_name)
_GRANTS_OF_ROLE: dict[str, list[tuple[str, str]]] = {
    "ANALYST": [("USER", "ALICE_ANALYST"), ("ROLE", "DATA_ENGINEER")],
    "DATA_ENGINEER": [("USER", "BOB_ENGINEER")],
    "PII_READ": [("ROLE", "ANALYST")],
    "PII_WRITE": [("ROLE", "DATA_ENGINEER")],
}


def _quoted_role(sql: str) -> str:
    # SHOW GRANTS {TO,OF} ROLE "ROLE_NAME"
    return sql.split('"')[1] if '"' in sql else ""


class _FakeCursor:
    def __init__(self) -> None:
        self.description: list | None = None
        self._rows: list = []

    def execute(self, sql, *_a, **_k):
        s = " ".join(sql.split())
        if s.startswith("SHOW ROLES"):
            self.description = [("name",), ("owner",), ("comment",)]
            self._rows = [(r, "USERADMIN", "") for r in _GRANTS_TO_ROLE]
        elif s.startswith("SHOW GRANTS TO ROLE"):
            role = _quoted_role(s)
            self.description = [("privilege",), ("granted_on",), ("name",), ("grantee_name",)]
            self._rows = [(p, g, n, role) for (p, g, n) in _GRANTS_TO_ROLE.get(role, [])]
        elif s.startswith("SHOW GRANTS OF ROLE"):
            role = _quoted_role(s)
            self.description = [("role",), ("granted_to",), ("grantee_name",)]
            self._rows = [(role, gt, gn) for (gt, gn) in _GRANTS_OF_ROLE.get(role, [])]
        elif s.startswith("SHOW USERS"):
            self.description = [("name",), ("default_role",), ("disabled",)]
            self._rows = [("ALICE_ANALYST", "ANALYST", "false"), ("BOB_ENGINEER", "DATA_ENGINEER", "false")]
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
def _live(monkeypatch):
    from agent_bom.cloud import snowflake as sf

    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _FakeConn())
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    return sf.discover_identity_live()


# ── Discovery payload ────────────────────────────────────────────────────


def test_status_ok_and_roles_users_discovered(_live) -> None:
    assert _live["status"] == "ok"
    role_names = {r["name"] for r in _live["roles"]}
    assert {"ANALYST", "DATA_ENGINEER", "PII_READ", "PII_WRITE"} <= role_names
    user_names = {u["name"] for u in _live["users"]}
    assert {"ALICE_ANALYST", "BOB_ENGINEER"} <= user_names
    assert next(u for u in _live["users"] if u["name"] == "ALICE_ANALYST")["default_role"] == "ANALYST"


def test_object_grants_on_sensitive_table(_live) -> None:
    grants = {(g["role"], g["privilege"], g["object_fqn"]) for g in _live["grants"]}
    assert ("PII_READ", "SELECT", _CUSTOMERS) in grants
    assert ("PII_WRITE", "INSERT", _CUSTOMERS) in grants
    assert ("PII_WRITE", "UPDATE", _CUSTOMERS) in grants
    # role->role USAGE must NOT leak into object grants
    assert all(g["object_fqn"] == _CUSTOMERS for g in _live["grants"])


def test_user_and_role_memberships(_live) -> None:
    user_mem = {(m["user"], m["role"]) for m in _live["role_memberships"] if m.get("member_type") == "user"}
    role_mem = {(m["role"], m["parent"]) for m in _live["role_memberships"] if m.get("member_type") == "role"}
    assert ("ALICE_ANALYST", "ANALYST") in user_mem
    assert ("BOB_ENGINEER", "DATA_ENGINEER") in user_mem
    # child -> parent role memberships (both SHOW directions, deduped)
    assert ("ANALYST", "PII_READ") in role_mem
    assert ("DATA_ENGINEER", "PII_WRITE") in role_mem
    assert ("DATA_ENGINEER", "ANALYST") in role_mem


def test_no_account_is_graceful(monkeypatch) -> None:
    from agent_bom.cloud import snowflake as sf

    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    assert sf.discover_identity_live()["status"] == "no_account"


def test_per_role_failure_degrades_to_warning(monkeypatch) -> None:
    from agent_bom.cloud import snowflake as sf

    class _BoomCursor(_FakeCursor):
        def execute(self, sql, *a, **k):
            if "SHOW GRANTS TO ROLE" in sql and "PII_READ" in sql:
                raise RuntimeError("insufficient privileges")
            super().execute(sql, *a, **k)

    class _BoomConn:
        def cursor(self):
            return _BoomCursor()

        def close(self):
            pass

    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _BoomConn())
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    res = sf.discover_identity_live()
    assert res["status"] == "ok"  # never raises into the scan
    assert any("PII_READ" in w for w in res["warnings"])


# ── Merge: live overlay wins over lagged ACCOUNT_USAGE rows ──────────────


def test_merge_prefers_live_and_unions(_live) -> None:
    from agent_bom.cloud import snowflake as sf

    lagged = {
        "status": "ok",
        "account": "acct1",
        "objects": [],
        "dependencies": [],
        # stale grant for a role that no longer has it, plus a still-valid one
        "grants": [{"role": "STALE_ROLE", "privilege": "SELECT", "object_fqn": _CUSTOMERS, "object_type": "table"}],
        "role_memberships": [{"user": "OLD_USER", "role": "STALE_ROLE"}],
    }
    merged = sf.merge_live_identity_into_object_graph(lagged, _live)
    grant_roles = {g["role"] for g in merged["grants"]}
    assert "PII_READ" in grant_roles  # live in
    assert "STALE_ROLE" in grant_roles  # lagged retained (union, not replace-all)
    mem_users = {m.get("user") for m in merged["role_memberships"]}
    assert "ALICE_ANALYST" in mem_users and "OLD_USER" in mem_users
    assert {u["name"] for u in merged["users"]} >= {"ALICE_ANALYST", "BOB_ENGINEER"}


# ── Graph build: USER/ROLE nodes + MEMBER_OF + HAS_PERMISSION ────────────


def _graph(_live):
    report = {"snowflake_object_graph": {**_live, "objects": [], "dependencies": []}}
    g = build_unified_graph_from_report(report)
    edges = list(g.edges.values()) if isinstance(g.edges, dict) else list(g.edges)
    return g, edges


def test_graph_user_and_role_nodes(_live) -> None:
    g, _ = _graph(_live)
    for role in ("ANALYST", "PII_READ", "PII_WRITE", "DATA_ENGINEER"):
        assert f"role:snowflake:{role}" in g.nodes
    assert "user:snowflake:ALICE_ANALYST" in g.nodes
    assert "user:snowflake:BOB_ENGINEER" in g.nodes


def test_graph_member_of_edges(_live) -> None:
    g, edges = _graph(_live)
    member_of = {(e.source, e.target) for e in edges if e.relationship.value == "member_of"}
    # user -> role
    assert ("user:snowflake:ALICE_ANALYST", "role:snowflake:ANALYST") in member_of
    assert ("user:snowflake:BOB_ENGINEER", "role:snowflake:DATA_ENGINEER") in member_of
    # role -> role (child assumes-member-of parent)
    assert ("role:snowflake:ANALYST", "role:snowflake:PII_READ") in member_of
    assert ("role:snowflake:DATA_ENGINEER", "role:snowflake:ANALYST") in member_of


def test_graph_role_has_permission_on_sensitive_table(_live) -> None:
    g, edges = _graph(_live)
    has_perm = {(e.source, e.target) for e in edges if e.relationship.value == "has_permission"}
    assert ("role:snowflake:PII_READ", f"data_store:snowflake:{_CUSTOMERS}") in has_perm
    assert ("role:snowflake:PII_WRITE", f"data_store:snowflake:{_CUSTOMERS}") in has_perm
