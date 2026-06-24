"""discover_auth_posture parses network policies + per-user auth matrix offline."""

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
    def __init__(self, account_np):
        self._account_np = account_np
        self.description = None
        self._rows: list = []

    def execute(self, sql, *_a, **_k):
        s = " ".join(sql.split())
        if "PARAMETERS LIKE 'NETWORK_POLICY'" in s:
            self.description = [("key",), ("value",)]
            self._rows = [("NETWORK_POLICY", self._account_np)]
        elif "SHOW NETWORK POLICIES" in s:
            self.description = [("name",), ("entries_in_allowed_ip_list",), ("entries_in_blocked_ip_list",)]
            self._rows = [("CORP_POLICY", 3, 1)]
        elif "ACCOUNT_USAGE.USERS" in s:
            self.description = [
                ("name",),
                ("disabled",),
                ("has_password",),
                ("has_rsa_public_key",),
                ("ext_authn_duo",),
                ("default_role",),
                ("type",),
                ("has_mfa",),
            ]
            self._rows = [
                # human, password, no MFA → weak
                ("WSAAD", False, True, False, False, "ANALYST", "PERSON", False),
                # human, password, Duo MFA → ok
                ("ALICE", False, True, False, True, "ANALYST", "PERSON", False),
                # service, key-pair, no MFA → not weak
                ("SVC_PIPE", False, False, True, False, "INGEST", "SERVICE", False),
                # disabled → ignored
                ("OLD_USER", True, True, False, False, "PUBLIC", "PERSON", False),
                # human, password, no MFA, EMPTY type column → must still be flagged
                # (live regression: empty type defaulted to lowercase "unknown" and
                # the uppercase "UNKNOWN" filter missed it — an ACCOUNTADMIN slipped through)
                ("ADMIN_X", False, True, False, False, "ACCOUNTADMIN", "", False),
            ]
        else:
            self.description = []
            self._rows = []

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class _FakeConn:
    def __init__(self, account_np):
        self._account_np = account_np

    def cursor(self):
        return _FakeCursor(self._account_np)

    def close(self):
        pass


def _run(monkeypatch, account_np=""):
    from agent_bom.cloud import snowflake as sf

    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _FakeConn(account_np))
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    return sf.discover_auth_posture()


def test_user_auth_matrix(monkeypatch) -> None:
    out = _run(monkeypatch)
    by = {u["name"]: u for u in out["users"]}
    assert by["WSAAD"]["auth_methods"] == ["password"] and by["WSAAD"]["has_mfa"] is False
    assert by["ALICE"]["has_mfa"] is True
    assert by["SVC_PIPE"]["auth_methods"] == ["key_pair"]
    assert by["OLD_USER"]["disabled"] is True


def test_network_policies_parsed(monkeypatch) -> None:
    out = _run(monkeypatch, account_np="")
    assert out["network_policies"][0]["name"] == "CORP_POLICY"
    assert out["network_policies"][0]["allowed_ip_count"] == 3


def test_no_account_network_policy_is_a_finding(monkeypatch) -> None:
    out = _run(monkeypatch, account_np="")
    titles = {f["title"] for f in out["findings"]}
    assert "No account-level network policy" in titles


def test_password_user_without_mfa_flagged_excludes_service_and_disabled(monkeypatch) -> None:
    out = _run(monkeypatch, account_np="CORP_POLICY")  # set account policy so only the MFA finding remains
    mfa_findings = [f for f in out["findings"] if f["title"] == "Password users without MFA"]
    assert mfa_findings, "expected an MFA finding"
    # WSAAD (PERSON) + ADMIN_X (empty type) qualify; ALICE has MFA, SVC_PIPE is
    # service, OLD_USER disabled. The empty-type user must NOT be missed.
    assert "2 enabled human user" in mfa_findings[0]["detail"]
    assert out["status"] == "ok"


def test_account_policy_present_suppresses_network_finding(monkeypatch) -> None:
    out = _run(monkeypatch, account_np="CORP_POLICY")
    assert out["account_network_policy"] == "CORP_POLICY"
    assert "No account-level network policy" not in {f["title"] for f in out["findings"]}


def test_no_account_is_graceful(monkeypatch) -> None:
    from agent_bom.cloud import snowflake as sf

    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    assert sf.discover_auth_posture()["status"] == "no_account"
