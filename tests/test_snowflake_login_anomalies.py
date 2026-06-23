"""Snowflake login-anomaly detection — impossible travel, distinct IPs, failed bursts."""

from __future__ import annotations

import agent_bom.cloud.snowflake as sf


class _FakeCursor:
    def __init__(self, per_user, impossible):
        self._per_user = per_user
        self._impossible = impossible
        self._rows: list = []
        self.description: list = []

    def execute(self, sql: str):
        if "LAG(" in sql or "rapid_switches" in sql:
            self.description = [("user_name",), ("rapid_switches",)]
            self._rows = self._impossible
        else:
            self.description = [("user_name",), ("distinct_ips",), ("logins",), ("failed",)]
            self._rows = self._per_user

    def fetchall(self):
        return self._rows

    def close(self):
        pass


class _FakeConn:
    def __init__(self, per_user, impossible):
        self._per_user, self._impossible = per_user, impossible

    def cursor(self):
        return _FakeCursor(self._per_user, self._impossible)

    def close(self):
        pass


def test_detects_impossible_travel_and_bursts(monkeypatch) -> None:
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    per_user = [("GRC_INGEST", 50, 78, 0), ("WSAAD", 2, 20, 5)]  # high-IP user + failed-burst admin
    impossible = [("GRC_INGEST", 4)]  # 4 rapid IP switches
    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _FakeConn(per_user, impossible))
    r = sf.discover_login_anomalies(days=30)
    assert r["status"] == "ok"
    assert r["impossible_travel"] == [{"user": "GRC_INGEST", "rapid_switches": 4}]
    assert {"user": "WSAAD", "failed": 5} in r["failed_bursts"]
    titles = {f["title"] for f in r["findings"]}
    assert "Possible impossible travel" in titles
    assert "High distinct source-IP count" in titles  # GRC_INGEST 50 > 20
    assert "Failed-login burst" in titles


def test_no_anomalies_no_findings(monkeypatch) -> None:
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "acct1")
    monkeypatch.setattr(sf, "_get_connection", lambda *a, **k: _FakeConn([("SVC", 1, 10, 0)], []))
    r = sf.discover_login_anomalies()
    assert r["status"] == "ok"
    assert r["findings"] == []


def test_no_account_returns_no_account(monkeypatch) -> None:
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    r = sf.discover_login_anomalies()
    assert r["status"] == "no_account"
