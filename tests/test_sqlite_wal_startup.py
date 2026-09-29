"""Concurrent WAL startup retries only lock contention and never caches failure."""

import sqlite3
import threading

import pytest

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore
from agent_bom.api.storage.sql import SQLiteBackend


@pytest.mark.parametrize("store_type", [SQLiteBackend, SQLiteComplianceHubStore])
@pytest.mark.parametrize("code", [sqlite3.SQLITE_BUSY, sqlite3.SQLITE_CORRUPT])
def test_wal_startup_contention_and_failed_connection_cleanup(monkeypatch, store_type, code):
    real_connect = sqlite3.connect
    opened = []

    class Connection:
        def __init__(self):
            self.inner = real_connect(":memory:")
            self.failed = False
            self.closed = False

        def execute(self, statement):
            if statement == "PRAGMA journal_mode=WAL" and not self.failed:
                self.failed = True
                error = sqlite3.OperationalError("injected SQLite startup error")
                error.sqlite_errorcode = code
                raise error
            return self.inner.execute(statement)

        def close(self):
            self.closed = True
            self.inner.close()

    def connect(*args, **kwargs):
        connection = Connection()
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    store = object.__new__(store_type)
    store._local = threading.local()
    store._db_path = "unused"
    store._connection_factory = None

    def get_connection():
        return store._conn() if store_type is SQLiteBackend else store._conn

    if code == sqlite3.SQLITE_BUSY:
        connection = get_connection()
        assert connection.execute("PRAGMA busy_timeout").fetchone() == (30000,)
        assert get_connection() is connection
        connection.close()
    else:
        with pytest.raises(sqlite3.OperationalError, match="injected"):
            get_connection()
        assert opened[0].closed
        assert getattr(store._local, "conn", None) is None


def test_wal_contention_budget_expires_and_closes_connection(monkeypatch):
    from agent_bom.api.storage import sqlite_connection

    class Connection:
        closed = False
        attempts = 0

        def execute(self, statement):
            self.attempts += 1
            error = sqlite3.OperationalError("injected persistent contention")
            error.sqlite_errorcode = sqlite3.SQLITE_BUSY
            raise error

        def close(self):
            self.closed = True

    connection = Connection()
    clock = iter([0.0, 29.0, 30.0])
    sleeps = []
    monkeypatch.setattr(sqlite3, "connect", lambda *args, **kwargs: connection)
    monkeypatch.setattr(sqlite_connection.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(sqlite_connection.time, "sleep", sleeps.append)
    with pytest.raises(sqlite3.OperationalError, match="persistent contention"):
        sqlite_connection.open_wal_connection("unused")
    assert connection.attempts == 2
    assert connection.closed
    assert sleeps == [0.05]
