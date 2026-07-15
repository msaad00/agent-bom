"""Postgres graph snapshot retention purge (pre-release scale hardening).

The SQLite backend purges expired snapshots on every save; the Postgres backend
previously committed with no retention delete, so snapshot history grew
unbounded. These tests pin the mirrored age-based purge on the Postgres path.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

RECENT = datetime.now(timezone.utc).isoformat()
OLD = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()


class _FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.rowcount = len(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class _FakeConn:
    """Minimal Postgres connection just rich enough to exercise the purge.

    Tracks ``graph_snapshots`` as ``{(tenant, scan_id): created_at}`` and records
    every DELETE the purge issues so tests can assert child-row cascades.
    """

    def __init__(self, snapshots):
        # snapshots: dict[(tenant, scan_id)] -> created_at iso string
        self.snapshots = dict(snapshots)
        self.deletes: list[tuple[str, tuple]] = []
        self.committed = 0
        self.rolled_back = 0

    # context-manager protocol used by pool.connection()
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        low = " ".join(sql.strip().lower().split())
        if low.startswith("select scan_id, created_at from graph_snapshots where tenant_id"):
            tenant = params[0]
            rows = [(scan, ts) for (t, scan), ts in self.snapshots.items() if t == tenant]
            return _FakeCursor(rows)
        if low.startswith("insert into graph_snapshots"):
            scan, tenant, created = params[0], params[1], params[2]
            self.snapshots[(tenant, scan)] = created
            return _FakeCursor()
        # previous-snapshot / latest lookups etc. — behave as empty history
        return _FakeCursor()

    def executemany(self, sql, seq):
        low = " ".join(sql.strip().lower().split())
        rows = list(seq)
        if low.startswith("delete from"):
            table = low.split()[2]
            for params in rows:
                self.deletes.append((table, tuple(params)))
                if table == "graph_snapshots":
                    tenant, scan = params
                    self.snapshots.pop((tenant, scan), None)
        return _FakeCursor(rows)

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1


class _FakePool:
    def __init__(self, conn):
        self._conn = conn

    def connection(self):
        return self._conn


def _make_store(conn, monkeypatch):
    from agent_bom.api import postgres_graph

    # Skip the schema/DDL bootstrap; we only exercise the purge method.
    monkeypatch.setattr(postgres_graph.PostgresGraphStore, "_init_tables", lambda self: None)
    monkeypatch.setattr(postgres_graph.PostgresGraphStore, "_init_optional_search_indexes", lambda self: None)
    return postgres_graph.PostgresGraphStore(pool=_FakePool(conn))


def test_purge_deletes_expired_and_keeps_recent(monkeypatch) -> None:
    conn = _FakeConn(
        {
            ("acme", "old"): OLD,
            ("acme", "recent"): RECENT,
        }
    )
    store = _make_store(conn, monkeypatch)

    store._purge_expired_snapshots(conn, "acme")

    assert ("acme", "old") not in conn.snapshots
    assert ("acme", "recent") in conn.snapshots
    # Every child table plus the snapshot row is purged for the expired scan.
    purged_tables = {table for table, _ in conn.deletes}
    assert purged_tables == set(postgres_purge_tables())
    for table in postgres_purge_tables():
        assert (table, ("acme", "old")) in conn.deletes
    assert conn.committed >= 1


def test_purge_scoped_to_tenant(monkeypatch) -> None:
    conn = _FakeConn(
        {
            ("acme", "old"): OLD,
            ("other", "old-other"): OLD,
        }
    )
    store = _make_store(conn, monkeypatch)

    store._purge_expired_snapshots(conn, "acme")

    # Only the saving tenant's expired snapshot is touched; the other tenant's
    # equally-old snapshot is never selected or deleted.
    assert ("acme", "old") not in conn.snapshots
    assert ("other", "old-other") in conn.snapshots
    assert all(params[0] == "acme" for _, params in conn.deletes)


def test_purge_is_best_effort_on_error(monkeypatch) -> None:
    conn = _FakeConn({("acme", "old"): OLD})
    store = _make_store(conn, monkeypatch)

    def _boom(sql, seq):
        raise RuntimeError("simulated /secret/path failure")

    monkeypatch.setattr(conn, "executemany", _boom)

    # Must not raise; rolls back the failed purge.
    store._purge_expired_snapshots(conn, "acme")
    assert conn.rolled_back >= 1


def test_purge_retains_unparseable_timestamps(monkeypatch) -> None:
    conn = _FakeConn({("acme", "junk"): "not-a-timestamp"})
    store = _make_store(conn, monkeypatch)

    store._purge_expired_snapshots(conn, "acme")

    assert ("acme", "junk") in conn.snapshots
    assert conn.deletes == []


def postgres_purge_tables():
    from agent_bom.api.postgres_graph import _GRAPH_RETENTION_PURGE_TABLES

    return _GRAPH_RETENTION_PURGE_TABLES


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
