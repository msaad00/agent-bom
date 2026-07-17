from __future__ import annotations

from agent_bom.api.connection_store import CloudConnectionRecord
from agent_bom.api.postgres_connection import PostgresConnectionStore


class _Cursor:
    def __init__(self, rows=()):
        self._rows = list(rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class _Connection:
    def __init__(self, state):
        self.state = state

    def execute(self, sql, params=None):
        normalized = " ".join(sql.lower().split())
        params = tuple(params or ())
        if normalized.startswith("insert into cloud_connections"):
            self.state[params[0]] = params
        elif normalized.startswith("select id, tenant_id"):
            row = self.state.get(params[1])
            return _Cursor([row] if row and row[1] == params[0] else [])
        return _Cursor()

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass


class _Pool:
    def __init__(self):
        self.state = {}

    def connection(self):
        return _Connection(self.state)


def test_last_scan_id_round_trips_through_postgres(monkeypatch):
    pool = _Pool()
    monkeypatch.setattr("agent_bom.api.postgres_connection._tenant_connection", lambda _pool: pool.connection())
    store = PostgresConnectionStore(pool=pool)
    record = CloudConnectionRecord(
        id="conn-1",
        tenant_id="acme",
        provider="aws",
        display_name="Production",
        role_ref="arn:aws:iam::123:role/read-only",
        external_id_encrypted="",
        created_at="2026-07-17T00:00:00Z",
        updated_at="2026-07-17T00:00:01Z",
        last_scan_at="2026-07-17T00:00:02Z",
        last_scan_id="scan-123",
    )

    store.put(record)

    restored = store.get("acme", "conn-1")
    assert restored is not None
    assert restored.last_scan_id == "scan-123"
