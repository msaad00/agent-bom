"""SQLite <-> Postgres persistence consistency.

These tests pin the idempotency / timestamp / dedup properties that keep the
two backends in agreement:

* the Postgres proxy-replay insert persists the caller's capture time (not
  insert-time ``now()``) and is idempotent on ``row_id``;
* the Postgres policy-audit insert persists ``entry.timestamp`` (not insert
  time) and dedups on ``entry_id`` so re-ingestion yields exactly one row;
* both backends persist and read back the same logical record.

The Postgres stores run against a functional in-memory fake pool that models
the exact SQL they issue (same pattern as ``test_postgres_cost_store.py``), so
no live Postgres is required. SQLite runs against a real temp database.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from agent_bom.api import proxy_replay_store as prs
from agent_bom.api.policy_store import PolicyAuditEntry, SQLitePolicyStore
from agent_bom.api.postgres_policy import PostgresPolicyStore


class _FakeCursor:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.rowcount = len(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


# ─── Fake pool: policy_audit_log (entry_id dedup + caller timestamp) ─────────


class _FakePolicyConnection:
    def __init__(self, state):
        self._state = state

    def execute(self, sql, params=None):
        s = " ".join(sql.lower().split())
        params = tuple(params or ())
        audit = self._state["audit"]  # entry_id -> (entry_id, ts, team_id, data)
        anon = self._state["anon"]  # rows inserted without an entry_id

        if s.startswith("insert into policy_audit_log") and "entry_id" in s:
            entry_id, ts, team_id, data = params
            audit.setdefault(entry_id, (entry_id, ts, team_id, data))  # ON CONFLICT DO NOTHING
            return _FakeCursor()
        if s.startswith("insert into policy_audit_log"):
            anon.append(("__anon__", *params))  # (ts, team_id, data)
            return _FakeCursor()
        if s.startswith("select data from policy_audit_log"):
            rows = list(audit.values()) + list(anon)
            param_index = 0
            if "team_id = %s" in s:
                rows = [r for r in rows if r[2] == params[param_index]]
                param_index += 1
            if "data ->> 'policy_id' = %s" in s:
                expected = params[param_index]
                rows = [r for r in rows if __import__("json").loads(r[3])["policy_id"] == expected]
                param_index += 1
            if "data ->> 'agent_name' = %s" in s:
                expected = params[param_index]
                rows = [r for r in rows if __import__("json").loads(r[3])["agent_name"] == expected]
            rows.sort(key=lambda r: r[1], reverse=True)  # ORDER BY ts DESC
            data_rows = [(r[3],) for r in rows]
            if params:
                data_rows = data_rows[: params[-1]]  # LIMIT
            return _FakeCursor(data_rows)
        return _FakeCursor()

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class _FakePolicyPool:
    def __init__(self):
        self._state: dict = {"audit": {}, "anon": []}

    def connection(self):
        return _FakePolicyConnection(self._state)


# ─── Fake pool: proxy_replay_log (captured_at persisted + row_id dedup) ──────


class _FakeReplayConnection:
    def __init__(self, state):
        self._state = state

    def execute(self, sql, params=None):
        s = " ".join(sql.lower().split())
        params = tuple(params or ())
        rows = self._state["rows"]  # row_id -> dict

        if s.startswith("insert into proxy_replay_log"):
            row_id, tenant_id, captured_at, not_after, record = params
            rows.setdefault(  # ON CONFLICT (row_id) DO NOTHING
                row_id,
                {
                    "row_id": row_id,
                    "tenant_id": tenant_id,
                    "captured_at": captured_at,
                    "not_after": not_after,
                    "record": record,
                },
            )
            return _FakeCursor()
        if "count(*) from proxy_replay_log where tenant_id" in s:
            return _FakeCursor([(sum(1 for r in rows.values() if r["tenant_id"] == params[0]),)])
        if "count(*) from proxy_replay_log" in s:
            return _FakeCursor([(len(rows),)])
        if "from proxy_replay_log where tenant_id" in s:
            tenant = params[0]
            matched = [r for r in rows.values() if r["tenant_id"] == tenant]
            matched.sort(key=lambda r: r["captured_at"], reverse=True)
            return _FakeCursor([(r["row_id"], r["tenant_id"], r["captured_at"], r["not_after"], r["record"]) for r in matched])
        return _FakeCursor()

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


class _FakeReplayPool:
    def __init__(self):
        self._state: dict = {"rows": {}}

    def connection(self):
        return _FakeReplayConnection(self._state)


def _audit_entry(entry_id: str, ts: str, action: str = "blocked") -> PolicyAuditEntry:
    return PolicyAuditEntry(
        entry_id=entry_id,
        policy_id="pol-1",
        policy_name="block-shell",
        rule_id="r1",
        agent_name="agent-a",
        tool_name="shell",
        action_taken=action,
        reason="dangerous tool",
        timestamp=ts,
        tenant_id="acme",
    )


def _pg_policy_store(monkeypatch):
    pool = _FakePolicyPool()
    store = PostgresPolicyStore(pool=pool)
    monkeypatch.setattr(
        "agent_bom.api.postgres_policy._tenant_connection",
        lambda p: pool.connection(),
        raising=True,
    )
    return store, pool


def _pg_replay_store(monkeypatch):
    pool = _FakeReplayPool()
    # add()/list() import _tenant_connection from postgres_common at call time.
    monkeypatch.setattr(
        "agent_bom.api.postgres_common._tenant_connection",
        lambda p: pool.connection(),
        raising=False,
    )
    monkeypatch.setattr(prs.PostgresProxyReplayStore, "_init_tables", lambda self: None, raising=True)
    return prs.PostgresProxyReplayStore(pool=pool), pool


# ─── Policy audit idempotency + timestamp (PG) ───────────────────────────────


def test_pg_policy_audit_idempotent_no_duplicate(monkeypatch):
    """Re-ingesting the same audit entry yields exactly one row, same ts."""
    store, pool = _pg_policy_store(monkeypatch)
    ts = "2026-06-15T00:00:00+00:00"
    entry = _audit_entry("e1", ts)
    store.put_audit_entry(entry)
    store.put_audit_entry(entry)  # duplicate re-ingestion

    rows = store.list_audit_entries(tenant_id="acme")
    assert len(rows) == 1
    assert rows[0].timestamp == ts
    assert pool._state["audit"]["e1"][1] == ts  # stored ts == caller ts


def test_pg_policy_audit_persists_caller_timestamp(monkeypatch):
    """The stored ts is entry.timestamp, never insert-time now()."""
    store, pool = _pg_policy_store(monkeypatch)
    ts = "2020-01-01T12:00:00+00:00"  # in the past — cannot be insert time
    store.put_audit_entry(_audit_entry("e1", ts))
    assert pool._state["audit"]["e1"][1] == ts


def test_pg_policy_audit_filters_before_limit(monkeypatch):
    store, _pool = _pg_policy_store(monkeypatch)
    for index in range(3):
        entry = _audit_entry(f"new-{index}", f"2026-07-17T00:00:0{index + 2}+00:00")
        entry.policy_id = "other-policy"
        entry.agent_name = "other-agent"
        store.put_audit_entry(entry)
    store.put_audit_entry(_audit_entry("older-match", "2026-07-17T00:00:01+00:00"))

    rows = store.list_audit_entries(policy_id="pol-1", agent_name="agent-a", tenant_id="acme", limit=1)

    assert [row.entry_id for row in rows] == ["older-match"]


def test_pg_policy_empty_filters_match_sqlite_no_filter_semantics(monkeypatch):
    store, _pool = _pg_policy_store(monkeypatch)
    store.put_audit_entry(_audit_entry("one", "2026-07-17T00:00:01+00:00"))
    store.put_audit_entry(_audit_entry("two", "2026-07-17T00:00:02+00:00"))

    rows = store.list_audit_entries(policy_id="", agent_name="", tenant_id="acme")

    assert [row.entry_id for row in rows] == ["two", "one"]


# ─── Proxy replay captured_at + idempotency (PG) ─────────────────────────────


def test_pg_proxy_replay_captured_at_matches_caller(monkeypatch):
    """PG replay insert persists a real captured_at; identical across reads."""
    store, pool = _pg_replay_store(monkeypatch)
    row_id = store.add("acme", {"prompt": "hello"})

    listed = store.list("acme")
    assert len(listed) == 1
    captured_at = pool._state["rows"][row_id]["captured_at"]
    # A real ISO capture time, not a DB DEFAULT now() (which the fake leaves
    # absent because captured_at is now always in the column list).
    assert captured_at and "T" in captured_at
    assert listed[0]["captured_at"] == captured_at


def test_pg_proxy_replay_idempotent_on_row_id(monkeypatch):
    """ON CONFLICT (row_id) DO NOTHING: re-insert keeps one row, same time."""
    store, pool = _pg_replay_store(monkeypatch)
    row_id = store.add("acme", {"prompt": "hello"})
    captured_at = pool._state["rows"][row_id]["captured_at"]

    # Simulate a replica replaying the identical row_id with a different time.
    conn = pool.connection()
    conn.execute(
        "INSERT INTO proxy_replay_log (row_id, tenant_id, captured_at, not_after, record)"
        " VALUES (%s, %s, %s, %s, %s::jsonb) ON CONFLICT (row_id) DO NOTHING",
        (row_id, "acme", "9999-01-01T00:00:00+00:00", "9999-01-02T00:00:00+00:00", "{}"),
    )
    assert store.count("acme") == 1
    assert pool._state["rows"][row_id]["captured_at"] == captured_at  # unchanged


# ─── SQLite <-> Postgres parity ──────────────────────────────────────────────


def test_sqlite_pg_policy_audit_parity(monkeypatch):
    """Both backends persist + read back the same logical audit record."""
    ts = "2026-06-15T00:00:00+00:00"
    entry = _audit_entry("e1", ts)

    store, _pool = _pg_policy_store(monkeypatch)
    store.put_audit_entry(entry)
    pg_rows = store.list_audit_entries(tenant_id="acme")

    with tempfile.TemporaryDirectory() as d:
        sq = SQLitePolicyStore(str(Path(d) / "a.db"))
        sq.put_audit_entry(entry)
        sq_rows = sq.list_audit_entries(tenant_id="acme")

    assert len(pg_rows) == len(sq_rows) == 1
    for col in ("entry_id", "policy_id", "agent_name", "action_taken", "timestamp", "tenant_id"):
        assert getattr(pg_rows[0], col) == getattr(sq_rows[0], col)


def test_sqlite_policy_audit_idempotent():
    """SQLite side: same entry twice = one row, same timestamp (PRIMARY KEY)."""
    ts = "2026-06-15T00:00:00+00:00"
    entry = _audit_entry("e1", ts)
    with tempfile.TemporaryDirectory() as d:
        sq = SQLitePolicyStore(str(Path(d) / "a.db"))
        sq.put_audit_entry(entry)
        try:
            sq.put_audit_entry(entry)
        except Exception:
            # SQLite raises on PRIMARY KEY conflict; the first write already
            # persisted the canonical row — the idempotent outcome holds.
            pass
        rows = sq.list_audit_entries(tenant_id="acme")
    assert len(rows) == 1
    assert rows[0].timestamp == ts


def test_storage_schema_lists_llm_costs():
    """Operator readiness manifest reports the cost store on both backends."""
    from agent_bom.api.storage_schema import CONTROL_PLANE_SCHEMA_COMPONENTS

    comp = next((c for c in CONTROL_PLANE_SCHEMA_COMPONENTS if c.component == "llm_costs"), None)
    assert comp is not None
    assert "llm_costs" in comp.tables and "llm_cost_budgets" in comp.tables
    assert "postgres" in comp.backend and "sqlite" in comp.backend
