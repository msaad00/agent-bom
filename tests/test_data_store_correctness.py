"""Data-layer store correctness regression tests (0.94.3).

Covers four store-integrity fixes:
  1. Postgres audit hash-chain links for non-``default`` tenants (RLS-scoped read).
  2. Snowflake fleet reads are tenant-scoped (no cross-tenant leakage).
  3. ClickHouse compliance/fleet timestamps are coerced before insert.
  4. SQLite compliance-hub store keeps a busy_timeout so concurrent writers
     don't silently lose rows.

The Postgres and Snowflake backends are exercised through in-memory fakes that
model the row-level-security semantics, so the tests are meaningful even where a
live cluster (or a superuser fixture that bypasses RLS) is unavailable.
"""

from __future__ import annotations

import threading

import pytest

# ─── Fix #1: Postgres audit hash-chain tenant scoping ────────────────────────


class _FakeResult:
    def __init__(self, rows: list[tuple]) -> None:
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class _FakeAuditPool:
    """In-memory pool that enforces audit_log RLS by the bound session tenant."""

    def __init__(self) -> None:
        self.audit_rows: list[dict] = []
        self.checkpoints: dict[str, tuple[int, str]] = {}
        # (tenant, bypass) captured for every audit_log SELECT — lets a test
        # prove reads are bound to the right tenant rather than 'default'.
        self.audit_read_sessions: list[tuple[str, bool]] = []

    def connection(self):
        return _FakeAuditConn(self)


class _FakeAuditConn:
    def __init__(self, pool: _FakeAuditPool) -> None:
        self.pool = pool
        self.tenant = "default"
        self.bypass = False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def commit(self):
        return None

    def _visible_audit(self) -> list[dict]:
        if self.bypass:
            return list(self.pool.audit_rows)
        return [r for r in self.pool.audit_rows if r["team_id"] == self.tenant]

    def execute(self, sql: str, params: tuple | None = None):
        s = " ".join(sql.split())
        p = tuple(params or ())

        if "set_config('app.tenant_id'" in s:
            self.tenant = p[0]
            return _FakeResult([])
        if "set_config('app.bypass_rls'" in s:
            self.bypass = p[0] == "1"
            return _FakeResult([])
        if "set_config('statement_timeout'" in s:
            return _FakeResult([])

        upper = s.upper()
        if upper.startswith(("CREATE", "ALTER", "DO $$")) or "CREATE OR REPLACE FUNCTION" in upper:
            return _FakeResult([])
        if "INSERT INTO CONTROL_PLANE_SCHEMA_VERSIONS" in upper:
            return _FakeResult([])

        if "SELECT COUNT(*) FROM audit_chain_checkpoint" in s:
            return _FakeResult([(len(self.pool.checkpoints),)])
        if "FROM audit_chain_checkpoint WHERE tenant_id" in s:
            cp = self.pool.checkpoints.get(p[0])
            return _FakeResult([(cp[0], cp[1])] if cp else [])
        if "INSERT INTO audit_chain_checkpoint" in s:
            if len(p) == 2:  # _upsert_checkpoint: (tenant, head), count += 1
                tenant, head = p
                prev = self.pool.checkpoints.get(tenant)
                self.pool.checkpoints[tenant] = ((prev[0] + 1) if prev else 1, head)
            else:  # hydrate: (tenant, count, head)
                self.pool.checkpoints[p[0]] = (int(p[1]), p[2])
            return _FakeResult([])

        if "SELECT DISTINCT team_id FROM audit_log" in s:
            self.pool.audit_read_sessions.append((self.tenant, self.bypass))
            teams = sorted({r["team_id"] for r in self._visible_audit()})
            return _FakeResult([(t,) for t in teams])
        if "SELECT DISTINCT ON (team_id)" in s:
            self.pool.audit_read_sessions.append((self.tenant, self.bypass))
            latest: dict[str, dict] = {}
            for r in sorted(self._visible_audit(), key=lambda r: (r["timestamp"], r["entry_id"])):
                latest[r["team_id"]] = r
            return _FakeResult([(t, r["hmac_signature"]) for t, r in latest.items()])
        if "SELECT hmac_signature FROM audit_log" in s:
            self.pool.audit_read_sessions.append((self.tenant, self.bypass))
            rows = [r for r in self._visible_audit() if r["team_id"] == p[0]]
            rows.sort(key=lambda r: (r["timestamp"], r["entry_id"]), reverse=True)
            return _FakeResult([(rows[0]["hmac_signature"],)] if rows else [])
        if "SELECT COUNT(*) FROM audit_log" in s:
            self.pool.audit_read_sessions.append((self.tenant, self.bypass))
            rows = self._visible_audit()
            if "team_id = %s" in s:
                rows = [r for r in rows if r["team_id"] == p[0]]
            return _FakeResult([(len(rows),)])
        if "FROM audit_log" in s and "ORDER BY timestamp ASC" in s:
            self.pool.audit_read_sessions.append((self.tenant, self.bypass))
            rows = [r for r in self._visible_audit() if r["team_id"] == p[0]]
            rows.sort(key=lambda r: (r["timestamp"], r["entry_id"]))
            limit = p[-1]
            return _FakeResult(
                [
                    (
                        r["entry_id"],
                        r["timestamp"],
                        r["action"],
                        r["actor"],
                        r["resource"],
                        r["details"],
                        r["prev_signature"],
                        r["hmac_signature"],
                    )
                    for r in rows[:limit]
                ]
            )
        if "INSERT INTO audit_log" in s:
            (entry_id, timestamp, action, actor, resource, team_id, details, prev_sig, hmac_sig) = p
            self.pool.audit_rows.append(
                {
                    "entry_id": entry_id,
                    "timestamp": timestamp,
                    "action": action,
                    "actor": actor,
                    "resource": resource,
                    "team_id": team_id,
                    "details": details,
                    "prev_signature": prev_sig,
                    "hmac_signature": hmac_sig,
                }
            )
            return _FakeResult([])

        return _FakeResult([])


def _make_audit_log():
    from agent_bom.api.postgres_audit import PostgresAuditLog

    pool = _FakeAuditPool()
    return PostgresAuditLog(pool=pool), pool


def _append_entry(log, tenant_id: str, action: str, ts: str) -> None:
    from agent_bom.api.audit_log import AuditEntry

    entry = AuditEntry(
        entry_id=f"{tenant_id}-{ts}",
        timestamp=ts,
        action=action,
        actor="system",
        resource=f"job/{action}",
        details={"tenant_id": tenant_id},
    )
    log.append(entry)


def test_postgres_audit_chain_links_for_non_default_tenant():
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    log, pool = _make_audit_log()
    token = set_current_tenant("acme")
    try:
        _append_entry(log, "acme", "scan", "2026-07-09T00:00:01Z")
        _append_entry(log, "acme", "scan", "2026-07-09T00:00:02Z")
        _append_entry(log, "acme", "policy_eval", "2026-07-09T00:00:03Z")

        verified, tampered = log.verify_integrity(tenant_id="acme")
    finally:
        reset_current_tenant(token)

    # The whole chain must verify — no broken links from an empty prev_signature.
    assert (verified, tampered) == (3, 0)

    # The stored chain actually links: each entry's prev_signature is the prior
    # entry's HMAC (would be "" for every row under the pre-fix raw-connection read).
    rows = sorted(pool.audit_rows, key=lambda r: r["timestamp"])
    assert rows[0]["prev_signature"] == ""
    assert rows[1]["prev_signature"] == rows[0]["hmac_signature"]
    assert rows[2]["prev_signature"] == rows[1]["hmac_signature"]

    # Every audit_log read during append was bound to 'acme' (RLS-scoped),
    # never the default fallback tenant that the raw connection resolved to.
    non_default_reads = [t for (t, _b) in pool.audit_read_sessions if t == "acme"]
    assert non_default_reads, "expected audit reads bound to the 'acme' tenant session"
    assert all(t != "default" or b for (t, b) in pool.audit_read_sessions)


def test_postgres_audit_chains_are_isolated_per_tenant():
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    log, _pool = _make_audit_log()

    for tenant in ("tenant-a", "tenant-b"):
        token = set_current_tenant(tenant)
        try:
            _append_entry(log, tenant, "scan", f"2026-07-09T01:00:01Z-{tenant}")
            _append_entry(log, tenant, "scan", f"2026-07-09T01:00:02Z-{tenant}")
            verified, tampered = log.verify_integrity(tenant_id=tenant)
        finally:
            reset_current_tenant(token)
        assert (verified, tampered) == (2, 0)


# ─── Fix #2: Snowflake fleet reads are tenant-scoped ─────────────────────────


class _TenantAwareSnowflakeCursor:
    """Cursor that stores fleet rows and honours a ``tenant_id = %s`` filter."""

    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows
        self._result: list[tuple] = []

    def execute(self, sql: str, params=None):
        s = " ".join(sql.split())
        p = tuple(params or ())
        if "FROM fleet_agents" not in s:
            self._result = []
            return self
        rows = self._rows
        if "tenant_id = %s" in s:
            # The tenant filter is always the last bound parameter here.
            wanted = p[-1]
            rows = [r for r in rows if r["tenant_id"] == wanted]
        if "WHERE name = %s" in s:
            name = p[0]
            rows = [r for r in rows if r["name"] == name]
        if "SELECT data" in s:
            self._result = [(r["data"],) for r in rows]
        else:  # list_summary columns
            self._result = [
                (r["agent_id"], r["canonical_id"], r["name"], r["lifecycle_state"], r["trust_score"], r["updated_at"])
                for r in rows
            ]
        return self

    def fetchone(self):
        return self._result[0] if self._result else None

    def fetchall(self):
        return list(self._result)


class _TenantAwareSnowflakeConn:
    def __init__(self, cursor) -> None:
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fleet_agent_json(agent_id: str, name: str, tenant_id: str) -> str:
    import json

    return json.dumps(
        {
            "agent_id": agent_id,
            "name": name,
            "agent_type": "custom",
            "lifecycle_state": "approved",
            "tenant_id": tenant_id,
        }
    )


def _snowflake_fleet_store():
    from agent_bom.api.snowflake_store import SnowflakeFleetStore

    rows = [
        {
            "agent_id": "a1",
            "canonical_id": "c1",
            "name": "agent-a",
            "lifecycle_state": "approved",
            "trust_score": 1.0,
            "updated_at": "2026-07-09T00:00:00Z",
            "tenant_id": "tenant-a",
            "data": _fleet_agent_json("a1", "agent-a", "tenant-a"),
        },
        {
            "agent_id": "b1",
            "canonical_id": "c2",
            "name": "agent-b",
            "lifecycle_state": "approved",
            "trust_score": 1.0,
            "updated_at": "2026-07-09T00:00:00Z",
            "tenant_id": "tenant-b",
            "data": _fleet_agent_json("b1", "agent-b", "tenant-b"),
        },
    ]
    cursor = _TenantAwareSnowflakeCursor(rows)
    conn = _TenantAwareSnowflakeConn(cursor)

    store = SnowflakeFleetStore.__new__(SnowflakeFleetStore)
    store._conn_params = {}  # type: ignore[attr-defined]
    store._connect = lambda: conn  # type: ignore[attr-defined]
    return store


def test_snowflake_fleet_list_all_is_tenant_scoped():
    store = _snowflake_fleet_store()

    tenant_a = store.list_all(tenant_id="tenant-a")
    assert {a.name for a in tenant_a} == {"agent-a"}
    assert all(a.tenant_id == "tenant-a" for a in tenant_a)

    # Tenant A must not see tenant B's agent.
    assert "agent-b" not in {a.name for a in tenant_a}


def test_snowflake_fleet_get_by_name_and_summary_are_tenant_scoped():
    store = _snowflake_fleet_store()

    # get_by_name scoped to tenant-a cannot resolve tenant-b's agent.
    assert store.get_by_name("agent-b", tenant_id="tenant-a") is None
    assert store.get_by_name("agent-b", tenant_id="tenant-b") is not None

    summary_a = store.list_summary(tenant_id="tenant-a")
    assert {row["name"] for row in summary_a} == {"agent-a"}


# ─── Fix #3: ClickHouse timestamp coercion ───────────────────────────────────


def _clickhouse_store():
    from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore

    return ClickHouseAnalyticsStore.__new__(ClickHouseAnalyticsStore)


def test_clickhouse_compliance_row_coerces_timestamp():
    store = _clickhouse_store()
    row = store._compliance_row(
        {
            "measured_at": "2026-07-09T12:34:56Z",
            "scan_id": "s1",
            "framework": "cis",
            "control_id": "1.1",
        }
    )
    # ISO string with 'Z'/tz must become ClickHouse DateTime text (no 'T'/'Z').
    assert row["measured_at"] == "2026-07-09 12:34:56"


def test_clickhouse_fleet_row_coerces_timestamp():
    store = _clickhouse_store()
    row = store._fleet_row({"agent_name": "a", "last_seen": "2026-07-09T00:00:00+00:00"})
    assert row["measured_at"] == "2026-07-09 00:00:00"


def test_clickhouse_compliance_row_matches_sibling_coercion():
    """The compliance/fleet rows now coerce exactly like the CIS-check sibling."""
    from agent_bom.api.clickhouse_store import _coerce_clickhouse_timestamp

    store = _clickhouse_store()
    ts = "2026-01-02T03:04:05Z"
    assert store._compliance_row({"measured_at": ts})["measured_at"] == _coerce_clickhouse_timestamp(ts)
    assert store._fleet_row({"last_seen": ts})["measured_at"] == _coerce_clickhouse_timestamp(ts)


# ─── Fix #4: SQLite hub store keeps writes under concurrency ─────────────────


def test_sqlite_hub_store_no_lost_writes_under_concurrency(tmp_path):
    from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore

    store = SQLiteComplianceHubStore(db_path=str(tmp_path / "hub.db"))
    tenant = "tenant-x"

    writers = 8
    per_writer = 25
    errors: list[Exception] = []
    barrier = threading.Barrier(writers + 2)

    def _writer(worker: int) -> None:
        try:
            barrier.wait()
            for i in range(per_writer):
                fid = f"w{worker}-f{i}"
                store.add(tenant, [{"id": fid, "severity": "high", "source": "test"}])
        except Exception as exc:  # pragma: no cover - only on regression
            errors.append(exc)

    def _reader() -> None:
        try:
            barrier.wait()
            for _ in range(per_writer):
                store.count(tenant)
                store.list(tenant)
        except Exception as exc:  # pragma: no cover - only on regression
            errors.append(exc)

    threads = [threading.Thread(target=_writer, args=(w,)) for w in range(writers)]
    threads += [threading.Thread(target=_reader) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"concurrent access raised: {errors!r}"
    # Every write landed — no silent 'database is locked' loss.
    assert store.count(tenant) == writers * per_writer


def test_sqlite_hub_store_sets_busy_timeout(tmp_path):
    from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore

    store = SQLiteComplianceHubStore(db_path=str(tmp_path / "hub.db"))
    busy_timeout = store._conn.execute("PRAGMA busy_timeout").fetchone()[0]
    assert busy_timeout == 30000


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
