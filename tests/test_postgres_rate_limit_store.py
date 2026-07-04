"""Regression tests for Postgres-backed sliding-window rate limiting."""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_bom.api.middleware import InMemoryRateLimitStore, PostgresRateLimitStore


@dataclass
class _FakeCursor:
    rows: list[tuple] = field(default_factory=list)
    rowcount: int = 0

    def fetchone(self):
        return self.rows[0] if self.rows else None


@dataclass
class _FakeConnection:
    hits: list[tuple[str, float]] = field(default_factory=list)
    executed: list[tuple[str, tuple | None]] = field(default_factory=list)

    def execute(self, sql: str, params: tuple | None = None):
        self.executed.append((sql, params))
        normalized = " ".join(sql.strip().lower().split())
        if normalized.startswith("create table") or normalized.startswith("create index"):
            return _FakeCursor()
        if normalized.startswith("delete from api_rate_limit_hits"):
            cutoff = float(params[0]) if params else 0.0
            self.hits = [(key, hit_at) for key, hit_at in self.hits if hit_at >= cutoff]
            return _FakeCursor()
        if "insert into api_rate_limit_hits" in normalized:
            self.hits.append((params[0], float(params[1])))
            return _FakeCursor()
        if "select count(*), min(hit_at)" in normalized:
            bucket_key, window_start = params
            matching = [hit_at for key, hit_at in self.hits if key == bucket_key and hit_at >= float(window_start)]
            oldest = min(matching) if matching else None
            return _FakeCursor(rows=[(len(matching), oldest)])
        return _FakeCursor()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakePool:
    def __init__(self) -> None:
        self._conn = _FakeConnection()

    def connection(self):
        return self._conn


def _fixed_window_count(key: str, now: float, *, window_seconds: int, timestamps: list[float]) -> int:
    """Simulate the old fixed-window Postgres counter for comparison tests."""
    window_started = int(now // window_seconds) * window_seconds
    return sum(1 for ts in timestamps if int(ts // window_seconds) * window_seconds == window_started)


def test_sliding_window_blocks_cross_bucket_burst_that_fixed_window_allowed():
    """Three hits at the end of bucket A must still count against a hit one second into bucket B."""
    window = 60
    bucket_a_start = 1_700_000_040.0
    first_bucket_end = bucket_a_start + 59.0
    next_bucket_start = bucket_a_start + 60.0

    memory = InMemoryRateLimitStore(window_seconds=window)
    for _ in range(3):
        memory.hit("tenant:read", first_bucket_end)

    fourth_count, _ = memory.hit("tenant:read", next_bucket_start)
    assert fourth_count == 4

    timestamps = [first_bucket_end, first_bucket_end, first_bucket_end, next_bucket_start]
    assert _fixed_window_count("tenant:read", next_bucket_start, window_seconds=window, timestamps=timestamps) == 1


def test_postgres_rate_limit_store_matches_in_memory_sliding_window():
    pool = _FakePool()
    store = PostgresRateLimitStore(window_seconds=60, pool=pool)
    memory = InMemoryRateLimitStore(window_seconds=60)
    base = 1_700_000_100.0

    for offset in (0.0, 5.0, 10.0, 55.0):
        now = base + offset
        pg_count, pg_reset = store.hit("tenant:scan", now)
        mem_count, mem_reset = memory.hit("tenant:scan", now)
        assert pg_count == mem_count
        assert pg_reset == mem_reset


def test_postgres_rate_limit_store_prunes_stale_hits():
    pool = _FakePool()
    store = PostgresRateLimitStore(window_seconds=60, pool=pool)
    base = 1_700_000_200.0

    store.hit("tenant:read", base)
    store.hit("tenant:read", base + 120.0)

    assert any("DELETE FROM api_rate_limit_hits" in sql for sql, _ in pool._conn.executed)
    assert not any(hit_at == base for _, hit_at in pool._conn.hits)
    assert any(hit_at == base + 120.0 for _, hit_at in pool._conn.hits)
