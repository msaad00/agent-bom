"""Write-path scale/availability guards for the Postgres Compliance Hub.

These pin three fixes to the bulk/connector ingest path that the read path
already carried but the write path never got:

* item 2 (P1): ``upsert_current_batch`` probed ``information_schema.columns``
  for the ``ledger_finding_id`` column once PER ROW. The probe is hoisted to
  once per batch/connection.
* item 3 (P0, #3980 class): ``_init_tables`` re-ran un-indexed backfill
  ``UPDATE``s on every process start (full-table scans that blew the 15s
  statement timeout at scale and re-matched already-correct rows forever). The
  backfills are now gated by a one-time completion marker and refined so they
  never re-match correct rows.

They use a connection spy so they run without a live Postgres (the store's own
tests mock psycopg for the same reason).
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from agent_bom.api import postgres_compliance_hub as hub_mod
from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore


@dataclass
class _FakeCursor:
    row: tuple[Any, ...] | None = None
    rowcount: int = 1

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.row

    def fetchall(self) -> list[tuple[Any, ...]]:
        return []


class _FakeBatchCursor:
    """Minimal cursor supporting the bulk ``executemany(..., returning=True)``.

    The batched current-state upsert records observations via
    ``conn.cursor().executemany(... RETURNING canonical_id)``. This fake reports
    no newly-inserted canonicals (``pgresult=None``, ``nextset()`` False), so the
    upsert short-circuits after the single ledger-column probe — exactly what the
    hoist test needs to assert.
    """

    pgresult = None

    def __enter__(self) -> "_FakeBatchCursor":
        return self

    def __exit__(self, *_exc: Any) -> None:
        return None

    def executemany(self, sql: str, params: Any, *, returning: bool = False) -> None:
        return None

    def fetchall(self) -> list[tuple[Any, ...]]:  # pragma: no cover - guarded by pgresult
        return []

    def nextset(self) -> bool:
        return False


@dataclass
class _UpsertConnSpy:
    """Answers every per-batch query so ``upsert_current_batch`` runs end-to-end.

    Observation writes go through a batched cursor that reports no inserts (so
    the upsert short-circuits); the partition-ensure + ledger-column probe still
    run once. Records executed SQL.
    """

    executed: list[str] = field(default_factory=list)

    def execute(self, sql: str, params: tuple | None = None) -> _FakeCursor:
        self.executed.append(" ".join(sql.split()).lower())
        return _FakeCursor(row=None, rowcount=1)

    def cursor(self) -> _FakeBatchCursor:
        return _FakeBatchCursor()

    def commit(self) -> None:  # pragma: no cover - trivial
        pass


def _payload(idx: int) -> dict[str, Any]:
    return {
        "id": f"find-{idx}",
        "title": f"Finding {idx}",
        "severity": "high",
        "cvss_score": 7.5,
        "origin": "bulk_ingest",
        "source": "test",
    }


def test_ledger_col_probe_hoisted_out_of_per_row_loop(monkeypatch):
    """The information_schema ledger-column probe runs once per batch, not per row."""
    probe_calls = {"count": 0}

    def _counting_probe(conn: Any) -> bool:
        probe_calls["count"] += 1
        return False

    monkeypatch.setattr(hub_mod, "_postgres_current_has_ledger_col", _counting_probe)

    spy = _UpsertConnSpy()

    @contextmanager
    def _fake_tenant_connection(pool: Any):
        yield spy

    monkeypatch.setattr(hub_mod, "_tenant_connection", _fake_tenant_connection)

    store = PostgresComplianceHubStore.__new__(PostgresComplianceHubStore)
    store._pool = object()

    findings = [_payload(i) for i in range(1, 6)]  # 5 rows in one batch
    store.upsert_current_batch(
        "tenant-a",
        findings,
        observed_at="2026-07-16T00:00:00Z",
        batch_id="batch-1",
        source="test",
    )

    assert probe_calls["count"] == 1, (
        f"ledger-column probe should run once per batch, ran {probe_calls['count']}x "
        "(per-row information_schema probe is the write-path amplifier)"
    )


@dataclass
class _InitConnSpy:
    """Records SQL and answers the backfill-marker + pkey probes.

    ``marker_present`` controls whether the one-time backfill completion marker
    is reported as already recorded (a large, already-migrated table).
    """

    marker_present: bool
    executed: list[str] = field(default_factory=list)

    def execute(self, sql: str, params: tuple | None = None) -> _FakeCursor:
        norm = " ".join(sql.split()).lower()
        self.executed.append(norm)
        if "from agent_bom_hub_backfills" in norm:
            return _FakeCursor(row=(1,) if self.marker_present else None)
        if "from pg_constraint" in norm and "string_agg" in norm:
            # Report the PK already collapsed so _migrate_primary_key is a no-op.
            return _FakeCursor(row=("tenant_id,finding_id",))
        return _FakeCursor(row=None)

    def commit(self) -> None:  # pragma: no cover - trivial
        pass

    def _backfill_updates(self) -> list[str]:
        return [
            s
            for s in self.executed
            if s.startswith("update compliance_hub_findings set") or s.startswith("update hub_findings_current set")
        ]


def _run_init(spy: _InitConnSpy, monkeypatch) -> None:
    @contextmanager
    def _fake_pool_connection():
        yield spy

    pool = type("_P", (), {"connection": staticmethod(_fake_pool_connection)})()
    # Neutralise heavy schema helpers that are unrelated to the backfill gate.
    for name in (
        "ensure_postgres_schema_version",
        "_ensure_tenant_rls",
        "ensure_postgres_reference_tables",
        "_migrate_lifecycle_observations_l2_postgres",
        "_migrate_current_ledger_ref_postgres",
        "_migrate_current_ledger_ordinal_postgres",
    ):
        if hasattr(hub_mod, name):
            result = True if name == "ensure_postgres_schema_version" else None
            monkeypatch.setattr(hub_mod, name, lambda *a, _result=result, **k: _result)

    store = PostgresComplianceHubStore.__new__(PostgresComplianceHubStore)
    store._pool = pool
    import threading

    store._ingest_stats_lock = threading.Lock()
    store._finding_count_by_tenant = {}
    store._init_tables()


def test_backfill_updates_skipped_when_marker_present(monkeypatch):
    """A large, already-migrated table runs no full-table backfill UPDATEs on boot."""
    spy = _InitConnSpy(marker_present=True)
    _run_init(spy, monkeypatch)

    offenders = spy._backfill_updates()
    assert offenders == [], (
        "backfill UPDATEs must be skipped once the completion marker is set "
        f"(would re-scan/rewrite the whole table every boot); ran: {offenders}"
    )


def test_backfill_updates_run_once_when_marker_absent(monkeypatch):
    """A fresh/un-migrated store still runs the backfills and records the marker."""
    spy = _InitConnSpy(marker_present=False)
    _run_init(spy, monkeypatch)

    assert spy._backfill_updates(), "backfill must run when no completion marker exists yet"
    assert any(s.startswith("insert into agent_bom_hub_backfills") for s in spy.executed), (
        "completion marker must be recorded after the one-time backfill"
    )
