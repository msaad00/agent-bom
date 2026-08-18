"""Postgres ledger filter parity and migration contracts.

SQLite already materialises ``scan_id`` on the append ledger.  These contracts
keep Postgres from falling back to per-row JSONB extraction, and require the
forward migration/runtime bootstrap to stay aligned for existing and new
installations.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

from agent_bom.api import postgres_compliance_hub as hub_module
from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

ROOT = Path(__file__).parent.parent
MIGRATION = ROOT / "deploy/supabase/postgres/alembic/versions/20260818_01_hub_ledger_scan_id.py"
RUNTIME_SCHEMA = ROOT / "deploy/supabase/postgres/runtime-schema.sql"


class _Rows:
    def __init__(self, rows: list[tuple[object, ...]]) -> None:
        self._rows = rows

    def fetchone(self) -> tuple[object, ...] | None:
        return self._rows[0] if self._rows else None

    def fetchall(self) -> list[tuple[object, ...]]:
        return self._rows


class _ReadConnection:
    def __init__(self) -> None:
        self.executed: list[tuple[str, tuple[object, ...] | None]] = []

    def execute(self, sql: str, params: tuple[object, ...] | None = None) -> _Rows:
        self.executed.append((sql, params))
        return _Rows([(0,)] if "COUNT(*)" in sql else [])


def test_postgres_ledger_filters_use_materialized_partial_indexes(monkeypatch) -> None:
    conn = _ReadConnection()

    @contextmanager
    def _connection(_pool):
        yield conn

    monkeypatch.setattr(hub_module, "_tenant_connection", _connection)
    monkeypatch.setattr(hub_module, "hydrate_finding_payloads_postgres", lambda _conn, _tenant, payloads: payloads)
    store = object.__new__(PostgresComplianceHubStore)
    store._pool = object()

    rows, total = store.list_page(
        "tenant-a",
        limit=25,
        severity="HIGH",
        scan_id="scan-42",
    )

    assert rows == [] and total == 0
    normalized = [" ".join(sql.split()) for sql, _params in conn.executed]
    assert normalized
    for sql in normalized:
        assert "severity <> '' AND LOWER(severity) = %s" in sql
        assert "scan_id = %s AND scan_id <> ''" in sql
        assert "payload->>'scan_id'" not in sql


def test_postgres_ledger_scan_id_is_forward_migrated_and_bootstrapped() -> None:
    assert MIGRATION.exists(), "released databases need a forward migration for the materialized scan_id"
    migration = MIGRATION.read_text()
    runtime = RUNTIME_SCHEMA.read_text()

    for sql in (migration, runtime):
        assert "scan_id TEXT NOT NULL DEFAULT ''" in sql
        assert "idx_hub_findings_tenant_scan" in sql
        assert "WHERE scan_id <> ''" in sql

    assert "COALESCE(NULLIF(payload->>'batch_id', ''), payload->>'scan_id', '')" in migration


def test_postgres_ledger_write_materializes_batch_or_scan_id() -> None:
    source = (ROOT / "src/agent_bom/api/postgres_compliance_hub.py").read_text()
    insert_start = source.index("INSERT INTO compliance_hub_findings")
    insert = source[insert_start : source.index("ON CONFLICT", insert_start)]

    assert "scan_id" in insert
    assert 'payload.get("batch_id") or payload.get("scan_id")' in source
