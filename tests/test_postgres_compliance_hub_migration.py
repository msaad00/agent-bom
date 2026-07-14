"""Regression tests for the Postgres Compliance Hub primary-key migration.

The dedup DELETE in ``_migrate_primary_key`` is a full-table self-join that,
on a large already-migrated table, exceeded the default 15s statement_timeout
and 500'd every store init (#3980). These tests pin the fix: the migration is a
true no-op (no DELETE, no DDL) once the collapsed ``(tenant_id, finding_id)``
primary key is in place, and still dedups + swaps the key on an old-shape or
missing primary key. They use a connection spy so they run without a live
Postgres (the store's own tests mock psycopg for the same reason).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore


@dataclass
class _FakeCursor:
    row: tuple[Any, ...] | None = None

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.row


@dataclass
class _ConnSpy:
    """Records executed SQL and answers the pkey-shape probe with ``pk_cols``."""

    pk_cols: str | None
    executed: list[str] = field(default_factory=list)

    def execute(self, sql: str, params: tuple | None = None) -> _FakeCursor:
        self.executed.append(sql)
        normalized = " ".join(sql.split()).lower()
        if "from pg_constraint" in normalized and "string_agg" in normalized:
            return _FakeCursor(row=(self.pk_cols,))
        return _FakeCursor()

    def _statements(self) -> list[str]:
        return [" ".join(s.split()).lower() for s in self.executed]

    def _issued_delete(self) -> bool:
        return any(s.startswith("delete from compliance_hub_findings a") for s in self._statements())

    def _issued_pk_ddl(self) -> bool:
        return any("add constraint compliance_hub_findings_pkey" in s for s in self._statements())

    def _issued_probe(self) -> bool:
        return any("from pg_constraint" in s and "string_agg" in s for s in self._statements())


def test_migration_is_true_no_op_when_pk_already_collapsed():
    """Already-migrated table: probe only, no dedup DELETE and no DDL (#3980)."""
    conn = _ConnSpy(pk_cols="tenant_id,finding_id")

    PostgresComplianceHubStore._migrate_primary_key(conn)

    assert conn._issued_probe(), "expected the pkey-shape probe to run"
    assert not conn._issued_delete(), "dedup self-join DELETE must not run when PK is already collapsed"
    assert not conn._issued_pk_ddl(), "no constraint swap when PK is already collapsed"
    # Probe is the only statement issued on the hot path.
    assert len(conn.executed) == 1


def test_migration_dedups_and_swaps_pk_on_old_shape():
    """Legacy (tenant_id, finding_id, ordinal) key: dedup DELETE + constraint swap."""
    conn = _ConnSpy(pk_cols="tenant_id,finding_id,ordinal")

    PostgresComplianceHubStore._migrate_primary_key(conn)

    assert conn._issued_probe()
    assert conn._issued_delete(), "old-shape table must be deduped before the unique key"
    assert conn._issued_pk_ddl(), "old-shape table must have the collapsed PK added"


def test_migration_runs_when_primary_key_missing():
    """No primary key at all: still dedup + add the collapsed key (safe fallback)."""
    conn = _ConnSpy(pk_cols=None)

    PostgresComplianceHubStore._migrate_primary_key(conn)

    assert conn._issued_delete()
    assert conn._issued_pk_ddl()
