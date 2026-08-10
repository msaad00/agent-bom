"""The governance audit chain must reject a fork, like its sibling already does.

``PostgresGovernanceAuditLog.append`` reads the tenant's chain head, seals the
record against it, and inserts. Two writers that read the same head both seal
against it, so both rows claim the same predecessor and the chain forks.
``UNIQUE (tenant_id, action_id)`` prevents duplicate *actions*; it says nothing
about two different actions claiming one parent.

Measured on live Postgres before the guard:

    6 processes x 8 appends -> 48 rows, 15 distinct prev_hash
                               verify_chain: 33 of 48 tampered
    16 threads, one process -> 16 rows,  5 distinct prev_hash

The module docstring claimed a single process "never forks a chain" and framed
the risk as cross-replica only. Both halves were wrong.

The user-visible effect is a false alarm rather than data loss:
``GET /v1/self-posture`` reports ``governance.audit_chain_integrity`` as FAIL
("broken or forked") on healthy data for any multi-replica deployment.

``audit_log`` — one file over — has carried a fork-guard unique index plus a
re-sign/retry loop since 20260719_01. These tests pin the same judgement onto
the second chain: the DDL exists in both authoritative places, and the store
re-seals rather than dropping the record when the database rejects a race.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "deploy/supabase/postgres/alembic/versions/20260810_01_governance_audit_fork_guard.py"
RUNTIME_SCHEMA = ROOT / "deploy/supabase/postgres/runtime-schema.sql"

_INDEX = "governance_audit_log_tenant_prevhash_uniq"


def _canonical_sql(text: str) -> str:
    return re.sub(r"[\s\"]+", "", text).lower()


def test_the_migration_creates_the_fork_guard_index() -> None:
    sql = MIGRATION.read_text()
    assert re.search(r'revision\s*=\s*"20260810_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260801_01"', sql), "must chain from the current head"
    canon = _canonical_sql(sql)
    assert f"createuniqueindexifnotexists{_INDEX}ongovernance_audit_log(tenant_id,prev_hash)" in canon
    assert f"DROP INDEX IF EXISTS {_INDEX}" in sql, "must be reversible"


def test_the_migration_backfills_prev_hash_before_indexing() -> None:
    """The column is new; existing rows carry prev_hash inside `data`.

    Creating the unique index over an all-empty column would collide on the
    first two rows of every tenant.
    """
    sql = MIGRATION.read_text()
    add = sql.index("ADD COLUMN IF NOT EXISTS prev_hash")
    backfill = sql.index("UPDATE governance_audit_log")
    create = sql.index("CREATE UNIQUE INDEX")
    assert add < backfill < create, "order must be add column, backfill, then index"


def test_the_runtime_schema_authority_carries_the_same_ddl() -> None:
    """Fresh deployments take the schema from here, not from the migration."""
    schema = _canonical_sql(RUNTIME_SCHEMA.read_text())
    assert f"createuniqueindexifnotexists{_INDEX}ongovernance_audit_log(tenant_id,prev_hash)" in schema
    assert "prev_hashtextnotnulldefault''" in schema


def test_the_store_retries_a_fork_race_instead_of_dropping_the_record() -> None:
    """A guard that turned a race into a lost audit record would be worse."""
    source = (ROOT / "src/agent_bom/api/postgres_governance_audit.py").read_text()
    assert "_MAX_APPEND_RETRIES" in source, "the append path must bound its retries"
    assert "_is_chain_fork_conflict" in source, "a fork race must be told apart from a real error"
    assert "prev_hash" in source, "the sealed prev_hash must be written to its own column"


class TestForkConflictDetection:
    """Only a unique violation on the fork-guard index may be retried."""

    def _exc(self, sqlstate: str, constraint: str | None):
        class _Diag:
            constraint_name = constraint

        class _FakeDbError(Exception):
            pass

        exc = _FakeDbError("boom")
        exc.sqlstate = sqlstate  # type: ignore[attr-defined]
        exc.diag = _Diag()  # type: ignore[attr-defined]
        return exc

    @pytest.mark.parametrize("constraint", [_INDEX, None, ""])
    def test_a_unique_violation_on_the_guard_is_a_fork(self, constraint) -> None:
        from agent_bom.api.postgres_governance_audit import _is_chain_fork_conflict

        assert _is_chain_fork_conflict(self._exc("23505", constraint)) is True

    def test_an_unrelated_error_is_not_retried(self) -> None:
        """Retrying a real error would spin instead of surfacing it."""
        from agent_bom.api.postgres_governance_audit import _is_chain_fork_conflict

        assert _is_chain_fork_conflict(self._exc("42P01", None)) is False

    def test_a_different_unique_index_is_not_treated_as_a_fork(self) -> None:
        from agent_bom.api.postgres_governance_audit import _is_chain_fork_conflict

        assert _is_chain_fork_conflict(self._exc("23505", "uq_governance_audit_tenant_action")) is False
