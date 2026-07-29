"""Policy audit deduplication must be tenant-safe and rollout-compatible.

The pre-fix schema used ``UNIQUE (entry_id)`` and old application replicas use
``ON CONFLICT (entry_id) DO NOTHING``.  Replacing that index with a composite
one fixes new replicas but makes every old replica fail during a rolling
deployment.  The compatible contract keeps the legacy conflict target while a
database trigger maps the logical ID to an injective tenant-derived physical
key.  The logical ID remains in the signed JSON payload and in a dedicated
column for operators.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "deploy/supabase/postgres/alembic/versions/20260729_01_policy_audit_tenant_scoped_index.py"


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _policy_index(sql: str) -> str:
    match = re.search(r"CREATE UNIQUE INDEX[^;]*uq_policy_audit_log_entry[^;]*;", sql)
    assert match, "the policy audit deduplication index is missing"
    return match.group(0)


def test_bootstrap_keeps_the_legacy_conflict_target_with_a_physical_key_trigger() -> None:
    sql = _read("deploy/supabase/postgres/init.sql")
    index = _policy_index(sql)

    assert re.search(r"ON\s+policy_audit_log\s*\(\s*entry_id\s*\)", index)
    assert "logical_entry_id TEXT" in sql
    assert "abom_policy_audit_key" in sql
    assert "abom_policy_audit_set_key" in sql
    assert "BEFORE INSERT OR UPDATE" in sql


def test_runtime_bootstrap_matches_the_rolling_deployment_contract() -> None:
    store = _read("src/agent_bom/api/postgres_policy.py")
    index = _policy_index(store)

    assert re.search(r"ON\s+policy_audit_log\s*\(\s*entry_id\s*\)", index)
    assert "logical_entry_id TEXT" in store
    assert "abom_policy_audit_key" in store
    assert "abom_policy_audit_set_key" in store


def test_writer_remains_compatible_with_old_and_new_database_shapes() -> None:
    store = _read("src/agent_bom/api/postgres_policy.py")

    assert "ON CONFLICT (entry_id) DO NOTHING" in store
    assert "ON CONFLICT (team_id, entry_id)" not in store


def test_migration_backfills_physical_keys_before_restoring_uniqueness() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    assert re.search(r'revision\s*=\s*"20260729_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260728_03"', sql)
    assert "ADD COLUMN IF NOT EXISTS logical_entry_id TEXT" in sql
    assert "abom_policy_audit_key" in sql
    assert "abom_policy_audit_set_key" in sql
    assert "UPDATE policy_audit_log" in sql
    assert sql.index("DROP INDEX IF EXISTS uq_policy_audit_log_entry") < sql.index("UPDATE policy_audit_log")
    assert sql.index("UPDATE policy_audit_log") < sql.rindex("CREATE UNIQUE INDEX uq_policy_audit_log_entry")


def test_migration_is_forward_only_after_cross_tenant_duplicates_are_accepted() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    assert "raise NotImplementedError" in sql
    assert "CREATE UNIQUE INDEX IF NOT EXISTS uq_policy_audit_log_entry" not in sql.split("def downgrade", 1)[1]
