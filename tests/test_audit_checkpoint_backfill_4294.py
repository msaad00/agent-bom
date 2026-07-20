"""Legacy audit-checkpoint backfill regression tests (#4294).

A tenant whose ``audit_log`` rows predate its first ``audit_chain_checkpoint``
upsert gets seeded at ``entry_count=1`` rather than its true historical count:
the migration-owned schema creates the checkpoint table empty and never
backfills it, so a tenant's first append after that seeds the checkpoint from
scratch. ``verify_integrity``'s truncation check (``len(entries) ==
checkpoint.entry_count``) then under-counts for that tenant until enough new
appends accrue, so a valid intact chain is mis-scored and a genuine tail
truncation can slip under the wrong count.

These tests prove (a) the one-time ``backfill_checkpoints`` reconciler heals an
already-under-seeded checkpoint from the audit_log chain links, is idempotent,
and leaves a correctly-seeded tenant untouched, and (b) the append seed path no
longer bakes ``entry_count=1`` for a legacy tenant.
"""

from __future__ import annotations

import os
import re
import uuid
from pathlib import Path

import pytest

from agent_bom.api.audit_log import AuditEntry, SQLiteAuditLog

_BACKFILL_MIGRATION = (
    Path(__file__).parent.parent
    / "deploy"
    / "supabase"
    / "postgres"
    / "alembic"
    / "versions"
    / "20260720_01_audit_checkpoint_legacy_backfill.py"
)


def _canonical_sql(text: str) -> str:
    return re.sub(r"[\s\"]+", "", text).lower()


def test_backfill_migration_is_chained_bypasses_rls_and_reconciles() -> None:
    """The migration-owned backfill heals legacy checkpoints for deployments
    whose runtime store never runs _hydrate_checkpoints (Postgres authoritative).

    It must chain from the current head, bypass FORCE RLS for the cross-tenant
    maintenance write, and idempotently reconcile entry_count + head_signature
    from the audit_log links (ON CONFLICT DO UPDATE)."""
    assert _BACKFILL_MIGRATION.exists()
    sql = _BACKFILL_MIGRATION.read_text()
    assert re.search(r'revision\s*=\s*"20260720_01"', sql)
    assert re.search(r'down_revision\s*=\s*"20260719_03"', sql)
    canon = _canonical_sql(sql)
    assert "set_config('app.bypass_rls','1',true)".replace("'", "") in canon.replace("'", "")
    assert "insertintoaudit_chain_checkpoint" in canon
    assert "onconflict(tenant_id)doupdateset" in canon
    assert "entry_count=excluded.entry_count" in canon
    assert "head_signature=excluded.head_signature" in canon


_REQUIRES_PG = pytest.mark.skipif(
    not os.environ.get("AGENT_BOM_POSTGRES_URL"),
    reason="requires a live PostgreSQL (AGENT_BOM_POSTGRES_URL); the mock pool cannot model the chain walk",
)


# ── SQLite ────────────────────────────────────────────────────────────────


def _sqlite_build_chain(log: SQLiteAuditLog, tenant: str, n: int) -> None:
    for i in range(n):
        log.append(AuditEntry(action="scan", actor="w", resource=f"pkg-{i}", details={"tenant_id": tenant}))


def _sqlite_corrupt_checkpoint_count(log: SQLiteAuditLog, tenant: str, value: int) -> None:
    log._conn.execute(
        "UPDATE audit_chain_checkpoint SET entry_count = ? WHERE tenant_id = ?",
        (value, tenant),
    )
    log._conn.commit()


def test_sqlite_backfill_heals_underseeded_checkpoint(tmp_path) -> None:
    log = SQLiteAuditLog(str(tmp_path / "audit.db"))
    tenant = "tenant-legacy"
    n = 6
    _sqlite_build_chain(log, tenant, n)
    true_tip = log._latest_signature_for_tenant(tenant)

    # Simulate the legacy under-seed: a checkpoint that says 1 while N rows exist.
    _sqlite_corrupt_checkpoint_count(log, tenant, 1)
    assert log._get_checkpoint(tenant).entry_count == 1
    # The truncation check now mis-scores the intact chain (count mismatch).
    _, tampered_before = log.verify_integrity(tenant_id=tenant)
    assert tampered_before >= 1

    healed = log.backfill_checkpoints()
    assert healed >= 1

    cp = log._get_checkpoint(tenant)
    assert cp.entry_count == n
    assert cp.head_signature == true_tip
    verified, tampered = log.verify_integrity(tenant_id=tenant)
    assert (verified, tampered) == (n, 0)

    # Idempotent: a second run yields the same checkpoint.
    log.backfill_checkpoints()
    cp2 = log._get_checkpoint(tenant)
    assert (cp2.entry_count, cp2.head_signature) == (n, true_tip)


def test_sqlite_backfill_leaves_correctly_seeded_tenant_untouched(tmp_path) -> None:
    log = SQLiteAuditLog(str(tmp_path / "audit.db"))
    tenant = "tenant-normal"
    n = 4
    _sqlite_build_chain(log, tenant, n)
    before = log._get_checkpoint(tenant)
    assert before.entry_count == n

    log.backfill_checkpoints()

    after = log._get_checkpoint(tenant)
    assert (after.entry_count, after.head_signature) == (before.entry_count, before.head_signature)
    assert log.verify_integrity(tenant_id=tenant) == (n, 0)


def test_sqlite_append_seed_uses_true_count_for_legacy_tenant(tmp_path) -> None:
    log = SQLiteAuditLog(str(tmp_path / "audit.db"))
    tenant = "tenant-legacy-seed"
    n = 5
    _sqlite_build_chain(log, tenant, n)
    # Drop the checkpoint row to model a tenant whose rows predate any checkpoint
    # (the migration-owned table is created empty and never batch-backfilled).
    log._conn.execute("DELETE FROM audit_chain_checkpoint WHERE tenant_id = ?", (tenant,))
    log._conn.commit()
    assert log._get_checkpoint(tenant) is None

    log.append(AuditEntry(action="scan", actor="w", resource="pkg-new", details={"tenant_id": tenant}))

    cp = log._get_checkpoint(tenant)
    # The seed must be the true row count (n + the new append), NOT 1.
    assert cp.entry_count == n + 1
    assert log.verify_integrity(tenant_id=tenant) == (n + 1, 0)


# ── Postgres (live, migration-owned schema, RLS on) ─────────────────────────


def _pg_build_chain(store, tenant: str, n: int) -> None:
    for i in range(n):
        store.append(AuditEntry(action="scan", actor="w", resource=f"pkg-{i}", details={"tenant_id": tenant}))


def _pg_exec(sql: str, params: tuple) -> None:
    from agent_bom.api.postgres_common import _get_pool, _tenant_connection, bypass_tenant_rls

    with bypass_tenant_rls(audit=False), _tenant_connection(_get_pool()) as conn:
        conn.execute(sql, params)
        conn.commit()


@_REQUIRES_PG
def test_postgres_backfill_heals_underseeded_checkpoint() -> None:
    from agent_bom.api.postgres_common import _current_tenant, set_current_tenant
    from agent_bom.api.postgres_store import PostgresAuditLog

    store = PostgresAuditLog()
    tenant = f"tenant-legacy-{uuid.uuid4().hex[:12]}"
    n = 6
    # verify_integrity's entry fetch reads under the ambient tenant RLS context
    # (matching how #4293's own regression drives it), so hold the tenant bound
    # for the whole body; the checkpoint mutation + backfill use their own
    # RLS-bypass connection.
    token = set_current_tenant(tenant)
    try:
        _pg_build_chain(store, tenant, n)
        true_tip = store._chain_tip_signature_from_log(tenant)
        assert true_tip

        # Simulate the legacy under-seed: entry_count=1 while N rows exist.
        _pg_exec("UPDATE audit_chain_checkpoint SET entry_count = 1 WHERE tenant_id = %s", (tenant,))
        assert store._get_checkpoint(tenant).entry_count == 1
        # The truncation check now mis-scores the intact chain (count mismatch).
        _, tampered_before = store.verify_integrity(tenant_id=tenant)
        assert tampered_before >= 1

        store.backfill_checkpoints()

        cp = store._get_checkpoint(tenant)
        assert cp.entry_count == n
        assert cp.head_signature == true_tip
        verified, tampered = store.verify_integrity(tenant_id=tenant)
        assert (verified, tampered) == (n, 0)

        # Idempotent.
        store.backfill_checkpoints()
        cp2 = store._get_checkpoint(tenant)
        assert (cp2.entry_count, cp2.head_signature) == (n, true_tip)
    finally:
        _current_tenant.reset(token)


@_REQUIRES_PG
def test_postgres_backfill_leaves_correctly_seeded_tenant_untouched() -> None:
    from agent_bom.api.postgres_common import _current_tenant, set_current_tenant
    from agent_bom.api.postgres_store import PostgresAuditLog

    store = PostgresAuditLog()
    tenant = f"tenant-normal-{uuid.uuid4().hex[:12]}"
    n = 5
    token = set_current_tenant(tenant)
    try:
        _pg_build_chain(store, tenant, n)
        before = store._get_checkpoint(tenant)
        assert before.entry_count == n

        store.backfill_checkpoints()

        after = store._get_checkpoint(tenant)
        assert (after.entry_count, after.head_signature) == (before.entry_count, before.head_signature)
        assert store.verify_integrity(tenant_id=tenant) == (n, 0)
    finally:
        _current_tenant.reset(token)


@_REQUIRES_PG
def test_postgres_append_seed_uses_true_count_for_legacy_tenant() -> None:
    from agent_bom.api.postgres_common import _current_tenant, set_current_tenant
    from agent_bom.api.postgres_store import PostgresAuditLog

    store = PostgresAuditLog()
    tenant = f"tenant-legacy-seed-{uuid.uuid4().hex[:12]}"
    n = 5
    token = set_current_tenant(tenant)
    try:
        _pg_build_chain(store, tenant, n)
        # Drop the checkpoint row: a legacy tenant whose rows predate any checkpoint.
        _pg_exec("DELETE FROM audit_chain_checkpoint WHERE tenant_id = %s", (tenant,))
        assert store._get_checkpoint(tenant) is None

        store.append(AuditEntry(action="scan", actor="w", resource="pkg-new", details={"tenant_id": tenant}))

        cp = store._get_checkpoint(tenant)
        assert cp.entry_count == n + 1
        assert store.verify_integrity(tenant_id=tenant) == (n + 1, 0)
    finally:
        _current_tenant.reset(token)
