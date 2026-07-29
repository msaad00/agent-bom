"""A tenant's policy audit record must never be discarded by another tenant's.

``policy_audit_log`` carried ``UNIQUE (entry_id)`` with no tenant column, and the
writer used ``ON CONFLICT (entry_id) DO NOTHING``. Two tenants writing the same
logical ``entry_id`` therefore collapsed to one row: the second write returned
success and vanished. Unique indexes are enforced *below* RLS, so FORCE ROW
LEVEL SECURITY does not help here.

An audit log that silently drops entries is worse than one that errors — the
sibling governance chain already learned this and scopes its index by tenant
(``uq_governance_audit_tenant_action``).
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_bootstrap_index_is_tenant_scoped() -> None:
    sql = _read("deploy/supabase/postgres/init.sql")
    match = re.search(r"CREATE UNIQUE INDEX[^;]*uq_policy_audit_log_entry[^;]*;", sql)
    assert match, "the policy audit uniqueness index is gone entirely"
    index = match.group(0)
    assert "team_id" in index, f"tenant-less uniqueness lets one tenant discard another's audit row: {index}"


def test_runtime_index_matches_the_bootstrap() -> None:
    store = _read("src/agent_bom/api/postgres_policy.py")
    match = re.search(r"CREATE UNIQUE INDEX[^\"']*uq_policy_audit_log_entry[^\"']*", store)
    assert match, "the store no longer creates the uniqueness index"
    assert "team_id" in match.group(0), "the store's index drifted from init.sql"


def test_conflict_target_includes_the_tenant() -> None:
    store = _read("src/agent_bom/api/postgres_policy.py")
    assert "ON CONFLICT (entry_id) DO NOTHING" not in store, "a tenant-less conflict target silently drops another tenant's audit entry"
    assert re.search(r"ON CONFLICT \(\s*team_id\s*,\s*entry_id\s*\)", store), (
        "the insert must dedupe within a tenant, not across the estate"
    )


def test_a_migration_rebuilds_the_index_for_existing_deployments() -> None:
    """A deployed database keeps the old index until Alembic replaces it."""
    versions = ROOT / "deploy" / "supabase" / "postgres" / "alembic" / "versions"
    hits = [p for p in versions.glob("*.py") if "uq_policy_audit_log_entry" in p.read_text(encoding="utf-8")]
    assert hits, "no migration rebuilds the tenant-scoped index for already-migrated databases"
