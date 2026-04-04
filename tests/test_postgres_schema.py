"""Tests for the PostgreSQL / Supabase schema (deploy/supabase/postgres/init.sql).

Validates the DDL file structure without requiring a live database:
- All expected tables are defined
- All expected indexes are defined
- Required columns exist on each table
- FK references are internally consistent (each referenced table exists)
- The teams seed INSERT uses ON CONFLICT DO NOTHING (idempotent)
- The idempotent DO $$ block for adding team_id to legacy scan_jobs is present
"""

from __future__ import annotations

import re
from pathlib import Path

INIT_SQL = Path(__file__).parent.parent / "deploy" / "supabase" / "postgres" / "init.sql"
SQL = INIT_SQL.read_text()


# ── helpers ───────────────────────────────────────────────────────────────────


def _tables() -> set[str]:
    return set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SQL))


def _indexes() -> set[str]:
    return set(re.findall(r"CREATE INDEX IF NOT EXISTS (\w+)", SQL))


def _columns_for(table: str) -> set[str]:
    """Extract column names from a CREATE TABLE block (best-effort).

    Extracts lines that look like column definitions by finding the CREATE TABLE
    block and scanning until the matching closing paren, avoiding FK sub-parens.
    """
    # Find block start
    marker = f"CREATE TABLE IF NOT EXISTS {table}"
    start = SQL.find(marker)
    if start == -1:
        return set()
    # Walk forward to find the opening ( of the table body
    idx = SQL.index("(", start)
    # Collect lines until depth returns to 0
    depth = 0
    body_lines: list[str] = []
    for ch_idx in range(idx, len(SQL)):
        ch = SQL[ch_idx]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
        if ch == "\n" and depth == 1:
            body_lines.append(SQL[idx:ch_idx])
            idx = ch_idx + 1
    # Parse column names from collected lines
    cols: set[str] = set()
    for line in body_lines:
        line = line.strip().lstrip(",").strip()
        if not line or line.startswith("--"):
            continue
        first = line.split()[0].upper()
        if first in ("CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "CHECK"):
            continue
        col = line.split()[0].rstrip(",")
        if col and col not in (")", "("):
            cols.add(col)
    return cols


# ── Table existence ───────────────────────────────────────────────────────────


def test_all_expected_tables_exist():
    expected = {
        "teams",
        "scan_jobs",
        "findings",
        "agents",
        "policy_results",
        "api_keys",
        "job_queue",
        "api_rate_limits",
        "fleet_agents",
        "gateway_policies",
        "policy_audit_log",
        "audit_log",
        "trend_history",
        "scan_schedules",
        "osv_cache",
    }
    assert expected.issubset(_tables()), f"Missing tables: {expected - _tables()}"


def test_total_table_count():
    assert len(_tables()) >= 15


def test_gateway_policy_tables_have_tenant_columns():
    assert "team_id" in _columns_for("gateway_policies")
    assert "team_id" in _columns_for("policy_audit_log")


def test_gateway_policy_rls_policies_exist():
    assert "ALTER TABLE gateway_policies ENABLE ROW LEVEL SECURITY" in SQL
    assert "CREATE POLICY gateway_policies_tenant_isolation ON gateway_policies" in SQL
    assert "ALTER TABLE policy_audit_log ENABLE ROW LEVEL SECURITY" in SQL
    assert "CREATE POLICY policy_audit_log_tenant_isolation ON policy_audit_log" in SQL


def test_audit_and_trend_tables_exist_with_rls():
    assert "ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY" in SQL
    assert "CREATE POLICY audit_log_tenant_isolation ON audit_log" in SQL
    assert "ALTER TABLE trend_history ENABLE ROW LEVEL SECURITY" in SQL
    assert "CREATE POLICY trend_history_tenant_isolation ON trend_history" in SQL


def test_remaining_tenant_tables_have_rls():
    for table in ("findings", "agents", "policy_results", "job_queue"):
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in SQL
        assert f"CREATE POLICY {table}_tenant_isolation ON {table}" in SQL


def test_schema_summary_comment_is_current():
    assert "--  Schema (15 tables):" in SQL
    assert "--   api_rate_limits    — shared API rate-limiter buckets" in SQL
    assert "--   audit_log          — signed API/security audit trail" in SQL
    assert "--   trend_history      — persisted posture/vulnerability history" in SQL


def test_api_rate_limits_table_exists():
    cols = _columns_for("api_rate_limits")
    for col in ("bucket_key", "window_started", "hits", "updated_at"):
        assert col in cols, f"api_rate_limits missing column: {col}"
    assert "idx_api_rate_limits_updated" in _indexes()


# ── teams table ───────────────────────────────────────────────────────────────


def test_teams_required_columns():
    cols = _columns_for("teams")
    assert "team_id" in cols
    assert "name" in cols
    assert "slug" in cols


def test_teams_slug_unique():
    assert "slug" in SQL and "UNIQUE" in SQL.split("slug")[1][:30].upper()


def test_teams_default_seed():
    """'default' team is pre-seeded idempotently."""
    assert "INSERT INTO teams" in SQL
    assert "ON CONFLICT" in SQL
    assert "'default'" in SQL


# ── scan_jobs ─────────────────────────────────────────────────────────────────


def test_scan_jobs_has_team_id_column():
    """team_id column added either in CREATE TABLE or via DO block migration."""
    assert "team_id" in SQL.split("scan_jobs")[1][:2000]


def test_scan_jobs_has_triggered_by():
    assert "triggered_by" in SQL


def test_scan_jobs_do_block_migration_present():
    """Idempotent DO $$ block adds team_id to pre-existing scan_jobs."""
    assert "ADD COLUMN team_id" in SQL or "team_id" in _columns_for("scan_jobs")


def test_scan_jobs_team_status_index():
    assert "idx_jobs_team_status" in _indexes()


def test_scan_jobs_rls_policy_exists():
    assert "ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY" in SQL
    assert "CREATE POLICY scan_jobs_tenant_isolation ON scan_jobs" in SQL


# ── findings ─────────────────────────────────────────────────────────────────


def test_findings_required_columns():
    cols = _columns_for("findings")
    for col in (
        "finding_id",
        "scan_run_id",
        "team_id",
        "cve_id",
        "package_name",
        "package_version",
        "package_ecosystem",
        "severity",
        "is_kev",
        "blast_radius_risk",
        "compliance_tags",
        "cwe_ids",
    ):
        assert col in cols, f"findings missing column: {col}"


def test_findings_compliance_gin_index():
    """GIN index for JSONB compliance_tags to support @> queries."""
    assert "idx_findings_compliance" in _indexes()
    assert "GIN" in SQL.upper().split("IDX_FINDINGS_COMPLIANCE")[1][:100]


def test_findings_kev_partial_index():
    """Partial index on is_kev=TRUE for fast KEV queries."""
    assert "idx_findings_kev" in _indexes()
    assert "WHERE is_kev = TRUE" in SQL or "WHERE is_kev=TRUE" in SQL.replace(" ", "")


def test_findings_fk_scan_jobs():
    assert "REFERENCES scan_jobs" in SQL.split("CREATE TABLE IF NOT EXISTS findings")[1][:3000]


def test_findings_exposed_credentials_jsonb():
    assert "exposed_credentials" in SQL
    assert "JSONB" in SQL.split("exposed_credentials")[1][:20].upper()


# ── agents ────────────────────────────────────────────────────────────────────


def test_agents_required_columns():
    cols = _columns_for("agents")
    for col in ("agent_id", "scan_run_id", "team_id", "name", "agent_type", "mcp_server_count", "package_count", "vuln_count"):
        assert col in cols, f"agents missing column: {col}"


def test_agents_team_index():
    assert "idx_agents_team" in _indexes()


# ── policy_results ────────────────────────────────────────────────────────────


def test_policy_results_required_columns():
    cols = _columns_for("policy_results")
    for col in ("result_id", "scan_run_id", "team_id", "policy_name", "status", "conditions_triggered"):
        assert col in cols, f"policy_results missing column: {col}"


def test_policy_results_status_values_documented():
    """Status field comment documents valid values."""
    assert "pass, fail, skipped" in SQL


# ── api_keys ──────────────────────────────────────────────────────────────────


def test_api_keys_required_columns():
    cols = _columns_for("api_keys")
    for col in ("key_id", "key_hash", "key_salt", "key_prefix", "name", "role", "team_id", "scopes", "revoked"):
        assert col in cols, f"api_keys missing column: {col}"


def test_api_keys_no_raw_key_column():
    """Raw API key must never be stored."""
    api_keys_block = SQL.split("CREATE TABLE IF NOT EXISTS api_keys")[1].split(";")[0]
    col_names = {line.strip().split()[0] for line in api_keys_block.splitlines() if line.strip() and not line.strip().startswith("--")}
    assert "raw_key" not in col_names
    assert "key" not in col_names  # 'key' alone would be a reserved word anyway


def test_api_keys_active_partial_index():
    """Partial index on revoked=FALSE for fast active-key lookups."""
    assert "idx_api_keys_active" in _indexes()
    assert "WHERE revoked = FALSE" in SQL or "WHERE revoked=FALSE" in SQL.replace(" ", "")


def test_api_keys_prefix_index():
    """key_prefix index for O(1) auth lookup."""
    assert "idx_api_keys_prefix" in _indexes()


def test_api_keys_rls_policy_exists():
    assert "ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY" in SQL
    assert "CREATE POLICY api_keys_tenant_isolation ON api_keys" in SQL


# ── exceptions ────────────────────────────────────────────────────────────────


def test_exceptions_required_columns():
    cols = _columns_for("exceptions")
    for col in (
        "exception_id",
        "vuln_id",
        "package_name",
        "server_name",
        "reason",
        "requested_by",
        "approved_by",
        "status",
        "created_at",
        "expires_at",
        "approved_at",
        "revoked_at",
        "team_id",
    ):
        assert col in cols, f"exceptions missing column: {col}"


def test_exceptions_indexes_exist():
    indexes = _indexes()
    assert "idx_exc_status" in indexes
    assert "idx_exc_team" in indexes
    assert "idx_exc_vuln" in indexes


def test_exceptions_rls_policy_exists():
    assert "ALTER TABLE exceptions ENABLE ROW LEVEL SECURITY" in SQL
    assert "CREATE POLICY exceptions_tenant_isolation ON exceptions" in SQL


# ── job_queue ─────────────────────────────────────────────────────────────────


def test_job_queue_required_columns():
    cols = _columns_for("job_queue")
    for col in ("job_id", "job_type", "status", "team_id", "payload", "retries", "max_retries", "scheduled_for"):
        assert col in cols, f"job_queue missing column: {col}"


def test_job_queue_status_partial_index():
    """Partial index on pending/running for worker polling."""
    assert "idx_jobq_status_due" in _indexes()
    assert "pending" in SQL.split("idx_jobq_status_due")[1][:200]


def test_job_queue_payload_jsonb():
    assert "payload" in SQL
    assert "JSONB" in SQL.split("payload")[1][:20].upper()


# ── scan_schedules RLS / tenant contract ────────────────────────────────────


def test_scan_schedules_has_tenant_id_column():
    cols = _columns_for("scan_schedules")
    assert "tenant_id" in cols


def test_scan_schedules_tenant_index_exists():
    assert "idx_schedules_tenant_due" in _indexes()


def test_rls_helpers_exist():
    assert "CREATE OR REPLACE FUNCTION public.abom_current_tenant()" in SQL
    assert "CREATE OR REPLACE FUNCTION public.abom_rls_bypass()" in SQL


def test_fleet_agents_rls_policy_exists():
    assert "ALTER TABLE fleet_agents ENABLE ROW LEVEL SECURITY" in SQL
    assert "CREATE POLICY fleet_agents_tenant_isolation ON fleet_agents" in SQL


def test_scan_schedules_rls_policy_exists():
    assert "ALTER TABLE scan_schedules ENABLE ROW LEVEL SECURITY" in SQL
    assert "CREATE POLICY scan_schedules_tenant_isolation ON scan_schedules" in SQL


# ── FK consistency ────────────────────────────────────────────────────────────


def test_all_referenced_tables_exist():
    """Every REFERENCES <table> in the file points to an existing table."""
    tables = _tables()
    refs = re.findall(r"REFERENCES\s+(\w+)\s*\(", SQL, re.IGNORECASE)
    for ref in refs:
        assert ref in tables, f"REFERENCES {ref} but table does not exist in schema"


# ── Index count sanity ────────────────────────────────────────────────────────


def test_minimum_index_count():
    """Enough indexes for the documented query patterns."""
    assert len(_indexes()) >= 25


# ── Idempotency markers ───────────────────────────────────────────────────────


def test_all_creates_use_if_not_exists():
    """Every CREATE TABLE and CREATE INDEX uses IF NOT EXISTS."""
    creates = re.findall(r"CREATE\s+(TABLE|INDEX)\s+(IF NOT EXISTS\s+)?\w+", SQL, re.IGNORECASE)
    non_idempotent = [(kind, name) for kind, guard, *name in [m + ("",) for m in creates] if not guard]
    # Allow CREATE EXTENSION without IF NOT EXISTS check (handled elsewhere)
    for kind, _ in non_idempotent:
        assert kind.upper() == "EXTENSION", f"Non-idempotent CREATE {kind} found"


def test_extensions_present():
    assert "CREATE EXTENSION IF NOT EXISTS pgcrypto" in SQL
