"""Postgres migrations own schema writes; runtime stores validate only."""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.api.storage_schema import ensure_postgres_schema_version

ROOT = Path(__file__).resolve().parents[1]


class _Result:
    def fetchone(self) -> tuple[int]:
        return (1,)


class _Connection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, statement: str, params: object = None) -> _Result:
        del params
        self.statements.append(" ".join(statement.split()))
        return _Result()


def test_configured_postgres_schema_check_is_read_only(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://agent_bom_app@postgres/agent_bom")
    connection = _Connection()

    should_bootstrap = ensure_postgres_schema_version(connection, "graph")

    assert should_bootstrap is False
    assert connection.statements == [
        "SELECT version FROM control_plane_schema_versions WHERE component = %s",
    ]


def test_legacy_postgres_db_setting_uses_the_same_read_only_contract(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", "postgresql://agent_bom_app@postgres/agent_bom")
    connection = _Connection()

    assert ensure_postgres_schema_version(connection, "graph") is False
    assert connection.statements == [
        "SELECT version FROM control_plane_schema_versions WHERE component = %s",
    ]


def test_legacy_postgres_db_setting_resolves_the_pool_url(monkeypatch) -> None:
    from agent_bom.api.postgres_common import resolve_postgres_url

    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv("AGENT_BOM_DB", "postgresql://agent_bom_app:secret@postgres/agent_bom")

    assert resolve_postgres_url() == "postgresql://agent_bom_app@postgres/agent_bom"


def test_every_postgres_store_guards_runtime_schema_ddl() -> None:
    offenders: list[str] = []
    runtime_schema_files = list((ROOT / "src" / "agent_bom" / "api").glob("postgres*.py"))
    runtime_schema_files.extend(
        ROOT / "src" / "agent_bom" / "api" / name
        for name in ("idempotency_store.py", "middleware.py", "proxy_replay_store.py", "shared_auth_state.py")
    )
    for path in sorted(runtime_schema_files):
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            if "ensure_postgres_schema_version(" not in line or line.lstrip().startswith("def "):
                continue
            if not any(
                guard in line
                for guard in ("if not ensure_postgres_schema_version(", "if ensure_postgres_schema_version(")
            ):
                offenders.append(f"{path.relative_to(ROOT)}:{line_number}")

    assert offenders == []


def test_compliance_ingest_does_not_probe_schema_on_each_write() -> None:
    source = (ROOT / "src" / "agent_bom" / "api" / "postgres_compliance_hub.py").read_text()
    write_path = source.split("def _write_ledger_batch", 1)[1].split("\n    def ", 1)[0]

    assert "ensure_postgres_reference_tables" not in write_path


def test_postgres_baseline_keeps_bootstrap_owner_out_of_runtime_without_self_demotion() -> None:
    baseline = (ROOT / "deploy" / "supabase" / "postgres" / "init.sql").read_text()

    assert "ALTER ROLE %I NOSUPERUSER NOBYPASSRLS" not in baseline
    assert "agent_bom_app" in baseline
    assert "REVOKE CREATE ON SCHEMA public FROM agent_bom_app" in baseline


def test_migration_schema_covers_every_runtime_postgres_table_and_component() -> None:
    api_root = ROOT / "src" / "agent_bom" / "api"
    runtime_paths = list(api_root.glob("postgres*.py"))
    runtime_paths.extend(
        api_root / name
        for name in (
            "hub_reference_store.py",
            "idempotency_store.py",
            "middleware.py",
            "proxy_replay_store.py",
            "shared_auth_state.py",
        )
    )
    runtime_source = "\n".join(path.read_text() for path in runtime_paths)
    migration_sql = (ROOT / "deploy" / "supabase" / "postgres" / "runtime-schema.sql").read_text()
    baseline_sql = (ROOT / "deploy" / "supabase" / "postgres" / "init.sql").read_text()

    runtime_tables = set(re.findall(r"CREATE TABLE IF NOT EXISTS\s+([a-z_]+)", runtime_source, re.IGNORECASE))
    migrated_tables = set(re.findall(r"CREATE TABLE IF NOT EXISTS\s+([a-z_]+)", baseline_sql + migration_sql, re.IGNORECASE))
    assert runtime_tables - migrated_tables == set()

    components = set(re.findall(r'ensure_postgres_schema_version\(conn,\s*"([^"]+)"', runtime_source))
    components.add("proxy_replay_log")
    marker_section = migration_sql.split("-- Readiness markers: deliberately last.", 1)[1]
    assert components == set(re.findall(r"'([a-z_]+)'", marker_section))
    assert migration_sql.rfind("INSERT INTO control_plane_schema_versions") > migration_sql.rfind("CREATE TABLE")


def test_migration_schema_uses_the_runtime_rls_contract_and_exact_dml_columns() -> None:
    sql = (ROOT / "deploy" / "supabase" / "postgres" / "runtime-schema.sql").read_text()

    assert "public.abom_current_tenant()" in sql
    assert "public.abom_rls_bypass()" in sql
    assert "app.current_tenant" not in sql
    for required_fragment in (
        "cloud_connections (id TEXT PRIMARY KEY",
        "display_name TEXT NOT NULL",
        "credential_refs (credential_ref_id TEXT PRIMARY KEY",
        "model_provider_keys (provider_key_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,provider TEXT NOT NULL,status TEXT NOT NULL",
        "model_virtual_keys (virtual_key_id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,provider_key_id TEXT NOT NULL",
        "scan_dispatch_queue (job_id TEXT PRIMARY KEY REFERENCES scan_jobs(job_id) ON DELETE CASCADE,tenant_id TEXT NOT NULL",
    ):
        assert required_fragment in sql
