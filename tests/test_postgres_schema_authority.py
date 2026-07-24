"""Postgres migrations own schema writes; runtime stores validate only."""

from __future__ import annotations

import importlib
import re
from pathlib import Path

from agent_bom.api.storage_schema import ensure_postgres_schema_version
from agent_bom.storage.base import StorageSchema, TableSchema

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
POSTGRES_DIR = ROOT / "deploy" / "supabase" / "postgres"

# Table-level constraint clauses share the comma-separated body with the column
# definitions; their leading keyword is how a parser tells the two apart.
_CONSTRAINT_KEYWORDS = frozenset({"primary", "foreign", "unique", "constraint", "check", "exclude", "like"})
_CREATE_TABLE_RE = re.compile(r"CREATE TABLE\s+(?:IF NOT EXISTS\s+)?([a-z_][a-z0-9_]*)\s*\(", re.IGNORECASE)
_ADD_COLUMN_RE = re.compile(
    r"ALTER TABLE\s+(?:IF EXISTS\s+)?([a-z_][a-z0-9_]*)\s+ADD COLUMN\s+(?:IF NOT EXISTS\s+)?([a-z_][a-z0-9_]*)",
    re.IGNORECASE,
)


def _read_sql_source(path: Path) -> str:
    """Read a SQL or Python file with implicit string concatenation resolved.

    Stores and revisions spell long DDL as adjacent double-quoted Python
    literals, so a column can straddle the seam between two lines. Joining them
    first lets one parser read ``.sql`` and ``.py`` sources alike.
    """

    return re.sub(r'"\s*\n\s*"', "", path.read_text())


def _split_top_level(body: str) -> list[str]:
    """Split a CREATE TABLE body on commas that are not nested or quoted."""

    parts: list[str] = []
    current: list[str] = []
    depth = 0
    in_quote = False
    for char in body:
        if in_quote:
            current.append(char)
            in_quote = char != "'"
            continue
        if char == "'":
            in_quote = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _columns_by_table(sql: str) -> dict[str, set[str]]:
    """Map every ``CREATE TABLE``/``ADD COLUMN`` in ``sql`` to its column names."""

    tables: dict[str, set[str]] = {}
    for match in _CREATE_TABLE_RE.finditer(sql):
        cursor = match.end()
        depth = 1
        in_quote = False
        while cursor < len(sql) and depth:
            char = sql[cursor]
            if in_quote:
                in_quote = char != "'"
            elif char == "'":
                in_quote = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            cursor += 1
        columns = tables.setdefault(match.group(1).lower(), set())
        for part in _split_top_level(sql[match.end() : cursor - 1]):
            name = part.split()[0].strip('"').lower()
            if name not in _CONSTRAINT_KEYWORDS:
                columns.add(name)
    for table, column in _ADD_COLUMN_RE.findall(sql):
        tables.setdefault(table.lower(), set()).add(column.lower())
    return tables


def _migration_authority_columns() -> dict[str, set[str]]:
    """Every column a migrated Postgres deployment actually ends up with.

    The authority is the baseline (``init.sql``), the wholesale runtime schema
    replayed by ``20260718_01`` (``runtime-schema.sql``), and the additive
    ``ALTER TABLE`` statements in the Alembic revisions — nothing else runs on a
    deployment where ``AGENT_BOM_POSTGRES_URL`` is configured.
    """

    sources = [POSTGRES_DIR / "init.sql", POSTGRES_DIR / "runtime-schema.sql"]
    sources.extend(sorted((POSTGRES_DIR / "alembic" / "versions").glob("*.py")))
    merged: dict[str, set[str]] = {}
    for path in sources:
        for table, columns in _columns_by_table(_read_sql_source(path)).items():
            merged.setdefault(table, set()).update(columns)
    return merged


def _declared_postgres_tables() -> list[tuple[str, TableSchema]]:
    """Discover every ``StorageSchema`` table that declares Postgres DDL.

    Discovery is by source scan + import rather than a hardcoded list so a store
    added later is covered by the parity guards without editing this file.
    """

    discovered: list[tuple[str, TableSchema]] = []
    for path in sorted((SRC / "agent_bom").rglob("*.py")):
        if "StorageSchema(" not in path.read_text():
            continue
        parts = list(path.relative_to(SRC).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts.pop()
        module = importlib.import_module(".".join(parts))
        for attribute, value in sorted(vars(module).items()):
            if not isinstance(value, StorageSchema):
                continue
            discovered.extend((f"{module.__name__}.{attribute}", table) for table in value.tables if table.ddl_for("postgres"))
    return discovered


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
    runtime_schema_files.append(ROOT / "src" / "agent_bom" / "cloud" / "runtime_workload_evidence_store.py")
    for path in sorted(runtime_schema_files):
        for line_number, line in enumerate(path.read_text().splitlines(), start=1):
            if "ensure_postgres_schema_version(" not in line or line.lstrip().startswith("def "):
                continue
            if not any(guard in line for guard in ("if not ensure_postgres_schema_version(", "if ensure_postgres_schema_version(")):
                offenders.append(f"{path.relative_to(ROOT)}:{line_number}")

    assert offenders == []


def test_compliance_ingest_does_not_probe_schema_on_each_write() -> None:
    source = (ROOT / "src" / "agent_bom" / "api" / "postgres_compliance_hub.py").read_text()
    write_path = source.split("def _write_ledger_batch", 1)[1].split("\n    def ", 1)[0]

    assert "ensure_postgres_reference_tables" not in write_path


def test_postgres_baseline_strips_demotable_owner_and_skips_bootstrap_role() -> None:
    """init.sql keeps the #3665 tenant-RLS safeguard: any demotable connecting
    role is stripped of SUPERUSER/BYPASSRLS as the last init step, while the
    protected cluster bootstrap role (oid 10, which Postgres refuses to demote)
    is warn-skipped so an Alembic baseline replay does not abort."""
    baseline = (ROOT / "deploy" / "supabase" / "postgres" / "init.sql").read_text()

    assert "ALTER ROLE %I NOSUPERUSER NOBYPASSRLS" in baseline
    # The bootstrap-role escape hatch must be present and loud, not silent.
    assert "oid FROM pg_roles WHERE rolname = current_user) = 10" in baseline
    assert "RAISE WARNING" in baseline
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
    runtime_paths.append(ROOT / "src" / "agent_bom" / "cloud" / "runtime_workload_evidence_store.py")
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


def test_declared_postgres_ddl_realises_every_logical_column() -> None:
    """A store's ``columns`` tuple and its Postgres ``CREATE TABLE`` must agree.

    The portable-schema seam only pays off if the logical column list and the
    per-backend DDL sitting next to it cannot drift; this asserts the Postgres
    side of that pair.
    """
    declared = _declared_postgres_tables()
    assert declared, "no StorageSchema Postgres tables discovered — the parity guards would pass vacuously"

    gaps = {
        f"{label}:{table.name}": sorted(set(table.columns) - _columns_by_table(table.ddl_for("postgres") or "").get(table.name, set()))
        for label, table in declared
    }
    assert {key: value for key, value in gaps.items() if value} == {}


def test_runtime_bootstrap_ddl_matches_the_declared_column_contract() -> None:
    """The DDL a store executes and the column tuple it declares must agree.

    The migration-parity guard below derives from ``StorageSchema.columns``, so
    that tuple has to stay the honest picture of what the store creates — a
    column added to the executed ``CREATE TABLE`` / ``ADD COLUMN`` but not to
    the declaration would slip past it.
    """
    declared = _declared_postgres_tables()
    assert declared, "no StorageSchema Postgres tables discovered — this guard would pass vacuously"

    executed: dict[str, set[str]] = {}
    for path in sorted((SRC / "agent_bom").rglob("*.py")):
        for table, columns in _columns_by_table(_read_sql_source(path)).items():
            executed.setdefault(table, set()).update(columns)

    drift = {f"{label}:{table.name}": sorted(executed.get(table.name, set()) ^ set(table.columns)) for label, table in declared}
    assert {key: value for key, value in drift.items() if value} == {}


def test_migration_authority_declares_every_column_the_postgres_stores_use() -> None:
    """Columns a store reads/writes must exist in migration-owned SQL.

    On a configured deployment ``ensure_postgres_schema_version`` returns False,
    so the stores' bootstrap ``CREATE TABLE`` / ``ADD COLUMN IF NOT EXISTS``
    statements never run and Alembic is the only thing that creates a column.
    A column that lands in the store but not in ``runtime-schema.sql`` (or a
    revision) therefore 500s with ``UndefinedColumn`` on the first real request
    while every fake-connection unit test stays green — the same class of defect
    the ``20260719_03`` attack_paths revision had to repair. This compares the
    two sides directly.
    """
    declared = _declared_postgres_tables()
    assert declared, "no StorageSchema Postgres tables discovered — this guard would pass vacuously"

    migrated = _migration_authority_columns()
    missing = {f"{label}:{table.name}": sorted(set(table.columns) - migrated.get(table.name, set())) for label, table in declared}
    assert {key: value for key, value in missing.items() if value} == {}
