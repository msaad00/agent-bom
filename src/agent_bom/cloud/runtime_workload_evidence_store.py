"""Durable persistence for CWPP runtime/EDR workload evidence (stage 3, #4158).

Three interchangeable backends behind one contract:

* :class:`InMemoryRuntimeWorkloadEvidenceStore` — explicit ephemeral opt-out
  (``AGENT_BOM_EPHEMERAL_STORE=1``); process-local, non-durable.
* :class:`SQLiteRuntimeWorkloadEvidenceStore` — node-local default, restart-safe,
  and safe under cross-process writers (WAL + busy timeout).
* :class:`PostgresRuntimeWorkloadEvidenceStore` — shared across control-plane
  replicas.

:func:`get_runtime_workload_evidence_store` selects the tier via
:func:`agent_bom.storage.factory.resolve_backend` with ``mode="durable"``
(Postgres → ephemeral opt-out → SQLite), matching the runtime event store so
CLI ingest and API enrichment share evidence across processes and workers.

Tenant isolation is application-level and follows the stage-1 lifecycle store
(:mod:`agent_bom.cloud.side_scan_lifecycle`): ``tenant_id`` leads every WHERE
clause and is part of the dedup key, so two tenants can carry the SAME logical
signal without one dropping or leaking into the other. Dedup is on
``(tenant_id, provider, account_id, workload_ref, dedup_key)``. Only redacted
metadata (never data-plane bytes) is stored — the signal already redacts itself
at construction.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Protocol

from agent_bom.cloud.runtime_workload_evidence import RuntimeWorkloadSignal, normalize_runtime_observed_at

if TYPE_CHECKING:
    from psycopg import Connection
    from psycopg_pool import ConnectionPool

_COLUMNS = (
    "tenant_id",
    "provider",
    "account_id",
    "workload_ref",
    "dedup_key",
    "workload_id",
    "signal_type",
    "severity",
    "observed_at",
    "source_id",
    "source_kind",
    "payload_json",
)
_RUNTIME_WORKLOAD_EVIDENCE_SCHEMA_VERSION = 2
_SQLITE_MIGRATION_PAGE_SIZE = 500
_KNOWN_CREDENTIAL_SQL_REGEX = (
    r"(sk|pk|rk)[-_](live|test|prod)[-_][[:alnum:]_]{10,}|"
    r"(AKIA|ASIA)[A-Z0-9]{16}|"
    r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}|"
    r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}|"
    r"xox[bpsar]-[A-Za-z0-9-]{10,}|"
    r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----|"
    r"[A-Za-z0-9_]+://[^[:space:]:]+:[^[:space:]@]+@|"
    r"(glpat|glcbt|gldt|glrt|glptt|glagent)-[A-Za-z0-9_-]{20,}|"
    r"ya29\.[A-Za-z0-9._-]{20,}|"
    r"sk-(proj-)?[A-Za-z0-9_-]{20,}|"
    r"(authorization[[:space:]]*:[[:space:]]*)?Bearer[[:space:]]+[^[:space:]]{8,}"
    r"|(api[_-]?key|credential|password|secret|token)[[:space:]]*[:=][[:space:]]*[^[:space:]]{4,}"
)
_SENSITIVE_METADATA_SQL_REGEX = (
    _KNOWN_CREDENTIAL_SQL_REGEX
    + r"|[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}"
    + r"|https?://[^[:space:]]+[?#][^[:space:]]*|[[:cntrl:]]"
)


def _row_values(signal: RuntimeWorkloadSignal) -> tuple[Any, ...]:
    return (
        signal.tenant_id,
        signal.provider,
        signal.account_id,
        signal.workload_ref,
        signal.dedup_key,
        signal.workload_id,
        signal.signal_type.value,
        signal.severity,
        signal.observed_at,
        signal.source_id,
        signal.source_kind,
        json.dumps(signal.to_dict(), sort_keys=True, separators=(",", ":")),
    )


def _signal_from_json(raw: str) -> RuntimeWorkloadSignal:
    payload = json.loads(raw)
    return RuntimeWorkloadSignal.from_dict(payload)


def _sqlite_component_version(connection: sqlite3.Connection) -> int:
    table = connection.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'control_plane_schema_versions'").fetchone()
    if table is None:
        return 0
    row = connection.execute(
        "SELECT version FROM control_plane_schema_versions WHERE component = ?",
        ("runtime_workload_evidence",),
    ).fetchone()
    return int(row[0]) if row is not None else 0


def _upgrade_sqlite_runtime_evidence_v2(connection: sqlite3.Connection) -> None:
    """Normalize legacy timestamps and rewrite payloads through current redaction."""
    last_rowid = 0
    while True:
        rows = connection.execute(
            "SELECT rowid, tenant_id, provider, account_id, workload_ref, dedup_key, "
            "signal_type, severity, observed_at, source_id, source_kind, payload_json "
            "FROM runtime_workload_evidence WHERE rowid > ? ORDER BY rowid LIMIT ?",
            (last_rowid, _SQLITE_MIGRATION_PAGE_SIZE),
        ).fetchall()
        if not rows:
            return
        updates: list[tuple[str, str, str, int]] = []
        for row in rows:
            normalized = normalize_runtime_observed_at(str(row["observed_at"]))
            if normalized is None:
                raise RuntimeError("runtime workload evidence contains an invalid legacy observation timestamp")
            try:
                payload = json.loads(str(row["payload_json"]))
            except (TypeError, ValueError) as exc:
                raise RuntimeError("runtime workload evidence contains an invalid legacy payload") from exc
            if not isinstance(payload, dict):
                raise RuntimeError("runtime workload evidence contains a non-object legacy payload")
            payload.update(
                {
                    "tenant_id": str(row["tenant_id"]),
                    "provider": str(row["provider"]),
                    "account_id": str(row["account_id"]),
                    "workload_ref": str(row["workload_ref"]),
                    "dedup_key": str(row["dedup_key"]),
                    "signal_type": str(row["signal_type"]),
                    "severity": str(row["severity"]),
                    "observed_at": normalized,
                    "source_id": str(row["source_id"]),
                    "source_kind": str(row["source_kind"]),
                }
            )
            try:
                signal = RuntimeWorkloadSignal.from_dict(payload)
            except (TypeError, ValueError) as exc:
                raise RuntimeError("runtime workload evidence legacy payload cannot be normalized safely") from exc
            safe_payload = json.dumps(signal.to_dict(), sort_keys=True, separators=(",", ":"))
            updates.append((signal.workload_id, signal.observed_at, safe_payload, int(row["rowid"])))
        connection.executemany(
            "UPDATE runtime_workload_evidence SET workload_id = ?, observed_at = ?, payload_json = ? WHERE rowid = ?",
            updates,
        )
        last_rowid = int(rows[-1]["rowid"])


class RuntimeWorkloadEvidenceStore(Protocol):
    """Contract shared by every runtime workload-evidence backend."""

    def init_schema(self) -> None: ...

    def put_batch(self, signals: list[RuntimeWorkloadSignal]) -> int:
        """Persist new signals, dedup on the scope key; return newly inserted count."""
        ...

    def list_for_tenant(self, tenant_id: str, *, limit: int = 5000) -> list[RuntimeWorkloadSignal]:
        """Return one tenant's signals, most recent first."""
        ...


class InMemoryRuntimeWorkloadEvidenceStore:
    """Process-local, non-durable store (default tier)."""

    def __init__(self) -> None:
        self._rows: dict[tuple[str, str, str, str, str], RuntimeWorkloadSignal] = {}
        self._lock = threading.Lock()

    def init_schema(self) -> None:  # pragma: no cover - nothing to create
        return None

    @staticmethod
    def _key(signal: RuntimeWorkloadSignal) -> tuple[str, str, str, str, str]:
        return (
            signal.tenant_id,
            signal.provider,
            signal.account_id.lower(),
            signal.workload_ref.lower(),
            signal.dedup_key,
        )

    def put_batch(self, signals: list[RuntimeWorkloadSignal]) -> int:
        inserted = 0
        with self._lock:
            for signal in signals:
                key = self._key(signal)
                if key not in self._rows:
                    self._rows[key] = signal
                    inserted += 1
        return inserted

    def list_for_tenant(self, tenant_id: str, *, limit: int = 5000) -> list[RuntimeWorkloadSignal]:
        with self._lock:
            rows = [s for s in self._rows.values() if s.tenant_id == tenant_id]
        rows.sort(key=lambda s: (s.observed_at, s.dedup_key), reverse=True)
        return rows[:limit]


class SQLiteRuntimeWorkloadEvidenceStore:
    """Node-local, restart-safe, cross-process-safe SQLite backend."""

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self._path = str(path)
        self._read_only = read_only
        if read_only:
            # Validate access without running migrations or creating SQLite
            # sidecar files. Optional export enrichment must be a pure read.
            with self._connect():
                pass
        else:
            self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        if self._read_only:
            uri = f"{Path(self._path).resolve().as_uri()}?mode=ro"
            connection = sqlite3.connect(uri, timeout=30, uri=True)
        else:
            connection = sqlite3.connect(self._path, timeout=30)
        connection.row_factory = sqlite3.Row
        if self._read_only:
            connection.execute("PRAGMA query_only=ON")
        else:
            connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def init_schema(self) -> None:
        with self._connect() as connection:
            from agent_bom.api.storage_schema import ensure_sqlite_schema_version

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS runtime_workload_evidence (
                    tenant_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    workload_ref TEXT NOT NULL,
                    dedup_key TEXT NOT NULL,
                    workload_id TEXT NOT NULL,
                    signal_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, provider, account_id, workload_ref, dedup_key)
                )
                """
            )
            component_version = _sqlite_component_version(connection)
            if component_version > _RUNTIME_WORKLOAD_EVIDENCE_SCHEMA_VERSION:
                raise RuntimeError("runtime workload evidence schema is newer than this agent-bom binary")
            if component_version < _RUNTIME_WORKLOAD_EVIDENCE_SCHEMA_VERSION:
                _upgrade_sqlite_runtime_evidence_v2(connection)
            # Match the ``list_for_tenant`` query: WHERE tenant_id = ?
            # ORDER BY observed_at DESC, dedup_key DESC. The leading tenant
            # predicate plus the two ORDER BY columns (same direction) lets the
            # planner satisfy the sort from the index instead of a temp b-tree.
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_rwe_tenant_observed_dedup "
                "ON runtime_workload_evidence (tenant_id, observed_at DESC, dedup_key DESC)"
            )
            # Drop the stale index that ordered by (tenant_id, workload_id,
            # observed_at) — unusable for the tenant read's ORDER BY.
            connection.execute("DROP INDEX IF EXISTS idx_rwe_tenant_workload_time")
            ensure_sqlite_schema_version(
                connection,
                "runtime_workload_evidence",
                version=_RUNTIME_WORKLOAD_EVIDENCE_SCHEMA_VERSION,
            )

    def put_batch(self, signals: list[RuntimeWorkloadSignal]) -> int:
        if not signals:
            return 0
        placeholders = ",".join("?" for _ in _COLUMNS)
        sql = f"INSERT OR IGNORE INTO runtime_workload_evidence ({','.join(_COLUMNS)}) VALUES ({placeholders})"  # noqa: S608
        with self._connect() as connection:
            before = connection.total_changes
            connection.executemany(sql, [_row_values(signal) for signal in signals])
            return connection.total_changes - before

    def list_for_tenant(self, tenant_id: str, *, limit: int = 5000) -> list[RuntimeWorkloadSignal]:
        with self._connect() as connection:
            if self._read_only:
                table_exists = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'runtime_workload_evidence'"
                ).fetchone()
                if table_exists is None:
                    return []
            if self._read_only:
                rows = connection.execute(
                    "SELECT payload_json FROM runtime_workload_evidence WHERE tenant_id = ? "
                    "ORDER BY julianday(observed_at) DESC, dedup_key DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT payload_json FROM runtime_workload_evidence WHERE tenant_id = ? "
                    "ORDER BY observed_at DESC, dedup_key DESC LIMIT ?",
                    (tenant_id, limit),
                ).fetchall()
        return [_signal_from_json(str(row["payload_json"])) for row in rows]


class PostgresRuntimeWorkloadEvidenceStore:
    """Shared Postgres backend with migration-owned schema and tenant RLS.

    Production construction uses the shared secret-aware Postgres pool and the
    same request-scoped tenant session as the rest of the control plane. An
    explicit ``dsn`` remains available only for isolated development/tests that
    own a throwaway table.
    """

    def __init__(
        self,
        dsn: str | None = None,
        *,
        table: str = "runtime_workload_evidence",
        pool: ConnectionPool | None = None,
    ) -> None:
        if not table.replace("_", "").isalnum():
            raise ValueError("table name must be alphanumeric/underscore")
        self._dsn = dsn
        self.table = table
        self._pool: Any = None
        if dsn is not None and pool is not None:
            raise ValueError("Pass either dsn or pool, not both")
        if dsn is None:
            from agent_bom.api.postgres_common import _get_pool

            self._pool = pool or _get_pool()
        else:
            self._pool = None
        self.init_schema()

    def _connect(self) -> Any:
        if self._dsn is None:
            raise RuntimeError("Direct Postgres connections require an explicit development/test DSN")
        import psycopg

        return psycopg.connect(self._dsn)

    @contextmanager
    def _tenant_connection(self, tenant_id: str) -> Iterator[Connection]:
        if self._pool is None:
            with self._connect() as conn:
                yield conn
            return

        from agent_bom.api.postgres_common import (
            _tenant_connection,
            reset_current_tenant,
            set_current_tenant,
        )

        token = set_current_tenant(tenant_id)
        try:
            with _tenant_connection(self._pool) as conn:
                yield conn
        finally:
            reset_current_tenant(token)

    def _create_schema(self, conn: Connection) -> None:
        # Serialize bootstrap DDL across processes. Every store construction runs
        # this path, so replicas and workers starting together each issue
        # CREATE INDEX / ALTER TABLE / DROP INDEX plus the v2 backfill UPDATE on
        # the same relation. Those take conflicting relation-level locks and
        # deadlock rather than queue — reproducible with concurrent writers
        # against real Postgres. The advisory lock is transaction-scoped, so it
        # releases on the commit below (or on rollback) with no cleanup path.
        conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"agent_bom.schema.{self.table}",))
        conn.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.table} (
                tenant_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                account_id TEXT NOT NULL,
                workload_ref TEXT NOT NULL,
                dedup_key TEXT NOT NULL,
                workload_id TEXT NOT NULL,
                signal_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                observed_at TIMESTAMPTZ NOT NULL,
                source_id TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (tenant_id, provider, account_id, workload_ref, dedup_key)
            )
            """  # noqa: S608  # nosec B608 -- table is validated in __init__; no values are interpolated
        )
        conn.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{self.table}_tenant_observed_dedup "  # noqa: S608
            f"ON {self.table} (tenant_id, observed_at DESC, dedup_key DESC)"
        )
        conn.execute("SET LOCAL TIME ZONE 'UTC'")
        conn.execute(
            f"""
            DO $$
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = current_schema()
                      AND table_name = '{self.table}'
                      AND column_name = 'observed_at'
                      AND data_type <> 'timestamp with time zone'
                ) THEN
                    ALTER TABLE {self.table}
                        ALTER COLUMN observed_at TYPE TIMESTAMPTZ
                        USING observed_at::timestamptz;
                END IF;
            END
            $$
            """  # noqa: S608  # nosec B608 -- table is validated in __init__; no values are interpolated
        )
        unsafe_identity = conn.execute(
            f"SELECT 1 FROM {self.table} "  # noqa: S608  # nosec B608 -- table is validated; values are parameterized
            "WHERE btrim(tenant_id) = '' OR btrim(provider) = '' OR btrim(account_id) = '' "
            "OR btrim(workload_ref) = '' OR btrim(workload_id) = '' OR btrim(source_id) = '' OR btrim(source_kind) = '' "
            "OR btrim(dedup_key) = '' OR length(tenant_id) > 256 OR length(account_id) > 512 "
            "OR length(workload_ref) > 2048 OR length(workload_id) > 4096 "
            "OR length(source_id) > 256 OR length(source_kind) > 128 "
            "OR length(dedup_key) > 512 OR provider NOT IN ('aws', 'azure', 'gcp') "
            "OR signal_type NOT IN ('process_exec', 'ioc_detection', 'network_connection', "
            "'file_integrity', 'behavioral_alert') "
            "OR workload_ref ~* %s OR workload_id ~* %s OR dedup_key ~* %s LIMIT 1",
            (_KNOWN_CREDENTIAL_SQL_REGEX, _KNOWN_CREDENTIAL_SQL_REGEX, _KNOWN_CREDENTIAL_SQL_REGEX),
        ).fetchone()
        if unsafe_identity is not None:
            raise RuntimeError("runtime workload evidence contains unsafe legacy identity rows")
        conn.execute(
            f"""
            WITH normalized AS (
                SELECT
                    ctid,
                    tenant_id,
                    provider,
                    account_id,
                    workload_ref,
                    workload_id,
                    signal_type,
                    CASE
                        WHEN lower(severity) IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')
                        THEN lower(severity)
                        ELSE 'unknown'
                    END AS severity,
                    observed_at,
                    source_id,
                    source_kind,
                    dedup_key,
                    payload_json::jsonb AS legacy_payload
                FROM {self.table}
            ),
            safe_metadata AS (
                SELECT
                    normalized.*,
                    CASE
                        WHEN COALESCE(legacy_payload->>'title', '') ~* %s THEN '<redacted>'
                        ELSE left(COALESCE(legacy_payload->>'title', ''), 256)
                    END AS safe_title,
                    COALESCE(
                        (
                            SELECT jsonb_object_agg(entry.key, to_jsonb(left(entry.value #>> '{{}}', 256)))
                            FROM jsonb_each(
                                CASE
                                    WHEN jsonb_typeof(legacy_payload->'evidence') = 'object'
                                    THEN legacy_payload->'evidence'
                                    ELSE '{{}}'::jsonb
                                END
                            ) AS entry(key, value)
                            WHERE entry.key IN (
                                'action', 'alert_id', 'alert_ref', 'category', 'count',
                                'destination_ref', 'event_type', 'file_ref', 'hash_ref', 'hash_type',
                                'indicator_ref', 'ioc_type', 'network_ref', 'outcome', 'process_ref',
                                'rule_id', 'rule_ref', 'source_ref', 'tactic_id', 'technique_id'
                            )
                              AND jsonb_typeof(entry.value) IN ('string', 'number', 'boolean')
                              AND NOT (entry.value #>> '{{}}') ~* %s
                        ),
                        '{{}}'::jsonb
                    ) AS safe_evidence
                FROM normalized
            ),
            scrubbed AS (
                SELECT
                    ctid,
                    jsonb_build_object(
                        'schema_version', 'agent-bom.cwpp.runtime_workload.evidence.v1',
                        'tenant_id', tenant_id,
                        'provider', provider,
                        'account_id', account_id,
                        'workload_ref', workload_ref,
                        'workload_id', workload_id,
                        'signal_type', signal_type,
                        'severity', severity,
                        'observed_at', to_char(
                            observed_at AT TIME ZONE 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
                        ),
                        'source_id', source_id,
                        'source_kind', source_kind,
                        'dedup_key', dedup_key,
                        'title', safe_title,
                        'evidence', safe_evidence
                    ) AS payload
                FROM safe_metadata
            )
            UPDATE {self.table} AS target
            SET payload_json = scrubbed.payload::text
            FROM scrubbed
            WHERE target.ctid = scrubbed.ctid
            """,  # noqa: S608  # nosec B608 -- table is validated; values are parameterized
            (_SENSITIVE_METADATA_SQL_REGEX, _SENSITIVE_METADATA_SQL_REGEX),
        )
        conn.execute(f"DROP INDEX IF EXISTS idx_{self.table}_tenant_time")  # noqa: S608
        conn.commit()

    def init_schema(self) -> None:
        if self._pool is not None:
            from agent_bom.api.storage_schema import ensure_postgres_schema_version

            with self._pool.connection() as conn:
                if not ensure_postgres_schema_version(conn, "runtime_workload_evidence", version=_RUNTIME_WORKLOAD_EVIDENCE_SCHEMA_VERSION):
                    return
                self._create_schema(conn)
            return

        with self._connect() as conn:
            self._create_schema(conn)

    def put_batch(self, signals: list[RuntimeWorkloadSignal]) -> int:
        if not signals:
            return 0
        tenant_ids = {signal.tenant_id for signal in signals}
        if len(tenant_ids) != 1:
            raise ValueError("A runtime workload evidence batch must contain exactly one tenant")
        tenant_id = next(iter(tenant_ids))
        placeholders = ",".join("%s" for _ in _COLUMNS)
        sql = (
            f"INSERT INTO {self.table} ({','.join(_COLUMNS)}) VALUES ({placeholders}) "  # noqa: S608  # nosec B608 — table validated in __init__, values parameterized
            "ON CONFLICT (tenant_id, provider, account_id, workload_ref, dedup_key) DO NOTHING"
        )
        inserted = 0
        with self._tenant_connection(tenant_id) as conn:
            with conn.cursor() as cur:
                for signal in signals:
                    cur.execute(sql, _row_values(signal))
                    inserted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            conn.commit()
        return inserted

    def list_for_tenant(self, tenant_id: str, *, limit: int = 5000) -> list[RuntimeWorkloadSignal]:
        with self._tenant_connection(tenant_id) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT payload_json FROM {self.table} WHERE tenant_id = %s "  # noqa: S608  # nosec B608 — table validated in __init__, values parameterized
                    "ORDER BY observed_at DESC, dedup_key DESC LIMIT %s",
                    (tenant_id, limit),
                )
                rows = cur.fetchall()
        return [_signal_from_json(str(row[0])) for row in rows]

    def drop_table(self) -> None:
        """Drop the backing relation (test cleanup helper)."""
        if self._pool is not None:
            raise RuntimeError("Migration-owned Postgres tables cannot be dropped by the runtime store")
        with self._connect() as conn:
            conn.execute(f"DROP TABLE IF EXISTS {self.table}")  # noqa: S608
            conn.commit()


# ── process-global default store (for the live enrichment read path) ─────────

_default_store: RuntimeWorkloadEvidenceStore | None = None
_default_lock = threading.Lock()


def get_runtime_workload_evidence_store() -> RuntimeWorkloadEvidenceStore:
    """Return the process default runtime workload-evidence store, durable by default.

    Selection (highest precedence first), via :mod:`agent_bom.storage.factory`:
    - Postgres (``AGENT_BOM_POSTGRES_URL`` / ``AGENT_BOM_DB`` Postgres URL):
      multi-replica — CLI ingest and API enrichment share one evidence table.
    - in-memory (``AGENT_BOM_EPHEMERAL_STORE=1``): explicit opt-out; signals are
      lost on restart and across processes/workers.
    - SQLite (default, or ``AGENT_BOM_DB`` file path): single-node durable —
      evidence survives a restart and is visible to a co-located API process.

    Tests and callers can still inject a store with
    :func:`set_runtime_workload_evidence_store`.
    """
    global _default_store
    with _default_lock:
        if _default_store is not None:
            return _default_store
        from agent_bom.storage.base import BackendKind
        from agent_bom.storage.factory import resolve_backend

        # mode="durable" matches runtime_event_store: Postgres → ephemeral only
        # on explicit opt-out → SQLite default. The prior always-InMemory factory
        # silently dropped CLI→API and multi-worker evidence.
        selection = resolve_backend(mode="durable")
        if selection.backend is BackendKind.POSTGRES:
            import os

            dsn = str(selection.dsn or os.environ.get("AGENT_BOM_POSTGRES_URL") or os.environ.get("AGENT_BOM_DB") or "")
            if not dsn.strip():
                raise RuntimeError("Postgres workload-evidence store selected but no Postgres URL is configured")
            # The production store resolves the configured URL, mounted secret
            # file/IAM token, pool bounds, and tenant RLS through postgres_common.
            # The raw password-free Compose DSN must never be connected directly.
            _default_store = PostgresRuntimeWorkloadEvidenceStore()
        elif selection.backend is BackendKind.MEMORY:
            _default_store = InMemoryRuntimeWorkloadEvidenceStore()
        else:
            _default_store = SQLiteRuntimeWorkloadEvidenceStore(selection.sqlite_path or "agent_bom.db")
        return _default_store


def get_optional_runtime_workload_evidence_store() -> RuntimeWorkloadEvidenceStore | None:
    """Return a non-mutating store for optional export enrichment.

    An explicitly initialized or injected store is reused. For the default
    SQLite tier, a missing or unreadable database means there is no optional
    evidence: do not create the state directory, database, schema, WAL, or SHM
    files merely to render a scan report. Durable ingest continues to use
    :func:`get_runtime_workload_evidence_store` and remains fail-closed.
    """
    with _default_lock:
        if _default_store is not None:
            return _default_store

    from agent_bom.api import durable_store

    backend = durable_store.select_backend()
    if backend != "sqlite":
        return get_runtime_workload_evidence_store()

    path = durable_store.sqlite_path(create_parent=False)
    if path == ":memory:" or not Path(path).is_file():
        return None
    try:
        return SQLiteRuntimeWorkloadEvidenceStore(path, read_only=True)
    except (OSError, sqlite3.Error):
        # Optional enrichment treats an inaccessible local evidence database as
        # absent. Corrupt/query failures still surface from list_for_tenant and
        # are sanitized by the caller's existing warning path.
        return None


def set_runtime_workload_evidence_store(store: RuntimeWorkloadEvidenceStore | None) -> None:
    global _default_store
    with _default_lock:
        _default_store = store


def reset_runtime_workload_evidence_store() -> None:
    set_runtime_workload_evidence_store(None)


__all__ = [
    "InMemoryRuntimeWorkloadEvidenceStore",
    "PostgresRuntimeWorkloadEvidenceStore",
    "RuntimeWorkloadEvidenceStore",
    "SQLiteRuntimeWorkloadEvidenceStore",
    "get_optional_runtime_workload_evidence_store",
    "get_runtime_workload_evidence_store",
    "reset_runtime_workload_evidence_store",
    "set_runtime_workload_evidence_store",
]
