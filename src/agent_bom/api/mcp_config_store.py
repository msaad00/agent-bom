"""Served MCP-client-config distribution store (#3908).

A governed, tenant-scoped way to compose *chosen connectors* + an *assigned
profile* (runtime role blueprint) into ONE distributable ``.mcp.json`` /
``mcpServers`` document that an MCP client can consume from a single URL.

Security invariants:

* **Reference-only, never secret-bearing.** The served document lists each
  connector's credential *env-var names* as ``${VAR}`` reference placeholders
  (resolved by the consuming client from its own secret manager) and each cloud
  connection by its opaque handle with ``has_secret`` — it NEVER embeds secret
  material. This mirrors the existing connection-secret model
  (:class:`agent_bom.api.connection_store.CloudConnectionRecord`) where
  ``to_public_dict`` only ever exposes references.
* **Tenant-scoped.** Assignments are keyed by tenant; a cross-tenant fetch is a
  miss. Postgres enforces this with FORCE ROW LEVEL SECURITY.
* **Read-only distribution.** The served document is produced by GET; creating
  or revoking an assignment is a separate config-gated write.

The store follows the durable-by-default tiering used across the control plane:
in-memory (explicit ephemeral opt-out), SQLite (single-node durable default),
and Postgres (multi-replica, tenant RLS).
"""

from __future__ import annotations

import builtins
import json
import secrets
import sqlite3
import threading
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded_identity_history_limit(limit: int) -> int:
    return max(1, min(int(limit), 1_000))


class McpConfigConflictError(ValueError):
    """The requested assignment would violate a profile-binding invariant."""


class McpConfigRevisionConflictError(McpConfigConflictError):
    """The assignment changed after the caller read it."""


@dataclass
class McpClientConfigAssignment:
    """One tenant-scoped MCP-client-config assignment.

    ``profile_id`` names a runtime role blueprint; ``connector_ids`` are registry
    server ids / connector names; ``connection_ids`` are cloud-connection handles.
    None of these carry secret material — they are references composed into the
    served document at read time.
    """

    config_id: str
    tenant_id: str
    name: str
    profile_id: str
    connector_ids: list[str] = field(default_factory=list)
    connection_ids: list[str] = field(default_factory=list)
    created_at: str = ""
    created_by: str = ""
    updated_at: str = ""
    revoked: bool = False
    # Optional canonical runtime binding. Empty keeps pre-#4152 assignments
    # distribution-only; a non-empty identity is unique per tenant while live.
    identity_id: str = ""
    issuer: str = ""
    environment: str = ""
    allowed_tools: list[str] = field(default_factory=list)
    required_scopes: list[str] = field(default_factory=list)
    policy_ids: list[str] = field(default_factory=list)
    owner: str = ""
    status: str = "active"
    revision: int = 1
    expires_at: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


def _assignment_from_storage_row(row: Any) -> McpClientConfigAssignment:
    """Decode JSON while treating indexed lifecycle columns as authoritative."""

    payload = json.loads(row[0])
    payload.update(
        {
            "config_id": str(row[1]),
            "tenant_id": str(row[2]),
            "identity_id": str(row[3] or ""),
            "issuer": str(row[4] or ""),
            "environment": str(row[5] or ""),
            "status": str(row[6] or "active"),
            "revision": max(1, int(row[7] or 1)),
            "updated_at": str(row[8] or payload.get("created_at", "")),
            "revoked": bool(row[9]),
        }
    )
    return McpClientConfigAssignment(**payload)


class McpConfigStore(Protocol):
    def put(self, assignment: McpClientConfigAssignment) -> None: ...

    def get(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None: ...

    def get_active_for_identity(self, tenant_id: str, identity_id: str) -> McpClientConfigAssignment | None: ...

    def list_for_identity(
        self,
        tenant_id: str,
        identity_id: str,
        *,
        limit: int = 200,
    ) -> builtins.list[McpClientConfigAssignment]: ...

    def compare_and_swap(
        self,
        assignment: McpClientConfigAssignment,
        *,
        expected_revision: int,
    ) -> McpClientConfigAssignment: ...

    def revoke(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None: ...

    def list_for_tenant(
        self, tenant_id: str, *, include_revoked: bool = False, limit: int = 200
    ) -> builtins.list[McpClientConfigAssignment]: ...


class InMemoryMcpConfigStore:
    def __init__(self) -> None:
        self._rows: dict[str, McpClientConfigAssignment] = {}
        self._active_by_identity: dict[tuple[str, str], str] = {}
        self._by_identity: dict[tuple[str, str], set[str]] = {}
        self._lock = threading.Lock()

    def put(self, assignment: McpClientConfigAssignment) -> None:
        with self._lock:
            existing = self._rows.get(assignment.config_id)
            if existing is not None:
                raise McpConfigConflictError("MCP client profile already exists; use compare-and-swap to update it")
            stored = deepcopy(assignment)
            self._assert_identity_available(stored)
            if existing is not None:
                self._remove_active_index(existing)
            self._rows[stored.config_id] = stored
            if stored.identity_id:
                self._by_identity.setdefault((stored.tenant_id, stored.identity_id), set()).add(stored.config_id)
            self._add_active_index(stored)

    @staticmethod
    def _is_active_binding(assignment: McpClientConfigAssignment) -> bool:
        return bool(assignment.identity_id and not assignment.revoked and assignment.status == "active")

    def _assert_identity_available(self, assignment: McpClientConfigAssignment) -> None:
        if not self._is_active_binding(assignment):
            return
        key = (assignment.tenant_id, assignment.identity_id)
        current = self._active_by_identity.get(key)
        if current is not None and current != assignment.config_id:
            raise McpConfigConflictError("The managed identity already has an active client profile")

    def _remove_active_index(self, assignment: McpClientConfigAssignment) -> None:
        if not assignment.identity_id:
            return
        key = (assignment.tenant_id, assignment.identity_id)
        if self._active_by_identity.get(key) == assignment.config_id:
            self._active_by_identity.pop(key, None)

    def _add_active_index(self, assignment: McpClientConfigAssignment) -> None:
        if self._is_active_binding(assignment):
            self._active_by_identity[(assignment.tenant_id, assignment.identity_id)] = assignment.config_id

    def get(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
        with self._lock:
            row = self._rows.get(config_id)
            if row is None or row.tenant_id != tenant_id:
                return None
            return deepcopy(row)

    def get_active_for_identity(self, tenant_id: str, identity_id: str) -> McpClientConfigAssignment | None:
        if not identity_id:
            return None
        with self._lock:
            config_id = self._active_by_identity.get((tenant_id, identity_id))
            row = self._rows.get(config_id) if config_id is not None else None
            return deepcopy(row) if row is not None else None

    def list_for_identity(
        self,
        tenant_id: str,
        identity_id: str,
        *,
        limit: int = 200,
    ) -> builtins.list[McpClientConfigAssignment]:
        if not identity_id:
            return []
        with self._lock:
            rows = [self._rows[config_id] for config_id in self._by_identity.get((tenant_id, identity_id), set())]
            return deepcopy(
                sorted(rows, key=lambda row: (row.updated_at or row.created_at, row.config_id), reverse=True)[
                    : _bounded_identity_history_limit(limit)
                ]
            )

    def compare_and_swap(
        self,
        assignment: McpClientConfigAssignment,
        *,
        expected_revision: int,
    ) -> McpClientConfigAssignment:
        with self._lock:
            current = self._rows.get(assignment.config_id)
            if current is None or current.tenant_id != assignment.tenant_id:
                raise McpConfigRevisionConflictError("MCP client profile no longer exists")
            if current.revision != expected_revision:
                raise McpConfigRevisionConflictError("MCP client profile revision is stale")
            if current.identity_id != assignment.identity_id:
                raise McpConfigConflictError("A canonical profile binding cannot be rebound to another identity")
            candidate = deepcopy(replace(assignment, revision=expected_revision + 1))
            self._assert_identity_available(candidate)
            self._remove_active_index(current)
            self._rows[candidate.config_id] = candidate
            self._add_active_index(candidate)
            return deepcopy(candidate)

    def revoke(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
        with self._lock:
            current = self._rows.get(config_id)
            if current is None or current.tenant_id != tenant_id:
                return None
            if current.revoked:
                return deepcopy(current)
            revoked = replace(
                current,
                revoked=True,
                status="revoked",
                revision=current.revision + 1,
                updated_at=_now_iso(),
            )
            self._remove_active_index(current)
            self._rows[config_id] = revoked
            return deepcopy(revoked)

    def list_for_tenant(
        self, tenant_id: str, *, include_revoked: bool = False, limit: int = 200
    ) -> builtins.list[McpClientConfigAssignment]:
        with self._lock:
            rows = [r for r in self._rows.values() if r.tenant_id == tenant_id and (include_revoked or not r.revoked)]
            return deepcopy(sorted(rows, key=lambda r: r.created_at, reverse=True)[:limit])


class SQLiteMcpConfigStore:
    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._write_lock = threading.Lock()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "mcp_client_configs", version=2)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mcp_client_configs (
                config_id  TEXT PRIMARY KEY,
                tenant_id  TEXT NOT NULL,
                name       TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                identity_id TEXT NOT NULL DEFAULT '',
                issuer TEXT NOT NULL DEFAULT '',
                environment TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'active',
                revision INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT '',
                revoked    INTEGER NOT NULL DEFAULT 0,
                data       TEXT NOT NULL
            )
            """
        )
        columns = {str(row[1]) for row in self._conn.execute("PRAGMA table_info(mcp_client_configs)").fetchall()}
        had_status = "status" in columns
        had_updated_at = "updated_at" in columns
        for column, ddl in (
            ("identity_id", "TEXT NOT NULL DEFAULT ''"),
            ("issuer", "TEXT NOT NULL DEFAULT ''"),
            ("environment", "TEXT NOT NULL DEFAULT ''"),
            ("status", "TEXT NOT NULL DEFAULT 'active'"),
            ("revision", "INTEGER NOT NULL DEFAULT 1"),
            ("updated_at", "TEXT NOT NULL DEFAULT ''"),
        ):
            if column not in columns:
                self._conn.execute(f"ALTER TABLE mcp_client_configs ADD COLUMN {column} {ddl}")  # noqa: S608
        if not had_status:
            self._conn.execute("UPDATE mcp_client_configs SET status = CASE WHEN revoked = 1 THEN 'revoked' ELSE 'active' END")
        if not had_updated_at:
            self._conn.execute("UPDATE mcp_client_configs SET updated_at = created_at WHERE updated_at = ''")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_mcp_client_configs_tenant ON mcp_client_configs(tenant_id, created_at)")
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_client_configs_active_identity "
            "ON mcp_client_configs(tenant_id, identity_id) "
            "WHERE identity_id <> '' AND revoked = 0 AND status = 'active'"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_mcp_client_configs_identity_history "
            "ON mcp_client_configs(tenant_id, identity_id, updated_at DESC) WHERE identity_id <> ''"
        )
        self._conn.commit()

    def put(self, assignment: McpClientConfigAssignment) -> None:
        with self._write_lock:
            existing = self._conn.execute(
                "SELECT tenant_id, identity_id FROM mcp_client_configs WHERE config_id = ?", (assignment.config_id,)
            ).fetchone()
            if existing is not None:
                raise McpConfigConflictError("MCP client profile already exists; use compare-and-swap to update it")
            try:
                self._conn.execute(
                    "INSERT INTO mcp_client_configs "
                    "(config_id, tenant_id, name, profile_id, identity_id, issuer, environment, status, revision, "
                    "created_at, updated_at, revoked, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    self._values(assignment),
                )
                self._conn.commit()
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise McpConfigConflictError("The managed identity already has an active client profile") from exc

    @staticmethod
    def _values(assignment: McpClientConfigAssignment) -> tuple[Any, ...]:
        return (
            assignment.config_id,
            assignment.tenant_id,
            assignment.name,
            assignment.profile_id,
            assignment.identity_id,
            assignment.issuer,
            assignment.environment,
            assignment.status,
            int(assignment.revision),
            assignment.created_at,
            assignment.updated_at,
            1 if assignment.revoked else 0,
            json.dumps(asdict(assignment), sort_keys=True),
        )

    def get(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
        row = self._conn.execute(
            "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
            "FROM mcp_client_configs WHERE config_id = ? AND tenant_id = ?",
            (config_id, tenant_id),
        ).fetchone()
        return _assignment_from_storage_row(row) if row else None

    def get_active_for_identity(self, tenant_id: str, identity_id: str) -> McpClientConfigAssignment | None:
        if not identity_id:
            return None
        row = self._conn.execute(
            "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
            "FROM mcp_client_configs "
            "WHERE tenant_id = ? AND identity_id = ? AND identity_id <> '' "
            "AND revoked = 0 AND status = 'active'",
            (tenant_id, identity_id),
        ).fetchone()
        return _assignment_from_storage_row(row) if row else None

    def list_for_identity(
        self,
        tenant_id: str,
        identity_id: str,
        *,
        limit: int = 200,
    ) -> builtins.list[McpClientConfigAssignment]:
        if not identity_id:
            return []
        rows = self._conn.execute(
            "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
            "FROM mcp_client_configs WHERE tenant_id = ? AND identity_id = ? AND identity_id <> '' "
            "ORDER BY updated_at DESC, config_id DESC LIMIT ?",
            (tenant_id, identity_id, _bounded_identity_history_limit(limit)),
        ).fetchall()
        return [_assignment_from_storage_row(row) for row in rows]

    def compare_and_swap(
        self,
        assignment: McpClientConfigAssignment,
        *,
        expected_revision: int,
    ) -> McpClientConfigAssignment:
        with self._write_lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT identity_id, revision FROM mcp_client_configs WHERE config_id = ? AND tenant_id = ?",
                    (assignment.config_id, assignment.tenant_id),
                ).fetchone()
                if row is None or int(row[1]) != expected_revision:
                    raise McpConfigRevisionConflictError("MCP client profile revision is stale")
                if str(row[0]) != assignment.identity_id:
                    raise McpConfigConflictError("A canonical profile binding cannot be rebound to another identity")
                candidate = replace(assignment, revision=expected_revision + 1)
                cursor = self._conn.execute(
                    "UPDATE mcp_client_configs SET name=?, profile_id=?, issuer=?, environment=?, status=?, "
                    "revision=?, updated_at=?, revoked=?, data=? "
                    "WHERE config_id=? AND tenant_id=? AND revision=?",
                    (
                        candidate.name,
                        candidate.profile_id,
                        candidate.issuer,
                        candidate.environment,
                        candidate.status,
                        candidate.revision,
                        candidate.updated_at,
                        1 if candidate.revoked else 0,
                        json.dumps(asdict(candidate), sort_keys=True),
                        candidate.config_id,
                        candidate.tenant_id,
                        expected_revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise McpConfigRevisionConflictError("MCP client profile revision is stale")
                self._conn.commit()
                return candidate
            except sqlite3.IntegrityError as exc:
                self._conn.rollback()
                raise McpConfigConflictError("The managed identity already has an active client profile") from exc
            except Exception:
                self._conn.rollback()
                raise

    def revoke(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
        with self._write_lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
                    "FROM mcp_client_configs WHERE config_id = ? AND tenant_id = ?",
                    (config_id, tenant_id),
                ).fetchone()
                if row is None:
                    self._conn.rollback()
                    return None
                current = _assignment_from_storage_row(row)
                if current.revoked:
                    self._conn.commit()
                    return current
                revoked = replace(
                    current,
                    revoked=True,
                    status="revoked",
                    revision=current.revision + 1,
                    updated_at=_now_iso(),
                )
                self._conn.execute(
                    "UPDATE mcp_client_configs SET status=?, revision=?, updated_at=?, revoked=1, data=? "
                    "WHERE config_id=? AND tenant_id=? AND revision=?",
                    (
                        revoked.status,
                        revoked.revision,
                        revoked.updated_at,
                        json.dumps(asdict(revoked), sort_keys=True),
                        config_id,
                        tenant_id,
                        current.revision,
                    ),
                )
                self._conn.commit()
                return revoked
            except Exception:
                self._conn.rollback()
                raise

    def list_for_tenant(
        self, tenant_id: str, *, include_revoked: bool = False, limit: int = 200
    ) -> builtins.list[McpClientConfigAssignment]:
        if include_revoked:
            rows = self._conn.execute(
                "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
                "FROM mcp_client_configs WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data, config_id, tenant_id, identity_id, issuer, environment, status, revision, updated_at, revoked "
                "FROM mcp_client_configs WHERE tenant_id = ? AND revoked = 0 ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [_assignment_from_storage_row(row) for row in rows]


# ── Composition (reference-only served document) ─────────────────────────────────


def _credential_reference(env_var: str, connector_id: str) -> dict[str, str]:
    """Represent one credential as a reference — never a value.

    ``value`` is the standard ``${VAR}`` env-expansion placeholder the consuming
    MCP client resolves from its own environment / secret manager. ``handle`` is
    an opaque control-plane reference to the connector's declared credential.
    """
    return {
        "value": f"${{{env_var}}}",
        "handle": f"connector:{connector_id}:{env_var}",
        "source": "reference",
    }


def build_served_mcp_config(
    assignment: McpClientConfigAssignment,
    *,
    registry: list[dict[str, Any]],
    profile: dict[str, Any] | None,
    connections: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compose the served ``.mcp.json`` document for ``assignment``.

    The result carries ``mcpServers`` (one entry per selected connector, with
    credential *references* only), the assigned ``profile`` blueprint, and any
    referenced cloud ``connections`` (by handle). It contains NO secret values.
    """
    by_id = {str(entry.get("id")): entry for entry in registry}
    servers: dict[str, Any] = {}
    unknown: list[str] = []
    for connector_id in assignment.connector_ids:
        entry = by_id.get(connector_id)
        if entry is None:
            unknown.append(connector_id)
            continue
        env_vars = [str(v) for v in (entry.get("credential_env_vars") or []) if str(v)]
        packages = entry.get("packages") or []
        server: dict[str, Any] = {
            "connector_id": connector_id,
            "name": entry.get("name") or connector_id,
            "transport": entry.get("transport") or "stdio",
            "publisher": entry.get("publisher"),
            "risk_level": entry.get("risk_level"),
            "packages": packages,
            # Credentials are references only — never resolved secret values.
            "env": {env_var: _credential_reference(env_var, connector_id) for env_var in env_vars},
            "credential_references": [f"connector:{connector_id}:{env_var}" for env_var in env_vars],
        }
        servers[str(entry.get("name") or connector_id)] = server

    connection_refs: list[dict[str, Any]] = []
    for conn in connections or []:
        connection_refs.append(
            {
                "connection_id": conn.get("connection_id") or conn.get("id"),
                "provider": conn.get("provider"),
                "display_name": conn.get("display_name"),
                # Reference the secret by presence flag + handle only.
                "has_secret": bool(conn.get("has_external_id")),
                "handle": f"connection:{conn.get('connection_id') or conn.get('id')}",
            }
        )

    return {
        "schema_version": "mcp.client.config.v1",
        "config_id": assignment.config_id,
        "tenant_id": assignment.tenant_id,
        "name": assignment.name,
        "profile": profile,
        "profile_id": assignment.profile_id,
        "mcpServers": servers,
        "connections": connection_refs,
        "unknown_connectors": unknown,
        "generated_at": _now_iso(),
        "read_only": True,
    }


# ── Lifecycle + selection ────────────────────────────────────────────────────────


def create_assignment(
    store: McpConfigStore,
    *,
    tenant_id: str,
    name: str,
    profile_id: str,
    connector_ids: list[str],
    connection_ids: list[str] | None = None,
    created_by: str = "",
    identity_id: str = "",
    issuer: str = "",
    environment: str = "",
    allowed_tools: list[str] | None = None,
    required_scopes: list[str] | None = None,
    policy_ids: list[str] | None = None,
    owner: str = "",
    expires_at: str = "",
) -> McpClientConfigAssignment:
    """Create and persist a tenant-scoped MCP-client-config assignment."""
    now = _now_iso()
    assignment = McpClientConfigAssignment(
        config_id=f"mcpcfg_{secrets.token_hex(8)}",
        tenant_id=tenant_id,
        name=name[:200],
        profile_id=profile_id,
        connector_ids=list(connector_ids),
        connection_ids=list(connection_ids or []),
        created_at=now,
        created_by=created_by[:200],
        updated_at=now,
        revoked=False,
        identity_id=identity_id.strip()[:200],
        issuer=issuer.strip()[:500],
        environment=environment.strip()[:120],
        allowed_tools=list(dict.fromkeys(allowed_tools or [])),
        required_scopes=list(dict.fromkeys(required_scopes or [])),
        policy_ids=list(dict.fromkeys(policy_ids or [])),
        owner=owner.strip()[:200],
        status="active",
        revision=1,
        expires_at=expires_at,
    )
    store.put(assignment)
    return assignment


def revoke_assignment(store: McpConfigStore, *, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
    return store.revoke(tenant_id, config_id)


_MCP_CONFIG_STORE: McpConfigStore | None = None


def get_mcp_config_store() -> McpConfigStore:
    """Return the process MCP-config store, durable by default (see module docs)."""
    global _MCP_CONFIG_STORE
    if _MCP_CONFIG_STORE is not None:
        return _MCP_CONFIG_STORE
    from agent_bom.api.durable_store import select_backend, sqlite_path

    backend = select_backend()
    if backend == "postgres":
        from agent_bom.api.postgres_mcp_config import PostgresMcpConfigStore

        _MCP_CONFIG_STORE = PostgresMcpConfigStore()
    elif backend == "memory":
        _MCP_CONFIG_STORE = InMemoryMcpConfigStore()
    else:
        _MCP_CONFIG_STORE = SQLiteMcpConfigStore(sqlite_path())
    return _MCP_CONFIG_STORE


def set_mcp_config_store(store: McpConfigStore | None) -> None:
    global _MCP_CONFIG_STORE
    _MCP_CONFIG_STORE = store
