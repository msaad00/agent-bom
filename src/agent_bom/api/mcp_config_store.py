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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_bom.api.storage_schema import ensure_sqlite_schema_version


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


class McpConfigStore(Protocol):
    def put(self, assignment: McpClientConfigAssignment) -> None: ...

    def get(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None: ...

    def list_for_tenant(
        self, tenant_id: str, *, include_revoked: bool = False, limit: int = 200
    ) -> builtins.list[McpClientConfigAssignment]: ...


class InMemoryMcpConfigStore:
    def __init__(self) -> None:
        self._rows: dict[str, McpClientConfigAssignment] = {}
        self._lock = threading.Lock()

    def put(self, assignment: McpClientConfigAssignment) -> None:
        with self._lock:
            self._rows[assignment.config_id] = assignment

    def get(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
        with self._lock:
            row = self._rows.get(config_id)
            if row is None or row.tenant_id != tenant_id:
                return None
            return row

    def list_for_tenant(
        self, tenant_id: str, *, include_revoked: bool = False, limit: int = 200
    ) -> builtins.list[McpClientConfigAssignment]:
        with self._lock:
            rows = [r for r in self._rows.values() if r.tenant_id == tenant_id and (include_revoked or not r.revoked)]
            return sorted(rows, key=lambda r: r.created_at, reverse=True)[:limit]


class SQLiteMcpConfigStore:
    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "mcp_client_configs")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mcp_client_configs (
                config_id  TEXT PRIMARY KEY,
                tenant_id  TEXT NOT NULL,
                name       TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                revoked    INTEGER NOT NULL DEFAULT 0,
                data       TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_mcp_client_configs_tenant ON mcp_client_configs(tenant_id, created_at)")
        self._conn.commit()

    def put(self, assignment: McpClientConfigAssignment) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO mcp_client_configs "
            "(config_id, tenant_id, name, profile_id, created_at, revoked, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                assignment.config_id,
                assignment.tenant_id,
                assignment.name,
                assignment.profile_id,
                assignment.created_at,
                1 if assignment.revoked else 0,
                json.dumps(asdict(assignment), sort_keys=True),
            ),
        )
        self._conn.commit()

    def get(self, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
        row = self._conn.execute(
            "SELECT data FROM mcp_client_configs WHERE config_id = ? AND tenant_id = ?", (config_id, tenant_id)
        ).fetchone()
        return McpClientConfigAssignment(**json.loads(row[0])) if row else None

    def list_for_tenant(
        self, tenant_id: str, *, include_revoked: bool = False, limit: int = 200
    ) -> builtins.list[McpClientConfigAssignment]:
        if include_revoked:
            rows = self._conn.execute(
                "SELECT data FROM mcp_client_configs WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?", (tenant_id, limit)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT data FROM mcp_client_configs WHERE tenant_id = ? AND revoked = 0 ORDER BY created_at DESC LIMIT ?",
                (tenant_id, limit),
            ).fetchall()
        return [McpClientConfigAssignment(**json.loads(r[0])) for r in rows]


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
    )
    store.put(assignment)
    return assignment


def revoke_assignment(store: McpConfigStore, *, tenant_id: str, config_id: str) -> McpClientConfigAssignment | None:
    assignment = store.get(tenant_id, config_id)
    if assignment is None:
        return None
    assignment.revoked = True
    assignment.updated_at = _now_iso()
    store.put(assignment)
    return assignment


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
