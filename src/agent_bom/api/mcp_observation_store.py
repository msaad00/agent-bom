"""Persisted MCP observation records for correlated inventory provenance."""

from __future__ import annotations

import sqlite3
import threading
from typing import Protocol

from pydantic import BaseModel, Field, field_validator

from agent_bom.api.storage_schema import ensure_sqlite_schema_version
from agent_bom.platform_invariants import normalize_tenant_id, normalize_timestamp, now_utc_iso


class MCPObservation(BaseModel):
    tenant_id: str = "default"
    observation_id: str
    server_stable_id: str
    server_fingerprint: str = ""
    server_name: str
    agent_name: str = ""
    transport: str = ""
    url: str | None = None
    auth_mode: str = "local-stdio"
    command: str = ""
    args: list[str] = Field(default_factory=list)
    config_path: str | None = None
    credential_env_vars: list[str] = Field(default_factory=list)
    security_warnings: list[str] = Field(default_factory=list)
    observed_via: list[str] = Field(default_factory=list)
    observed_scopes: list[str] = Field(default_factory=list)
    scan_sources: list[str] = Field(default_factory=list)
    source_agents: list[str] = Field(default_factory=list)
    configured_locally: bool = False
    fleet_present: bool = False
    gateway_registered: bool = False
    runtime_observed: bool = False
    first_seen: str | None = None
    last_seen: str | None = None
    last_synced: str | None = None
    updated_at: str = Field(default_factory=now_utc_iso)

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _normalize_tenant_id(cls, value: str | None) -> str:
        return normalize_tenant_id(value)

    @field_validator("first_seen", "last_seen", "last_synced", "updated_at", mode="before")
    @classmethod
    def _normalize_timestamp(cls, value: str | None) -> str | None:
        return normalize_timestamp(value)


def _pick_timestamp(*values: str | None, prefer: str) -> str | None:
    candidates = [value for value in values if value]
    if not candidates:
        return None
    return min(candidates) if prefer == "min" else max(candidates)


def merge_observations(existing: MCPObservation | None, incoming: MCPObservation) -> MCPObservation:
    if existing is None:
        return incoming
    if existing.tenant_id != incoming.tenant_id:
        raise ValueError("tenant mismatch in observation merge")
    return MCPObservation(
        tenant_id=incoming.tenant_id,
        observation_id=incoming.observation_id,
        server_stable_id=incoming.server_stable_id or existing.server_stable_id,
        server_fingerprint=incoming.server_fingerprint or existing.server_fingerprint,
        server_name=incoming.server_name or existing.server_name,
        agent_name=incoming.agent_name or existing.agent_name,
        transport=incoming.transport or existing.transport,
        url=incoming.url or existing.url,
        auth_mode=incoming.auth_mode or existing.auth_mode,
        command=incoming.command or existing.command,
        args=incoming.args or existing.args,
        config_path=incoming.config_path or existing.config_path,
        credential_env_vars=sorted(set(existing.credential_env_vars) | set(incoming.credential_env_vars)),
        security_warnings=sorted(set(existing.security_warnings) | set(incoming.security_warnings)),
        observed_via=sorted(set(existing.observed_via) | set(incoming.observed_via)),
        observed_scopes=sorted(set(existing.observed_scopes) | set(incoming.observed_scopes)),
        scan_sources=sorted(set(existing.scan_sources) | set(incoming.scan_sources)),
        source_agents=sorted(set(existing.source_agents) | set(incoming.source_agents)),
        # Preserve the strongest persisted assertion rather than letting a later
        # read-path discovery pass rewrite provenance state opportunistically.
        configured_locally=existing.configured_locally,
        fleet_present=existing.fleet_present or incoming.fleet_present,
        gateway_registered=existing.gateway_registered or incoming.gateway_registered,
        runtime_observed=existing.runtime_observed or incoming.runtime_observed,
        first_seen=_pick_timestamp(existing.first_seen, incoming.first_seen, prefer="min"),
        last_seen=_pick_timestamp(existing.last_seen, incoming.last_seen, prefer="max"),
        last_synced=_pick_timestamp(existing.last_synced, incoming.last_synced, prefer="max"),
    )


class MCPObservationStore(Protocol):
    def put(self, observation: MCPObservation) -> None: ...
    def get(self, tenant_id: str, observation_id: str) -> MCPObservation | None: ...
    def list_by_tenant(self, tenant_id: str) -> list[MCPObservation]: ...


class InMemoryMCPObservationStore:
    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], MCPObservation] = {}
        self._lock = threading.Lock()

    def put(self, observation: MCPObservation) -> None:
        normalized = MCPObservation.model_validate(observation.model_dump())
        with self._lock:
            self._rows[(normalized.tenant_id, normalized.observation_id)] = normalized

    def get(self, tenant_id: str, observation_id: str) -> MCPObservation | None:
        with self._lock:
            return self._rows.get((tenant_id, observation_id))

    def list_by_tenant(self, tenant_id: str) -> list[MCPObservation]:
        with self._lock:
            return sorted(
                [row for (row_tenant, _), row in self._rows.items() if row_tenant == tenant_id],
                key=lambda row: (row.agent_name.lower(), row.server_name.lower(), row.observation_id),
            )


class SQLiteMCPObservationStore:
    def __init__(self, db_path: str = "agent_bom_jobs.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        return self._local.conn

    def _init_db(self) -> None:
        ensure_sqlite_schema_version(self._conn, "mcp_observations")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS mcp_observations (
                tenant_id TEXT NOT NULL,
                observation_id TEXT NOT NULL,
                server_name TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, observation_id)
            )
        """)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_mcp_observations_tenant_server ON mcp_observations(tenant_id, server_name)")
        self._conn.commit()

    def put(self, observation: MCPObservation) -> None:
        normalized = MCPObservation.model_validate(observation.model_dump())
        self._conn.execute(
            """INSERT OR REPLACE INTO mcp_observations
               (tenant_id, observation_id, server_name, updated_at, data)
               VALUES (?, ?, ?, ?, ?)""",
            (
                normalized.tenant_id,
                normalized.observation_id,
                normalized.server_name,
                normalized.updated_at,
                normalized.model_dump_json(),
            ),
        )
        self._conn.commit()

    def get(self, tenant_id: str, observation_id: str) -> MCPObservation | None:
        row = self._conn.execute(
            "SELECT data FROM mcp_observations WHERE tenant_id = ? AND observation_id = ?",
            (tenant_id, observation_id),
        ).fetchone()
        if row is None:
            return None
        return MCPObservation.model_validate_json(row[0])

    def list_by_tenant(self, tenant_id: str) -> list[MCPObservation]:
        rows = self._conn.execute(
            "SELECT data FROM mcp_observations WHERE tenant_id = ? ORDER BY server_name, updated_at DESC",
            (tenant_id,),
        ).fetchall()
        return [MCPObservation.model_validate_json(row[0]) for row in rows]
