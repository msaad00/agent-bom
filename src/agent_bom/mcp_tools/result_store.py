"""Tenant/caller-bound, durable, bounded MCP scan result cache.

SQLite shares a state directory across local workers. Configured Postgres shares
results across hosts and requires an operator-applied migration. Storage errors
propagate: there is no process-local or anonymous fallback.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS mcp_scan_results (
    tenant_id TEXT NOT NULL, result_id TEXT NOT NULL, owner_digest TEXT NOT NULL,
    created_at DOUBLE PRECISION NOT NULL, expires_at DOUBLE PRECISION NOT NULL,
    data TEXT NOT NULL, PRIMARY KEY (tenant_id, result_id)
)
"""
_INDEX_SQL = "CREATE INDEX IF NOT EXISTS idx_mcp_result_expiry ON mcp_scan_results (tenant_id, expires_at, result_id)"
_ORDER_INDEX_SQL = "CREATE INDEX IF NOT EXISTS idx_mcp_result_order ON mcp_scan_results (tenant_id, created_at DESC, result_id DESC)"
MAX_RESULT_BYTES = 128 * 1024 * 1024


class ResultStore(Protocol):
    @property
    def ttl_seconds(self) -> float: ...

    def put(self, owner: str, result: dict[str, Any]) -> str: ...

    def get(self, owner: str, result_id: str) -> dict[str, Any] | None: ...


def scan_result_owner(request_ctx_getter: Callable[[], Any]) -> str:
    """Use verified token material, never request metadata or a shared client ID.

    Token rotation intentionally loses access to prior cached results. Stdio
    processes share their OS user's state; HTTP without a verified token is denied.
    """
    from mcp.server.auth.middleware.auth_context import get_access_token

    token = get_access_token()
    if token is not None and isinstance(token.token, str) and token.token:
        return "token:" + hashlib.sha256(token.token.encode()).hexdigest()
    try:
        context = request_ctx_getter()
    except LookupError:
        return "local"
    if getattr(context, "request", None) is not None:
        raise ValueError("MCP scan results require an authenticated HTTP caller")
    return "local"


class DurableScanResultStore:
    """Resolve server-bound tenant and deployment configuration per operation."""

    def __init__(
        self,
        *,
        max_entries: int,
        ttl_seconds: float,
        path: Path | None = None,
        tenant_id: str | None = None,
        clock: Callable[[], float] = time.time,
        max_result_bytes: int = MAX_RESULT_BYTES,
    ) -> None:
        if max_entries < 1 or max_result_bytes < 1 or not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("MCP result limits must be positive and finite")
        self._max_entries = int(max_entries)
        self._ttl = float(ttl_seconds)
        self._path = path
        self._tenant_id = tenant_id
        self._clock = clock
        self._max_result_bytes = max_result_bytes
        self._sqlite_ready: set[Path] = set()
        self._init_lock = threading.Lock()

    @property
    def ttl_seconds(self) -> float:
        return self._ttl

    def _tenant(self) -> str:
        from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id

        tenant = self._tenant_id if self._tenant_id is not None else resolve_mcp_tool_tenant_id()
        if not tenant.strip():
            raise ValueError("MCP result tenant must not be empty")
        return tenant

    @contextmanager
    def _connection(self, tenant: str, *, write: bool) -> Iterator[tuple[Any, str]]:
        from agent_bom.api.storage_schema import (
            ensure_postgres_schema_version,
            postgres_deployment_configured,
        )

        if self._path is None and postgres_deployment_configured():
            from agent_bom.api.postgres_common import _get_pool, _tenant_connection, reset_current_tenant, set_current_tenant

            token = set_current_tenant(tenant)
            try:
                with _tenant_connection(_get_pool()) as pg_conn:
                    ensure_postgres_schema_version(pg_conn, "mcp_scan_results")
                    if write:
                        pg_conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", ("mcp-results:" + tenant,))
                    yield pg_conn, "%s"
            finally:
                reset_current_tenant(token)
            return

        from agent_bom.storage.state_home import state_path

        path = self._path if self._path is not None else state_path("mcp-scan-results.db")
        self._prepare_sqlite(path)
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=30)
        try:
            with conn:
                if write:
                    conn.execute("BEGIN IMMEDIATE")
                yield conn, "?"
        finally:
            conn.close()

    def _prepare_sqlite(self, path: Path) -> None:
        from agent_bom.api.storage_schema import ensure_sqlite_schema_version

        with self._init_lock:
            if path in self._sqlite_ready:
                return
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
            conn = sqlite3.connect(path.resolve().as_uri() + "?mode=rw", uri=True, timeout=30)
            try:
                with conn:
                    conn.execute(_TABLE_SQL)
                    conn.execute(_INDEX_SQL)
                    conn.execute(_ORDER_INDEX_SQL)
                    ensure_sqlite_schema_version(conn, "mcp_scan_results")
            finally:
                conn.close()
            self._sqlite_ready.add(path)

    @staticmethod
    def _owner_digest(owner: str) -> str:
        if not owner:
            raise ValueError("MCP result owner must not be empty")
        return hashlib.sha256(owner.encode()).hexdigest()

    def put(self, owner: str, result: dict[str, Any]) -> str:
        serialized = json.dumps(result, separators=(",", ":"), default=str)
        if len(serialized.encode()) > self._max_result_bytes:
            raise ValueError("MCP result exceeds the durable cache size limit")
        tenant, digest = self._tenant(), self._owner_digest(owner)
        now, result_id = self._clock(), secrets.token_urlsafe(24)
        with self._connection(tenant, write=True) as (conn, mark):
            conn.execute(f"DELETE FROM mcp_scan_results WHERE tenant_id={mark} AND expires_at<={mark}", (tenant, now))  # nosec B608
            conn.execute(
                "INSERT INTO mcp_scan_results (tenant_id,result_id,owner_digest,created_at,expires_at,data) "
                f"VALUES ({','.join([mark] * 6)})",  # nosec B608
                (tenant, result_id, digest, now, now + self._ttl, serialized),
            )
            conn.execute(
                f"DELETE FROM mcp_scan_results WHERE tenant_id={mark} AND result_id NOT IN "  # nosec B608
                f"(SELECT result_id FROM mcp_scan_results WHERE tenant_id={mark} ORDER BY created_at DESC,result_id DESC LIMIT {mark})",
                (tenant, tenant, self._max_entries),
            )
        return result_id

    def get(self, owner: str, result_id: str) -> dict[str, Any] | None:
        tenant, digest = self._tenant(), self._owner_digest(owner)
        with self._connection(tenant, write=False) as (conn, mark):
            row = conn.execute(
                f"SELECT data FROM mcp_scan_results WHERE tenant_id={mark} AND result_id={mark} "  # nosec B608
                f"AND owner_digest={mark} AND expires_at>{mark}",
                (tenant, result_id, digest, self._clock()),
            ).fetchone()
        if row is None:
            return None
        result = json.loads(row[0])
        return result if isinstance(result, dict) else None
