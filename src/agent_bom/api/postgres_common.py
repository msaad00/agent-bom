"""Shared PostgreSQL connection, tenant-session, and RLS helpers.

This module centralizes the pool singleton and the request-scoped tenant
context that the Postgres-backed stores rely on. Keeping the plumbing here
lets the store modules split by responsibility without duplicating the same
session and row-level-security setup.
"""

from __future__ import annotations

import inspect
import logging
import os
from contextlib import contextmanager
from contextvars import ContextVar, Token

from agent_bom.config import (
    POSTGRES_CONNECT_TIMEOUT_SECONDS,
    POSTGRES_POOL_MAX_SIZE,
    POSTGRES_POOL_MIN_SIZE,
    POSTGRES_STATEMENT_TIMEOUT_MS,
)

logger = logging.getLogger(__name__)

_pool = None
_current_tenant: ContextVar[str] = ContextVar("agent_bom_postgres_tenant", default="default")
_bypass_tenant_rls: ContextVar[bool] = ContextVar("agent_bom_postgres_bypass_rls", default=False)


def set_current_tenant(tenant_id: str) -> Token[str]:
    """Bind the current Postgres tenant context for the active request/task."""
    return _current_tenant.set((tenant_id or "default").strip() or "default")


def reset_current_tenant(token: Token[str]) -> None:
    """Restore the previous Postgres tenant context."""
    _current_tenant.reset(token)


@contextmanager
def bypass_tenant_rls():
    """Temporarily disable Postgres tenant RLS for trusted internal tasks."""
    stack = inspect.stack(context=0)
    frame = stack[1] if len(stack) > 1 else None
    caller = f"{frame.filename}:{frame.lineno}" if frame else "unknown"
    logger.warning("Postgres tenant RLS bypass activated caller=%s", caller)
    token = _bypass_tenant_rls.set(True)
    try:
        yield
    finally:
        _bypass_tenant_rls.reset(token)


def is_tenant_rls_bypassed() -> bool:
    """Return whether the current task is running with tenant RLS bypassed."""
    return _bypass_tenant_rls.get()


def _get_pool():
    """Lazy-create a connection pool (singleton)."""
    global _pool
    if _pool is None:
        try:
            import psycopg_pool
        except ImportError as exc:
            raise ImportError("PostgreSQL support requires psycopg. Install with: pip install 'agent-bom[postgres]'") from exc

        url = os.environ.get("AGENT_BOM_POSTGRES_URL", "")
        if not url:
            raise ValueError("AGENT_BOM_POSTGRES_URL env var is required for PostgreSQL storage.")
        min_size = max(1, POSTGRES_POOL_MIN_SIZE)
        max_size = max(min_size, POSTGRES_POOL_MAX_SIZE)
        kwargs: dict[str, object] = {}
        if POSTGRES_CONNECT_TIMEOUT_SECONDS > 0:
            kwargs["connect_timeout"] = POSTGRES_CONNECT_TIMEOUT_SECONDS
        _pool = psycopg_pool.ConnectionPool(
            url,
            min_size=min_size,
            max_size=max_size,
            kwargs=kwargs,
        )
    return _pool


def reset_pool():
    """Reset the connection pool (for testing)."""
    global _pool
    _pool = None


def _apply_tenant_session(conn) -> None:
    """Attach tenant session settings used by Postgres RLS policies."""
    conn.execute("SELECT set_config('app.tenant_id', %s, true)", (_current_tenant.get(),))
    conn.execute("SELECT set_config('app.bypass_rls', %s, true)", ("1" if _bypass_tenant_rls.get() else "0",))
    if POSTGRES_STATEMENT_TIMEOUT_MS > 0:
        conn.execute("SELECT set_config('statement_timeout', %s, false)", (str(POSTGRES_STATEMENT_TIMEOUT_MS),))


def _ensure_rls_helpers(conn) -> None:
    """Create shared SQL helpers used by tenant RLS policies."""
    conn.execute("""
        CREATE OR REPLACE FUNCTION public.abom_current_tenant()
        RETURNS TEXT
        LANGUAGE SQL
        STABLE
        AS $$
            SELECT COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'default')
        $$;
    """)
    conn.execute("""
        CREATE OR REPLACE FUNCTION public.abom_rls_bypass()
        RETURNS BOOLEAN
        LANGUAGE SQL
        STABLE
        AS $$
            SELECT COALESCE(NULLIF(current_setting('app.bypass_rls', true), ''), '0') = '1'
        $$;
    """)


def _ensure_tenant_rls(conn, table: str, column: str) -> None:
    """Enable tenant RLS for a table using the shared tenant session helpers."""
    _ensure_rls_helpers(conn)
    conn.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")  # nosec B608
    conn.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")  # nosec B608
    conn.execute(
        f"""
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM pg_policies
                WHERE schemaname = 'public'
                  AND tablename = '{table}'
                  AND policyname = '{table}_tenant_isolation'
            ) THEN
                EXECUTE 'CREATE POLICY {table}_tenant_isolation ON {table}
                    USING (public.abom_rls_bypass() OR {column} = public.abom_current_tenant())
                    WITH CHECK (public.abom_rls_bypass() OR {column} = public.abom_current_tenant())';
            END IF;
        END
        $$;
        """  # nosec B608
    )


@contextmanager
def _tenant_connection(pool):
    """Open a connection with the current tenant/bypass settings attached."""
    with pool.connection() as conn:
        _apply_tenant_session(conn)
        yield conn
