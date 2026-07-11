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
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, cast

from agent_bom.config import (
    ALLOW_SUPERUSER_DB,
    POSTGRES_CONNECT_TIMEOUT_SECONDS,
    POSTGRES_POOL_MAX_SIZE,
    POSTGRES_POOL_MIN_SIZE,
    POSTGRES_STATEMENT_TIMEOUT_MS,
)

if TYPE_CHECKING:
    from urllib.parse import ParseResult

    # psycopg ships no type stubs and is an optional dependency, so these
    # resolve to Any under mypy. The runtime fallbacks below let the store
    # modules import the aliases without requiring psycopg to be installed.
    from psycopg import Connection
    from psycopg_pool import ConnectionPool
else:
    Connection = object
    ConnectionPool = object

logger = logging.getLogger(__name__)

_pool = None
_rls_role_checked = False
_current_tenant: ContextVar[str] = ContextVar("agent_bom_postgres_tenant", default="default")
_bypass_tenant_rls: ContextVar[bool] = ContextVar("agent_bom_postgres_bypass_rls", default=False)


class RlsRolePrivilegeError(RuntimeError):
    """Raised when the connected Postgres role can bypass tenant RLS.

    Postgres superusers and roles with ``BYPASSRLS`` ignore
    ``FORCE ROW LEVEL SECURITY``, so every ``*_tenant_isolation`` policy in
    this module becomes a no-op and tenants can read each other's rows. We
    refuse to start rather than serve traffic with tenant isolation silently
    disabled.
    """


def set_current_tenant(tenant_id: str) -> Token[str]:
    """Bind the current Postgres tenant context for the active request/task."""
    return _current_tenant.set((tenant_id or "default").strip() or "default")


def reset_current_tenant(token: Token[str]) -> None:
    """Restore the previous Postgres tenant context."""
    _current_tenant.reset(token)


def _audit_rls_bypass_activation(*, caller: str) -> None:
    """Best-effort signed audit entry for trusted RLS bypass activation."""
    try:
        from agent_bom.api.audit_log import log_action

        log_action(
            "postgres.rls_bypass_activated",
            actor="system",
            resource="postgres/tenant-rls",
            tenant_id=_current_tenant.get(),
            policy="tenant_rls_bypass",
            outcome="activated",
            method="context_manager",
            source_field=caller,
        )
    except Exception:
        logger.debug("Postgres tenant RLS bypass audit log write failed", exc_info=True)


@contextmanager
def bypass_tenant_rls(*, audit: bool = True) -> Iterator[None]:
    """Temporarily disable Postgres tenant RLS for trusted internal tasks."""
    stack = inspect.stack(context=0)
    frame = next((candidate for candidate in stack[1:] if os.path.basename(candidate.filename) != "contextlib.py"), None)
    caller = f"{os.path.basename(frame.filename)}:{frame.lineno}" if frame else "unknown"
    logger.warning("Postgres tenant RLS bypass activated caller=%s", caller)
    if audit:
        _audit_rls_bypass_activation(caller=caller)
    token = _bypass_tenant_rls.set(True)
    try:
        yield
    finally:
        _bypass_tenant_rls.reset(token)


def is_tenant_rls_bypassed() -> bool:
    """Return whether the current task is running with tenant RLS bypassed."""
    return _bypass_tenant_rls.get()


def _parse_and_validate_postgres_url() -> tuple[ParseResult, str]:
    """Parse ``AGENT_BOM_POSTGRES_URL`` and reject privileged role names.

    Compose stacks must use the DML-only ``agent_bom_app`` role — never the
    bootstrap admin role created by the official Postgres image. Returns the
    parsed URL and the validated username.
    """
    from urllib.parse import urlparse

    url = os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip()
    if not url:
        raise ValueError("AGENT_BOM_POSTGRES_URL env var is required for PostgreSQL storage.")

    parsed = urlparse(url)
    username = (parsed.username or "").strip()
    forbidden = {"postgres", "root", "admin", "superuser", "administrator"}
    if username.lower() in forbidden:
        raise ValueError(
            f"AGENT_BOM_POSTGRES_URL must not use privileged role {username!r}. "
            "Connect as the NOSUPERUSER NOBYPASSRLS app role (agent_bom_app)."
        )
    return parsed, username


def resolve_postgres_url() -> str:
    """Build the Postgres conninfo URL with **no password** embedded.

    The secret — a static password or a short-lived auth token — is resolved
    separately by :func:`resolve_postgres_secret` and handed to the pool via
    connection kwargs, so it never lives inside the DSN string (which can leak
    into logs, ``pg_stat_activity``, or crash dumps). Compose stacks must use
    the DML-only ``agent_bom_app`` role — never the bootstrap admin role.
    """
    from urllib.parse import quote, urlunparse

    parsed, username = _parse_and_validate_postgres_url()
    host = parsed.hostname
    if not host:
        # No network authority to rebuild (e.g. a socket-style DSN); return the
        # DSN unchanged. Any secret still travels via resolve_postgres_secret.
        return urlunparse(parsed)

    netloc = host + (f":{parsed.port}" if parsed.port else "")
    if username:
        netloc = f"{quote(username, safe='')}@{netloc}"
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def resolve_postgres_secret() -> str | None:
    """Resolve the Postgres password or short-lived auth token, kept out of the DSN.

    Resolution order:

    * ``AGENT_BOM_POSTGRES_AUTH_MODE=iam`` — true no-passwords mode: fetch a
      short-lived token from the configured provider (default AWS RDS IAM)
      instead of any stored password.
    * default (``password``) — prefer ``AGENT_BOM_POSTGRES_PASSWORD_FILE``
      (Docker secret / mounted file), else any password embedded in
      ``AGENT_BOM_POSTGRES_URL``; ``None`` when neither is present.

    The returned value is passed to the pool via ``kwargs={"password": ...}``.
    """
    from pathlib import Path

    from agent_bom.api.postgres_auth import (
        AUTH_MODE_IAM,
        postgres_auth_mode,
        resolve_postgres_auth_token_provider,
    )

    parsed, username = _parse_and_validate_postgres_url()

    if postgres_auth_mode() == AUTH_MODE_IAM:
        host = parsed.hostname
        if not host:
            raise ValueError("AGENT_BOM_POSTGRES_URL must include a hostname for IAM auth mode.")
        if not username:
            raise ValueError("AGENT_BOM_POSTGRES_URL must include a username for IAM auth mode.")
        provider = resolve_postgres_auth_token_provider()
        return provider.get_auth_token(host=host, port=parsed.port or 5432, username=username)

    password_file = os.environ.get("AGENT_BOM_POSTGRES_PASSWORD_FILE", "").strip()
    if password_file:
        path = Path(password_file)
        if not path.is_file():
            raise ValueError(f"AGENT_BOM_POSTGRES_PASSWORD_FILE not found: {password_file}")
        password = path.read_text(encoding="utf-8").strip("\r\n")
        if not password:
            raise ValueError(f"AGENT_BOM_POSTGRES_PASSWORD_FILE is empty: {password_file}")
        if not username:
            raise ValueError(
                "AGENT_BOM_POSTGRES_URL must include a username when using AGENT_BOM_POSTGRES_PASSWORD_FILE (expected agent_bom_app)."
            )
        if not parsed.hostname:
            raise ValueError("AGENT_BOM_POSTGRES_URL must include a hostname.")
        return password

    return parsed.password or None


def _get_pool() -> ConnectionPool:
    """Lazy-create a connection pool (singleton)."""
    global _pool
    if _pool is None:
        try:
            import psycopg_pool
        except ImportError as exc:
            raise ImportError("PostgreSQL support requires psycopg. Install with: pip install 'agent-bom[postgres]'") from exc

        from agent_bom.api.postgres_auth import AUTH_MODE_IAM, postgres_auth_mode

        url = resolve_postgres_url()
        auth_mode = postgres_auth_mode()
        password = resolve_postgres_secret() if auth_mode != AUTH_MODE_IAM else None
        min_size = max(1, POSTGRES_POOL_MIN_SIZE)
        max_size = max(min_size, POSTGRES_POOL_MAX_SIZE)
        kwargs: dict[str, object] = {}
        if POSTGRES_CONNECT_TIMEOUT_SECONDS > 0:
            kwargs["connect_timeout"] = POSTGRES_CONNECT_TIMEOUT_SECONDS
        if password is not None:
            # Keep the secret out of the conninfo/DSN; psycopg forwards these
            # per-connection kwargs to libpq for every new connection.
            kwargs["password"] = password
        if auth_mode == AUTH_MODE_IAM:
            import psycopg

            class IamAuthConnection(psycopg.Connection):
                """Resolve a fresh short-lived IAM token for every connection."""

                @classmethod
                def connect(  # type: ignore[override]
                    cls, conninfo: str = "", **connect_kwargs: object
                ) -> object:
                    connect_kwargs["password"] = resolve_postgres_secret()
                    return super().connect(conninfo, **connect_kwargs)  # type: ignore[arg-type]

            _pool = psycopg_pool.ConnectionPool(
                conninfo=url,
                min_size=min_size,
                max_size=max_size,
                kwargs=kwargs,
                connection_class=IamAuthConnection,
            )
        else:
            _pool = psycopg_pool.ConnectionPool(
                conninfo=url,
                min_size=min_size,
                max_size=max_size,
                kwargs=kwargs,
            )
    pool = cast(ConnectionPool, _pool)
    _guard_rls_capable_role(pool)
    return pool


def _guard_rls_capable_role(pool: ConnectionPool) -> None:
    """Fail closed when the connected role can bypass tenant RLS.

    Tenant isolation on Postgres is enforced entirely through the
    ``FORCE ROW LEVEL SECURITY`` policies created by :func:`_ensure_tenant_rls`.
    Superusers and ``BYPASSRLS`` roles ignore that clause, so if the app
    connects as such a role every tenant policy is void and cross-tenant reads
    succeed. We inspect the role once per pool and refuse to continue unless the
    operator has explicitly opted into a single-tenant / dev setup via
    ``AGENT_BOM_ALLOW_SUPERUSER_DB`` (#3665).
    """
    global _rls_role_checked
    if _rls_role_checked:
        return
    try:
        with pool.connection() as conn:
            cursor = conn.execute("SELECT rolsuper, rolbypassrls, rolname FROM pg_roles WHERE rolname = current_user")
            row = cursor.fetchone() if cursor is not None else None
    except Exception:
        # Best-effort probe: a transient connect error or a store mock without a
        # real role table must not mask the primary failure. A genuinely
        # RLS-bypassing role is still caught on the next successful pool use.
        logger.debug("Postgres RLS role guard could not inspect role attributes", exc_info=True)
        return

    _rls_role_checked = True
    if not row:
        return
    rolsuper, rolbypassrls = bool(row[0]), bool(row[1])
    role_name = row[2] if len(row) > 2 and row[2] else "current_user"
    if not (rolsuper or rolbypassrls):
        return

    attrs = " and ".join(label for label, present in (("SUPERUSER", rolsuper), ("BYPASSRLS", rolbypassrls)) if present)
    message = (
        f"Postgres role {role_name!r} has {attrs}, which bypasses FORCE ROW LEVEL SECURITY "
        "and silently disables agent-bom tenant isolation — cross-tenant reads/writes would "
        "succeed. Connect as a NOSUPERUSER NOBYPASSRLS role (e.g. run "
        f"'ALTER ROLE {role_name} NOSUPERUSER NOBYPASSRLS;' or point AGENT_BOM_POSTGRES_URL at the "
        "dedicated agent_bom_app role). For a single-tenant or local dev deployment, set "
        "AGENT_BOM_ALLOW_SUPERUSER_DB=1 to acknowledge this and downgrade to a warning."
    )
    if ALLOW_SUPERUSER_DB:
        logger.warning(
            "AGENT_BOM_ALLOW_SUPERUSER_DB is set: %s Tenant isolation is NOT enforced by the database.",
            message,
        )
        return
    raise RlsRolePrivilegeError(message)


def reset_pool() -> None:
    """Reset the connection pool (for testing)."""
    global _pool, _rls_role_checked
    _pool = None
    _rls_role_checked = False


def _apply_tenant_session(conn: Connection) -> None:
    """Attach tenant session settings used by Postgres RLS policies."""
    conn.execute("SELECT set_config('app.tenant_id', %s, true)", (_current_tenant.get(),))
    conn.execute("SELECT set_config('app.bypass_rls', %s, true)", ("1" if _bypass_tenant_rls.get() else "0",))
    if POSTGRES_STATEMENT_TIMEOUT_MS > 0:
        conn.execute("SELECT set_config('statement_timeout', %s, false)", (str(POSTGRES_STATEMENT_TIMEOUT_MS),))


def _ensure_rls_helpers(conn: Connection) -> None:
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


def _ensure_tenant_rls(conn: Connection, table: str, column: str) -> None:
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
def _tenant_connection(pool: ConnectionPool) -> Iterator[Connection]:
    """Open a connection with the current tenant/bypass settings attached."""
    with pool.connection() as conn:
        _apply_tenant_session(conn)
        yield conn
