"""Shared PostgreSQL connection, tenant-session, and RLS helpers.

This module centralizes the application/maintenance pools and request-scoped tenant
context that the Postgres-backed stores rely on. Keeping the plumbing here
lets the store modules split by responsibility without duplicating the same
session and row-level-security setup.
"""

from __future__ import annotations

import inspect
import logging
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING

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
_idempotency_fence_pool = None
_maintenance_pool = None
_rls_role_checked = False
_maintenance_roles_checked = False
_current_tenant: ContextVar[str] = ContextVar("agent_bom_postgres_tenant", default="default")
_bypass_tenant_rls: ContextVar[bool] = ContextVar("agent_bom_postgres_bypass_rls", default=False)

_RLS_MAINTENANCE_MARKER_ROLE = "agent_bom_rls_maintenance"
_IDEMPOTENCY_FENCE_POOL_MAX_SIZE = 4
_MAINTENANCE_POOL_MAX_SIZE = 4


class RlsRolePrivilegeError(RuntimeError):
    """Raised when the connected Postgres role can bypass tenant RLS.

    Postgres superusers and roles with ``BYPASSRLS`` ignore
    ``FORCE ROW LEVEL SECURITY``, so every ``*_tenant_isolation`` policy in
    this module becomes a no-op and tenants can read each other's rows. We
    refuse to start rather than serve traffic with tenant isolation silently
    disabled.
    """


class MaintenanceRoleConfigurationError(RuntimeError):
    """Raised when Postgres maintenance credentials do not fail closed."""


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
        logger.debug("Postgres tenant RLS bypass audit log write failed", exc_info=False)


@contextmanager
def bypass_tenant_rls(*, audit: bool = True, warn: bool = True) -> Iterator[None]:
    """Temporarily disable tenant RLS for a trusted internal task.

    ``warn=False`` is reserved for bounded high-frequency maintenance polling;
    it also avoids the stack inspection cost. Callers performing operator or
    user-triggered maintenance retain the warning and signed audit by default.
    """
    caller = "bounded-maintenance-poll"
    if warn or audit:
        stack = inspect.stack(context=0)
        frame = next((candidate for candidate in stack[1:] if os.path.basename(candidate.filename) != "contextlib.py"), None)
        caller = f"{os.path.basename(frame.filename)}:{frame.lineno}" if frame else "unknown"
    if warn:
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


def _normalize_postgres_conninfo_url(url: str) -> str:
    """Accept SQLAlchemy dialect URLs and rewrite them for psycopg conninfo.

    Operators sometimes paste Alembic-style ``postgresql+psycopg://`` DSNs into
    ``AGENT_BOM_POSTGRES_URL``. psycopg_pool treats the full scheme as an
    unknown connection option and refuses to connect. Strip the ``+driver``
    suffix so both forms work.
    """
    for prefix, replacement in (
        ("postgresql+psycopg://", "postgresql://"),
        ("postgres+psycopg://", "postgresql://"),
        ("postgresql+psycopg2://", "postgresql://"),
        ("postgres+psycopg2://", "postgresql://"),
    ):
        if url.lower().startswith(prefix):
            return replacement + url[len(prefix) :]
    return url


def _parse_and_validate_postgres_url() -> tuple[ParseResult, str]:
    """Parse ``AGENT_BOM_POSTGRES_URL`` and reject privileged role names.

    Compose stacks must use the DML-only ``agent_bom_app`` role — never the
    bootstrap admin role created by the official Postgres image. Returns the
    parsed URL and the validated username.
    """
    from urllib.parse import unquote, urlparse

    url = os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip()
    if not url:
        legacy_url = os.environ.get("AGENT_BOM_DB", "").strip()
        if legacy_url.lower().startswith(("postgres://", "postgresql://", "postgresql+psycopg://")):
            url = legacy_url
    if not url:
        raise ValueError("AGENT_BOM_POSTGRES_URL or a Postgres AGENT_BOM_DB value is required for PostgreSQL storage.")

    url = _normalize_postgres_conninfo_url(url)
    parsed = urlparse(url)
    username = unquote(parsed.username or "").strip()
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

    if parsed.password is None:
        return None
    from urllib.parse import unquote

    return unquote(parsed.password)


def _parse_and_validate_postgres_maintenance_url() -> tuple[ParseResult, str]:
    """Parse the dedicated maintenance DSN without falling back to the app DSN."""
    from urllib.parse import unquote, urlparse

    url = os.environ.get("AGENT_BOM_POSTGRES_MAINTENANCE_URL", "").strip()
    if not url:
        raise ValueError(
            "AGENT_BOM_POSTGRES_MAINTENANCE_URL is required for cross-tenant Postgres maintenance; "
            "the application pool is never used as a fallback."
        )
    parsed = urlparse(_normalize_postgres_conninfo_url(url))
    username = unquote(parsed.username or "").strip()
    if not username:
        raise ValueError("AGENT_BOM_POSTGRES_MAINTENANCE_URL must include the dedicated maintenance username.")
    if not parsed.hostname:
        raise ValueError("AGENT_BOM_POSTGRES_MAINTENANCE_URL must include a hostname.")
    forbidden = {"postgres", "root", "admin", "superuser", "administrator"}
    if username.lower() in forbidden:
        raise ValueError(
            f"AGENT_BOM_POSTGRES_MAINTENANCE_URL must not use privileged role {username!r}. "
            "Connect as the NOSUPERUSER NOBYPASSRLS maintenance login."
        )
    return parsed, username


def resolve_postgres_maintenance_url() -> str:
    """Return a password-free DSN for the dedicated maintenance pool."""
    from urllib.parse import quote, urlunparse

    parsed, username = _parse_and_validate_postgres_maintenance_url()
    host = parsed.hostname
    assert host is not None  # validated above
    netloc = f"{quote(username, safe='')}@{host}" + (f":{parsed.port}" if parsed.port else "")
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def resolve_postgres_maintenance_secret() -> str | None:
    """Resolve the maintenance password separately from its password-free DSN."""
    from pathlib import Path

    parsed, _username = _parse_and_validate_postgres_maintenance_url()
    password_file = os.environ.get("AGENT_BOM_POSTGRES_MAINTENANCE_PASSWORD_FILE", "").strip()
    if password_file:
        path = Path(password_file)
        if not path.is_file():
            raise ValueError(f"AGENT_BOM_POSTGRES_MAINTENANCE_PASSWORD_FILE not found: {password_file}")
        password = path.read_text(encoding="utf-8").strip("\r\n")
        if not password:
            raise ValueError(f"AGENT_BOM_POSTGRES_MAINTENANCE_PASSWORD_FILE is empty: {password_file}")
        return password
    if parsed.password is None:
        return None
    from urllib.parse import unquote

    return unquote(parsed.password)


def _new_application_pool(*, min_size: int, max_size: int) -> ConnectionPool:
    """Build a bounded app-role pool with the shared password/IAM contract."""

    try:
        import psycopg_pool
    except ImportError as exc:
        raise ImportError("PostgreSQL support requires psycopg. Install with: pip install 'agent-bom[postgres]'") from exc

    from agent_bom.api.postgres_auth import AUTH_MODE_IAM, postgres_auth_mode

    url = resolve_postgres_url()
    auth_mode = postgres_auth_mode()
    password = resolve_postgres_secret() if auth_mode != AUTH_MODE_IAM else None
    kwargs: dict[str, object] = {}
    if POSTGRES_CONNECT_TIMEOUT_SECONDS > 0:
        kwargs["connect_timeout"] = POSTGRES_CONNECT_TIMEOUT_SECONDS
    if password is not None:
        # Keep the secret out of the conninfo/DSN; psycopg forwards these
        # per-connection kwargs to libpq for every new connection.
        kwargs["password"] = password
    if auth_mode == AUTH_MODE_IAM:
        import psycopg

        base_connect: Callable[..., object] = getattr(psycopg.Connection.connect, "__func__", psycopg.Connection.connect)

        def connect_with_iam_token(cls: type[object], conninfo: str = "", **connect_kwargs: object) -> object:
            """Resolve a fresh short-lived IAM token for every connection."""
            connect_kwargs["password"] = resolve_postgres_secret()
            return base_connect(cls, conninfo, **connect_kwargs)

        # Construct the optional psycopg subclass dynamically so importing
        # this module remains dependency-free in non-Postgres installs.
        iam_auth_connection_class = type(
            "IamAuthConnection",
            (psycopg.Connection,),
            {"connect": classmethod(connect_with_iam_token)},
        )
        return psycopg_pool.ConnectionPool(
            conninfo=url,
            min_size=min_size,
            max_size=max_size,
            kwargs=kwargs,
            connection_class=iam_auth_connection_class,
            open=True,
        )
    return psycopg_pool.ConnectionPool(
        conninfo=url,
        min_size=min_size,
        max_size=max_size,
        kwargs=kwargs,
        open=True,
    )


def _get_pool() -> ConnectionPool:
    """Lazy-create the shared application connection pool."""
    global _pool
    if _pool is None:
        min_size = max(1, POSTGRES_POOL_MIN_SIZE)
        max_size = max(min_size, POSTGRES_POOL_MAX_SIZE)
        _pool = _new_application_pool(min_size=min_size, max_size=max_size)
    _guard_rls_capable_role(_pool)
    return _pool


def _get_idempotency_fence_pool() -> ConnectionPool:
    """Return a small app-role pool reserved for durable commit row locks."""

    global _idempotency_fence_pool
    if _idempotency_fence_pool is None:
        max_size = max(1, min(_IDEMPOTENCY_FENCE_POOL_MAX_SIZE, POSTGRES_POOL_MAX_SIZE))
        _idempotency_fence_pool = _new_application_pool(min_size=1, max_size=max_size)
    _guard_rls_capable_role(_idempotency_fence_pool)
    return _idempotency_fence_pool


def _guard_maintenance_role_separation(app_pool: ConnectionPool, maintenance_pool: ConnectionPool) -> None:
    """Prove that only the dedicated login inherits the maintenance marker."""
    global _maintenance_roles_checked
    if _maintenance_roles_checked:
        return

    role_sql = """
        SELECT
            session_user,
            COALESCE((SELECT rolcanlogin FROM pg_roles WHERE rolname = session_user), FALSE),
            COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname = session_user), FALSE),
            COALESCE((SELECT rolbypassrls FROM pg_roles WHERE rolname = session_user), FALSE),
            pg_has_role(session_user, 'agent_bom_rls_maintenance', 'MEMBER')
    """
    try:
        with app_pool.connection() as conn:
            cursor = conn.execute(role_sql)
            app_row = cursor.fetchone() if cursor is not None else None
        with maintenance_pool.connection() as conn:
            cursor = conn.execute(role_sql)
            maintenance_row = cursor.fetchone() if cursor is not None else None
    except Exception as exc:
        raise MaintenanceRoleConfigurationError(
            "Unable to validate the Postgres maintenance role boundary. Ensure the "
            f"{_RLS_MAINTENANCE_MARKER_ROLE} marker role exists and run migrations before starting maintenance workers."
        ) from exc

    if not app_row or not maintenance_row:
        raise MaintenanceRoleConfigurationError("Postgres maintenance role validation returned no role identity.")

    app_name, app_can_login, app_super, app_bypass, app_member = app_row
    maintenance_name, maintenance_can_login, maintenance_super, maintenance_bypass, maintenance_member = maintenance_row
    if str(app_name) == str(maintenance_name):
        raise MaintenanceRoleConfigurationError("Postgres application and maintenance pools must use distinct login identities.")
    if not bool(app_can_login):
        raise MaintenanceRoleConfigurationError(f"Postgres application role {app_name!r} must be a LOGIN role.")
    if bool(app_super) or bool(app_bypass):
        if not ALLOW_SUPERUSER_DB:
            raise MaintenanceRoleConfigurationError(f"Postgres application role {app_name!r} must be NOSUPERUSER NOBYPASSRLS.")
        logger.warning(
            "AGENT_BOM_ALLOW_SUPERUSER_DB is set: Postgres application role %r can bypass "
            "tenant RLS. This acknowledgement is restricted to disposable single-tenant/dev use; "
            "the distinct maintenance identity remains mandatory.",
            app_name,
        )
    if bool(app_member):
        raise MaintenanceRoleConfigurationError(
            f"Postgres application role {app_name!r} must not be a member of {_RLS_MAINTENANCE_MARKER_ROLE}."
        )
    if not bool(maintenance_can_login):
        raise MaintenanceRoleConfigurationError(f"Postgres maintenance role {maintenance_name!r} must be a LOGIN role.")
    if bool(maintenance_super) or bool(maintenance_bypass):
        raise MaintenanceRoleConfigurationError(f"Postgres maintenance role {maintenance_name!r} must be NOSUPERUSER NOBYPASSRLS.")
    if not bool(maintenance_member):
        raise MaintenanceRoleConfigurationError(
            f"Postgres maintenance role {maintenance_name!r} must be a member of {_RLS_MAINTENANCE_MARKER_ROLE}."
        )
    _maintenance_roles_checked = True


def _get_maintenance_pool() -> ConnectionPool:
    """Lazy-create the separately bounded, fail-closed maintenance pool."""
    global _maintenance_pool
    if _maintenance_pool is None:
        _app_parsed, app_username = _parse_and_validate_postgres_url()
        _maintenance_parsed, maintenance_username = _parse_and_validate_postgres_maintenance_url()
        if app_username.casefold() == maintenance_username.casefold():
            raise MaintenanceRoleConfigurationError(
                "AGENT_BOM_POSTGRES_URL and AGENT_BOM_POSTGRES_MAINTENANCE_URL must use distinct login identities."
            )

        try:
            import psycopg_pool
        except ImportError as exc:
            raise ImportError("PostgreSQL support requires psycopg. Install with: pip install 'agent-bom[postgres]'") from exc

        kwargs: dict[str, object] = {}
        if POSTGRES_CONNECT_TIMEOUT_SECONDS > 0:
            kwargs["connect_timeout"] = POSTGRES_CONNECT_TIMEOUT_SECONDS
        password = resolve_postgres_maintenance_secret()
        if password is not None:
            kwargs["password"] = password
        max_size = max(1, min(_MAINTENANCE_POOL_MAX_SIZE, POSTGRES_POOL_MAX_SIZE))
        _maintenance_pool = psycopg_pool.ConnectionPool(
            conninfo=resolve_postgres_maintenance_url(),
            min_size=1,
            max_size=max_size,
            kwargs=kwargs,
            open=True,
        )
        try:
            _guard_maintenance_role_separation(_get_pool(), _maintenance_pool)
        except Exception:
            close = getattr(_maintenance_pool, "close", None)
            if callable(close):
                close()
            _maintenance_pool = None
            raise
    return _maintenance_pool


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
        logger.debug("Postgres RLS role guard could not inspect role attributes", exc_info=False)
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


def preflight_rls_capable_role() -> None:
    """Enforce application and maintenance role guards at server bind time.

    :func:`_guard_rls_capable_role` otherwise runs lazily on the first pool use
    (the first request), so an RLS-bypassing role is only detected mid-flight as
    a per-request 500. Building the pool here triggers the same guard at boot so
    an unsafe role — or the operator's explicit ``AGENT_BOM_ALLOW_SUPERUSER_DB``
    acknowledgement — is surfaced before uvicorn accepts traffic (epic #4274).
    """
    _get_pool()
    _get_idempotency_fence_pool()
    _get_maintenance_pool()


def reset_pool() -> None:
    """Close and reset application, idempotency-fence, and maintenance pools."""
    global _pool, _idempotency_fence_pool, _maintenance_pool, _rls_role_checked, _maintenance_roles_checked
    for pool in (_pool, _idempotency_fence_pool, _maintenance_pool):
        close = getattr(pool, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                logger.debug("Postgres pool close skipped during reset", exc_info=False)
    _pool = None
    _idempotency_fence_pool = None
    _maintenance_pool = None
    _rls_role_checked = False
    _maintenance_roles_checked = False


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
            SELECT
                COALESCE(NULLIF(current_setting('app.bypass_rls', true), ''), '0') = '1'
                AND pg_has_role(session_user, 'agent_bom_rls_maintenance', 'MEMBER')
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
    """Open a tenant-bound app connection; never activate maintenance bypass."""
    if _bypass_tenant_rls.get():
        raise MaintenanceRoleConfigurationError(
            "Tenant RLS bypass requires an explicit _maintenance_connection(); the application pool cannot self-authorize maintenance."
        )
    with pool.connection() as conn:
        _apply_tenant_session(conn)
        yield conn


@contextmanager
def _maintenance_connection(pool: ConnectionPool | None = None) -> Iterator[Connection]:
    """Open the dedicated maintenance connection inside a scoped bypass context."""
    if not _bypass_tenant_rls.get():
        raise MaintenanceRoleConfigurationError("A Postgres maintenance connection is valid only inside bypass_tenant_rls().")
    maintenance_pool = pool if pool is not None else _get_maintenance_pool()
    if pool is not None and pool is _pool:
        raise MaintenanceRoleConfigurationError("The application pool cannot be used as a maintenance pool.")
    with maintenance_pool.connection() as conn:
        _apply_tenant_session(conn)
        yield conn
