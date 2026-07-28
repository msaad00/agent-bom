"""Require a trusted database principal for cross-tenant maintenance.

Revision ID: 20260728_03
Revises: 20260728_02
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

from alembic import op

revision = "20260728_03"
down_revision = "20260728_02"
branch_labels = None
depends_on = None


def _allow_superuser_db() -> bool:
    """Match the runtime's explicit disposable/single-tenant acknowledgement."""

    return os.environ.get("AGENT_BOM_ALLOW_SUPERUSER_DB", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _runtime_password(url_name: str, password_file_name: str, expected_role: str) -> str | None:
    """Resolve a runtime-role password supplied to the trusted migration job."""

    raw_url = os.environ.get(url_name, "").strip()
    if not raw_url:
        return None
    parsed = urlsplit(raw_url.replace("postgresql+psycopg://", "postgresql://", 1))
    username = unquote(parsed.username or "")
    if username != expected_role:
        raise RuntimeError(f"{url_name} must use the fixed {expected_role} role")
    password_file = os.environ.get(password_file_name, "").strip()
    if password_file:
        path = Path(password_file)
        if not path.is_file():
            raise RuntimeError(f"{password_file_name} not found: {password_file}")
        password = path.read_text(encoding="utf-8").strip("\r\n")
        if not password:
            raise RuntimeError(f"{password_file_name} is empty: {password_file}")
        return password
    return unquote(parsed.password) if parsed.password is not None else None


def _can_alter_role(bind: object, role: str) -> bool:
    """Return whether the migration principal may rotate ``role`` safely."""

    row = bind.exec_driver_sql(  # type: ignore[attr-defined]
        """
        SELECT r.rolsuper OR (r.rolcreaterole AND EXISTS (
          SELECT 1
          FROM pg_auth_members m
          WHERE m.member = r.oid
            AND m.roleid = (SELECT oid FROM pg_roles WHERE rolname = %s)
            AND m.admin_option
        ))
        FROM pg_roles r
        WHERE r.rolname = session_user
        """,
        (role,),
    ).fetchone()
    return bool(row and row[0])


def _validate_existing_runtime_login(raw_url: str, password: str, expected_role: str) -> None:
    """Prove an externally provisioned runtime password already matches."""

    import psycopg

    conninfo = raw_url.replace("postgresql+psycopg://", "postgresql://", 1)
    try:
        with psycopg.connect(conninfo, password=password, connect_timeout=5) as conn:
            row = conn.execute("SELECT session_user").fetchone()
    except Exception:
        raise RuntimeError(
            f"The migration principal cannot rotate {expected_role}; pre-provision that role "
            "with the supplied runtime credential or grant the migration principal CREATEROLE "
            "plus ADMIN OPTION."
        ) from None
    if not row or str(row[0]) != expected_role:
        raise RuntimeError(f"The supplied runtime credential must authenticate as {expected_role}.")


def _bootstrap_password_was_applied(bind: object, role: str, password: str) -> bool:
    """Detect the same-transaction init.sql path before its roles are visible."""

    setting = "init.app_password" if role == "agent_bom_app" else "init.maintenance_password"
    row = bind.exec_driver_sql(  # type: ignore[attr-defined]
        "SELECT current_setting(%s, true) = %s",
        (setting, password),
    ).fetchone()
    return bool(row and row[0])


def _configure_runtime_passwords() -> None:
    """Align pre-populated runtime Secrets when the admin may manage the roles.

    Fresh Compose initialization already sets both passwords before demoting its
    schema owner. Managed Postgres/RDS migration principals retain role-admin
    authority and use this path. A DBA-preprovisioned role without delegated
    ADMIN OPTION is left unchanged and is validated by API startup.
    """

    from psycopg import sql

    bind = op.get_bind()
    driver_connection = bind.connection.driver_connection
    for role, url_name, file_name in (
        ("agent_bom_app", "AGENT_BOM_POSTGRES_URL", "AGENT_BOM_POSTGRES_PASSWORD_FILE"),
        (
            "agent_bom_maintenance",
            "AGENT_BOM_POSTGRES_MAINTENANCE_URL",
            "AGENT_BOM_POSTGRES_MAINTENANCE_PASSWORD_FILE",
        ),
    ):
        password = _runtime_password(url_name, file_name, role)
        if password is not None and _can_alter_role(bind, role):
            # PostgreSQL utility statements do not accept bind parameters.
            # psycopg composition quotes the fixed allowlisted identifier and
            # secret literal without raw string interpolation.
            driver_connection.execute(
                sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(role), sql.Literal(password))
            )
        elif password is not None and not _bootstrap_password_was_applied(bind, role, password):
            _validate_existing_runtime_login(os.environ[url_name].strip(), password, role)


def upgrade() -> None:
    allow_privileged_app = "TRUE" if _allow_superuser_db() else "FALSE"
    op.execute(
        f"""
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_rls_maintenance') THEN
            CREATE ROLE agent_bom_rls_maintenance NOLOGIN NOSUPERUSER NOBYPASSRLS;
          ELSIF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE rolname = 'agent_bom_rls_maintenance'
              AND (rolcanlogin OR rolsuper OR rolbypassrls)
          ) THEN
            RAISE EXCEPTION 'agent_bom_rls_maintenance must be NOLOGIN NOSUPERUSER NOBYPASSRLS';
          END IF;

          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_maintenance') THEN
            CREATE ROLE agent_bom_maintenance LOGIN NOSUPERUSER NOBYPASSRLS;
          ELSIF EXISTS (
            SELECT 1 FROM pg_roles
            WHERE rolname = 'agent_bom_maintenance'
              AND (NOT rolcanlogin OR rolsuper OR rolbypassrls)
          ) THEN
            RAISE EXCEPTION 'agent_bom_maintenance must be LOGIN NOSUPERUSER NOBYPASSRLS';
          END IF;

          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
            IF EXISTS (
              SELECT 1 FROM pg_roles
              WHERE rolname = 'agent_bom_app'
                AND (
                  NOT rolcanlogin
                  OR ((rolsuper OR rolbypassrls) AND NOT {allow_privileged_app})
                )
            ) THEN
              RAISE EXCEPTION 'agent_bom_app must be LOGIN; privileged attributes require explicit dev acknowledgement';
            END IF;
            IF pg_has_role('agent_bom_app', 'agent_bom_rls_maintenance', 'MEMBER') THEN
              RAISE EXCEPTION 'agent_bom_app must never inherit agent_bom_rls_maintenance';
            END IF;
          END IF;

          IF NOT pg_has_role('agent_bom_maintenance', 'agent_bom_rls_maintenance', 'MEMBER') THEN
            GRANT agent_bom_rls_maintenance TO agent_bom_maintenance;
          END IF;
        END $$
        """
    )
    _configure_runtime_passwords()
    op.execute(
        """
        CREATE OR REPLACE FUNCTION public.abom_rls_bypass()
        RETURNS BOOLEAN
        LANGUAGE SQL
        STABLE
        AS $$
          SELECT COALESCE(NULLIF(current_setting('app.bypass_rls', true), ''), '0') = '1'
             AND pg_has_role(session_user, 'agent_bom_rls_maintenance', 'MEMBER')
        $$
        """
    )
    # Own the queue shape in the forward migration instead of assuming a
    # historical runtime-schema/bootstrap side effect. IF NOT EXISTS preserves
    # every queued row on upgrades and makes Alembic-only installs complete.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_dispatch_queue (
          job_id TEXT PRIMARY KEY REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
          tenant_id TEXT NOT NULL,
          created_at TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'pending',
          claimed_by TEXT,
          lease_expires_at TEXT
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS idx_dispatch_pending ON scan_dispatch_queue(status, created_at)")
    op.execute("ALTER TABLE scan_dispatch_queue ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE scan_dispatch_queue FORCE ROW LEVEL SECURITY")
    op.execute("DROP POLICY IF EXISTS scan_dispatch_queue_tenant_isolation ON scan_dispatch_queue")
    op.execute("DROP POLICY IF EXISTS scan_dispatch_queue_maintenance ON scan_dispatch_queue")
    op.execute(
        """
        CREATE POLICY scan_dispatch_queue_tenant_isolation ON scan_dispatch_queue
          FOR ALL TO agent_bom_app
          USING (tenant_id = public.abom_current_tenant())
          WITH CHECK (tenant_id = public.abom_current_tenant())
        """
    )
    op.execute(
        """
        CREATE POLICY scan_dispatch_queue_maintenance ON scan_dispatch_queue
          FOR ALL TO agent_bom_rls_maintenance
          USING (public.abom_rls_bypass())
          WITH CHECK (public.abom_rls_bypass())
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
          EXECUTE format(
            'GRANT CONNECT ON DATABASE %I TO agent_bom_maintenance',
            current_database()
          );
          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'agent_bom_app') THEN
            GRANT SELECT, INSERT, UPDATE, DELETE ON scan_dispatch_queue TO agent_bom_app;
          END IF;
        END $$;

        GRANT USAGE ON SCHEMA public TO agent_bom_rls_maintenance;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public
          TO agent_bom_rls_maintenance;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public
          TO agent_bom_rls_maintenance;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
          GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO agent_bom_rls_maintenance;
        ALTER DEFAULT PRIVILEGES IN SCHEMA public
          GRANT USAGE, SELECT ON SEQUENCES TO agent_bom_rls_maintenance;
        REVOKE CREATE ON SCHEMA public FROM agent_bom_maintenance;
        REVOKE CREATE ON SCHEMA public FROM agent_bom_rls_maintenance;
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Trusted maintenance RLS is a security boundary and intentionally irreversible.")
