#!/usr/bin/env python3
"""Compose/Docker one-shot: stamp init.sql baselines if needed, then Alembic upgrade.

Ships inside the control-plane image (copied under deploy/supabase/postgres/).
Used by ``deploy/docker-compose.platform.yml`` so image upgrades apply schema
changes the same way Helm's pre-upgrade migration Job does.

Contract:
  * Connect as the Postgres bootstrap/admin role (DDL), never ``agent_bom_app``.
  * Prefer ``ALEMBIC_DATABASE_PASSWORD_FILE`` (Docker secret) over embedding
    passwords in ``ALEMBIC_DATABASE_URL``. The one-shot migration process also
    receives the distinct app and maintenance secrets solely to provision or
    validate those fixed runtime roles; the admin secret never reaches the API.
  * Databases first created from ``init.sql`` have no ``alembic_version`` row —
    stamp baseline ``20260416_01`` once, then ``upgrade head``.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

BASELINE_REVISION = "20260416_01"
ALEMBIC_CONFIG = "deploy/supabase/postgres/alembic.ini"
# Presence of this table means init.sql (or an earlier baseline) already landed.
BOOTSTRAP_MARKER_TABLE = "audit_log"


def _normalize_sqlalchemy_url(url: str) -> str:
    """Select the shipped psycopg v3 driver for driverless Postgres URLs."""
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    return url


def top_up_observation_partition_runway(connection: Any) -> int:
    """Extend the hub observations partition runway; run after every upgrade.

    ``hub_findings_current_observations`` is monthly RANGE-partitioned and both
    runtime roles are DML-only (``init.sql`` revokes CREATE on schema
    ``public``), so only the migration owner can create a child. Provisioning a
    fixed window once would simply move the ingest cliff, so every Alembic
    upgrade tops the runway back up to a full year ahead.

    Deliberately not swallowed: a migration owner that cannot provision must
    fail the deploy loudly rather than ship a database that will stop accepting
    current-dated ingest on a date certain.
    """
    src = Path(__file__).resolve().parents[3] / "src"
    if src.is_dir() and str(src) not in sys.path:
        sys.path.insert(0, str(src))
    from agent_bom.api.hub_observations_partition import provision_observation_partition_runway

    # The shared helper speaks psycopg's ``execute(sql, tuple)`` contract, so
    # unwrap the DBAPI connection while retaining Alembic's transaction.
    return provision_observation_partition_runway(connection.connection.driver_connection)


def _repo_root() -> Path:
    # Image layout: /opt/agent-bom/deploy/supabase/postgres/compose_migrate.py
    here = Path(__file__).resolve()
    for candidate in (Path("/opt/agent-bom"), here.parents[3], Path.cwd()):
        if (candidate / ALEMBIC_CONFIG).is_file():
            return candidate
    raise SystemExit(f"error: cannot find {ALEMBIC_CONFIG} from {here}")


def _resolve_database_url() -> str:
    url = os.environ.get("ALEMBIC_DATABASE_URL", "").strip()
    if not url:
        raise SystemExit("error: set ALEMBIC_DATABASE_URL (bootstrap/admin role) before compose migrations")
    url = _normalize_sqlalchemy_url(url)
    parts = urlsplit(url)
    if parts.password:
        return url
    # The Alembic/admin connection is a separate trust boundary from the
    # least-privilege runtime app connection. Never reuse the app password file
    # merely because both URLs are present in the migration Job environment.
    password_file_name = "ALEMBIC_DATABASE_PASSWORD_FILE"
    password_file = os.environ.get(password_file_name, "").strip()
    if not password_file:
        return url
    path = Path(password_file)
    if not path.is_file():
        raise SystemExit(f"error: {password_file_name} not found: {password_file}")
    password = path.read_text(encoding="utf-8").strip("\r\n")
    if not password:
        raise SystemExit(f"error: {password_file_name} is empty: {password_file}")
    if not parts.username or not parts.hostname:
        raise SystemExit("error: ALEMBIC_DATABASE_URL must include username and hostname")
    host = parts.hostname
    netloc = f"{quote(parts.username, safe='')}:{quote(password, safe='')}@{host}"
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _needs_baseline_stamp(url: str) -> bool:
    try:
        import sqlalchemy
    except ImportError as exc:  # pragma: no cover - image always has sqlalchemy via alembic
        raise SystemExit(f"error: sqlalchemy required for compose migrate: {exc}") from exc

    engine = sqlalchemy.create_engine(url)
    try:
        with engine.connect() as conn:
            has_version = conn.execute(
                sqlalchemy.text("SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'alembic_version'")
            ).scalar()
            if has_version:
                row = conn.execute(sqlalchemy.text("SELECT version_num FROM alembic_version LIMIT 1")).scalar()
                if row:
                    return False
            has_bootstrap = conn.execute(
                sqlalchemy.text("SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = :table"),
                {"table": BOOTSTRAP_MARKER_TABLE},
            ).scalar()
            return bool(has_bootstrap)
    finally:
        engine.dispose()


def _run_alembic(root: Path, config_path: str, *args: str) -> None:
    cmd = ["alembic", "-c", config_path, *args]
    print("+", " ".join(cmd), flush=True)
    subprocess.check_call(cmd, cwd=str(root))


def _runtime_credential(url_name: str, password_file_name: str, expected_role: str) -> tuple[str, str] | None:
    """Resolve one fixed runtime-role credential without accepting rebinding."""
    raw_url = os.environ.get(url_name, "").strip()
    if not raw_url:
        return None
    parsed = urlsplit(raw_url.replace("postgresql+psycopg://", "postgresql://", 1))
    if unquote(parsed.username or "") != expected_role:
        raise SystemExit(f"error: {url_name} must use the fixed {expected_role} role")
    password_file = os.environ.get(password_file_name, "").strip()
    if password_file:
        path = Path(password_file)
        if not path.is_file():
            raise SystemExit(f"error: {password_file_name} not found: {password_file}")
        password = path.read_text(encoding="utf-8").strip("\r\n")
    else:
        password = unquote(parsed.password) if parsed.password is not None else ""
    if not password:
        raise SystemExit(f"error: {url_name} must supply a non-empty runtime-role password")
    return raw_url, password


def _reconcile_runtime_role_passwords(admin_url: str) -> None:
    """Idempotently align fixed Postgres logins after every schema upgrade."""
    try:
        import sqlalchemy
        from psycopg import sql
    except ImportError as exc:  # pragma: no cover - control-plane image includes both
        raise SystemExit("error: sqlalchemy and psycopg are required to reconcile runtime roles") from exc

    credentials = tuple(
        item
        for item in (
            (
                "agent_bom_app",
                _runtime_credential(
                    "AGENT_BOM_POSTGRES_URL",
                    "AGENT_BOM_POSTGRES_PASSWORD_FILE",
                    "agent_bom_app",
                ),
            ),
            (
                "agent_bom_maintenance",
                _runtime_credential(
                    "AGENT_BOM_POSTGRES_MAINTENANCE_URL",
                    "AGENT_BOM_POSTGRES_MAINTENANCE_PASSWORD_FILE",
                    "agent_bom_maintenance",
                ),
            ),
        )
        if item[1] is not None
    )
    if not credentials:
        return

    engine = sqlalchemy.create_engine(admin_url)
    try:
        with engine.begin() as conn:
            driver_connection = conn.connection.driver_connection
            for role, resolved in credentials:
                assert resolved is not None
                raw_url, password = resolved
                can_alter = conn.exec_driver_sql(
                    """
                    SELECT r.rolsuper OR (r.rolcreaterole AND EXISTS (
                      SELECT 1 FROM pg_auth_members m
                      WHERE m.member = r.oid
                        AND m.roleid = (SELECT oid FROM pg_roles WHERE rolname = %s)
                        AND m.admin_option
                    ))
                    FROM pg_roles r
                    WHERE r.rolname = session_user
                    """,
                    (role,),
                ).scalar()
                if can_alter:
                    driver_connection.execute(
                        sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                            sql.Identifier(role),
                            sql.Literal(password),
                        )
                    )
                    continue
                try:
                    import psycopg

                    conninfo = raw_url.replace("postgresql+psycopg://", "postgresql://", 1)
                    with psycopg.connect(conninfo, password=password, connect_timeout=5) as runtime_conn:
                        row = runtime_conn.execute("SELECT session_user").fetchone()
                except Exception:
                    raise SystemExit(
                        f"error: migration principal cannot rotate {role}; grant role-admin authority "
                        "or pre-provision the supplied credential"
                    ) from None
                if not row or str(row[0]) != role:
                    raise SystemExit(f"error: supplied runtime credential must authenticate as {role}")
    finally:
        engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Postgres migrations and reconcile the fixed runtime roles.")
    parser.add_argument("--config", default=ALEMBIC_CONFIG, help="Alembic configuration path relative to the repository root.")
    args = parser.parse_args([] if argv is None else argv)
    root = _repo_root()
    url = _resolve_database_url()
    os.environ["ALEMBIC_DATABASE_URL"] = url
    # Keep PASSWORD_FILE for operator diagnostics; ALEMBIC_DATABASE_URL now
    # carries the admin secret only in this child process.
    if _needs_baseline_stamp(url):
        print(
            f"compose-migrate: init.sql baseline detected without alembic_version; stamping {BASELINE_REVISION}",
            flush=True,
        )
        _run_alembic(root, args.config, "stamp", BASELINE_REVISION)
    _run_alembic(root, args.config, "upgrade", "head")
    _reconcile_runtime_role_passwords(url)
    print("compose-migrate: upgrade head OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
