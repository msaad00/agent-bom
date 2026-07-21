#!/usr/bin/env python3
"""Compose/Docker one-shot: stamp init.sql baselines if needed, then Alembic upgrade.

Ships inside the control-plane image (copied under deploy/supabase/postgres/).
Used by ``deploy/docker-compose.platform.yml`` so image upgrades apply schema
changes the same way Helm's pre-upgrade migration Job does.

Contract:
  * Connect as the Postgres bootstrap/admin role (DDL), never ``agent_bom_app``.
  * Prefer ``AGENT_BOM_POSTGRES_PASSWORD_FILE`` (Docker secret) over embedding
    passwords in ``AGENT_BOM_POSTGRES_URL``.
  * Databases first created from ``init.sql`` have no ``alembic_version`` row —
    stamp baseline ``20260416_01`` once, then ``upgrade head``.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote_plus, urlsplit, urlunsplit

BASELINE_REVISION = "20260416_01"
ALEMBIC_CONFIG = "deploy/supabase/postgres/alembic.ini"
# Presence of this table means init.sql (or an earlier baseline) already landed.
BOOTSTRAP_MARKER_TABLE = "audit_log"


def _repo_root() -> Path:
    # Image layout: /opt/agent-bom/deploy/supabase/postgres/compose_migrate.py
    here = Path(__file__).resolve()
    for candidate in (Path("/opt/agent-bom"), here.parents[3], Path.cwd()):
        if (candidate / ALEMBIC_CONFIG).is_file():
            return candidate
    raise SystemExit(f"error: cannot find {ALEMBIC_CONFIG} from {here}")


def _resolve_database_url() -> str:
    url = (os.environ.get("ALEMBIC_DATABASE_URL") or os.environ.get("AGENT_BOM_POSTGRES_URL") or "").strip()
    if not url:
        raise SystemExit(
            "error: set ALEMBIC_DATABASE_URL or AGENT_BOM_POSTGRES_URL "
            "(bootstrap/admin role) before compose migrations"
        )
    parts = urlsplit(url)
    if parts.password:
        return url
    password_file = os.environ.get("AGENT_BOM_POSTGRES_PASSWORD_FILE", "").strip()
    if not password_file:
        return url
    path = Path(password_file)
    if not path.is_file():
        raise SystemExit(f"error: AGENT_BOM_POSTGRES_PASSWORD_FILE not found: {password_file}")
    password = path.read_text(encoding="utf-8").strip("\r\n")
    if not password:
        raise SystemExit(f"error: AGENT_BOM_POSTGRES_PASSWORD_FILE is empty: {password_file}")
    if not parts.username or not parts.hostname:
        raise SystemExit("error: AGENT_BOM_POSTGRES_URL must include username and hostname")
    host = parts.hostname
    netloc = f"{quote_plus(parts.username)}:{quote_plus(password)}@{host}"
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
                sqlalchemy.text(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'public' AND table_name = 'alembic_version'"
                )
            ).scalar()
            if has_version:
                row = conn.execute(sqlalchemy.text("SELECT version_num FROM alembic_version LIMIT 1")).scalar()
                if row:
                    return False
            has_bootstrap = conn.execute(
                sqlalchemy.text(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = 'public' AND table_name = :table"
                ),
                {"table": BOOTSTRAP_MARKER_TABLE},
            ).scalar()
            return bool(has_bootstrap)
    finally:
        engine.dispose()


def _run_alembic(root: Path, *args: str) -> None:
    cmd = ["alembic", "-c", ALEMBIC_CONFIG, *args]
    print("+", " ".join(cmd), flush=True)
    subprocess.check_call(cmd, cwd=str(root))


def main() -> int:
    root = _repo_root()
    url = _resolve_database_url()
    os.environ["ALEMBIC_DATABASE_URL"] = url
    # Keep PASSWORD_FILE for alembic/env.py fallback; URL now carries the secret.
    if _needs_baseline_stamp(url):
        print(
            f"compose-migrate: init.sql baseline detected without alembic_version; "
            f"stamping {BASELINE_REVISION}",
            flush=True,
        )
        _run_alembic(root, "stamp", BASELINE_REVISION)
    _run_alembic(root, "upgrade", "head")
    print("compose-migrate: upgrade head OK", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
