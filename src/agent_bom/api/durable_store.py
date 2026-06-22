"""Durable-by-default backend selection for control-plane lifecycle stores.

A control plane must not lose issued agent identities, JIT grants, or runtime
sessions on a single-replica restart. Historically these stores defaulted to an
in-memory backend unless ``AGENT_BOM_DB`` (or ``AGENT_BOM_POSTGRES_URL``) was
explicitly set, so a process restart silently dropped every issued token and
grant. This module flips that default: without any configuration the stores
persist to a durable SQLite file, and in-memory is used only when an operator
explicitly opts out via ``AGENT_BOM_EPHEMERAL_STORE=1`` (or, in tests, via the
isolated ``AGENT_BOM_STATE_DIR`` temp dir).

Selection order (highest precedence first):

1. ``AGENT_BOM_POSTGRES_URL`` set  -> Postgres (multi-replica, tenant RLS).
2. ``AGENT_BOM_DB`` points at Postgres (``postgres://`` / ``postgresql://``)
   -> Postgres.
3. ``AGENT_BOM_EPHEMERAL_STORE`` truthy -> in-memory (explicit opt-out; state
   is lost on restart).
4. ``AGENT_BOM_DB`` set (a file path) -> SQLite at that path.
5. otherwise -> durable SQLite at the default state-dir path (single-node
   durable). This is the new default; it replaces the old in-memory fallback.

Scalability: the SQLite default is single-node durable — it survives restarts
but is local to one replica. Set ``AGENT_BOM_POSTGRES_URL`` for multi-replica
deployments so identity, JIT, and session state stay consistent across every
control-plane replica (mirrors the cost-store store-swap).
"""

from __future__ import annotations

import os
from pathlib import Path

# Default on-disk database filename used when neither AGENT_BOM_DB nor Postgres
# is configured. Lives under AGENT_BOM_STATE_DIR (or ~/.agent-bom/) so it shares
# the per-user/per-process state dir that conftest isolates in tests.
DEFAULT_STATE_DB_FILENAME = "control-plane.db"


def state_dir() -> Path:
    """Return the directory durable state is written to.

    Respects ``AGENT_BOM_STATE_DIR`` (set per-process to a temp dir in tests, so
    the durable default never touches the real home dir during a test run) and
    falls back to the per-user ``~/.agent-bom`` directory. Mirrors the
    resolution used by the runtime protection-engine kill-switch.
    """
    return Path(os.environ.get("AGENT_BOM_STATE_DIR", Path.home() / ".agent-bom"))


def default_state_db_path() -> str:
    """Return the durable SQLite path used when no backend is configured.

    Creates the parent directory if needed so first-run boot does not fail on a
    missing ``~/.agent-bom`` directory.
    """
    directory = state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    return str(directory / DEFAULT_STATE_DB_FILENAME)


def ephemeral_requested() -> bool:
    """True when the operator explicitly opted out of durability.

    ``AGENT_BOM_EPHEMERAL_STORE`` is the only way to get the legacy in-memory
    behaviour (state lost on restart). Useful for ephemeral CI jobs and tests
    that want a throwaway store without a file on disk.
    """
    raw = os.environ.get("AGENT_BOM_EPHEMERAL_STORE")
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _is_postgres_url(value: str) -> bool:
    return value.strip().lower().startswith(("postgres://", "postgresql://"))


def postgres_configured() -> bool:
    """True when a Postgres backend is configured for control-plane stores."""
    if os.environ.get("AGENT_BOM_POSTGRES_URL"):
        return True
    db = os.environ.get("AGENT_BOM_DB", "")
    return bool(db) and _is_postgres_url(db)


def sqlite_path() -> str:
    """Return the SQLite path for the durable default backend.

    Uses ``AGENT_BOM_DB`` when it points at a file path; otherwise the durable
    default under the state dir.
    """
    db = os.environ.get("AGENT_BOM_DB", "")
    if db and not _is_postgres_url(db):
        return db
    return default_state_db_path()


def select_backend() -> str:
    """Resolve the backend tier for a control-plane lifecycle store.

    Returns one of ``"postgres"``, ``"memory"``, or ``"sqlite"``. The default
    (no env config) is ``"sqlite"`` — durable by default. ``"memory"`` is only
    returned on an explicit ``AGENT_BOM_EPHEMERAL_STORE`` opt-out and never when
    Postgres is configured (Postgres durability always wins).
    """
    if postgres_configured():
        return "postgres"
    if ephemeral_requested():
        return "memory"
    return "sqlite"
