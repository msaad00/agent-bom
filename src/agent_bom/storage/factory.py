"""Single source of truth for storage-backend selection.

Before this module, three stores each decided their backend by hand:

* ``cost_store.get_cost_store`` and ``proxy_replay_store.get_proxy_replay_store``
  branched on ``AGENT_BOM_POSTGRES_URL`` then ``AGENT_BOM_DB`` then in-memory;
* ``runtime_event_store`` delegated to ``durable_store.select_backend()`` (which
  is durable-by-default: SQLite unless an explicit ephemeral opt-out).

Two subtly different precedence ladders for the same decision is exactly how a
store ends up on the wrong tier. :func:`resolve_backend` centralises the choice
and can resolve from either an explicit DSN (``sqlite://…`` / ``postgresql://…``
/ ``memory://``) or the process environment, returning a typed
:class:`BackendSelection`. Both legacy ladders are preserved as named modes so
no store changes tier:

* ``mode="env"`` (default) reproduces the cost/replay ladder exactly:
  Postgres → SQLite(``AGENT_BOM_DB``) → in-memory.
* ``mode="durable"`` reproduces ``durable_store.select_backend()``:
  Postgres → in-memory(only on explicit ephemeral opt-out) → durable SQLite.

Adding a backend (MySQL, ClickHouse, …) becomes a new scheme registered here,
not a fourth bespoke ladder copied into a store.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from agent_bom.storage.base import BackendKind

# DSN scheme → backend tier. Adding a backend registers one entry here instead
# of forking a store's selection logic.
_SCHEME_TO_BACKEND: dict[str, BackendKind] = {
    "sqlite": BackendKind.SQLITE,
    "file": BackendKind.SQLITE,
    "postgres": BackendKind.POSTGRES,
    "postgresql": BackendKind.POSTGRES,
    "memory": BackendKind.MEMORY,
    "inmemory": BackendKind.MEMORY,
}


@dataclass(frozen=True)
class BackendSelection:
    """The resolved backend tier plus the SQLite path (when applicable).

    ``sqlite_path`` is populated only for :attr:`BackendKind.SQLITE`; it is the
    file path a ``SQLite*Store`` should open. ``dsn`` carries the originating
    Postgres URL when selection came from an explicit DSN (``None`` when the
    store reads its URL from the pool/env itself, matching today's behaviour).
    """

    backend: BackendKind
    sqlite_path: str | None = None
    dsn: str | None = None


def _is_postgres_url(value: str) -> bool:
    return value.strip().lower().startswith(("postgres://", "postgresql://"))


def _scheme(value: str) -> str | None:
    head, sep, _ = value.partition("://")
    return head.strip().lower() if sep else None


def resolve_from_dsn(dsn: str) -> BackendSelection:
    """Resolve a backend from an explicit DSN string.

    ``sqlite:///path/to.db`` / ``file:///path`` → SQLite at that path,
    ``postgresql://…`` / ``postgres://…`` → Postgres, ``memory://`` → in-memory.
    A bare filesystem path (no ``://``) is treated as a SQLite file, matching
    how ``AGENT_BOM_DB`` accepts a plain path today.
    """
    scheme = _scheme(dsn)
    if scheme is None:
        # Bare path → SQLite file (AGENT_BOM_DB-style).
        return BackendSelection(BackendKind.SQLITE, sqlite_path=dsn)
    backend = _SCHEME_TO_BACKEND.get(scheme)
    if backend is None:
        raise ValueError(f"unsupported storage DSN scheme: {scheme!r}")
    if backend is BackendKind.SQLITE:
        # Strip the scheme; tolerate sqlite:///abs and sqlite://rel forms.
        _, _, rest = dsn.partition("://")
        path = rest.lstrip("/") if rest.startswith("/") else rest
        # sqlite:///abs/path keeps the leading slash; re-add it for triple-slash.
        if dsn.lower().startswith(("sqlite:///", "file:///")):
            path = "/" + path
        return BackendSelection(BackendKind.SQLITE, sqlite_path=path or ":memory:")
    if backend is BackendKind.POSTGRES:
        return BackendSelection(BackendKind.POSTGRES, dsn=dsn)
    return BackendSelection(BackendKind.MEMORY)


def _resolve_from_env_durable() -> BackendSelection:
    """Durable-by-default ladder (matches ``durable_store.select_backend``)."""
    from agent_bom.api import durable_store

    backend = durable_store.select_backend()
    if backend == "postgres":
        return BackendSelection(BackendKind.POSTGRES)
    if backend == "memory":
        return BackendSelection(BackendKind.MEMORY)
    return BackendSelection(BackendKind.SQLITE, sqlite_path=durable_store.sqlite_path())


def _resolve_from_env_simple() -> BackendSelection:
    """Postgres → SQLite(AGENT_BOM_DB) → in-memory (cost/replay ladder)."""
    if os.environ.get("AGENT_BOM_POSTGRES_URL"):
        return BackendSelection(BackendKind.POSTGRES)
    db = os.environ.get("AGENT_BOM_DB")
    if db:
        if _is_postgres_url(db):
            return BackendSelection(BackendKind.POSTGRES, dsn=db)
        return BackendSelection(BackendKind.SQLITE, sqlite_path=db)
    return BackendSelection(BackendKind.MEMORY)


def resolve_backend(dsn_or_env: str | None = None, *, mode: str = "env") -> BackendSelection:
    """Resolve which storage backend a store should use.

    Args:
        dsn_or_env: An explicit DSN (``sqlite://…`` / ``postgresql://…`` /
            ``memory://`` / bare path). When ``None`` (the common case) the
            process environment is consulted instead.
        mode: Which environment ladder to apply when ``dsn_or_env`` is ``None``:

            * ``"env"`` (default) — Postgres → SQLite(``AGENT_BOM_DB``) →
              in-memory. The ladder ``cost_store`` / ``proxy_replay_store`` use.
            * ``"durable"`` — durable-by-default (Postgres → in-memory only on
              explicit ``AGENT_BOM_EPHEMERAL_STORE`` → SQLite). The ladder
              ``runtime_event_store`` uses.

    Returns:
        A :class:`BackendSelection` naming the tier and, for SQLite, the path.
    """
    if dsn_or_env is not None:
        return resolve_from_dsn(dsn_or_env)
    if mode == "durable":
        return _resolve_from_env_durable()
    if mode == "env":
        return _resolve_from_env_simple()
    raise ValueError(f"unknown backend resolution mode: {mode!r}")
