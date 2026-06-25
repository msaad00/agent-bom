"""Shared store contracts and the portable-schema seam.

The control-plane stores fall into a small *family* of shapes — they are not
one mega-interface (a cost record is not a runtime observation), so forcing all
of them through a single class would lie about the contract. Instead this module
captures the handful of things they genuinely share:

* every durable store is **tenant-scoped** (every read / write takes or filters
  by a tenant id) and knows how to **initialise its own schema** —
  :class:`TenantScopedStore`;
* some stores additionally support **TTL / retention cleanup** —
  :class:`CleanupCapable`.

These are :class:`~typing.Protocol`\\s with ``runtime_checkable`` so a store can
*declare* conformance structurally (no inheritance, no import cycles) and the
conformance test can assert it with ``isinstance``.

The :class:`StorageSchema` dataclass is the **portable-schema seam**: a store
declares its table contract once (logical columns + per-backend DDL), so the
SQLite and Postgres definitions are reviewed side by side and cannot silently
drift apart again. :data:`BackendKind` is the shared vocabulary the factory and
the stores agree on.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable


class BackendKind(str, Enum):
    """The storage tiers every control-plane store family supports.

    ``str``-valued so it round-trips through env / DSN parsing and JSON status
    surfaces without extra conversion. The values match the strings
    :func:`agent_bom.api.durable_store.select_backend` already returns, so the
    factory and the legacy selector speak the same language.
    """

    SQLITE = "sqlite"
    POSTGRES = "postgres"
    MEMORY = "memory"


@runtime_checkable
class TenantScopedStore(Protocol):
    """Structural contract shared by every durable control-plane store.

    A conforming store can (re)create its own schema idempotently via
    :meth:`init_schema` and isolates rows by tenant on every read/write. The
    concrete record types differ per store family, so the read/write methods are
    intentionally *not* pinned here — this protocol captures only the universal
    seam (schema bootstrap + tenant scoping marker) that lets the factory and
    the conformance test treat any backend uniformly.
    """

    def init_schema(self) -> None:
        """Idempotently create tables / indexes for this store's backend."""
        ...


@runtime_checkable
class CleanupCapable(Protocol):
    """Stores that expire rows on a TTL / retention tick.

    Mirrors the ``cleanup_expired`` / ``cleanup_audit_log`` methods the replay
    and policy-audit stores already expose, surfaced as a shared capability so
    the lifecycle tick can treat any cleanup-capable backend uniformly.
    """

    def cleanup_expired(self) -> int:
        """Delete expired rows; return the number removed."""
        ...


@dataclass(frozen=True)
class TableSchema:
    """One table's portable definition: logical columns + per-backend DDL.

    ``columns`` is the backend-agnostic logical column list (the source of truth
    a reviewer reads). ``ddl_by_backend`` maps a :class:`BackendKind` value to
    the exact ``CREATE TABLE`` statement that realises those columns on that
    backend. Keeping both next to each other is the whole point of the seam: a
    column added to ``columns`` but missing from one backend's DDL is visible in
    one place instead of buried in two files.
    """

    name: str
    columns: tuple[str, ...]
    ddl_by_backend: Mapping[str, str] = field(default_factory=dict)

    def ddl_for(self, backend: BackendKind | str) -> str | None:
        """Return the ``CREATE TABLE`` statement for ``backend`` if declared."""
        key = backend.value if isinstance(backend, BackendKind) else str(backend)
        return self.ddl_by_backend.get(key)


@dataclass(frozen=True)
class StorageSchema:
    """A store's full table contract, declared once and shared across backends.

    This is the reference implementation of the portable-schema seam (see the
    ``llm_costs`` reference in :mod:`agent_bom.api.cost_store`). It does not
    *execute* DDL — the stores keep their existing, audited ``_init_db`` /
    ``_init_tables`` paths — it makes the contract *inspectable* so:

    * a conformance / parity test can assert the SQLite and Postgres DDL cover
      the same logical columns, catching drift at test time, and
    * a new backend is added by registering one more entry in ``ddl_by_backend``
      rather than forking a store.
    """

    component: str
    tables: tuple[TableSchema, ...]

    def table(self, name: str) -> TableSchema | None:
        for t in self.tables:
            if t.name == name:
                return t
        return None

    def backends(self) -> frozenset[str]:
        """Every backend any table in this schema declares DDL for."""
        out: set[str] = set()
        for t in self.tables:
            out.update(t.ddl_by_backend.keys())
        return frozenset(out)

    def drift_report(self) -> dict[str, list[str]]:
        """Map each table to the backends missing a DDL definition.

        Empty dict ⇒ every table defines DDL for every backend the schema
        mentions (no drift). Used by the conformance test to fail loudly the
        moment a column/table lands on one backend but not its sibling.
        """
        declared = self.backends()
        report: dict[str, list[str]] = {}
        for t in self.tables:
            missing = sorted(declared - set(t.ddl_by_backend.keys()))
            if missing:
                report[t.name] = missing
        return report
