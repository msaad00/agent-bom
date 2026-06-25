"""Shared storage foundation for agent-bom control-plane stores.

Historically every control-plane store (cost, policy, runtime-event, proxy
replay, …) reimplemented its own SQLite + Postgres + in-memory triad with no
shared contract. Backend selection was duplicated three different ways
(``os.environ`` checks in ``cost_store`` / ``proxy_replay_store`` vs
``durable_store.select_backend()`` in ``runtime_event_store``), and each store
hand-rolled its DDL twice — which is exactly how the SQLite⇄Postgres column /
timestamp / dedup drift a prior audit caught crept in.

This package gives those stores one shared seam:

* :mod:`agent_bom.storage.base` — the structural :class:`~typing.Protocol`
  family each store family already satisfies, plus the :class:`BackendKind`
  vocabulary and the :class:`StorageSchema` source-of-truth-schema seam so a
  store's table shape is declared once and shared across backends.
* :mod:`agent_bom.storage.factory` — :func:`~agent_bom.storage.factory.resolve_backend`,
  the single place backend selection from a DSN / environment lives, so adding
  a new backend (MySQL, ClickHouse, …) is a registration rather than a fork of
  every store.

The foundation is **additive**: existing stores declare conformance and route
their selection through the factory, but every method signature, table shape,
and the #21 idempotency / caller-supplied-timestamp guarantees stay exactly as
they were.
"""

from __future__ import annotations

from agent_bom.storage.base import (
    BackendKind,
    CleanupCapable,
    StorageSchema,
    TenantScopedStore,
)
from agent_bom.storage.factory import (
    BackendSelection,
    resolve_backend,
)

__all__ = [
    "BackendKind",
    "BackendSelection",
    "CleanupCapable",
    "StorageSchema",
    "TenantScopedStore",
    "resolve_backend",
]
