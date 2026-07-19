"""Storage-backed graph build workspace (#4075, PR-1 of the producer-streaming series).

Foundation for streaming the correlated-graph *producer*
(:func:`agent_bom.graph.builder.build_unified_graph_from_report`) to a
storage-backed staging area instead of materialising the entire
:class:`~agent_bom.graph.container.UnifiedGraph` in memory.

A :class:`GraphBuildWorkspace` accepts nodes and edges in **bounded batches** —
spilling each batch to a backing store (a private SQLite temp DB, or the shared
Postgres) and never retaining the full set — and yields them back in bounded
batches for a downstream consumer (the persist write path). Its in-memory
working set is bounded by ``batch_size``, not by the total graph size.

Scope of this PR (PR-1 of the four-PR series):

* the workspace primitive + both backends (SQLite + Postgres), tenant-scoped,
  idempotent, cross-process safe on Postgres;
* the first bounded consumer — the persist path can stream a graph through the
  workspace into the store and produce a byte-identical snapshot (opt-in via
  ``AGENT_BOM_GRAPH_BUILD_WORKSPACE`` so the shipped default path is unchanged).

Re-plumbing the builder's phases to emit **directly** into the workspace — which
removes the builder's own materialisation and realises the #4055 peak-RSS bound
end to end — is PR-2/3/4 of the series and is intentionally out of scope here.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import uuid
from collections.abc import Iterable, Iterator
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol

from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import RelationshipType

_DEFAULT_BATCH_SIZE = 1000
_UNIT_SEP = "\x1f"


def _batch_size() -> int:
    raw = os.environ.get("AGENT_BOM_GRAPH_WRITE_BATCH_SIZE", str(_DEFAULT_BATCH_SIZE))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_BATCH_SIZE
    return value if value > 0 else _DEFAULT_BATCH_SIZE


def _normalize_tenant(tenant_id: str) -> str:
    return tenant_id or "default"


def _edge_key(edge: UnifiedEdge) -> str:
    rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
    return f"{edge.source}{_UNIT_SEP}{edge.target}{_UNIT_SEP}{rel}"


def _node_from_payload(payload: dict[str, Any]) -> UnifiedNode:
    """Reconstruct a node so its persisted form is byte-identical to the original.

    :meth:`UnifiedNode.from_dict` injects ``canonical_id`` into ``attributes``
    when absent; the persist path serialises ``node.attributes`` verbatim, so we
    restore the exact stored attributes to avoid that one-key drift.
    """
    node = UnifiedNode.from_dict(payload)
    node.attributes = dict(payload.get("attributes", {}))
    return node


def _edge_from_payload(payload: dict[str, Any]) -> UnifiedEdge:
    return UnifiedEdge.from_dict(payload)


class WorkspaceBackend(Protocol):
    """Bounded, tenant-scoped staging store for graph nodes and edges."""

    def add_node_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str]]) -> None: ...

    def add_edge_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str]]) -> None: ...

    def iter_node_payloads(self, tenant_id: str, batch_size: int) -> Iterator[str]: ...

    def iter_edge_payloads(self, tenant_id: str, batch_size: int) -> Iterator[str]: ...

    def count_nodes(self, tenant_id: str) -> int: ...

    def count_edges(self, tenant_id: str) -> int: ...

    def close(self) -> None: ...


class _SQLiteWorkspaceBackend:
    """Process-local staging store backed by a private SQLite temp database."""

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            fd, name = tempfile.mkstemp(prefix="abom-gws-", suffix=".db")
            os.close(fd)
            self._path = Path(name)
            self._owns_file = True
        else:
            self._path = Path(db_path)
            self._owns_file = False
        self._conn = sqlite3.connect(str(self._path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS ws_nodes ("
            "tenant_id TEXT NOT NULL, node_id TEXT NOT NULL, "
            "seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, "
            "UNIQUE(tenant_id, node_id))"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS ws_edges ("
            "tenant_id TEXT NOT NULL, edge_key TEXT NOT NULL, "
            "seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, "
            "UNIQUE(tenant_id, edge_key))"
        )
        self._conn.commit()

    def _upsert(self, table: str, key_col: str, tenant_id: str, rows: Iterable[tuple[str, str]]) -> None:
        self._conn.executemany(
            f"INSERT INTO {table} (tenant_id, {key_col}, payload) VALUES (?, ?, ?) "  # nosec B608 - static table/col
            f"ON CONFLICT(tenant_id, {key_col}) DO UPDATE SET payload=excluded.payload",
            ((tenant_id, key, payload) for key, payload in rows),
        )
        self._conn.commit()

    def add_node_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str]]) -> None:
        self._upsert("ws_nodes", "node_id", tenant_id, rows)

    def add_edge_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str]]) -> None:
        self._upsert("ws_edges", "edge_key", tenant_id, rows)

    def _iter_payloads(self, table: str, tenant_id: str, batch_size: int) -> Iterator[str]:
        cur = self._conn.cursor()
        cur.execute(
            f"SELECT payload FROM {table} WHERE tenant_id = ? ORDER BY seq",  # nosec B608 - static table
            (tenant_id,),
        )
        try:
            while True:
                batch = cur.fetchmany(batch_size)
                if not batch:
                    return
                for (payload,) in batch:
                    yield payload
        finally:
            cur.close()

    def iter_node_payloads(self, tenant_id: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("ws_nodes", tenant_id, batch_size)

    def iter_edge_payloads(self, tenant_id: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("ws_edges", tenant_id, batch_size)

    def _count(self, table: str, tenant_id: str) -> int:
        row = self._conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE tenant_id = ?",  # nosec B608 - static table
            (tenant_id,),
        ).fetchone()
        return int(row[0]) if row else 0

    def count_nodes(self, tenant_id: str) -> int:
        return self._count("ws_nodes", tenant_id)

    def count_edges(self, tenant_id: str) -> int:
        return self._count("ws_edges", tenant_id)

    def close(self) -> None:
        try:
            self._conn.close()
        finally:
            if self._owns_file:
                for suffix in ("", "-wal", "-shm"):
                    p = Path(str(self._path) + suffix)
                    try:
                        p.unlink()
                    except FileNotFoundError:
                        pass


class _PostgresWorkspaceBackend:
    """Shared, cross-process staging store backed by Postgres.

    Rows are namespaced by ``workspace_id`` so independent concurrent builds do
    not collide, and scoped by ``tenant_id`` for isolation. A ``BIGSERIAL``
    sequence gives a globally monotonic insertion order across writers, so a
    reader observes a deterministic order regardless of which process wrote a
    row. Reads use a server-side named cursor so the working set stays bounded
    by ``itersize`` rather than the total row count.
    """

    def __init__(self, dsn: str, workspace_id: str) -> None:
        import psycopg

        self._psycopg = psycopg
        self._dsn = dsn
        self._workspace_id = workspace_id
        self._conn = psycopg.connect(dsn, autocommit=True)
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        # payload is stored as TEXT, not JSONB: JSONB normalises key order, which
        # would change the persisted ``attributes`` byte-for-byte after the
        # downstream ``json.dumps``. TEXT preserves the exact serialised bytes so
        # the workspace round-trip stays byte-identical to the direct save.
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS graph_build_workspace_nodes ("
            "workspace_id TEXT NOT NULL, tenant_id TEXT NOT NULL, node_id TEXT NOT NULL, "
            "seq BIGSERIAL, payload TEXT NOT NULL, "
            "PRIMARY KEY (workspace_id, tenant_id, node_id))"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS graph_build_workspace_edges ("
            "workspace_id TEXT NOT NULL, tenant_id TEXT NOT NULL, edge_key TEXT NOT NULL, "
            "seq BIGSERIAL, payload TEXT NOT NULL, "
            "PRIMARY KEY (workspace_id, tenant_id, edge_key))"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_gbw_nodes_seq ON graph_build_workspace_nodes (workspace_id, tenant_id, seq)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_gbw_edges_seq ON graph_build_workspace_edges (workspace_id, tenant_id, seq)")

    def _upsert(self, table: str, key_col: str, tenant_id: str, rows: Iterable[tuple[str, str]]) -> None:
        sql = (
            f"INSERT INTO {table} (workspace_id, tenant_id, {key_col}, payload) "  # nosec B608 - static table/col
            f"VALUES (%s, %s, %s, %s) "
            f"ON CONFLICT (workspace_id, tenant_id, {key_col}) DO UPDATE SET payload = EXCLUDED.payload"
        )
        with self._conn.cursor() as cur:
            params = ((self._workspace_id, tenant_id, key, payload) for key, payload in rows)
            cur.executemany(sql, params)

    def add_node_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str]]) -> None:
        self._upsert("graph_build_workspace_nodes", "node_id", tenant_id, rows)

    def add_edge_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str]]) -> None:
        self._upsert("graph_build_workspace_edges", "edge_key", tenant_id, rows)

    def _iter_payloads(self, table: str, tenant_id: str, batch_size: int) -> Iterator[str]:
        # Server-side named cursor streams rows in bounded chunks (itersize) so
        # the client never buffers the whole result set — a plain client cursor
        # would fetch every row on execute, defeating the memory bound. A named
        # cursor requires an open transaction, so wrap the scan in one (the
        # connection is autocommit for writes).
        name = f"gbw_{uuid.uuid4().hex}"
        with self._conn.transaction(), self._conn.cursor(name=name) as cur:
            cur.itersize = batch_size
            cur.execute(
                f"SELECT payload FROM {table} WHERE workspace_id = %s AND tenant_id = %s ORDER BY seq",  # nosec B608
                (self._workspace_id, tenant_id),
            )
            for (payload,) in cur:
                # payload is TEXT — yield the exact stored bytes.
                yield payload if isinstance(payload, str) else json.dumps(payload)

    def iter_node_payloads(self, tenant_id: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("graph_build_workspace_nodes", tenant_id, batch_size)

    def iter_edge_payloads(self, tenant_id: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("graph_build_workspace_edges", tenant_id, batch_size)

    def _count(self, table: str, tenant_id: str) -> int:
        row = self._conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE workspace_id = %s AND tenant_id = %s",  # nosec B608 - static table
            (self._workspace_id, tenant_id),
        ).fetchone()
        return int(row[0]) if row else 0

    def count_nodes(self, tenant_id: str) -> int:
        return self._count("graph_build_workspace_nodes", tenant_id)

    def count_edges(self, tenant_id: str) -> int:
        return self._count("graph_build_workspace_edges", tenant_id)

    def close(self) -> None:
        # Drop only this workspace's rows; the shared tables persist for reuse.
        try:
            self._conn.execute(
                "DELETE FROM graph_build_workspace_nodes WHERE workspace_id = %s",
                (self._workspace_id,),
            )
            self._conn.execute(
                "DELETE FROM graph_build_workspace_edges WHERE workspace_id = %s",
                (self._workspace_id,),
            )
        finally:
            self._conn.close()


class GraphBuildWorkspace:
    """Bounded, storage-backed staging area for a graph build.

    ``add_nodes``/``add_edges`` consume producer iterables in bounded batches and
    spill each batch to the backing store without retaining it; ``iter_nodes``/
    ``iter_edges`` stream the staged items back in bounded batches. The peak
    in-memory working set is proportional to ``batch_size``, not to the total
    number of nodes/edges.

    The caller must yield **deduplicated** producers — unique node ``id`` and
    unique ``(source, target, relationship)`` edge keys — exactly the invariant
    :class:`~agent_bom.graph.container.UnifiedGraph` maintains and that
    :func:`~agent_bom.db.graph_store.save_graph_streaming` requires downstream.
    Re-adding the same key is idempotent (last write wins on the payload).
    """

    def __init__(
        self,
        backend: WorkspaceBackend,
        *,
        tenant_id: str = "",
        batch_size: int | None = None,
    ) -> None:
        self._backend = backend
        self._tenant_id = _normalize_tenant(tenant_id)
        self._batch_size = batch_size if (batch_size and batch_size > 0) else _batch_size()

    @property
    def tenant_id(self) -> str:
        return self._tenant_id

    def add_nodes(self, nodes: Iterable[UnifiedNode]) -> None:
        for batch in _batched(((n.id, json.dumps(n.to_dict(), default=str)) for n in nodes), self._batch_size):
            self._backend.add_node_payloads(self._tenant_id, batch)

    def add_edges(self, edges: Iterable[UnifiedEdge]) -> None:
        for batch in _batched(((_edge_key(e), json.dumps(e.to_dict(), default=str)) for e in edges), self._batch_size):
            self._backend.add_edge_payloads(self._tenant_id, batch)

    def iter_nodes(self) -> Iterator[UnifiedNode]:
        for payload in self._backend.iter_node_payloads(self._tenant_id, self._batch_size):
            yield _node_from_payload(json.loads(payload))

    def iter_edges(self) -> Iterator[UnifiedEdge]:
        for payload in self._backend.iter_edge_payloads(self._tenant_id, self._batch_size):
            yield _edge_from_payload(json.loads(payload))

    def node_count(self) -> int:
        return self._backend.count_nodes(self._tenant_id)

    def edge_count(self) -> int:
        return self._backend.count_edges(self._tenant_id)

    def close(self) -> None:
        self._backend.close()

    def __enter__(self) -> GraphBuildWorkspace:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _batched(items: Iterable[tuple[str, str]], size: int) -> Iterator[list[tuple[str, str]]]:
    batch: list[tuple[str, str]] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def open_graph_build_workspace(
    *,
    tenant_id: str = "",
    workspace_id: str = "",
    backend: str = "auto",
    batch_size: int | None = None,
) -> GraphBuildWorkspace:
    """Open a build workspace on the appropriate backend.

    ``backend="auto"`` selects Postgres when ``AGENT_BOM_POSTGRES_URL`` is set,
    otherwise a private SQLite temp database. ``workspace_id`` namespaces a build
    on the shared Postgres tables (defaults to a fresh UUID); it is ignored by
    the process-local SQLite backend.
    """
    wsid = workspace_id or uuid.uuid4().hex
    dsn = os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip()
    chosen = backend
    if chosen == "auto":
        chosen = "postgres" if dsn else "sqlite"

    impl: WorkspaceBackend
    if chosen == "postgres":
        if not dsn:
            raise ValueError("AGENT_BOM_POSTGRES_URL is required for the postgres workspace backend.")
        impl = _PostgresWorkspaceBackend(dsn, wsid)
    elif chosen == "sqlite":
        impl = _SQLiteWorkspaceBackend()
    else:
        raise ValueError(f"unknown workspace backend {backend!r}")
    return GraphBuildWorkspace(impl, tenant_id=tenant_id, batch_size=batch_size)
