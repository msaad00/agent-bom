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

The follow-on foundation adds **random-access reads** to both backends —
``get_node_payload`` / ``iter_node_payloads_by_type`` /
``iter_edge_payloads_by_source`` / ``iter_edge_payloads_by_target`` — backed by
indexed ``entity_type`` / ``source_id`` / ``target_id`` columns. These are the
read side a store-backed producer needs so the builder's Phase-B overlays can
query the staged graph without materialising the whole node set. They are
**default-off and unwired**: no builder, container, or persist consumer calls
them yet. The store-backed live graph container that consumes them (removing the
builder's own materialisation to realise the #4055 peak-RSS bound end to end) is
a later PR held for owner sign-off, and is intentionally out of scope here.
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
from typing import Any, Protocol, TypeVar

from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

_DEFAULT_BATCH_SIZE = 1000
_UNIT_SEP = "\x1f"
_RowT = TypeVar("_RowT", bound=tuple[str, ...])


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


def _node_entity_type(node: UnifiedNode) -> str:
    """The entity_type as stored in the random-access index column.

    Mirrors the ``EntityType.value`` string every graph surface indexes on, so
    ``iter_node_payloads_by_type(entity_type)`` matches ``UnifiedGraph.nodes_by_type``.
    """
    et = node.entity_type
    return et.value if isinstance(et, EntityType) else str(et)


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
    """Bounded, tenant-scoped staging store for graph nodes and edges.

    Node rows are ``(node_id, payload, entity_type)`` and edge rows are
    ``(edge_key, payload, source_id, target_id)``; the extra columns back the
    random-access read methods (``get_node_payload`` /
    ``iter_node_payloads_by_type`` / ``iter_edge_payloads_by_source`` /
    ``iter_edge_payloads_by_target``) without ever parsing the opaque payload.
    """

    def add_node_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str, str]]) -> None: ...

    def add_edge_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str, str, str]]) -> None: ...

    def iter_node_payloads(self, tenant_id: str, batch_size: int) -> Iterator[str]: ...

    def iter_edge_payloads(self, tenant_id: str, batch_size: int) -> Iterator[str]: ...

    # Random-access reads (#4075 PR-2 foundation) — the read side a store-backed
    # producer needs so Phase-B overlays can query without materialising the
    # whole node set. No consumer is wired to these yet.
    def get_node_payload(self, tenant_id: str, node_id: str) -> str | None: ...

    def get_edge_payload(self, tenant_id: str, edge_key: str) -> str | None: ...

    def iter_node_payloads_by_type(self, tenant_id: str, entity_type: str, batch_size: int) -> Iterator[str]: ...

    def iter_edge_payloads_by_source(self, tenant_id: str, node_id: str, batch_size: int) -> Iterator[str]: ...

    def iter_edge_payloads_by_target(self, tenant_id: str, node_id: str, batch_size: int) -> Iterator[str]: ...

    # Keyset-paged reads (#4075 PR-3) — each call runs one bounded, self-contained
    # query (no server-side cursor left open), so the store-backed live graph
    # container can interleave write-back between pages without a cursor conflict.
    # ``fetch_node_page`` rows are ``(seq, node_id, payload)``; ``fetch_edge_page``
    # rows are ``(seq, payload)``. Both order by ``seq`` (insertion order) and
    # return rows with ``seq > after_seq`` — keyset the last seq to page forward.
    def fetch_node_page(self, tenant_id: str, after_seq: int, limit: int, entity_type: str | None = None) -> list[tuple[int, str, str]]: ...

    def fetch_edge_page(
        self, tenant_id: str, after_seq: int, limit: int, source_id: str | None = None, target_id: str | None = None
    ) -> list[tuple[int, str]]: ...

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
        # ``entity_type`` (nodes) and ``source_id``/``target_id`` (edges) back the
        # random-access read indexes; kept in lock-step with the Postgres backend
        # (graph_build_workspace_nodes/_edges). SQLite workspace DBs are private
        # temp files created fresh per build, so the columns live directly in the
        # CREATE TABLE (no ALTER-migration path is reachable, unlike shared PG).
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS ws_nodes ("
            "tenant_id TEXT NOT NULL, node_id TEXT NOT NULL, "
            "seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, "
            "entity_type TEXT NOT NULL DEFAULT '', "
            "UNIQUE(tenant_id, node_id))"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS ws_edges ("
            "tenant_id TEXT NOT NULL, edge_key TEXT NOT NULL, "
            "seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL, "
            "source_id TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '', "
            "UNIQUE(tenant_id, edge_key))"
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ws_nodes_type ON ws_nodes (tenant_id, entity_type, seq)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ws_edges_source ON ws_edges (tenant_id, source_id, seq)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ws_edges_target ON ws_edges (tenant_id, target_id, seq)")
        self._conn.commit()

    def _upsert(
        self,
        table: str,
        key_col: str,
        extra_cols: tuple[str, ...],
        tenant_id: str,
        rows: Iterable[tuple[str, ...]],
    ) -> None:
        cols = ("tenant_id", key_col, "payload", *extra_cols)
        placeholders = ", ".join("?" for _ in cols)
        updates = ", ".join(f"{c}=excluded.{c}" for c in ("payload", *extra_cols))
        self._conn.executemany(
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders}) "  # nosec B608 - static table/cols
            f"ON CONFLICT(tenant_id, {key_col}) DO UPDATE SET {updates}",
            ((tenant_id, *row) for row in rows),
        )
        self._conn.commit()

    def add_node_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str, str]]) -> None:
        self._upsert("ws_nodes", "node_id", ("entity_type",), tenant_id, rows)

    def add_edge_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str, str, str]]) -> None:
        self._upsert("ws_edges", "edge_key", ("source_id", "target_id"), tenant_id, rows)

    def _iter_payloads(
        self,
        table: str,
        tenant_id: str,
        batch_size: int,
        *,
        where_col: str | None = None,
        where_val: str | None = None,
    ) -> Iterator[str]:
        cur = self._conn.cursor()
        params: tuple[str, ...] = (tenant_id,)
        predicate = ""
        if where_col is not None:
            predicate = f" AND {where_col} = ?"
            params = (tenant_id, str(where_val))
        cur.execute(
            f"SELECT payload FROM {table} WHERE tenant_id = ?{predicate} ORDER BY seq",  # nosec B608 - static table/col
            params,
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

    def get_node_payload(self, tenant_id: str, node_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT payload FROM ws_nodes WHERE tenant_id = ? AND node_id = ?",
            (tenant_id, node_id),
        ).fetchone()
        return str(row[0]) if row else None

    def get_edge_payload(self, tenant_id: str, edge_key: str) -> str | None:
        row = self._conn.execute(
            "SELECT payload FROM ws_edges WHERE tenant_id = ? AND edge_key = ?",
            (tenant_id, edge_key),
        ).fetchone()
        return str(row[0]) if row else None

    def fetch_node_page(self, tenant_id: str, after_seq: int, limit: int, entity_type: str | None = None) -> list[tuple[int, str, str]]:
        params: tuple[Any, ...] = (tenant_id,)
        predicate = ""
        if entity_type is not None:
            predicate = " AND entity_type = ?"
            params = (tenant_id, entity_type)
        params = (*params, after_seq, limit)
        rows = self._conn.execute(
            f"SELECT seq, node_id, payload FROM ws_nodes WHERE tenant_id = ?{predicate} "  # nosec B608 - static cols
            "AND seq > ? ORDER BY seq LIMIT ?",
            params,
        ).fetchall()
        return [(int(seq), str(node_id), str(payload)) for seq, node_id, payload in rows]

    def fetch_edge_page(
        self, tenant_id: str, after_seq: int, limit: int, source_id: str | None = None, target_id: str | None = None
    ) -> list[tuple[int, str]]:
        params: tuple[Any, ...] = (tenant_id,)
        predicate = ""
        if source_id is not None:
            predicate = " AND source_id = ?"
            params = (tenant_id, source_id)
        elif target_id is not None:
            predicate = " AND target_id = ?"
            params = (tenant_id, target_id)
        params = (*params, after_seq, limit)
        rows = self._conn.execute(
            f"SELECT seq, payload FROM ws_edges WHERE tenant_id = ?{predicate} "  # nosec B608 - static cols
            "AND seq > ? ORDER BY seq LIMIT ?",
            params,
        ).fetchall()
        return [(int(seq), str(payload)) for seq, payload in rows]

    def iter_node_payloads_by_type(self, tenant_id: str, entity_type: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("ws_nodes", tenant_id, batch_size, where_col="entity_type", where_val=entity_type)

    def iter_edge_payloads_by_source(self, tenant_id: str, node_id: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("ws_edges", tenant_id, batch_size, where_col="source_id", where_val=node_id)

    def iter_edge_payloads_by_target(self, tenant_id: str, node_id: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("ws_edges", tenant_id, batch_size, where_col="target_id", where_val=node_id)

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
            "seq BIGSERIAL, payload TEXT NOT NULL, entity_type TEXT NOT NULL DEFAULT '', "
            "PRIMARY KEY (workspace_id, tenant_id, node_id))"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS graph_build_workspace_edges ("
            "workspace_id TEXT NOT NULL, tenant_id TEXT NOT NULL, edge_key TEXT NOT NULL, "
            "seq BIGSERIAL, payload TEXT NOT NULL, "
            "source_id TEXT NOT NULL DEFAULT '', target_id TEXT NOT NULL DEFAULT '', "
            "PRIMARY KEY (workspace_id, tenant_id, edge_key))"
        )
        # Idempotent column migration for shared tables created by an earlier
        # version (the PG workspace tables persist across builds), mirroring the
        # postgres_graph._init_tables ADD COLUMN IF NOT EXISTS pattern.
        self._conn.execute("ALTER TABLE graph_build_workspace_nodes ADD COLUMN IF NOT EXISTS entity_type TEXT NOT NULL DEFAULT ''")
        self._conn.execute("ALTER TABLE graph_build_workspace_edges ADD COLUMN IF NOT EXISTS source_id TEXT NOT NULL DEFAULT ''")
        self._conn.execute("ALTER TABLE graph_build_workspace_edges ADD COLUMN IF NOT EXISTS target_id TEXT NOT NULL DEFAULT ''")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_gbw_nodes_seq ON graph_build_workspace_nodes (workspace_id, tenant_id, seq)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_gbw_edges_seq ON graph_build_workspace_edges (workspace_id, tenant_id, seq)")
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_gbw_nodes_type ON graph_build_workspace_nodes (workspace_id, tenant_id, entity_type, seq)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_gbw_edges_source ON graph_build_workspace_edges (workspace_id, tenant_id, source_id, seq)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_gbw_edges_target ON graph_build_workspace_edges (workspace_id, tenant_id, target_id, seq)"
        )

    def _upsert(
        self,
        table: str,
        key_col: str,
        extra_cols: tuple[str, ...],
        tenant_id: str,
        rows: Iterable[tuple[str, ...]],
    ) -> None:
        cols = ("workspace_id", "tenant_id", key_col, "payload", *extra_cols)
        placeholders = ", ".join("%s" for _ in cols)
        updates = ", ".join(f"{c} = EXCLUDED.{c}" for c in ("payload", *extra_cols))
        sql = (
            f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders}) "  # nosec B608 - static table/cols
            f"ON CONFLICT (workspace_id, tenant_id, {key_col}) DO UPDATE SET {updates}"
        )
        with self._conn.cursor() as cur:
            params = ((self._workspace_id, tenant_id, *row) for row in rows)
            cur.executemany(sql, params)

    def add_node_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str, str]]) -> None:
        self._upsert("graph_build_workspace_nodes", "node_id", ("entity_type",), tenant_id, rows)

    def add_edge_payloads(self, tenant_id: str, rows: Iterable[tuple[str, str, str, str]]) -> None:
        self._upsert("graph_build_workspace_edges", "edge_key", ("source_id", "target_id"), tenant_id, rows)

    def _iter_payloads(
        self,
        table: str,
        tenant_id: str,
        batch_size: int,
        *,
        where_col: str | None = None,
        where_val: str | None = None,
    ) -> Iterator[str]:
        # Server-side named cursor streams rows in bounded chunks (itersize) so
        # the client never buffers the whole result set — a plain client cursor
        # would fetch every row on execute, defeating the memory bound. A named
        # cursor requires an open transaction, so wrap the scan in one (the
        # connection is autocommit for writes).
        params: tuple[str, ...] = (self._workspace_id, tenant_id)
        predicate = ""
        if where_col is not None:
            predicate = f" AND {where_col} = %s"
            params = (self._workspace_id, tenant_id, str(where_val))
        name = f"gbw_{uuid.uuid4().hex}"
        with self._conn.transaction(), self._conn.cursor(name=name) as cur:
            cur.itersize = batch_size
            cur.execute(
                f"SELECT payload FROM {table} WHERE workspace_id = %s AND tenant_id = %s{predicate} ORDER BY seq",  # nosec B608
                params,
            )
            for (payload,) in cur:
                # payload is TEXT — yield the exact stored bytes.
                yield payload if isinstance(payload, str) else json.dumps(payload)

    def iter_node_payloads(self, tenant_id: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("graph_build_workspace_nodes", tenant_id, batch_size)

    def iter_edge_payloads(self, tenant_id: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("graph_build_workspace_edges", tenant_id, batch_size)

    def get_node_payload(self, tenant_id: str, node_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT payload FROM graph_build_workspace_nodes WHERE workspace_id = %s AND tenant_id = %s AND node_id = %s",
            (self._workspace_id, tenant_id, node_id),
        ).fetchone()
        if not row:
            return None
        payload = row[0]
        return payload if isinstance(payload, str) else json.dumps(payload)

    def get_edge_payload(self, tenant_id: str, edge_key: str) -> str | None:
        row = self._conn.execute(
            "SELECT payload FROM graph_build_workspace_edges WHERE workspace_id = %s AND tenant_id = %s AND edge_key = %s",
            (self._workspace_id, tenant_id, edge_key),
        ).fetchone()
        if not row:
            return None
        payload = row[0]
        return payload if isinstance(payload, str) else json.dumps(payload)

    def fetch_node_page(self, tenant_id: str, after_seq: int, limit: int, entity_type: str | None = None) -> list[tuple[int, str, str]]:
        params: tuple[Any, ...] = (self._workspace_id, tenant_id)
        predicate = ""
        if entity_type is not None:
            predicate = " AND entity_type = %s"
            params = (self._workspace_id, tenant_id, entity_type)
        params = (*params, after_seq, limit)
        rows = self._conn.execute(
            f"SELECT seq, node_id, payload FROM graph_build_workspace_nodes "  # nosec B608 - static cols
            f"WHERE workspace_id = %s AND tenant_id = %s{predicate} AND seq > %s ORDER BY seq LIMIT %s",
            params,
        ).fetchall()
        return [(int(seq), str(node_id), p if isinstance(p, str) else json.dumps(p)) for seq, node_id, p in rows]

    def fetch_edge_page(
        self, tenant_id: str, after_seq: int, limit: int, source_id: str | None = None, target_id: str | None = None
    ) -> list[tuple[int, str]]:
        params: tuple[Any, ...] = (self._workspace_id, tenant_id)
        predicate = ""
        if source_id is not None:
            predicate = " AND source_id = %s"
            params = (self._workspace_id, tenant_id, source_id)
        elif target_id is not None:
            predicate = " AND target_id = %s"
            params = (self._workspace_id, tenant_id, target_id)
        params = (*params, after_seq, limit)
        rows = self._conn.execute(
            f"SELECT seq, payload FROM graph_build_workspace_edges "  # nosec B608 - static cols
            f"WHERE workspace_id = %s AND tenant_id = %s{predicate} AND seq > %s ORDER BY seq LIMIT %s",
            params,
        ).fetchall()
        return [(int(seq), p if isinstance(p, str) else json.dumps(p)) for seq, p in rows]

    def iter_node_payloads_by_type(self, tenant_id: str, entity_type: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("graph_build_workspace_nodes", tenant_id, batch_size, where_col="entity_type", where_val=entity_type)

    def iter_edge_payloads_by_source(self, tenant_id: str, node_id: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("graph_build_workspace_edges", tenant_id, batch_size, where_col="source_id", where_val=node_id)

    def iter_edge_payloads_by_target(self, tenant_id: str, node_id: str, batch_size: int) -> Iterator[str]:
        return self._iter_payloads("graph_build_workspace_edges", tenant_id, batch_size, where_col="target_id", where_val=node_id)

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
        rows = ((n.id, json.dumps(n.to_dict(), default=str), _node_entity_type(n)) for n in nodes)
        for batch in _batched(rows, self._batch_size):
            self._backend.add_node_payloads(self._tenant_id, batch)

    def add_edges(self, edges: Iterable[UnifiedEdge]) -> None:
        rows = ((_edge_key(e), json.dumps(e.to_dict(), default=str), e.source, e.target) for e in edges)
        for batch in _batched(rows, self._batch_size):
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


def _batched(items: Iterable[_RowT], size: int) -> Iterator[list[_RowT]]:
    batch: list[_RowT] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def open_workspace_backend(*, workspace_id: str = "", backend: str = "auto") -> WorkspaceBackend:
    """Open a raw :class:`WorkspaceBackend` on the appropriate store.

    ``backend="auto"`` selects Postgres when ``AGENT_BOM_POSTGRES_URL`` is set,
    otherwise a private SQLite temp database. ``workspace_id`` namespaces a build
    on the shared Postgres tables (defaults to a fresh UUID); it is ignored by the
    process-local SQLite backend. Shared by :func:`open_graph_build_workspace` and
    the store-backed live graph container.
    """
    wsid = workspace_id or uuid.uuid4().hex
    dsn = os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip()
    chosen = backend
    if chosen == "auto":
        chosen = "postgres" if dsn else "sqlite"

    if chosen == "postgres":
        if not dsn:
            raise ValueError("AGENT_BOM_POSTGRES_URL is required for the postgres workspace backend.")
        return _PostgresWorkspaceBackend(dsn, wsid)
    if chosen == "sqlite":
        return _SQLiteWorkspaceBackend()
    raise ValueError(f"unknown workspace backend {backend!r}")


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
    impl = open_workspace_backend(workspace_id=workspace_id, backend=backend)
    return GraphBuildWorkspace(impl, tenant_id=tenant_id, batch_size=batch_size)
