"""Unified graph store backends for API persistence and querying.

This module gives the API a pluggable graph persistence layer so unified
graph reads/writes follow the same backend selection model as the rest of
the control plane. SQLite remains the default local backend; Postgres can
provide the same contract for multi-tenant API deployments.
"""

from __future__ import annotations

import base64
import json
import re
import sqlite3
import threading
import time
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from agent_bom.graph.delta_digest import PriorSnapshotDigest

from agent_bom.db import graph_store as sqlite_graph_store
from agent_bom.graph import (
    AttackPath,
    EntityType,
    NodeDimensions,
    NodeStatus,
    RelationshipType,
    UnifiedEdge,
    UnifiedGraph,
    UnifiedNode,
    technique_mappings_from_json,
)
from agent_bom.graph.analysis import GraphAnalysisStatus, analysis_status_map_from_dict, analysis_status_map_to_dict
from agent_bom.graph.completeness import (
    COMPLIANCE_NODE_BUDGET,
    bounded_walk_reason,
    graph_completeness,
    impact_completeness,
)
from agent_bom.graph.correlation import CorrelationRunStatus, GraphCorrelationRun
from agent_bom.graph.ocsf import FINDING_ENTITY_TYPES
from agent_bom.graph.severity_floor import severity_floor_sql

_FINDING_ENTITY_TYPE_VALUES = frozenset(entity_type.value for entity_type in FINDING_ENTITY_TYPES)

# Deep OFFSET paging is O(offset): the store still walks and discards every
# skipped row, so ``offset=490000`` costs seconds even with the sort indexes.
# Past this threshold callers must switch to the flat keyset ``cursor=`` path.
# Shallow, human-scale offset browsing below the cap stays supported.
MAX_NODE_PAGE_OFFSET = 10_000


def _assert_offset_within_cap(offset: int, cursor: str | None) -> None:
    """Refuse a deep OFFSET at the store, not only at the route.

    Every node-paging read shares the cap, so a caller that reaches a store
    directly (MCP, a job, a future route) cannot buy an O(offset) scan the HTTP
    surface would have refused.
    """
    if not cursor and offset > MAX_NODE_PAGE_OFFSET:
        raise ValueError(
            f"offset={offset} exceeds the maximum supported node offset ({MAX_NODE_PAGE_OFFSET}); "
            "use the cursor= keyset parameter from the previous page's next_cursor for deep pagination."
        )


_CREATE_PRESET_TABLE_SQLITE = """\
CREATE TABLE IF NOT EXISTS graph_filter_presets (
    name TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    description TEXT DEFAULT '',
    filters TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (name, tenant_id)
)
"""

_API_GRAPH_TENANT_TABLE_KEYS: dict[str, tuple[str, ...]] = {
    "graph_filter_presets": ("name",),
    "graph_node_search": ("node_id", "scan_id"),
}

_CREATE_SEARCH_TABLE_SQLITE = """\
CREATE VIRTUAL TABLE IF NOT EXISTS graph_node_search
USING fts5(
    tenant_id UNINDEXED,
    scan_id UNINDEXED,
    node_id UNINDEXED,
    entity_type,
    severity,
    compliance_tags,
    data_sources,
    search_text
)
"""

# Schema init + legacy-tenant backfill are DML that take the WAL write lock. The
# read path used to run them on every ``_open_ro_conn`` call, so a single read
# could stall behind the write lock for seconds under load. Run them once per
# process per database path instead; the write path still re-applies them on
# every ``_open_rw_conn`` so newly created databases stay current.
_SCHEMA_INIT_LOCK = threading.Lock()
_SCHEMA_INITIALIZED_PATHS: set[str] = set()


def _escape_like_query(query: str) -> str:
    """Escape SQL LIKE wildcards so search terms are treated literally."""
    return query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _node_search_text(node: UnifiedNode) -> str:
    parts: list[str] = [
        node.id,
        node.label,
        node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type),
        node.severity or "",
        " ".join(node.compliance_tags),
        " ".join(node.data_sources),
        json.dumps(node.attributes, default=str, sort_keys=True),
        json.dumps(node.dimensions.to_dict(), sort_keys=True),
    ]
    return " ".join(part for part in parts if part).lower()


def _node_sort_key(node: UnifiedNode) -> tuple[int, float, str, str]:
    return (int(node.severity_id or 0), float(node.risk_score or 0.0), node.label or "", node.id)


def encode_graph_cursor(node: UnifiedNode) -> str:
    payload = json.dumps(list(_node_sort_key(node)), separators=(",", ":"), ensure_ascii=True).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def decode_graph_cursor(cursor: str) -> tuple[int, float, str, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        values = json.loads(raw)
        if not isinstance(values, list) or len(values) != 4:
            raise ValueError
        severity_id, risk_score, label, node_id = values
        return int(severity_id), float(risk_score), str(label), str(node_id)
    except Exception as exc:  # pragma: no cover - normalized into ValueError for route handling
        raise ValueError("Invalid graph cursor") from exc


_DYNAMIC_RELATIONSHIP_VALUES = {
    RelationshipType.INVOKED.value,
    RelationshipType.ACCESSED.value,
    RelationshipType.DELEGATED_TO.value,
}


class GraphStoreProtocol(Protocol):
    """Shared graph store contract used by the API pipeline and routes."""

    def latest_snapshot_id(self, *, tenant_id: str = "") -> str: ...

    def previous_snapshot_id(self, *, tenant_id: str = "", before_scan_id: str = "") -> str: ...

    def save_graph(self, graph: UnifiedGraph) -> None: ...

    def save_graph_streaming(
        self,
        *,
        scan_id: str,
        tenant_id: str = "",
        nodes: Iterable[UnifiedNode],
        edges: Iterable[UnifiedEdge],
        attack_paths: Iterable[AttackPath] = (),
        interaction_risks: Iterable[Any] = (),
        analysis_status: Mapping[str, GraphAnalysisStatus] | None = None,
        created_at: str = "",
        snapshot_kind: str = "scan",
        correlation_id: str = "",
        evidence_manifest_sha256: str = "",
    ) -> dict[str, int]: ...

    def create_correlation_run(self, run: GraphCorrelationRun) -> tuple[GraphCorrelationRun, bool]: ...

    def get_correlation_run(self, *, tenant_id: str, correlation_id: str) -> GraphCorrelationRun | None: ...

    def list_correlation_runs(self, *, tenant_id: str, limit: int = 100) -> list[GraphCorrelationRun]: ...

    def update_correlation_run(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        status: CorrelationRunStatus,
        manifest_sha256: str = "",
        output_scan_id: str = "",
        failure_code: str = "",
        started_at: str = "",
        completed_at: str = "",
    ) -> GraphCorrelationRun: ...

    def prior_delta_digest(self, *, tenant_id: str = "", scan_id: str = "") -> "PriorSnapshotDigest": ...

    def load_graph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        relationship_types: frozenset[str] | None = None,
        node_budget: int | None = None,
    ) -> UnifiedGraph: ...

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]: ...

    def active_edges_at(self, at: str, *, tenant_id: str = "") -> list[dict[str, Any]]: ...

    def changed_edges_between_scans(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]: ...

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50, since: str | None = None) -> list[dict[str, Any]]: ...

    def graph_history(self, *, tenant_id: str = "", limit: int = 50, since: str | None = None) -> dict[str, Any]: ...

    def evidence_manifest(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        baseline_scan_id: str = "",
    ) -> dict[str, Any]: ...

    def delete_tenant(self, *, tenant_id: str = "") -> int: ...

    def snapshot_stats(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> dict[str, Any]: ...

    def page_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> tuple[str, str, list[UnifiedNode], int, str | None]: ...

    def edges_for_node_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[Any]: ...

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        compliance_prefixes: set[str] | None = None,
        data_sources: set[str] | None = None,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[UnifiedNode], int, str | None]: ...

    def query_inventory(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        asset_entity_types: set[str],
        entity_types: set[str] | None = None,
        search: str = "",
        environment: str = "",
        provider: str = "",
        source: str = "",
        severity: str = "",
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]: ...

    def nodes_by_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[UnifiedNode]: ...

    def bfs_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> tuple[list[list[str]], set[str], bool, bool]:
        """Paths and reachable set from ``source``, plus how the walk was bounded.

        The last two elements are part of the answer, not diagnostics. Without
        them a caller cannot tell "these are all the reachable nodes" from
        "these are the first ``max_nodes`` we got to" (third element,
        budget-bounded) or "these are the ones within ``max_depth``" (fourth,
        depth-bounded, and only ever true when the frontier still had unwalked
        neighbours). Either way the surface downstream must not report the
        bound as the total.
        """
        ...

    def impact_of(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
        max_depth: int = 4,
    ) -> dict[str, Any] | None: ...

    def traverse_subgraph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        roots: list[str],
        direction: str = "forward",
        max_depth: int = 4,
        max_nodes: int = 500,
        max_edges: int = 10_000,
        deadline_monotonic: float | None = None,
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
        include_roots: bool = True,
    ) -> tuple[UnifiedGraph, dict[str, int], bool]: ...

    def attack_paths_for_sources(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str],
    ) -> list[AttackPath]: ...

    def attack_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[str, str, list[AttackPath], int]: ...

    def node_context(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
    ) -> dict[str, Any] | None: ...

    def compliance_summary(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        framework: str = "",
    ) -> dict[str, Any]: ...

    def save_preset(self, *, tenant_id: str, name: str, description: str, filters: dict[str, Any], created_at: str) -> None: ...

    def list_presets(self, *, tenant_id: str) -> list[dict[str, Any]]: ...

    def delete_preset(self, *, tenant_id: str, name: str) -> bool: ...


def containment_drilldown_graph(
    store: GraphStoreProtocol,
    *,
    node_id: str,
    tenant_id: str = "",
    scan_id: str = "",
    node_budget: int | None = None,
) -> UnifiedGraph:
    """Fetch only the containment subtree a roll-up drill-down reads.

    ``drill_down`` answers one container's direct children, but its aggregates
    (descendant counts, severity histogram, exposure flags) cover each child's
    whole subtree. The subtree under ``node_id`` is therefore the exact part of
    the estate the answer depends on — and the only part worth fetching.

    Loading the full snapshot instead made a twenty-row answer cost time linear
    in estate size. Measured on SQLite, drilling into one application whose
    answer is twenty children either way:

        snapshot     full load        containment walk
         5,065 nodes    55.1 ms          1.2 ms  (21 nodes read)
        20,046 nodes   270.2 ms          1.4 ms  (21 nodes read)
        40,091 nodes   580.5 ms          1.2 ms  (21 nodes read)
        80,181 nodes 1,141.6 ms          1.2 ms  (21 nodes read)

    The walk is ``traverse_subgraph``, the incremental primitive that already
    made ``impact_of`` sublinear, rather than a new store method — every backend
    that can traverse gets this without a protocol change.

    **The budget is a dispatch threshold, not a cap on the answer.** A container
    whose subtree does not fit falls back to the full load and returns exactly
    what it would have returned before. Truncating instead would have been both
    dishonest-looking and pointless: at the root of the tree the subtree *is* the
    estate, so the walk is strictly more expensive than one bulk read, and every
    ``descendant_count`` in the response would silently become a floor. The cost
    of that choice is the wasted partial walk before a fallback — measured at
    +44 ms on an 80,181-node root drill that already took 1,189 ms. The fast path
    is for the drill targets below the top, which is where drill-down goes.

    This is why ``traverse_subgraph`` reporting its own truncation matters here:
    the flag is what selects the fallback. A walk that under-reported itself as
    complete would ship bounded aggregates as if they were totals.

    ``max_depth`` is set to the node budget deliberately: a walk of depth *d*
    visits at least *d + 1* distinct nodes, so the node budget — which reports
    itself as truncation — always binds first. ``max_depth`` cuts a walk
    *without* setting that flag, so a depth-bound walk would return a short
    subtree that looks complete, and the fallback would never fire.

    A backend that cannot traverse incrementally (the experimental Neptune
    adapter implements only part of the protocol) takes the same fallback, so
    its answer is unchanged rather than a 501.
    """
    from agent_bom.graph.rollup import ROLLUP_CONTAINMENT_RELATIONSHIP_TYPES, ROLLUP_RELATIONSHIPS

    def _full_load() -> UnifiedGraph:
        return store.load_graph(
            tenant_id=tenant_id,
            scan_id=scan_id,
            relationship_types=ROLLUP_RELATIONSHIPS,
        )

    budget = node_budget if node_budget is not None else _drilldown_subtree_budget()
    try:
        graph, _depths, truncated = store.traverse_subgraph(
            tenant_id=tenant_id,
            scan_id=scan_id,
            roots=[node_id],
            direction="forward",
            max_depth=budget,
            max_nodes=budget,
            # Every visited node also matches on the edge that reached it, so the
            # edge budget must clear the node budget or it, not the node budget,
            # becomes the binding limit.
            max_edges=budget * 4,
            relationship_types=set(ROLLUP_CONTAINMENT_RELATIONSHIP_TYPES),
            include_roots=True,
        )
    except _unsupported_traversal_errors():
        return _full_load()
    if truncated:
        return _full_load()
    _attach_sibling_relationships(store, graph, tenant_id=tenant_id, scan_id=scan_id)
    return graph


def _attach_sibling_relationships(
    store: Any,
    graph: UnifiedGraph,
    *,
    tenant_id: str,
    scan_id: str,
) -> None:
    """Add the non-containment edges *between* the subtree's nodes.

    The walk above deliberately follows containment only — following ``USES``
    would leave the subtree and stop being a drill-down. But ``drill_down`` also
    aggregates the relationships *between* the children it returns, and those
    are exactly the edges the walk excluded, so the drill-down drew a row of
    disconnected cards for the same reason the top level did.

    Scoped to the subtree's own node ids, so the read stays proportional to the
    answer rather than to the estate — the property
    :func:`containment_drilldown_graph` exists to protect. Edges with one
    endpoint outside the subtree come back from the store (the query matches on
    either endpoint) and are dropped here; the roll-up would discard them
    anyway, having nothing at this level to attribute them to.

    A backend that cannot answer a scoped edge query keeps the subtree it
    already has: fewer relationships drawn, never a failed drill-down.
    """
    node_ids = set(graph.nodes)
    if not node_ids:
        return
    unsupported: tuple[type[BaseException], ...] = (*_unsupported_traversal_errors(), AttributeError)
    try:
        edges = store.edges_for_node_ids(tenant_id=tenant_id, scan_id=scan_id, node_ids=node_ids)
    except unsupported:
        return
    for edge in edges:
        if edge.source in node_ids and edge.target in node_ids:
            graph.add_edge(edge)


def _drilldown_subtree_budget() -> int:
    from agent_bom.config import GRAPH_ROLLUP_DRILLDOWN_SUBTREE_BUDGET

    return GRAPH_ROLLUP_DRILLDOWN_SUBTREE_BUDGET


def _unsupported_traversal_errors() -> tuple[type[BaseException], ...]:
    """Backends that implement only part of the protocol, resolved lazily.

    Imported inside the call so selecting SQLite or Postgres never pulls the
    optional Neptune adapter into the import graph.
    """
    from agent_bom.api.neptune_graph import NeptuneGraphStoreUnsupportedOperationError

    return (NeptuneGraphStoreUnsupportedOperationError,)


class SQLiteGraphStore:
    """SQLite-backed graph store wrapper around the low-level graph DB helpers."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self._db_path = Path(db_path or sqlite_graph_store.default_graph_db_path()).expanduser()

    def _exists(self) -> bool:
        return self._db_path.exists()

    def _ensure_parent(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

    def _open_rw_conn(self) -> sqlite3.Connection:
        self._ensure_parent()
        conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        sqlite_graph_store._init_db(conn)
        conn.execute(_CREATE_PRESET_TABLE_SQLITE)
        conn.execute(_CREATE_SEARCH_TABLE_SQLITE)
        sqlite_graph_store._backfill_empty_tenant_ids(conn, _API_GRAPH_TENANT_TABLE_KEYS)
        conn.commit()
        return conn

    def _ensure_schema_initialized(self) -> None:
        """Apply schema init + legacy-tenant backfill once per process.

        This is the DML that ``_open_ro_conn`` previously ran on every read,
        taking the WAL write lock each time. Running it once (through a
        read-write connection identical to ``_open_rw_conn``) leaves the read
        path free of the write lock while keeping the on-disk schema current.
        """
        key = str(self._db_path)
        if key in _SCHEMA_INITIALIZED_PATHS:
            return
        with _SCHEMA_INIT_LOCK:
            if key in _SCHEMA_INITIALIZED_PATHS:
                return
            conn = self._open_rw_conn()
            try:
                _SCHEMA_INITIALIZED_PATHS.add(key)
                # The DDL replay above re-runs every CREATE INDEX, and SQLite
                # documents a stats refresh as the thing to do after a schema
                # change. It also means a store that has only ever been read in
                # this process still gets statistics, so the node-read plans do
                # not depend on a write having happened first.
                sqlite_graph_store.refresh_query_planner_stats(conn)
            finally:
                conn.close()

    def _open_ro_conn(self) -> sqlite3.Connection | None:
        if not self._exists():
            return None
        self._ensure_schema_initialized()
        try:
            conn = sqlite3.connect(f"{self._db_path.resolve().as_uri()}?mode=ro", uri=True, timeout=10)
        except sqlite3.OperationalError:
            # Fall back to a normal connection if the platform/filesystem cannot
            # honor the read-only URI (e.g. missing WAL sidecar write access).
            conn = sqlite3.connect(str(self._db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _search_query_expression(query: str) -> str:
        tokens = [token.strip() for token in re.findall(r"[A-Za-z0-9_.:-]+", query) if token.strip()]
        if not tokens:
            return ""
        escaped = [token.replace('"', '""') for token in tokens]
        return " AND ".join(f'"{token}"*' for token in escaped)

    @staticmethod
    def _should_use_fts(query: str) -> bool:
        return any(char.isalnum() for char in query)

    @staticmethod
    def _matches_compliance_prefixes(node: UnifiedNode, prefixes: set[str]) -> bool:
        if not prefixes:
            return True
        node_prefixes = {tag.split("-")[0].upper() if "-" in tag else tag.upper() for tag in node.compliance_tags}
        return bool(node_prefixes.intersection(prefixes))

    @staticmethod
    def _space_token_filter(column: str, token: str) -> tuple[str, list[Any]]:
        escaped = _escape_like_query(token.lower())
        clause = f"({column} = ? OR {column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\')"
        params = [escaped, f"{escaped} %", f"% {escaped}", f"% {escaped} %"]
        return clause, params

    @staticmethod
    def _compliance_prefix_filter(column: str, prefix: str) -> tuple[str, list[Any]]:
        escaped = _escape_like_query(prefix.lower())
        clause = (
            f"({column} = ? OR {column} LIKE ? ESCAPE '\\' OR "
            f"{column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\' OR {column} LIKE ? ESCAPE '\\')"
        )
        params = [escaped, f"{escaped}-%", f"{escaped} %", f"% {escaped}-%", f"% {escaped} %"]
        return clause, params

    def _refresh_snapshot_search_index(self, conn: sqlite3.Connection, *, tenant_id: str, scan_id: str) -> None:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn.execute("DELETE FROM graph_node_search WHERE tenant_id = ? AND scan_id = ?", (tenant_id, scan_id))
        # Stream the snapshot's node rows in bounded batches rather than
        # ``.fetchall()`` of every row + a full ``UnifiedNode`` per row: this
        # refresh runs at the persist peak while the builder's in-memory graph is
        # still resident, so a fetchall added a second O(N) materialisation of the
        # whole node set on top of it. A separate read cursor iterates a different
        # table (graph_nodes) than the one being written (graph_node_search), so
        # interleaving the reads and the batched inserts is safe on one
        # connection; peak stays proportional to the batch size, not the snapshot
        # size (#4075). Rows written are byte-identical to the fetchall path.
        batch_size = sqlite_graph_store._graph_write_batch_size()
        select_cur = conn.execute(
            """
            SELECT
                id, entity_type, label, category_uid, class_uid, type_uid,
                status, risk_score, severity, severity_id, first_seen, last_seen,
                attributes, compliance_tags, data_sources, dimensions
            FROM graph_nodes
            WHERE tenant_id = ? AND scan_id = ?
            """,
            (tenant_id, scan_id),
        )
        insert_sql = """
            INSERT INTO graph_node_search (
                tenant_id, scan_id, node_id, entity_type, severity, compliance_tags, data_sources, search_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """

        def _search_row(row: sqlite3.Row) -> tuple[Any, ...]:
            node = self._node_from_row(row)
            return (
                tenant_id,
                scan_id,
                node.id,
                node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type),
                node.severity.lower(),
                " ".join(node.compliance_tags).lower(),
                " ".join(node.data_sources).lower(),
                _node_search_text(node),
            )

        try:
            while True:
                batch = select_cur.fetchmany(batch_size)
                if not batch:
                    break
                conn.executemany(insert_sql, [_search_row(row) for row in batch])
        finally:
            select_cur.close()

    def delete_tenant(self, *, tenant_id: str = "") -> int:
        """Delete graph rows for one tenant and return the number of rows removed."""
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_rw_conn()
        try:
            total = 0
            for table in (
                "graph_node_search",
                "attack_paths",
                "interaction_risks",
                "graph_edges",
                "graph_nodes",
                "graph_snapshots",
                "graph_filter_presets",
            ):
                cursor = conn.execute(f"DELETE FROM {table} WHERE tenant_id = ?", (tenant_id,))  # nosec B608 - table list is static
                total += max(cursor.rowcount, 0)
            conn.commit()
            return total
        finally:
            conn.close()

    @staticmethod
    def _node_from_row(row: sqlite3.Row) -> UnifiedNode:
        return UnifiedNode(
            id=row["id"],
            entity_type=EntityType(row["entity_type"]),
            label=row["label"],
            category_uid=row["category_uid"],
            class_uid=row["class_uid"],
            type_uid=row["type_uid"],
            status=NodeStatus(row["status"]),
            risk_score=row["risk_score"],
            severity=row["severity"] or "",
            severity_id=row["severity_id"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            attributes=json.loads(row["attributes"]),
            compliance_tags=json.loads(row["compliance_tags"]),
            data_sources=json.loads(row["data_sources"]),
            dimensions=NodeDimensions.from_dict(json.loads(row["dimensions"])),
        )

    @staticmethod
    def _edge_from_row(row: sqlite3.Row) -> UnifiedEdge:
        return UnifiedEdge(
            source=row["source_id"],
            target=row["target_id"],
            relationship=RelationshipType(row["relationship"]),
            direction=row["direction"],
            weight=row["weight"],
            traversable=bool(row["traversable"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            valid_from=row["valid_from"] or row["first_seen"],
            valid_to=row["valid_to"],
            confidence=row["confidence"],
            provenance=json.loads(row["provenance"] or "{}"),
            source_scan_id=row["source_scan_id"] or row["scan_id"],
            source_run_id=row["source_run_id"] or "",
            evidence=json.loads(row["evidence"]),
            activity_id=row["activity_id"],
        )

    @staticmethod
    def _reverse_edge(edge: UnifiedEdge) -> UnifiedEdge:
        return UnifiedEdge(
            source=edge.target,
            target=edge.source,
            relationship=edge.relationship,
            direction=edge.direction,
            weight=edge.weight,
            traversable=edge.traversable,
            first_seen=edge.first_seen,
            last_seen=edge.last_seen,
            valid_from=edge.valid_from,
            valid_to=edge.valid_to,
            confidence=edge.confidence,
            provenance=edge.provenance,
            source_scan_id=edge.source_scan_id,
            source_run_id=edge.source_run_id,
            evidence=edge.evidence,
            activity_id=edge.activity_id,
        )

    def _frontier_edge_query(
        self,
        *,
        tenant_id: str,
        scan_id: str,
        frontier: set[str],
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
    ) -> tuple[str, list[Any]]:
        """Build the per-hop "edges touching these nodes" query, and its parameters.

        Written as a UNION of two endpoint-anchored branches rather than the
        obvious ``source_id IN (...) OR target_id IN (...)`` disjunction. SQLite
        cannot drive a single index from that disjunction: it settles on
        ``idx_ge_tenant_scan`` and reads every edge in the snapshot, once per
        node the walk visits, making traversal cost visited x snapshot_edges.
        Split into two branches, each is an index seek against
        ``idx_ge_tenant_scan_source`` / ``idx_ge_tenant_scan_target``, so a hop
        costs its own degree.

        Both halves are load-bearing: the disjunction ignores those indexes even
        when they exist, and the UNION falls back to a full snapshot scan when
        they do not. Neither relies on ``sqlite_stat1``, which a freshly written
        customer database does not have.

        ``ORDER BY rowid`` reproduces the row order the scan happened to yield
        (index entries for one snapshot are ordered by rowid, i.e. insertion
        order), so ``discovery_order``, ``parent_by_node`` and every path built
        from them are unchanged — and are now pinned to insertion order outright
        instead of inherited from whichever plan the query planner picked.
        """
        placeholders = ",".join("?" for _ in frontier)
        # Sorted so the emitted SQL and parameters are deterministic across runs.
        ordered_frontier = sorted(frontier)
        shared: list[str] = []
        shared_params: list[Any] = []
        if traversable_only:
            shared.append("traversable = 1")
        if relationship_types:
            rel_values = sorted(rel.value if isinstance(rel, RelationshipType) else str(rel) for rel in relationship_types)
            shared.append(f"relationship IN ({','.join('?' for _ in rel_values)})")
            shared_params.extend(rel_values)
        if static_only:
            shared.append(f"relationship NOT IN ({','.join('?' for _ in _DYNAMIC_RELATIONSHIP_VALUES)})")
            shared_params.extend(sorted(_DYNAMIC_RELATIONSHIP_VALUES))
        if dynamic_only:
            shared.append(f"relationship IN ({','.join('?' for _ in _DYNAMIC_RELATIONSHIP_VALUES)})")
            shared_params.extend(sorted(_DYNAMIC_RELATIONSHIP_VALUES))
        shared_sql = ("".join(f" AND {clause}" for clause in shared)) if shared else ""

        def branch(column: str) -> str:
            # nosec B608 - every interpolated fragment is built in this function
            # and none is caller-supplied: ``column`` is one of two string
            # literals at the call sites below, and ``placeholders``/
            # ``shared_sql`` contribute only ``?`` markers. Values travel in
            # ``params``.
            return f"SELECT rowid FROM graph_edges WHERE tenant_id = ? AND scan_id = ? AND {column} IN ({placeholders}){shared_sql}"  # nosec B608

        params: list[Any] = [
            tenant_id,
            scan_id,
            *ordered_frontier,
            *shared_params,
            tenant_id,
            scan_id,
            *ordered_frontier,
            *shared_params,
        ]
        sql = f"""
            SELECT *
            FROM graph_edges
            WHERE rowid IN (
                {branch("source_id")}
                UNION
                {branch("target_id")}
            )
            ORDER BY rowid
            """  # nosec B608 - clause fragments and placeholders are generated internally
        return sql, params

    def _filtered_edge_rows(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        scan_id: str,
        frontier: set[str],
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
    ) -> list[sqlite3.Row]:
        """Edges touching the frontier, as two index-anchored reads.

        This is the inner loop of every incremental walk, run once per frontier
        node. It used to be one query with ``(source_id IN (...) OR target_id IN
        (...))``, which SQLite can only serve from the composite indexes as a
        MULTI-INDEX OR — and it only chooses that plan when ``sqlite_stat1`` has
        been populated. On a freshly written store, which has never been
        ``ANALYZE``d, the planner instead prefix-scanned ``(tenant_id, scan_id)``
        and read EVERY edge in the snapshot on EVERY hop: 12,876us per hop on an
        80,181-node snapshot, so a walk that materialised 21 nodes still cost
        time linear in estate size.

        Splitting the OR into a UNION of two single-column lookups makes each
        branch independently index-anchored, so the plan does not depend on
        whether statistics happen to exist: 33us per hop, stats or no stats.
        ``UNION`` (not ``UNION ALL``) because an edge whose both endpoints are in
        the frontier matches both branches.
        """
        if not frontier:
            return []
        sql, params = self._frontier_edge_query(
            tenant_id=tenant_id,
            scan_id=scan_id,
            frontier=frontier,
            traversable_only=traversable_only,
            relationship_types=relationship_types,
            static_only=static_only,
            dynamic_only=dynamic_only,
        )
        return conn.execute(sql, params).fetchall()

    def nodes_by_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[UnifiedNode]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        if not node_ids:
            return []
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return []
            placeholders = ",".join("?" for _ in node_ids)
            rows = conn.execute(
                f"""
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                FROM graph_nodes
                WHERE tenant_id = ? AND scan_id = ? AND id IN ({placeholders})
                """,  # nosec B608 - placeholders are generated internally
                [tenant_id, effective_scan_id, *node_ids],
            ).fetchall()
            return [self._node_from_row(row) for row in rows]
        finally:
            conn.close()

    def _walk_graph(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        scan_id: str,
        roots: list[str],
        direction: str,
        max_depth: int,
        max_nodes: int,
        max_edges: int,
        deadline_monotonic: float | None,
        traversable_only: bool,
        relationship_types: set[RelationshipType] | None,
        static_only: bool,
        dynamic_only: bool,
        include_roots: bool,
    ) -> tuple[str, str, set[str], dict[str, int], dict[tuple[str, str, str], UnifiedEdge], dict[str, str], list[str], bool, bool]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
        if not effective_scan_id:
            return scan_id, "", set(), {}, {}, {}, [], False, False

        existing_roots = {node.id for node in self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=set(roots))}
        visited: set[str] = set()
        depth_by_node: dict[str, int] = {}
        traversed_edges: dict[tuple[str, str, str], UnifiedEdge] = {}
        parent_by_node: dict[str, str] = {}
        discovery_order: list[str] = []
        truncated = False
        depth_limited = False
        edge_count = 0

        def _neighbors(node_id: str) -> list[str]:
            found: list[str] = []
            for row in self._filtered_edge_rows(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                frontier={node_id},
                traversable_only=traversable_only,
                relationship_types=relationship_types,
                static_only=static_only,
                dynamic_only=dynamic_only,
            ):
                edge = self._edge_from_row(row)
                if direction in {"forward", "both"}:
                    if edge.source == node_id:
                        found.append(edge.target)
                    elif edge.is_bidirectional and edge.target == node_id:
                        found.append(edge.source)
                if direction in {"reverse", "both"}:
                    if edge.target == node_id:
                        found.append(edge.source)
                    elif edge.is_bidirectional and edge.source == node_id:
                        found.append(edge.target)
            return found

        queue: list[tuple[str, int]] = []
        for root in roots:
            if root not in existing_roots:
                continue
            queue.append((root, 0))
            depth_by_node[root] = 0
            if include_roots:
                visited.add(root)

        index = 0
        while index < len(queue):
            if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
                truncated = True
                break
            current, depth = queue[index]
            index += 1
            if depth >= max_depth:
                # Frontier node: only a *demonstrably* unwalked neighbour makes
                # this an incomplete answer. Costs one edge lookup per frontier
                # node, and only until the first one that leaves work behind.
                if not depth_limited and any(neighbor not in visited for neighbor in _neighbors(current)):
                    depth_limited = True
                continue
            for row in self._filtered_edge_rows(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                frontier={current},
                traversable_only=traversable_only,
                relationship_types=relationship_types,
                static_only=static_only,
                dynamic_only=dynamic_only,
            ):
                edge = self._edge_from_row(row)
                candidates: list[str] = []
                if direction in {"forward", "both"}:
                    if edge.source == current:
                        candidates.append(edge.target)
                    elif edge.is_bidirectional and edge.target == current:
                        candidates.append(edge.source)
                if direction in {"reverse", "both"}:
                    if edge.target == current:
                        candidates.append(edge.source)
                    elif edge.is_bidirectional and edge.source == current:
                        candidates.append(edge.target)
                if not candidates:
                    continue

                edge_count += 1
                if edge_count > max_edges:
                    truncated = True
                    break

                rel = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
                traversed_edges.setdefault((edge.source, edge.target, rel), edge)

                for neighbor in candidates:
                    if neighbor in visited:
                        continue
                    if len(visited) >= max_nodes:
                        truncated = True
                        continue
                    visited.add(neighbor)
                    depth_by_node[neighbor] = depth + 1
                    parent_by_node.setdefault(neighbor, current)
                    discovery_order.append(neighbor)
                    queue.append((neighbor, depth + 1))
            if truncated and (edge_count > max_edges or (deadline_monotonic is not None and time.monotonic() >= deadline_monotonic)):
                break

        if include_roots:
            visited.update(existing_roots)

        return (
            effective_scan_id,
            created_at,
            visited,
            depth_by_node,
            traversed_edges,
            parent_by_node,
            discovery_order,
            truncated,
            depth_limited,
        )

    def bfs_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source: str,
        max_depth: int = 4,
        traversable_only: bool = True,
    ) -> tuple[list[list[str]], set[str], bool, bool]:
        conn = self._open_ro_conn()
        if conn is None:
            return [], set(), False, False
        try:
            (
                _effective_scan_id,
                _created_at,
                visited,
                _depth_by_node,
                _edges,
                parent_by_node,
                discovery_order,
                truncated,
                depth_limited,
            ) = self._walk_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                roots=[source],
                direction="forward",
                max_depth=max_depth,
                max_nodes=5000,
                max_edges=25_000,
                deadline_monotonic=None,
                traversable_only=traversable_only,
                relationship_types=None,
                static_only=False,
                dynamic_only=False,
                include_roots=True,
            )
            if source not in visited:
                return [], set(), truncated, depth_limited

            paths: list[list[str]] = []
            for node_id in discovery_order:
                if node_id == source:
                    continue
                path = [node_id]
                current = node_id
                while current in parent_by_node:
                    current = parent_by_node[current]
                    path.append(current)
                path.reverse()
                if path and path[0] == source:
                    paths.append(path)
            reachable = set(visited)
            reachable.discard(source)
            return paths, reachable, truncated, depth_limited
        finally:
            conn.close()

    def impact_of(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
        max_depth: int = 4,
    ) -> dict[str, Any] | None:
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            effective_scan_id, _created_at, visited, depth_by_node, _edges, _parents, _order, truncated, depth_limited = self._walk_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                roots=[node_id],
                direction="reverse",
                max_depth=max_depth,
                max_nodes=5000,
                max_edges=25_000,
                deadline_monotonic=None,
                traversable_only=False,
                relationship_types=None,
                static_only=False,
                dynamic_only=False,
                include_roots=True,
            )
            if not effective_scan_id or node_id not in visited:
                return None

            affected_nodes = sorted(node for node in visited if node != node_id)
            affected_node_rows = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=set(affected_nodes))
            affected_by_type: dict[str, int] = {}
            for node in affected_node_rows:
                entity_type = node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type)
                affected_by_type[entity_type] = affected_by_type.get(entity_type, 0) + 1

            return {
                "node_id": node_id,
                "affected_nodes": affected_nodes,
                "affected_by_type": affected_by_type,
                "affected_count": len(affected_nodes),
                "max_depth_reached": max((depth_by_node.get(node, 0) for node in affected_nodes), default=0),
                "completeness": impact_completeness(
                    affected_count=len(affected_nodes),
                    truncated=truncated,
                    depth_limited=depth_limited,
                ),
            }
        finally:
            conn.close()

    def traverse_subgraph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        roots: list[str],
        direction: str = "forward",
        max_depth: int = 4,
        max_nodes: int = 500,
        max_edges: int = 10_000,
        deadline_monotonic: float | None = None,
        traversable_only: bool = False,
        relationship_types: set[RelationshipType] | None = None,
        static_only: bool = False,
        dynamic_only: bool = False,
        include_roots: bool = True,
    ) -> tuple[UnifiedGraph, dict[str, int], bool]:
        # Resolve the tenant up front so the returned graph is labelled with the
        # tenant it was actually read under. `_walk_graph` normalized a local
        # copy while the graph kept the caller's raw string, so a default-tenant
        # traversal came back labelled "" where every other read says "default".
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id), {}, False
        try:
            effective_scan_id, created_at, visited, depth_by_node, traversed_edges, _parents, _order, truncated, depth_limited = (
                self._walk_graph(
                    conn,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    roots=roots,
                    direction=direction,
                    max_depth=max_depth,
                    max_nodes=max_nodes,
                    max_edges=max_edges,
                    deadline_monotonic=deadline_monotonic,
                    traversable_only=traversable_only,
                    relationship_types=relationship_types,
                    static_only=static_only,
                    dynamic_only=dynamic_only,
                    include_roots=include_roots,
                )
            )
            graph = UnifiedGraph(scan_id=effective_scan_id, tenant_id=tenant_id, created_at=created_at)
            if not effective_scan_id:
                return graph, {}, False
            node_rows = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids=visited)
            for node in node_rows:
                graph.add_node(node)
            for edge in traversed_edges.values():
                if edge.source in graph.nodes and edge.target in graph.nodes:
                    graph.add_edge(edge)
            # A bounded walk must say so. #4595 gave the in-memory container and
            # the Postgres store this shape; the default backend was left
            # returning a fresh GraphCompleteness that reads "complete,
            # returned: 0" over a non-empty result. Now that drill-down answers
            # from a traversal, that laundering is reachable from a shipped
            # endpoint. The denominator is the snapshot's recorded node_count --
            # a single-row primary-key lookup, never a COUNT over graph_nodes.
            #
            # Two bounds are reported independently: the node budget and the
            # depth cap. Collapsing them would leave a caller unable to tell
            # whether raising max_depth could recover the missing nodes.
            snapshot_row = conn.execute(
                "SELECT node_count FROM graph_snapshots WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()
            snapshot_nodes = int(snapshot_row["node_count"] or 0) if snapshot_row is not None else 0
            graph.completeness.truncated = truncated
            graph.completeness.depth_limited = depth_limited
            graph.completeness.node_budget = max_nodes if truncated else None
            graph.completeness.reason = bounded_walk_reason(truncated=truncated, depth_limited=depth_limited)
            graph.completeness.total_nodes = snapshot_nodes or len(graph.nodes)
            graph.completeness.returned_nodes = len(graph.nodes)
            return graph, depth_by_node, truncated
        finally:
            conn.close()

    def attack_paths_for_sources(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        source_ids: set[str],
    ) -> list[AttackPath]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        if not source_ids:
            return []
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return []
            placeholders = ",".join("?" for _ in source_ids)
            rows = conn.execute(
                f"""
                SELECT source_node, target_node, path_nodes, path_edges, composite_risk,
                       summary, credential_exposure, tool_exposure, vuln_ids,
                       reachability, reachability_basis, technique_mappings
                FROM attack_paths
                WHERE tenant_id = ? AND scan_id = ? AND source_node IN ({placeholders})
                """,  # nosec B608 - placeholders are generated internally
                [tenant_id, effective_scan_id, *source_ids],
            ).fetchall()
            return [
                AttackPath(
                    source=row["source_node"],
                    target=row["target_node"],
                    hops=json.loads(row["path_nodes"]),
                    edges=json.loads(row["path_edges"]),
                    composite_risk=row["composite_risk"],
                    summary=row["summary"] or "",
                    credential_exposure=json.loads(row["credential_exposure"]),
                    tool_exposure=json.loads(row["tool_exposure"]),
                    vuln_ids=json.loads(row["vuln_ids"]),
                    reachability=row["reachability"] or "unknown",
                    reachability_basis=json.loads(row["reachability_basis"] or "[]"),
                    technique_mappings=technique_mappings_from_json(row["technique_mappings"]),
                )
                for row in rows
            ]
        finally:
            conn.close()

    def attack_paths(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[str, str, list[AttackPath], int]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return scan_id, "", [], 0
        try:
            effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return scan_id, "", [], 0
            total = conn.execute(
                "SELECT COUNT(*) FROM attack_paths WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()[0]
            rows = conn.execute(
                """
                SELECT source_node, target_node, path_nodes, path_edges, composite_risk,
                       summary, credential_exposure, tool_exposure, vuln_ids,
                       reachability, reachability_basis, technique_mappings
                FROM attack_paths
                WHERE tenant_id = ? AND scan_id = ?
                ORDER BY composite_risk DESC, source_node ASC, target_node ASC
                LIMIT ? OFFSET ?
                """,
                (tenant_id, effective_scan_id, limit, offset),
            ).fetchall()
            return (
                effective_scan_id,
                created_at,
                [
                    AttackPath(
                        source=row["source_node"],
                        target=row["target_node"],
                        hops=json.loads(row["path_nodes"]),
                        edges=json.loads(row["path_edges"]),
                        composite_risk=row["composite_risk"],
                        summary=row["summary"] or "",
                        credential_exposure=json.loads(row["credential_exposure"]),
                        tool_exposure=json.loads(row["tool_exposure"]),
                        vuln_ids=json.loads(row["vuln_ids"]),
                        reachability=row["reachability"] or "unknown",
                        reachability_basis=json.loads(row["reachability_basis"] or "[]"),
                        technique_mappings=technique_mappings_from_json(row["technique_mappings"]),
                    )
                    for row in rows
                ],
                int(total or 0),
            )
        finally:
            conn.close()

    def node_context(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_id: str,
    ) -> dict[str, Any] | None:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return None
            nodes = self.nodes_by_ids(tenant_id=tenant_id, scan_id=effective_scan_id, node_ids={node_id})
            if not nodes:
                return None
            rows = conn.execute(
                """
                SELECT *
                FROM graph_edges
                WHERE tenant_id = ? AND scan_id = ? AND (source_id = ? OR target_id = ?)
                ORDER BY source_id ASC, target_id ASC, relationship ASC
                """,
                [tenant_id, effective_scan_id, node_id, node_id],
            ).fetchall()

            edges_out: list[UnifiedEdge] = []
            edges_in: list[UnifiedEdge] = []
            neighbors: list[str] = []
            sources: list[str] = []

            for row in rows:
                edge = self._edge_from_row(row)
                if edge.source == node_id:
                    edges_out.append(edge)
                    neighbors.append(edge.target)
                    if edge.is_bidirectional:
                        reverse = self._reverse_edge(edge)
                        edges_in.append(reverse)
                        sources.append(edge.target)
                if edge.target == node_id:
                    edges_in.append(edge)
                    sources.append(edge.source)
                    if edge.is_bidirectional:
                        reverse = self._reverse_edge(edge)
                        edges_out.append(reverse)
                        neighbors.append(edge.source)

            return {
                "node": nodes[0],
                "edges_out": edges_out,
                "edges_in": edges_in,
                "neighbors": neighbors,
                "sources": sources,
                "impact": self.impact_of(tenant_id=tenant_id, scan_id=effective_scan_id, node_id=node_id),
            }
        finally:
            conn.close()

    def compliance_summary(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        framework: str = "",
    ) -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        # The same budget Postgres applies. This read used to be unbounded here
        # and bounded there, so the two backends answered the same leadership
        # question from different amounts of the estate — and only one of them
        # said so.
        compliance_node_budget = COMPLIANCE_NODE_BUDGET
        empty = {
            "scan_id": scan_id,
            "framework_count": 0,
            "total_tagged_findings": 0,
            "frameworks": {},
            "completeness": {
                **graph_completeness(returned=0),
                "node_budget": compliance_node_budget,
            },
        }
        conn = self._open_ro_conn()
        if conn is None:
            return empty
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return empty

            rows = conn.execute(
                """
                SELECT id, entity_type, severity, compliance_tags
                FROM graph_nodes
                WHERE tenant_id = ? AND scan_id = ? AND json_array_length(compliance_tags) > 0
                ORDER BY id ASC
                LIMIT ?
                """,
                [tenant_id, effective_scan_id, compliance_node_budget + 1],
            ).fetchall()
            truncated = len(rows) > compliance_node_budget
            rows = rows[:compliance_node_budget]

            framework_filter = framework.upper()
            framework_stats: dict[str, dict[str, Any]] = defaultdict(
                lambda: {
                    "total_findings": 0,
                    "by_severity": defaultdict(int),
                    "by_entity_type": defaultdict(int),
                    "tags": set(),
                    "node_ids": [],
                }
            )

            for row in rows:
                tags = json.loads(row["compliance_tags"])
                if not tags:
                    continue
                for tag in tags:
                    prefix = tag.split("-")[0].upper() if "-" in tag else tag.upper()
                    if framework_filter and framework_filter != prefix:
                        continue
                    stats = framework_stats[prefix]
                    stats["total_findings"] += 1
                    stats["by_severity"][row["severity"] or "unknown"] += 1
                    stats["by_entity_type"][row["entity_type"]] += 1
                    stats["tags"].add(tag)
                    if row["id"] not in stats["node_ids"]:
                        stats["node_ids"].append(row["id"])

            frameworks: dict[str, Any] = {}
            for name, stats in sorted(framework_stats.items()):
                frameworks[name] = {
                    "total_findings": stats["total_findings"],
                    "by_severity": dict(stats["by_severity"]),
                    "by_entity_type": dict(stats["by_entity_type"]),
                    "tags": sorted(stats["tags"]),
                    "node_count": len(stats["node_ids"]),
                    "node_ids": stats["node_ids"][:100],
                }

            return {
                "scan_id": effective_scan_id,
                "framework_count": len(frameworks),
                "total_tagged_findings": sum(stats["total_findings"] for stats in frameworks.values()),
                "frameworks": frameworks,
                "completeness": {
                    **graph_completeness(
                        returned=len(rows),
                        truncated=truncated,
                        reason="node_budget" if truncated else "",
                    ),
                    "node_budget": compliance_node_budget,
                },
            }
        finally:
            conn.close()

    def latest_snapshot_id(self, *, tenant_id: str = "") -> str:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return ""
        try:
            return sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
        finally:
            conn.close()

    def previous_snapshot_id(self, *, tenant_id: str = "", before_scan_id: str = "") -> str:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return ""
        try:
            return sqlite_graph_store.previous_snapshot_id(conn, tenant_id=tenant_id, before_scan_id=before_scan_id)
        finally:
            conn.close()

    def save_graph(self, graph: UnifiedGraph) -> None:
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            conn.execute(_CREATE_PRESET_TABLE_SQLITE)
            conn.execute(_CREATE_SEARCH_TABLE_SQLITE)
            sqlite_graph_store.save_graph(conn, graph)
            self._refresh_snapshot_search_index(conn, tenant_id=graph.tenant_id, scan_id=graph.scan_id)
            sqlite_graph_store._backfill_empty_tenant_ids(conn, _API_GRAPH_TENANT_TABLE_KEYS)
            conn.commit()

    def save_graph_streaming(
        self,
        *,
        scan_id: str,
        tenant_id: str = "",
        nodes: Iterable[UnifiedNode],
        edges: Iterable[UnifiedEdge],
        attack_paths: Iterable[AttackPath] = (),
        interaction_risks: Iterable[Any] = (),
        analysis_status: Mapping[str, GraphAnalysisStatus] | None = None,
        created_at: str = "",
        snapshot_kind: str = "scan",
        correlation_id: str = "",
        evidence_manifest_sha256: str = "",
    ) -> dict[str, int]:
        """Persist a snapshot from node/edge iterables without materialising a graph.

        Bounded-memory equivalent of :meth:`save_graph` (#4055): peak RSS is
        decoupled from graph size for producers that yield nodes/edges lazily.
        """
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            conn.execute(_CREATE_PRESET_TABLE_SQLITE)
            conn.execute(_CREATE_SEARCH_TABLE_SQLITE)
            counts = sqlite_graph_store.save_graph_streaming(
                conn,
                scan_id=scan_id,
                tenant_id=tenant_id,
                nodes=nodes,
                edges=edges,
                attack_paths=attack_paths,
                interaction_risks=interaction_risks,
                analysis_status=analysis_status,
                created_at=created_at,
                snapshot_kind=snapshot_kind,
                correlation_id=correlation_id,
                evidence_manifest_sha256=evidence_manifest_sha256,
            )
            self._refresh_snapshot_search_index(conn, tenant_id=tenant_id, scan_id=scan_id)
            sqlite_graph_store._backfill_empty_tenant_ids(conn, _API_GRAPH_TENANT_TABLE_KEYS)
            conn.commit()
            return counts

    def iter_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> Iterator[UnifiedNode]:
        """Yield a snapshot's nodes without building the whole graph in memory."""
        conn = self._open_ro_conn()
        if conn is None:
            return
        try:
            yield from sqlite_graph_store.iter_graph_nodes(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                entity_types=entity_types,
                min_severity_rank=min_severity_rank,
            )
        finally:
            conn.close()

    def iter_edges(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        relationship_types: frozenset[str] | None = None,
        node_ids: set[str] | None = None,
    ) -> Iterator[UnifiedEdge]:
        """Yield a snapshot's edges without building the whole graph in memory."""
        conn = self._open_ro_conn()
        if conn is None:
            return
        try:
            yield from sqlite_graph_store.iter_graph_edges(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                relationship_types=relationship_types,
                node_ids=node_ids,
            )
        finally:
            conn.close()

    def load_graph(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        relationship_types: frozenset[str] | None = None,
        node_budget: int | None = None,
    ) -> UnifiedGraph:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
        try:
            # The budget is pushed into the query, as Postgres does: bounding
            # after materialization declared the right completeness while still
            # having read every row.
            return sqlite_graph_store.load_graph(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                entity_types=entity_types,
                min_severity_rank=min_severity_rank,
                relationship_types=relationship_types,
                node_budget=node_budget,
            )
        finally:
            conn.close()

    def prior_delta_digest(self, *, tenant_id: str = "", scan_id: str = "") -> "PriorSnapshotDigest":
        """Bounded prior-snapshot digest for delta alerts (see #4055/#4075)."""
        from agent_bom.graph.delta_digest import PriorSnapshotDigestBuilder

        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return PriorSnapshotDigestBuilder().build()
        try:
            return sqlite_graph_store.prior_delta_digest(conn, tenant_id=tenant_id, scan_id=scan_id)
        finally:
            conn.close()

    def diff_snapshots(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "nodes_added": [],
                "nodes_removed": [],
                "nodes_changed": [],
                "edges_added": [],
                "edges_removed": [],
            }
        try:
            return sqlite_graph_store.diff_snapshots(conn, scan_id_old, scan_id_new, tenant_id=tenant_id)
        finally:
            conn.close()

    def active_edges_at(self, at: str, *, tenant_id: str = "") -> list[dict[str, Any]]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            return sqlite_graph_store.active_edges_at(conn, at, tenant_id=tenant_id)
        finally:
            conn.close()

    def changed_edges_between_scans(self, scan_id_old: str, scan_id_new: str, *, tenant_id: str = "") -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "scan_id_old": scan_id_old,
                "scan_id_new": scan_id_new,
                "edges_added": [],
                "edges_removed": [],
                "edges_changed": [],
                "edges_unchanged": [],
                "summary": {"added": 0, "removed": 0, "changed": 0, "unchanged": 0},
            }
        try:
            return sqlite_graph_store.changed_edges_between_scans(conn, scan_id_old, scan_id_new, tenant_id=tenant_id)
        finally:
            conn.close()

    def list_snapshots(self, *, tenant_id: str = "", limit: int = 50, since: str | None = None) -> list[dict[str, Any]]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            return sqlite_graph_store.list_snapshots(conn, tenant_id=tenant_id, limit=limit, since=since)
        finally:
            conn.close()

    def create_correlation_run(self, run: GraphCorrelationRun) -> tuple[GraphCorrelationRun, bool]:
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            return sqlite_graph_store.create_correlation_run(conn, run)

    def get_correlation_run(self, *, tenant_id: str, correlation_id: str) -> GraphCorrelationRun | None:
        conn = self._open_ro_conn()
        if conn is None:
            return None
        try:
            return sqlite_graph_store.get_correlation_run(conn, tenant_id=tenant_id, correlation_id=correlation_id)
        finally:
            conn.close()

    def list_correlation_runs(self, *, tenant_id: str, limit: int = 100) -> list[GraphCorrelationRun]:
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            return sqlite_graph_store.list_correlation_runs(conn, tenant_id=tenant_id, limit=limit)
        finally:
            conn.close()

    def update_correlation_run(
        self,
        *,
        tenant_id: str,
        correlation_id: str,
        status: CorrelationRunStatus,
        manifest_sha256: str = "",
        output_scan_id: str = "",
        failure_code: str = "",
        started_at: str = "",
        completed_at: str = "",
    ) -> GraphCorrelationRun:
        with sqlite_graph_store.open_graph_db(self._db_path) as conn:
            return sqlite_graph_store.update_correlation_run(
                conn,
                tenant_id=tenant_id,
                correlation_id=correlation_id,
                status=status,
                manifest_sha256=manifest_sha256,
                output_scan_id=output_scan_id,
                failure_code=failure_code,
                started_at=started_at,
                completed_at=completed_at,
            )

    def graph_history(self, *, tenant_id: str = "", limit: int = 50, since: str | None = None) -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "schema_version": "agent-bom.graph_history/v1",
                "tenant_id": tenant_id,
                "retention_policy": sqlite_graph_store.graph_retention_policy(),
                "snapshots": [],
            }
        try:
            return sqlite_graph_store.graph_history(conn, tenant_id=tenant_id, limit=limit, since=since)
        finally:
            conn.close()

    def evidence_manifest(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        baseline_scan_id: str = "",
    ) -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "schema_version": "agent-bom.graph_evidence_manifest/v1",
                "tenant_id": tenant_id,
                "scan_id": "",
                "generated_at": "",
                "retention_policy": sqlite_graph_store.graph_retention_policy(),
                "included_tables": [
                    "graph_snapshots",
                    "graph_nodes",
                    "graph_edges",
                    "attack_paths",
                    "interaction_risks",
                ],
                "excluded_private_fields": [
                    "graph_nodes.attributes",
                    "graph_edges.provenance",
                    "graph_edges.evidence",
                    "attack_paths.credential_exposure",
                ],
            }
        try:
            return sqlite_graph_store.graph_evidence_manifest(
                conn,
                tenant_id=tenant_id,
                scan_id=scan_id,
                baseline_scan_id=baseline_scan_id,
            )
        finally:
            conn.close()

    def snapshot_stats(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
    ) -> dict[str, Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return {
                "total_nodes": 0,
                "total_edges": 0,
                "node_types": {},
                "severity_counts": {},
                "relationship_types": {},
                "attack_path_count": 0,
                "interaction_risk_count": 0,
                "max_attack_path_risk": 0.0,
                "highest_interaction_risk": 0.0,
                "analysis_status": {},
            }
        try:
            effective_scan_id, _created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return {
                    "total_nodes": 0,
                    "total_edges": 0,
                    "node_types": {},
                    "severity_counts": {},
                    "relationship_types": {},
                    "attack_path_count": 0,
                    "interaction_risk_count": 0,
                    "max_attack_path_risk": 0.0,
                    "highest_interaction_risk": 0.0,
                    "analysis_status": {},
                }

            analysis_row = conn.execute(
                "SELECT analysis_status FROM graph_snapshots WHERE scan_id = ? AND tenant_id = ?",
                (effective_scan_id, tenant_id),
            ).fetchone()
            analysis_status = analysis_status_map_to_dict(
                analysis_status_map_from_dict(json.loads((analysis_row[0] if analysis_row else "{}") or "{}"))
            )

            node_where = ["tenant_id = ?", "scan_id = ?"]
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join("?" for _ in entity_types)
                node_where.append(f"entity_type IN ({placeholders})")
                params.extend(sorted(entity_types))
            sev_sql, sev_params = severity_floor_sql(min_severity_rank)
            if sev_sql:
                node_where.append(sev_sql)
                params.extend(sev_params)
            where_sql = " AND ".join(node_where)

            # Unfiltered node/edge totals AND the entity-type / severity breakdowns
            # are materialised on the snapshot row at write time. Re-deriving them
            # here re-scans graph_nodes with two GROUP BYs (1-2s at 500k-1M nodes)
            # plus a double id-membership edge subquery, so read the stored values
            # and only fall back to the live queries when the snapshot row is missing
            # or the cached breakdown was never populated (older snapshots). Any
            # active entity-type or severity filter narrows the set, so the recompute
            # path still runs.
            filters_active = bool(entity_types) or bool(min_severity_rank)
            stored_node_count: int | None = None
            stored_edge_count: int | None = None
            cached_node_types: dict[str, int] | None = None
            cached_severity_counts: dict[str, int] | None = None
            if not filters_active:
                snap_row = conn.execute(
                    "SELECT node_count, edge_count, risk_summary, node_type_counts "
                    "FROM graph_snapshots WHERE scan_id = ? AND tenant_id = ?",
                    (effective_scan_id, tenant_id),
                ).fetchone()
                if snap_row is not None:
                    stored_node_count = snap_row[0] if snap_row[0] is not None else None
                    stored_edge_count = snap_row[1] if snap_row[1] is not None else None
                    # node_type_counts is NULL for snapshots written before the
                    # breakdown was materialised — fall back to the live GROUP BY
                    # for those. risk_summary already carries the severity counts.
                    if snap_row[3] is not None:
                        cached_node_types = {str(k): int(v) for k, v in json.loads(snap_row[3]).items()}
                        cached_severity_counts = {str(k): int(v) for k, v in json.loads(snap_row[2] or "{}").items() if k}

            if stored_node_count is not None:
                total_nodes = stored_node_count
            else:
                total_nodes = conn.execute(
                    f"SELECT COUNT(*) FROM graph_nodes WHERE {where_sql}",  # nosec B608 - where_sql is built from static clause fragments
                    params,
                ).fetchone()[0]
            if cached_node_types is not None:
                node_types = cached_node_types
            else:
                node_type_rows = conn.execute(
                    f"SELECT entity_type, COUNT(*) FROM graph_nodes WHERE {where_sql} GROUP BY entity_type",  # nosec B608 - where_sql is built from static clause fragments
                    params,
                ).fetchall()
                node_types = {str(row[0]): int(row[1]) for row in node_type_rows}
            if cached_severity_counts is not None:
                severity_counts = cached_severity_counts
            else:
                severity_rows = conn.execute(
                    f"SELECT severity, COUNT(*) FROM graph_nodes WHERE {where_sql} AND severity <> '' GROUP BY severity",  # nosec B608 - where_sql is built from static clause fragments
                    params,
                ).fetchall()
                severity_counts = {str(row[0]): int(row[1]) for row in severity_rows}
            if stored_edge_count is not None:
                total_edges = stored_edge_count
            else:
                total_edges = conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM graph_edges
                    WHERE tenant_id = ? AND scan_id = ?
                      AND source_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                      AND target_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                    """,  # nosec B608 - where_sql is built from static clause fragments
                    [tenant_id, effective_scan_id, *params, *params],
                ).fetchone()[0]
            rel_rows = conn.execute(
                f"""
                SELECT relationship, COUNT(*)
                FROM graph_edges
                WHERE tenant_id = ? AND scan_id = ?
                  AND source_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                  AND target_id IN (SELECT id FROM graph_nodes WHERE {where_sql})
                GROUP BY relationship
                """,  # nosec B608 - where_sql is built from static clause fragments
                [tenant_id, effective_scan_id, *params, *params],
            ).fetchall()
            attack_row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(composite_risk), 0.0) FROM attack_paths WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()
            interaction_row = conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(risk_score), 0.0) FROM interaction_risks WHERE tenant_id = ? AND scan_id = ?",
                (tenant_id, effective_scan_id),
            ).fetchone()
            return {
                "total_nodes": int(total_nodes or 0),
                "total_edges": int(total_edges or 0),
                "node_types": node_types,
                "severity_counts": severity_counts,
                "relationship_types": {str(row[0]): int(row[1]) for row in rel_rows},
                "attack_path_count": int((attack_row[0] if attack_row else 0) or 0),
                "interaction_risk_count": int((interaction_row[0] if interaction_row else 0) or 0),
                "max_attack_path_risk": float((attack_row[1] if attack_row else 0.0) or 0.0),
                "highest_interaction_risk": float((interaction_row[1] if interaction_row else 0.0) or 0.0),
                "analysis_status": analysis_status,
            }
        finally:
            conn.close()

    def page_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> tuple[str, str, list[UnifiedNode], int, str | None]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        _assert_offset_within_cap(offset, cursor)
        conn = self._open_ro_conn()
        if conn is None:
            return scan_id, "", [], 0, None
        try:
            effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return scan_id, "", [], 0, None
            where = ["tenant_id = ?", "scan_id = ?"]
            params: list[Any] = [tenant_id, effective_scan_id]
            if entity_types:
                placeholders = ",".join("?" for _ in entity_types)
                where.append(f"entity_type IN ({placeholders})")
                params.extend(sorted(entity_types))
            sev_sql, sev_params = severity_floor_sql(min_severity_rank)
            if sev_sql:
                where.append(sev_sql)
                params.extend(sev_params)
            where_sql = " AND ".join(where)
            total = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM graph_nodes WHERE {where_sql}",  # nosec B608 - where_sql is built from static clause fragments
                    params,
                ).fetchone()[0]
                or 0
            )
            row_params = list(params)
            cursor_clause = ""
            if cursor:
                severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                cursor_clause = """
                AND (
                    severity_id < ?
                    OR (severity_id = ? AND risk_score < ?)
                    OR (severity_id = ? AND risk_score = ? AND label > ?)
                    OR (severity_id = ? AND risk_score = ? AND label = ? AND id > ?)
                )
                """
                row_params.extend(
                    [severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id]
                )
            rows = conn.execute(
                f"""
                SELECT
                    id, entity_type, label, category_uid, class_uid, type_uid,
                    status, risk_score, severity, severity_id, first_seen, last_seen,
                    attributes, compliance_tags, data_sources, dimensions
                FROM graph_nodes
                WHERE {where_sql}
                {cursor_clause}
                ORDER BY severity_id DESC, risk_score DESC, label ASC, id ASC
                LIMIT ? OFFSET ?
                """,  # nosec B608 - where_sql is built from static clause fragments
                [*row_params, limit + 1 if cursor else limit, 0 if cursor else offset],
            ).fetchall()
            has_more = len(rows) > limit if cursor else offset + limit < total
            rows = rows[:limit]
            nodes = [self._node_from_row(row) for row in rows]
            next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None
            return effective_scan_id, created_at, nodes, total, next_cursor
        finally:
            conn.close()

    def query_inventory(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        asset_entity_types: set[str],
        entity_types: set[str] | None = None,
        search: str = "",
        environment: str = "",
        provider: str = "",
        source: str = "",
        severity: str = "",
        min_severity_rank: int = 0,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Query exact inventory rows and whole-query facets in native SQL.

        The snapshot is resolved once and every count, facet, row, relationship,
        and finding summary is evaluated against that immutable tenant-scoped
        snapshot. Facets are self-excluding: each bucket honors every active
        filter except its own dimension.
        """
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        _assert_offset_within_cap(offset, cursor)
        conn = self._open_ro_conn()
        if conn is None:
            return self._empty_inventory_result(scan_id=scan_id)
        try:
            effective_scan_id, created_at = sqlite_graph_store._resolve_snapshot(conn, tenant_id=tenant_id, scan_id=scan_id)
            if not effective_scan_id:
                return self._empty_inventory_result(scan_id="")

            asset_types = sorted(asset_entity_types)
            asset_placeholders = ",".join("?" for _ in asset_types)
            finding_types = sorted(_FINDING_ENTITY_TYPE_VALUES)
            finding_placeholders = ",".join("?" for _ in finding_types)
            cte = f"""
                WITH finding_links AS (
                    SELECT e.source_id AS asset_id, f.severity_id
                    FROM graph_edges e
                    JOIN graph_nodes f ON f.tenant_id = e.tenant_id AND f.scan_id = e.scan_id AND f.id = e.target_id
                    WHERE e.tenant_id = ? AND e.scan_id = ? AND f.entity_type IN ({finding_placeholders})
                    UNION ALL
                    SELECT e.target_id AS asset_id, f.severity_id
                    FROM graph_edges e
                    JOIN graph_nodes f ON f.tenant_id = e.tenant_id AND f.scan_id = e.scan_id AND f.id = e.source_id
                    WHERE e.tenant_id = ? AND e.scan_id = ? AND f.entity_type IN ({finding_placeholders})
                ), finding_rollup AS (
                    SELECT asset_id, MAX(COALESCE(severity_id, 0)) AS finding_severity_rank
                    FROM finding_links GROUP BY asset_id
                ), assets_raw AS (
                    SELECT n.*,
                           NULLIF(LOWER(COALESCE(json_extract(n.dimensions, '$.environment'),
                                                  json_extract(n.attributes, '$.environment'), '')), '') AS inventory_environment,
                           NULLIF(LOWER(COALESCE(json_extract(n.dimensions, '$.cloud_provider'),
                                                  json_extract(n.attributes, '$.provider'),
                                                  json_extract(n.attributes, '$.cloud_provider'), '')), '') AS inventory_provider,
                           NULLIF(LOWER(COALESCE(json_extract(n.dimensions, '$.ecosystem'),
                                                  json_extract(n.attributes, '$.ecosystem'), '')), '') AS inventory_ecosystem,
                           finding_rollup.finding_severity_rank
                    FROM graph_nodes n
                    LEFT JOIN finding_rollup ON finding_rollup.asset_id = n.id
                    WHERE n.tenant_id = ? AND n.scan_id = ?
                      AND n.entity_type IN ({asset_placeholders})
                ), assets AS (
                    SELECT *, CASE finding_severity_rank
                        WHEN 5 THEN 'critical' WHEN 4 THEN 'high'
                        WHEN 3 THEN 'medium' WHEN 2 THEN 'low' WHEN 1 THEN 'info'
                        ELSE NULL END AS finding_severity
                    FROM assets_raw
                )
            """  # nosec B608 - placeholders only; type values are bound
            cte_params: list[Any] = [
                tenant_id,
                effective_scan_id,
                *finding_types,
                tenant_id,
                effective_scan_id,
                *finding_types,
                tenant_id,
                effective_scan_id,
                *asset_types,
            ]

            normalized = {
                "environment": environment.strip().lower(),
                "provider": provider.strip().lower(),
                "source": source.strip().lower(),
                "severity": severity.strip().lower(),
            }

            def filtered_where(*, exclude: str = "") -> tuple[str, list[Any]]:
                clauses: list[str] = []
                params: list[Any] = []
                if entity_types and exclude != "type":
                    values = sorted(entity_types)
                    clauses.append(f"entity_type IN ({','.join('?' for _ in values)})")
                    params.extend(values)
                if search.strip():
                    clauses.append("(LOWER(label) LIKE ? ESCAPE '\\' OR LOWER(attributes) LIKE ? ESCAPE '\\')")
                    token = f"%{_escape_like_query(search.strip().lower())}%"
                    params.extend([token, token])
                if normalized["environment"] and exclude != "environment":
                    clauses.append("inventory_environment = ?")
                    params.append(normalized["environment"])
                if normalized["provider"] and exclude != "provider":
                    clauses.append("inventory_provider = ?")
                    params.append(normalized["provider"])
                if normalized["source"] and exclude != "source":
                    clauses.append("EXISTS (SELECT 1 FROM json_each(assets.data_sources) src WHERE LOWER(src.value) = ?)")
                    params.append(normalized["source"])
                if normalized["severity"] and exclude != "severity":
                    clauses.append("finding_severity = ?")
                    params.append(normalized["severity"])
                if min_severity_rank and exclude != "severity":
                    clauses.append("COALESCE(finding_severity_rank, 0) >= ?")
                    params.append(min_severity_rank)
                return (" AND ".join(clauses) if clauses else "1 = 1"), params

            where_sql, where_params = filtered_where()
            facet_sql = [
                f"SELECT '__total__' AS facet, NULL AS value, COUNT(*) AS count FROM assets WHERE {where_sql}"  # nosec B608 - generated clauses only
            ]
            facet_params: list[Any] = [*where_params]
            facet_columns = {
                "type": "entity_type",
                "environment": "inventory_environment",
                "provider": "inventory_provider",
                "severity": "finding_severity",
            }
            for facet, column in facet_columns.items():
                facet_where, current_params = filtered_where(exclude=facet)
                facet_sql.append(
                    f"SELECT '{facet}', {column}, COUNT(*) FROM assets WHERE {facet_where} GROUP BY {column}"  # nosec B608 - static mapping
                )
                facet_params.extend(current_params)
            source_where, source_params = filtered_where(exclude="source")
            facet_sql.append(
                f"""
                    SELECT 'source', value, COUNT(DISTINCT id) FROM (
                        SELECT assets.id, NULLIF(LOWER(src.value), '') AS value
                        FROM assets JOIN json_each(assets.data_sources) src
                        WHERE {source_where}
                        UNION ALL
                        SELECT assets.id, NULL FROM assets
                        WHERE {source_where} AND json_array_length(data_sources) = 0
                    ) source_buckets GROUP BY value
                """  # nosec B608 - source_where contains only generated placeholders
            )
            facet_params.extend([*source_params, *source_params])
            facet_rows = conn.execute(cte + " UNION ALL ".join(facet_sql), [*cte_params, *facet_params]).fetchall()
            facets: dict[str, list[dict[str, Any]]] = {name: [] for name in ("type", "source", "provider", "environment", "severity")}
            total = 0
            for facet, value, count in facet_rows:
                if facet == "__total__":
                    total = int(count or 0)
                    continue
                facets[str(facet)].append({"value": value if value not in {"", None} else None, "count": int(count)})
            for buckets in facets.values():
                buckets.sort(key=lambda bucket: (-int(bucket["count"]), "" if bucket["value"] is None else str(bucket["value"])))

            row_params = [*cte_params, *where_params]
            cursor_clause = ""
            if cursor:
                severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                cursor_clause = """
                    AND (severity_id < ?
                      OR (severity_id = ? AND risk_score < ?)
                      OR (severity_id = ? AND risk_score = ? AND label > ?)
                      OR (severity_id = ? AND risk_score = ? AND label = ? AND id > ?))
                """
                row_params.extend(
                    [severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id]
                )
            rows = conn.execute(
                cte
                + f"""
                    SELECT id, entity_type, label, category_uid, class_uid, type_uid,
                           status, risk_score, severity, severity_id, first_seen, last_seen,
                           attributes, compliance_tags, data_sources, dimensions
                    FROM assets
                    WHERE {where_sql} {cursor_clause}
                    ORDER BY severity_id DESC, risk_score DESC, label ASC, id ASC
                    LIMIT ? OFFSET ?
                """,  # nosec B608 - clauses contain only generated placeholders
                [*row_params, limit + 1, 0 if cursor else offset],
            ).fetchall()
            has_more = len(rows) > limit or (not cursor and offset + limit < total)
            nodes = [self._node_from_row(row) for row in rows[:limit]]
            next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None

            finding_summaries, relationship_counts = self._inventory_page_context(
                conn,
                tenant_id=tenant_id,
                scan_id=effective_scan_id,
                node_ids={node.id for node in nodes},
                finding_types=finding_types,
            )
            finding_count = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM graph_nodes WHERE tenant_id = ? AND scan_id = ? AND entity_type IN ({finding_placeholders})",  # nosec B608 - placeholders only
                    [tenant_id, effective_scan_id, *finding_types],
                ).fetchone()[0]
                or 0
            )
            return {
                "scan_id": effective_scan_id,
                "created_at": created_at,
                "nodes": nodes,
                "total": total,
                "next_cursor": next_cursor,
                "facets": facets,
                "finding_summaries": finding_summaries,
                "relationship_counts": relationship_counts,
                "finding_count": finding_count,
            }
        finally:
            conn.close()

    @staticmethod
    def _empty_inventory_result(*, scan_id: str) -> dict[str, Any]:
        return {
            "scan_id": scan_id,
            "created_at": "",
            "nodes": [],
            "total": 0,
            "next_cursor": None,
            "facets": {name: [] for name in ("type", "source", "provider", "environment", "severity")},
            "finding_summaries": {},
            "relationship_counts": {},
            "finding_count": 0,
        }

    def _inventory_page_context(
        self,
        conn: sqlite3.Connection,
        *,
        tenant_id: str,
        scan_id: str,
        node_ids: set[str],
        finding_types: list[str],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
        if not node_ids:
            return {}, {}
        node_values = sorted(node_ids)
        node_marks = ",".join("?" for _ in node_values)
        finding_marks = ",".join("?" for _ in finding_types)
        rows = conn.execute(
            f"""
                SELECT a.id, f.id,
                       CASE LOWER(COALESCE(f.severity, '')) WHEN 'informational' THEN 'info'
                            ELSE LOWER(COALESCE(f.severity, '')) END
                FROM graph_nodes a
                JOIN graph_edges e ON e.tenant_id = a.tenant_id AND e.scan_id = a.scan_id
                    AND (e.source_id = a.id OR e.target_id = a.id)
                JOIN graph_nodes f ON f.tenant_id = e.tenant_id AND f.scan_id = e.scan_id
                    AND f.id = CASE WHEN e.source_id = a.id THEN e.target_id ELSE e.source_id END
                WHERE a.tenant_id = ? AND a.scan_id = ? AND a.id IN ({node_marks})
                  AND f.entity_type IN ({finding_marks})
                GROUP BY a.id, f.id, f.severity
                ORDER BY a.id, f.severity_id DESC, f.id
            """,  # nosec B608 - placeholder lists only
            [tenant_id, scan_id, *node_values, *finding_types],
        ).fetchall()
        summaries: dict[str, dict[str, Any]] = {}
        for asset_id, finding_id, finding_severity in rows:
            summary = summaries.setdefault(str(asset_id), {"total": 0, "by_severity": {}, "ids": [], "top_severity": ""})
            summary["total"] += 1
            summary["ids"].append(str(finding_id))
            if finding_severity:
                by_severity = summary["by_severity"]
                by_severity[str(finding_severity)] = int(by_severity.get(str(finding_severity), 0)) + 1
                if not summary["top_severity"]:
                    summary["top_severity"] = str(finding_severity)
        relationship_rows = conn.execute(
            f"""
                SELECT node_id, COUNT(*) FROM (
                    SELECT source_id AS node_id, source_id, target_id, relationship FROM graph_edges
                    WHERE tenant_id = ? AND scan_id = ? AND source_id IN ({node_marks})
                    UNION
                    SELECT target_id AS node_id, source_id, target_id, relationship FROM graph_edges
                    WHERE tenant_id = ? AND scan_id = ? AND target_id IN ({node_marks})
                ) GROUP BY node_id
            """,  # nosec B608 - placeholder lists only
            [tenant_id, scan_id, *node_values, tenant_id, scan_id, *node_values],
        ).fetchall()
        return summaries, {str(row[0]): int(row[1]) for row in relationship_rows}

    def edges_for_node_ids(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        node_ids: set[str],
    ) -> list[Any]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        if not node_ids:
            return []
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            effective_scan_id = scan_id or sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
            if not effective_scan_id:
                return []
            placeholders = ",".join("?" for _ in node_ids)
            rows = conn.execute(
                f"""
                SELECT *
                FROM graph_edges
                WHERE tenant_id = ? AND scan_id = ?
                  AND (source_id IN ({placeholders}) OR target_id IN ({placeholders}))
                """,  # nosec B608 - placeholders are generated solely from "?" markers
                [tenant_id, effective_scan_id, *node_ids, *node_ids],
            ).fetchall()
            return [self._edge_from_row(row) for row in rows]
        finally:
            conn.close()

    def search_nodes(
        self,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        query: str,
        entity_types: set[str] | None = None,
        min_severity_rank: int = 0,
        compliance_prefixes: set[str] | None = None,
        data_sources: set[str] | None = None,
        cursor: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[UnifiedNode], int, str | None]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        _assert_offset_within_cap(offset, cursor)
        conn = self._open_ro_conn()
        if conn is None:
            return [], 0, None
        try:
            conn_ro: sqlite3.Connection = conn
            effective_scan_id = scan_id or sqlite_graph_store.latest_snapshot_id(conn, tenant_id=tenant_id)
            if not effective_scan_id:
                return [], 0, None
            fts_query = self._search_query_expression(query)
            search_where = [
                "gns.tenant_id = ?",
                "gns.scan_id = ?",
            ]
            params: list[Any] = [tenant_id, effective_scan_id]
            like_query = f"%{_escape_like_query(query.lower())}%"

            def _run_search(*, use_fts: bool) -> tuple[list[UnifiedNode], int, str | None]:
                local_where = list(search_where)
                local_params = list(params)
                if use_fts:
                    local_where.append("gns.graph_node_search MATCH ?")
                    local_params.append(fts_query)
                else:
                    local_where.append("gns.search_text LIKE ? ESCAPE '\\'")
                    local_params.append(like_query)
                if entity_types:
                    placeholders = ",".join("?" for _ in entity_types)
                    local_where.append(f"gn.entity_type IN ({placeholders})")
                    local_params.extend(sorted(entity_types))
                sev_sql, sev_params = severity_floor_sql(min_severity_rank, column="gn.severity_id", entity_column="gn.entity_type")
                if sev_sql:
                    local_where.append(sev_sql)
                    local_params.extend(sev_params)
                if compliance_prefixes:
                    prefix_filters = []
                    for prefix in sorted(compliance_prefixes):
                        clause, clause_params = self._compliance_prefix_filter("gns.compliance_tags", prefix)
                        prefix_filters.append(clause)
                        local_params.extend(clause_params)
                    local_where.append("(" + " OR ".join(prefix_filters) + ")")
                if data_sources:
                    source_filters = []
                    for source in sorted(data_sources):
                        clause, clause_params = self._space_token_filter("gns.data_sources", source)
                        source_filters.append(clause)
                        local_params.extend(clause_params)
                    local_where.append("(" + " OR ".join(source_filters) + ")")
                row_params = list(local_params)
                cursor_clause = ""
                if cursor:
                    severity_id, risk_score, label, node_id = decode_graph_cursor(cursor)
                    cursor_clause = """
                    AND (
                        gn.severity_id < ?
                        OR (gn.severity_id = ? AND gn.risk_score < ?)
                        OR (gn.severity_id = ? AND gn.risk_score = ? AND gn.label > ?)
                        OR (gn.severity_id = ? AND gn.risk_score = ? AND gn.label = ? AND gn.id > ?)
                    )
                    """
                    row_params.extend(
                        [severity_id, severity_id, risk_score, severity_id, risk_score, label, severity_id, risk_score, label, node_id]
                    )

                where_sql = " AND ".join(local_where)
                total = int(
                    conn_ro.execute(
                        "SELECT COUNT(*) " + from_clause + " WHERE " + where_sql,
                        local_params,
                    ).fetchone()[0]
                    or 0
                )
                if total == 0:
                    return [], 0, None
                rows = conn_ro.execute(
                    """
                    SELECT
                        gn.id, gn.entity_type, gn.label, gn.category_uid, gn.class_uid, gn.type_uid,
                        gn.status, gn.risk_score, gn.severity, gn.severity_id, gn.first_seen, gn.last_seen,
                        gn.attributes, gn.compliance_tags, gn.data_sources, gn.dimensions
                    """
                    + from_clause
                    + " WHERE "
                    + where_sql
                    + cursor_clause
                    + " ORDER BY gn.severity_id DESC, gn.risk_score DESC, gn.label ASC, gn.id ASC LIMIT ? OFFSET ?",
                    [*row_params, limit + 1 if cursor else limit, 0 if cursor else offset],
                ).fetchall()
                has_more = len(rows) > limit if cursor else offset + limit < total
                rows = rows[:limit]
                nodes = [self._node_from_row(row) for row in rows]
                next_cursor = encode_graph_cursor(nodes[-1]) if has_more and nodes else None
                return nodes, total, next_cursor

            from_clause = """
                FROM graph_node_search gns
                JOIN graph_nodes gn
                  ON gn.id = gns.node_id
                 AND gn.scan_id = gns.scan_id
                 AND gn.tenant_id = gns.tenant_id
            """
            use_fts = bool(fts_query and self._should_use_fts(query))
            try:
                return _run_search(use_fts=use_fts)
            except sqlite3.OperationalError:
                if not use_fts:
                    raise
                return _run_search(use_fts=False)
        finally:
            conn.close()

    def save_preset(self, *, tenant_id: str, name: str, description: str, filters: dict[str, Any], created_at: str) -> None:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_rw_conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO graph_filter_presets VALUES (?, ?, ?, ?, ?)",
                (name, tenant_id, description, json.dumps(filters), created_at),
            )
            conn.commit()
        finally:
            conn.close()

    def list_presets(self, *, tenant_id: str) -> list[dict[str, Any]]:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_ro_conn()
        if conn is None:
            return []
        try:
            rows = conn.execute(
                "SELECT name, description, filters, created_at FROM graph_filter_presets WHERE tenant_id = ? ORDER BY name",
                (tenant_id,),
            ).fetchall()
            return [
                {
                    "name": row["name"],
                    "description": row["description"],
                    "filters": json.loads(row["filters"]),
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        finally:
            conn.close()

    def delete_preset(self, *, tenant_id: str, name: str) -> bool:
        tenant_id = sqlite_graph_store.normalize_graph_tenant_id(tenant_id)
        conn = self._open_rw_conn()
        try:
            cursor = conn.execute(
                "DELETE FROM graph_filter_presets WHERE name = ? AND tenant_id = ?",
                (name, tenant_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
