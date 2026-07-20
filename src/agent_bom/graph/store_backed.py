"""Store-backed live :class:`UnifiedGraph` (#4075 PR-3 — proven but unwired).

The graph *producer* (:func:`agent_bom.graph.builder.build_unified_graph_from_report`)
and its Phase-B overlays build the whole correlated graph in RAM: they add and
merge nodes/edges, then random-access + mutate the full node set in a forward-
feeding chain. That in-RAM materialisation is the remaining wall on the #4055
write-path peak-RSS bound.

:class:`StoreBackedUnifiedGraph` presents the **exact** public
:class:`~agent_bom.graph.container.UnifiedGraph` interface while backing storage
with the #4295 indexed build workspace (SQLite temp DB or shared Postgres). Only
a bounded working set lives in RAM:

* a bounded **LRU node cache** (``capacity`` objects) that also serves as the
  identity map — while a node is cached it is the one canonical object, so an
  in-place mutation is visible to the next accessor (``UnifiedNode`` is
  ``slots=True`` and not weak-referenceable, so a strong-ref LRU, not a weak map,
  holds identity);
* **dirty-tracking write-back**: any node handed to a caller is tracked and its
  in-place mutations (``graph.get_node(id).attributes.update(...)`` /
  ``graph.nodes[id].attributes[...] = ...`` / ``for n in graph.nodes.values(): n.…``)
  are persisted on eviction and before serialisation. A node must be mutated
  within ``capacity`` node-accesses of being handed out (every current overlay
  mutates a node immediately or within a bounded window — see the audit); the
  default ``capacity`` is sized well above any overlay's working set;
* adjacency / reverse-adjacency served by **keyset-paged indexed queries**, with
  bidirectional-reverse edges synthesised on read exactly as the in-RAM
  container materialises them.

``add_node`` merge-union and ``add_edge`` dedup + bidirectional-reverse semantics
are byte-identical to :class:`UnifiedGraph`; ``to_dict()`` on the same build is
byte-identical. Every traversal / filter / view algorithm is **inherited
unchanged** from :class:`UnifiedGraph` and runs against the store-backed
``nodes`` / ``edges`` / ``adjacency`` / ``reverse_adjacency`` views.

**Default-off and unwired.** No builder, overlay, or persist caller constructs
this container in production; the shipped path still materialises the in-RAM
:class:`UnifiedGraph`. Tests are the only callers. Wiring the builder/overlays
through it (and the deferred build-latency + PG-workspace-RLS decisions) is held
for owner sign-off as PR-4.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, Optional

from agent_bom.graph.analysis import GraphAnalysisStatus
from agent_bom.graph.build_workspace import (
    WorkspaceBackend,
    _edge_from_payload,
    _edge_key,
    _node_entity_type,
    _node_from_payload,
    _normalize_tenant,
    open_workspace_backend,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.severity import SEVERITY_RANK
from agent_bom.graph.types import EntityType
from agent_bom.graph.util import _now_iso

if TYPE_CHECKING:
    from collections.abc import Mapping

_DEFAULT_CAPACITY = 4096
_DEFAULT_PAGE_SIZE = 1000


def _node_to_row(node: UnifiedNode) -> tuple[str, str, str]:
    return (node.id, json.dumps(node.to_dict(), default=str), _node_entity_type(node))


def _edge_to_row(edge: UnifiedEdge) -> tuple[str, str, str, str]:
    return (_edge_key(edge), json.dumps(edge.to_dict(), default=str), edge.source, edge.target)


def _reverse_edge(edge: UnifiedEdge) -> UnifiedEdge:
    """Synthesise the reverse of a bidirectional edge, matching container.add_edge."""
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
        source_scan_id=edge.source_scan_id,
        source_run_id=edge.source_run_id,
        evidence=edge.evidence,
        confidence=edge.confidence,
        provenance=edge.provenance,
        activity_id=edge.activity_id,
    )


class _NodesView:
    """Read mapping-view over the store-backed node set.

    Supports exactly what the overlays + inherited algorithms use — ``[id]``,
    ``in``, ``.get``, ``.values()``, ``.items()``, iteration (keys), ``len`` — and
    dirty-tracks every node it hands out so in-place mutations are written back.
    No ``__setitem__`` / ``__delitem__``: the overlays never assign or delete
    ``graph.nodes[id]`` (verified by the interface-identity audit).
    """

    __slots__ = ("_g",)

    def __init__(self, graph: StoreBackedUnifiedGraph) -> None:
        self._g = graph

    def __getitem__(self, node_id: str) -> UnifiedNode:
        node = self._g._resolve_node(node_id)
        if node is None:
            raise KeyError(node_id)
        self._g._mark_dirty(node_id)
        return node

    def get(self, node_id: str, default: Any = None) -> Any:
        node = self._g._resolve_node(node_id)
        if node is None:
            return default
        self._g._mark_dirty(node_id)
        return node

    def __contains__(self, node_id: object) -> bool:
        return isinstance(node_id, str) and self._g._has_node(node_id)

    def __iter__(self) -> Iterator[str]:
        for _seq, node_id, _payload in self._g._iter_node_rows():
            yield node_id

    def keys(self) -> Iterator[str]:
        return iter(self)

    def values(self) -> Iterator[UnifiedNode]:
        return self._g._iter_nodes(mark_dirty=True)

    def items(self) -> Iterator[tuple[str, UnifiedNode]]:
        for node in self._g._iter_nodes(mark_dirty=True):
            yield node.id, node

    def __len__(self) -> int:
        return self._g._node_count()


class _EdgesView:
    """Read sequence-view over the store-backed edge set (originals only, by seq).

    Mirrors the in-RAM ``UnifiedGraph.edges`` list for the surface overlays and
    inherited algorithms use: iteration and ``len``.
    """

    __slots__ = ("_g",)

    def __init__(self, graph: StoreBackedUnifiedGraph) -> None:
        self._g = graph

    def __iter__(self) -> Iterator[UnifiedEdge]:
        return self._g._iter_edges()

    def __len__(self) -> int:
        return self._g._edge_count()


class _AdjacencyView:
    """``.get(node_id, default)`` view returning the adjacency edge list.

    Forward and reverse orientations reconstruct the in-RAM container's
    adjacency — original edges plus synthesised reverses for bidirectional edges —
    from indexed source/target queries.
    """

    __slots__ = ("_g", "_reverse")

    def __init__(self, graph: StoreBackedUnifiedGraph, *, reverse: bool) -> None:
        self._g = graph
        self._reverse = reverse

    def get(self, node_id: str, default: Any = None) -> Any:
        edges = self._g._reverse_adjacency(node_id) if self._reverse else self._g._adjacency(node_id)
        if edges:
            return edges
        return default if default is not None else edges

    def __getitem__(self, node_id: str) -> list[UnifiedEdge]:
        return self._g._reverse_adjacency(node_id) if self._reverse else self._g._adjacency(node_id)


class StoreBackedUnifiedGraph(UnifiedGraph):
    """A :class:`UnifiedGraph` whose node/edge storage lives in the build workspace.

    Constructed only in tests for PR-3 (see the module docstring). Instances own
    the backend when created via :func:`open_store_backed_unified_graph`; when
    handed an existing backend (a shared, tenant-scoped store) they do not.
    """

    # This subclass deliberately does NOT run the ``@dataclass`` __init__: it
    # provides its own, and exposes ``nodes`` / ``edges`` / ``adjacency`` /
    # ``reverse_adjacency`` as store-backed properties instead of dict fields.
    def __init__(
        self,
        backend: WorkspaceBackend,
        *,
        tenant_id: str = "",
        scan_id: str = "",
        created_at: str = "",
        analysis_status: Optional[dict[str, GraphAnalysisStatus]] = None,
        capacity: int = _DEFAULT_CAPACITY,
        page_size: int = _DEFAULT_PAGE_SIZE,
        owns_backend: bool = False,
    ) -> None:
        self._backend = backend
        self._tenant = _normalize_tenant(tenant_id)
        self._capacity = max(1, capacity)
        self._page_size = max(1, page_size)
        self._owns_backend = owns_backend

        # Strong-ref LRU cache: a node stays canonical (one object, mutations
        # visible) while cached. ``capacity`` must exceed the largest working set
        # any single caller holds-and-mutates across other node accesses — all
        # current overlays mutate a node within a bounded window of handing it out
        # (see the interface-identity audit); the default is sized well above that.
        self._cache: OrderedDict[str, UnifiedNode] = OrderedDict()
        self._dirty: set[str] = set()

        self._nodes_view = _NodesView(self)
        self._edges_view = _EdgesView(self)
        self._adjacency_view = _AdjacencyView(self, reverse=False)
        self._reverse_adjacency_view = _AdjacencyView(self, reverse=True)

        # Graph-level fields mirror the in-RAM dataclass (small, bounded, in RAM).
        self.attack_paths = []
        self.attack_campaigns = []
        self.interaction_risks = []
        self.analysis_status = dict(analysis_status or {})
        self.nhi_governance_findings = []
        self.scan_id = scan_id
        self.tenant_id = tenant_id
        self.created_at = created_at or _now_iso()

    # ── Store-backed views (shadow the dataclass fields) ─────────────────────

    @property
    def nodes(self) -> Any:  # type: ignore[override]
        return self._nodes_view

    @property
    def edges(self) -> Any:  # type: ignore[override]
        return self._edges_view

    @property
    def adjacency(self) -> Any:  # type: ignore[override]
        return self._adjacency_view

    @property
    def reverse_adjacency(self) -> Any:  # type: ignore[override]
        return self._reverse_adjacency_view

    # ── Node cache / dirty write-back ────────────────────────────────────────

    def _cache_put(self, node_id: str, node: UnifiedNode) -> None:
        self._cache[node_id] = node
        self._cache.move_to_end(node_id)
        while len(self._cache) > self._capacity:
            old_id, old_node = self._cache.popitem(last=False)
            if old_id in self._dirty:
                self._write_back(old_id, old_node)
                self._dirty.discard(old_id)

    def _resolve_node(self, node_id: str) -> Optional[UnifiedNode]:
        """Return the canonical cached object for ``node_id`` (or load it, or ``None``)."""
        cached = self._cache.get(node_id)
        if cached is not None:
            self._cache.move_to_end(node_id)
            return cached
        payload = self._backend.get_node_payload(self._tenant, node_id)
        if payload is None:
            return None
        node = _node_from_payload(json.loads(payload))
        self._cache_put(node_id, node)
        return node

    def _mark_dirty(self, node_id: str) -> None:
        self._dirty.add(node_id)

    def _write_back(self, node_id: str, node: UnifiedNode) -> None:
        self._backend.add_node_payloads(self._tenant, [_node_to_row(node)])

    def flush(self) -> None:
        """Persist all dirty (mutated / handed-out) nodes to the store."""
        if not self._dirty:
            return
        for node_id in list(self._dirty):
            node = self._cache.get(node_id)
            if node is not None:
                self._write_back(node_id, node)
        self._dirty.clear()

    def _has_node(self, node_id: str) -> bool:
        if node_id in self._cache:
            return True
        return self._backend.get_node_payload(self._tenant, node_id) is not None

    def _node_count(self) -> int:
        return self._backend.count_nodes(self._tenant)

    def _edge_count(self) -> int:
        return self._backend.count_edges(self._tenant)

    # ── Keyset-paged iteration (write-back safe between pages) ────────────────

    def _iter_node_rows(self, *, entity_type: str | None = None) -> Iterator[tuple[int, str, str]]:
        self.flush()
        after = 0
        while True:
            page = self._backend.fetch_node_page(self._tenant, after, self._page_size, entity_type)
            if not page:
                return
            for seq, node_id, payload in page:
                after = seq
                yield seq, node_id, payload

    def _iter_nodes(self, *, mark_dirty: bool, entity_type: str | None = None) -> Iterator[UnifiedNode]:
        for _seq, node_id, payload in self._iter_node_rows(entity_type=entity_type):
            cached = self._cache.get(node_id)
            node = cached if cached is not None else _node_from_payload(json.loads(payload))
            if cached is None:
                self._cache_put(node_id, node)
            if mark_dirty:
                self._mark_dirty(node_id)
            yield node

    def _iter_edges(self) -> Iterator[UnifiedEdge]:
        after = 0
        while True:
            page = self._backend.fetch_edge_page(self._tenant, after, self._page_size)
            if not page:
                return
            for seq, payload in page:
                after = seq
                yield _edge_from_payload(json.loads(payload))

    def _collect_edges(self, *, source: str | None = None, target: str | None = None) -> list[UnifiedEdge]:
        out: list[UnifiedEdge] = []
        after = 0
        while True:
            page = self._backend.fetch_edge_page(self._tenant, after, self._page_size, source_id=source, target_id=target)
            if not page:
                return out
            for seq, payload in page:
                after = seq
                out.append(_edge_from_payload(json.loads(payload)))

    def _adjacency(self, node_id: str) -> list[UnifiedEdge]:
        out: list[UnifiedEdge] = list(self._collect_edges(source=node_id))
        for edge in self._collect_edges(target=node_id):
            if edge.is_bidirectional:
                out.append(_reverse_edge(edge))
        return out

    def _reverse_adjacency(self, node_id: str) -> list[UnifiedEdge]:
        out: list[UnifiedEdge] = list(self._collect_edges(target=node_id))
        for edge in self._collect_edges(source=node_id):
            if edge.is_bidirectional:
                out.append(_reverse_edge(edge))
        return out

    # ── Mutation (store-backed overrides) ────────────────────────────────────

    def add_node(self, node: UnifiedNode) -> None:
        existing = self._resolve_node(node.id)
        if existing is not None:
            _merge_node(existing, node)
            self._mark_dirty(node.id)
            return
        # New node: insert immediately so ``seq`` fixes insertion order (matching
        # the in-RAM dict's first-insert ordering), then cache for identity.
        self._backend.add_node_payloads(self._tenant, [_node_to_row(node)])
        self._cache_put(node.id, node)

    def add_edge(self, edge: UnifiedEdge) -> None:
        key = _edge_key(edge)
        existing_payload = self._backend.get_edge_payload(self._tenant, key)
        if existing_payload is not None:
            if edge.evidence:
                stored = _edge_from_payload(json.loads(existing_payload))
                changed = False
                for evidence_key, value in edge.evidence.items():
                    if value in (None, "", [], {}):
                        continue
                    if evidence_key not in stored.evidence or stored.evidence[evidence_key] in (None, "", [], {}):
                        stored.evidence[evidence_key] = value
                        changed = True
                if changed:
                    self._backend.add_edge_payloads(self._tenant, [_edge_to_row(stored)])
            return
        self._backend.add_edge_payloads(self._tenant, [_edge_to_row(edge)])

    # ── Query overrides that must not fan out over the whole node set ─────────

    def get_node(self, node_id: str) -> Optional[UnifiedNode]:
        node = self._resolve_node(node_id)
        if node is not None:
            self._mark_dirty(node_id)
        return node

    def has_node(self, node_id: str) -> bool:
        return self._has_node(node_id)

    def nodes_by_type(self, entity_type: EntityType) -> list[UnifiedNode]:
        et = entity_type.value if isinstance(entity_type, EntityType) else str(entity_type)
        return list(self._iter_nodes(mark_dirty=True, entity_type=et))

    def to_dict(self) -> dict[str, Any]:
        self.flush()
        return super().to_dict()

    @classmethod
    def from_dict(cls, data: "Mapping[str, Any]") -> "StoreBackedUnifiedGraph":  # type: ignore[override]
        raise NotImplementedError(
            "StoreBackedUnifiedGraph is built via add_node/add_edge against a store backend; "
            "use open_store_backed_unified_graph(...) then replay nodes/edges."
        )

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def close(self) -> None:
        if self._owns_backend:
            self._backend.close()

    def __enter__(self) -> "StoreBackedUnifiedGraph":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"StoreBackedUnifiedGraph(tenant={self._tenant!r}, nodes={self._node_count()}, edges={self._edge_count()})"

    __eq__ = object.__eq__
    __hash__ = object.__hash__


def _merge_node(existing: UnifiedNode, incoming: UnifiedNode) -> None:
    """In-place merge-union mirroring :meth:`UnifiedGraph.add_node` exactly."""
    existing.last_seen = incoming.last_seen or _now_iso()
    existing.attributes.update(incoming.attributes)
    if SEVERITY_RANK.get(incoming.severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
        existing.severity = incoming.severity
        existing.severity_id = incoming.severity_id
    if incoming.risk_score > existing.risk_score:
        existing.risk_score = incoming.risk_score
    existing_sources = set(existing.data_sources)
    for ds in incoming.data_sources:
        if ds not in existing_sources:
            existing.data_sources.append(ds)
            existing_sources.add(ds)
    existing_tags = set(existing.compliance_tags)
    for tag in incoming.compliance_tags:
        if tag not in existing_tags:
            existing.compliance_tags.append(tag)
            existing_tags.add(tag)
    existing.dimensions = existing.dimensions.merge(incoming.dimensions)


def open_store_backed_unified_graph(
    *,
    tenant_id: str = "",
    scan_id: str = "",
    created_at: str = "",
    analysis_status: Optional[dict[str, GraphAnalysisStatus]] = None,
    workspace_id: str = "",
    backend: str = "auto",
    capacity: int = _DEFAULT_CAPACITY,
    page_size: int | None = None,
) -> StoreBackedUnifiedGraph:
    """Open a store-backed live graph on the appropriate workspace backend.

    ``backend="auto"`` selects Postgres when ``AGENT_BOM_POSTGRES_URL`` is set,
    otherwise a private SQLite temp database (mirrors
    :func:`~agent_bom.graph.build_workspace.open_graph_build_workspace`). The
    returned container owns and closes its backend.
    """
    impl = open_workspace_backend(workspace_id=workspace_id, backend=backend)
    return StoreBackedUnifiedGraph(
        impl,
        tenant_id=tenant_id,
        scan_id=scan_id,
        created_at=created_at,
        analysis_status=analysis_status,
        capacity=capacity,
        page_size=page_size or _DEFAULT_PAGE_SIZE,
        owns_backend=True,
    )
