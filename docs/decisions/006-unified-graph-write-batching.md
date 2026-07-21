# ADR-006: Unified Graph Write Batching

**Status:** Accepted
**Date:** 2026-04-25

## Context

Large graph snapshots can contain many nodes, search rows, edges, attack paths,
and interaction risks. Persisting those rows one at a time is slow, but building
full intermediate row lists before writing can make memory scale with total graph
size. That is the wrong failure mode for fleet-scale scans.

SQLite and Postgres already share the same logical persistence contract:
`save_graph(graph)` receives a `UnifiedGraph` and writes the same graph objects
in the same order. The batching change should preserve that contract instead of
creating backend-specific graph save APIs.

## Decision

Use one operator-facing graph write batch-size setting across SQLite and
Postgres:

- `AGENT_BOM_GRAPH_WRITE_BATCH_SIZE`

Each backend maps that shared setting to its own write implementation. Row
sources are lazy iterators, and the batching helper materializes only one batch
window at a time. That keeps graph write memory bounded by the batch size rather
than total graph size.

Temporal edge continuity is part of the same invariant. Both backends preserve
`first_seen` / `valid_from` for retained edges and close missing prior edges
with tenant-and-snapshot-scoped database updates. They do not load or sort the
previous snapshot's edge keys in Python; otherwise a small new snapshot after a
large prior snapshot would still consume O(previous edges) memory.

Batching helpers are intentionally generic. They operate on row iterables and
SQL statements, not on graph-specific types. This keeps the pattern reusable for
future write-heavy paths without creating separate one-off batching code.

Compatibility fallbacks may write rows individually when a test or lightweight
connection object does not expose `executemany`, but they still consume bounded
batches. The fallback can give up round-trip efficiency; it must not give up the
bounded-memory invariant.

## Consequences

- **Positive:** Operators tune one graph write batch knob instead of separate
  SQLite and Postgres settings.
- **Positive:** Backend implementations can differ internally while preserving
  the shared `save_graph(graph)` contract.
- **Positive:** Lazy row generation keeps write-path memory tied to the batch
  window, not to either the current or previous graph size.
- **Positive:** The batching primitive is reusable outside graph persistence.
- **Trade-off:** One shared knob may not be optimal for every backend in every
  deployment. If benchmarks prove a backend-specific need, add optional
  backend-specific overrides while keeping `AGENT_BOM_GRAPH_WRITE_BATCH_SIZE`
  as the default.
- **Boundary:** This decision covers write-path batching only. Read-path
  windowing, streaming reads, materialized drilldowns, and UI virtualization are
  separate graph-scale concerns.

## Realized bound and residual producer wall

The write path is bounded end to end and regression-guarded:

- The streamed save + the prior-snapshot delta both stay bounded by the batch
  window / an id-only prior digest rather than the graph size. `save_graph`'s
  SQLite search-index refresh streams in bounded batches too, not a `fetchall`
  re-materialization of the node set.
- Guards: `test_graph_store_streamed_persistence.py` (streamed-save peak flat as
  N grows), `test_graph_persist_memory_bound.py` (prior digest is a small,
  non-eroding fraction of a full prior load), `test_search_index_refresh_streaming.py`
  (bounded search-index refresh), and — at the shipped pipeline entrypoint —
  `test_graph_persist_pipeline_scale_bound.py`, which pins that persisting a
  *large new* snapshot through `_persist_graph_snapshot` peaks at a small,
  non-eroding fraction of materializing that snapshot (≈0.12–0.2 measured, 4x-N
  span). That last guard exists because a re-materialization of the *incoming*
  snapshot is invisible to the prior-side guards.

### Producer: store-backed build (opt-in) — realized reduction

By default the graph **producer** `build_unified_graph_from_report` materializes
the whole correlated `UnifiedGraph` — nodes, edges, and its adjacency /
reverse-adjacency / dedup indexes — in RAM, with correlation overlays that query
the whole graph, before persist. So peak RSS for a single build+persist is set by
the producer, not the write path.

`AGENT_BOM_GRAPH_STORE_BACKED_BUILD` moves that materialization off the heap
when forced on, and — when unset — auto-enables once a cheap entity estimate of
the incoming report reaches `AGENT_BOM_GRAPH_STORE_BACKED_MIN_ENTITIES` (default
5000). Explicit `0/false/off` always wins. When enabled, `_persist_graph_snapshot`
builds the graph into a per-build `StoreBackedUnifiedGraph` (see ADR-adjacent
`src/agent_bom/graph/store_backed.py`) on a **throwaway private SQLite build
workspace** — never the shared Postgres workspace tables, so no cross-tenant
workspace data lives mid-build and the workspace-RLS question is moot. Phase-A
emission and every Phase-B overlay (cnapp / effective-permissions /
nhi-governance / attack-path-fusion / a2a-mcp / cost / aspm / runtime / repo) run
against the store **unchanged**; only a bounded LRU working set + one keyset page
live in RAM. The context manager drops the workspace after the build+persist,
even on exception. CLI / export builders that never pass a container stay
in-RAM; below-threshold API scans keep the byte-identical in-RAM producer. This
is a measured peak-RSS reduction (~2.5–3× lower producer peak, residual O(N)
floor ~0.37), not a claim of strict bounded memory — multi-million-node estates
still need a server-side backend. Large builds write O(graph) bytes to pod
ephemeral storage while the throwaway SQLite workspace is open.

Two overlays mutated a *held* node subset across passes (cnapp exposure marks;
effective-permissions admin-equivalence marks) — a pattern the store's
hand-out/write-back-on-eviction contract cannot serve once the held objects are
evicted. Both were made store-safe with a minimal, byte-identical change:
single-pass filtering (no full-node materialization) + re-resolving the node
through the graph immediately before the mutation. In-RAM this re-resolve returns
the same object, so the default path is unchanged.

**Realized reduction (measured, not projected).** The store-backed build removes
the dominant resident structures — the whole-node dict + adjacency /
reverse-adjacency + dedup indexes — so the producer's peak drops to a small
fraction of the in-RAM producer, and the advantage **widens with scale** (the
in-RAM peak grows strictly faster): store/in-RAM peak measured ≈0.72 at 3.6k
nodes → 0.52 at 7.2k → 0.44 at 14.4k → 0.39 at 28.8k, with in-RAM ≈2.45 KB/node
(flat) versus store falling 1.72→0.98 KB/node.

**Residual (honest boundary).** This is a large, measured reduction, **not** a
strict sub-linear bound: a residual O(N) term survives — Phase-A's in-pass
id-bookkeeping maps plus a few overlays' bounded node subsets stay resident — so
the ratio converges to a constant fraction (~0.37) rather than to zero. Removing
that residual (streaming Phase-A / two-pass overlays that never hold an O(N)
working set) is the remaining #4075 work. Until then, still steer
multi-million-node graphs to a server-side backend.

Guards: `tests/graph/test_store_backed_build_wiring.py` (builder-into-store
byte-identical + overlays store-safe under LRU eviction + producer-peak advantage
widens with scale + default-off unchanged) and
`tests/api/test_store_backed_build_persist.py` (persisted snapshot byte-identical
flag-on vs -off on both SQLite and live Postgres persist targets).
