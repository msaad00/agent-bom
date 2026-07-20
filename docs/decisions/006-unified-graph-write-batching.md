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

The remaining, un-bounded stage is the graph **producer**:
`build_unified_graph_from_report` still materializes the whole correlated
`UnifiedGraph` — nodes, edges, and its adjacency / reverse-adjacency / dedup
indexes, with correlation overlays that query the whole graph — in memory before
persist. So peak RSS for a single build+persist is set by the producer, not the
write path. Removing that wall (streaming/two-pass overlays that emit into the
storage-backed `GraphBuildWorkspace` instead of a resident graph) is the builder
re-plumb tracked by #4075; a generator wrapper around the existing builder does
not move peak RSS because the correlation phase already holds the whole graph.
Until then, steer multi-million-node graphs to a server-side backend.
