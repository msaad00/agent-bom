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
  window, not to graph size.
- **Positive:** The batching primitive is reusable outside graph persistence.
- **Trade-off:** One shared knob may not be optimal for every backend in every
  deployment. If benchmarks prove a backend-specific need, add optional
  backend-specific overrides while keeping `AGENT_BOM_GRAPH_WRITE_BATCH_SIZE`
  as the default.
- **Boundary:** This decision covers write-path batching only. Read-path
  windowing, streaming reads, materialized drilldowns, and UI virtualization are
  separate graph-scale concerns.
