# ADR-008: Pluggable Neptune Graph Backend

**Status:** Proposed
**Date:** 2026-05-13

## Context

The self-hosted control plane currently persists graph snapshots through
`GraphStoreProtocol` with SQLite as the local default and Postgres as the
multi-tenant control-plane backend. That contract already covers snapshot
writes, search, pagination, node context, bounded traversal, attack paths,
diffs, compliance summaries, saved filters, and tenant deletion.

Enterprise graph platforms such as Amazon Neptune solve a different scale
problem: long-lived relationship stores with graph-native traversal and
managed operational scaling. Adding that lane should not make Neptune a
required dependency, weaken the Postgres default, or turn roadmap positioning
into a shipped-product claim.

## Decision

Keep SQLite and Postgres as the shipped defaults. Add Neptune as an optional
enterprise graph-store backend only after the adapter can satisfy the same
`GraphStoreProtocol` contract or explicitly decline unsupported operations with
typed, fail-closed errors.

The Neptune lane maps the API graph store contract, not the analysis-only
`GraphBackend` contract in `src/agent_bom/graph_backend.py`. `GraphBackend`
supports local analytics such as centrality and shortest paths; it is not the
API persistence boundary.

The adapter design is:

- **Configuration:** opt in with a backend selector such as
  `AGENT_BOM_GRAPH_BACKEND=neptune` plus endpoint, AWS auth mode, region, TLS,
  and optional IAM role settings. Missing config must fail startup for the
  Neptune backend rather than falling back silently to another tenant's store.
- **Dependency boundary:** keep AWS/Gremlin dependencies in an optional extra.
  Base installs, CLI scans, SQLite, and Postgres deployments must not import
  those packages at module import time.
- **Tenant isolation:** every vertex and edge carries `tenant_id`; every query
  includes the tenant predicate; cross-tenant traversals are not supported.
  IAM/network isolation is defense in depth, not a substitute for tenant
  predicates.
- **Snapshot model:** preserve `scan_id` as the immutable snapshot key.
  Vertices and edges are versioned by `(tenant_id, scan_id, id)` or
  `(tenant_id, scan_id, source, target, relationship)`. Temporal edge fields
  remain attributes on relationships.
- **Query language:** implement through Gremlin or Neptune openCypher behind
  repository methods. Do not expose arbitrary graph queries through the public
  API until auth, tenant scoping, audit, and query budgets are designed.
- **Audit posture:** backend selection, connection failures, query timeouts,
  and tenant deletes emit normal API audit events. The adapter must never log
  credentials, raw SigV4 material, or full customer graph payloads.
- **Failure modes:** unsupported operations return deterministic 501-style
  adapter errors through the API layer; transient Neptune errors map to 503;
  tenant delete failures are fail-closed and require operator retry.

## Operation Mapping

| `GraphStoreProtocol` operation | Neptune strategy | Initial support |
|---|---|---|
| `save_graph` | batch upsert vertices/edges by tenant and scan | required |
| `latest_snapshot_id`, `previous_snapshot_id`, `list_snapshots` | snapshot metadata vertices or side table | required |
| `page_nodes`, `nodes_by_ids` | tenant + scan filtered vertex queries | required |
| `edges_for_node_ids`, `node_context` | bounded incident-edge traversal | required |
| `search_nodes` | start with exact/contains properties; add OpenSearch only as a separate design | required, may be slower |
| `attack_paths`, `attack_paths_for_sources` | materialized path vertices/edges, not ad hoc deep traversal | required |
| `traverse_subgraph`, `bfs_paths`, `impact_of` | graph-native bounded traversal with max node/edge/deadline budgets | required |
| `diff_snapshots`, temporal edge queries | scan-scoped compare queries over versioned relationships | required |
| `compliance_summary` | aggregate vertex properties by framework prefix | required |
| presets | keep in Postgres/API store unless a graph-only deployment exists | optional |
| `delete_tenant` | delete all tenant-scoped graph objects with audited count | required |

## Migration Strategy

1. Add a `NeptuneGraphStore` skeleton behind an optional import boundary and
   feature flag.
2. Add mocked adapter contract tests that exercise the full
   `GraphStoreProtocol` surface without requiring AWS.
3. Add a local serializer that exports a `UnifiedGraph` into the exact
   vertex/edge/property mutations the adapter will submit.
4. Add an integration smoke that runs only when Neptune endpoint credentials
   are present.
5. Document first command, credential boundary, produced artifact, and rollback
   path before advertising the backend as available.

## Consequences

- **Positive:** The product can pursue Neptune-grade scale without rewriting the
  API or UI surfaces.
- **Positive:** The self-hosted Postgres path remains the default and stays
  honest for most deployments.
- **Positive:** Tenant, audit, and failure behavior are defined before any AWS
  dependency enters the runtime.
- **Trade-off:** The first Neptune milestone is a design and contract milestone,
  not a shipped managed graph backend.
- **Trade-off:** Search may need a separate indexed text service at very large
  scale; that is outside the first adapter.
- **Boundary:** This ADR does not add Neptune code, Gremlin/openCypher public
  query endpoints, WebGL rendering, or production latency claims.
