# API orphan routes audit (#3666 Phase 2)

**Status:** soft-deprecation landed for confirmed product orphans; routes remain
callable (non-breaking). Deletion is deferred to a later Phase after a
deprecation window.

This audit covers the ten routes flagged in [#3666](https://github.com/msaad00/agent-bom/issues/3666)
item 4 (no UI / CLI / MCP / hand-doc product consumer). Evidence was gathered
by searching `ui/`, `src/agent_bom/cli/`, `src/agent_bom/mcp_tools/`,
`src/agent_bom/mcp_server.py`, `sdks/`, and `site-docs/` for path string
literals. API unit/demo tests that hit a route directly do **not** count as
product consumers.

## Decision matrix

| Route | Method | Disposition | Consumer evidence | Notes |
|---|---|---|---|---|
| `/v1/agents/mesh` | GET | **soft-deprecate** | No UI/CLI/MCP literals | Mesh topology for React Flow; demo bootstrap still exercises it |
| `/v1/graph/legend` | GET | **soft-deprecate** | No UI/CLI/MCP literals | Legend is unused by current graph UI |
| `/v1/cortex/telemetry` | GET | **soft-deprecate** | No UI/CLI/MCP literals | Snowflake Cortex aggregate; sibling per-agent route kept |
| `/v1/posture/backpressure` | GET | **soft-deprecate** | No UI/CLI/MCP literals | Operator backpressure snapshot; no dashboard/CLI surface |
| `/v1/estate/correlations` | GET | **soft-deprecate** | No UI/CLI/MCP literals | Local↔cloud correlation; API tests only |
| `/v1/cis/trends` | GET | **soft-deprecate** | No UI/CLI/MCP literals | CIS time-bucket trends; analytics tests only |
| `/v1/credentials/posture` | GET | **soft-deprecate** | No UI/CLI/MCP literals | Credential rotation rollup; sources API tests only |
| `/v1/auth/saml/relay-state` | POST | **keep** | Auth protocol path (middleware allowlist + SAML login flow) | Not a product orphan; required for SP-initiated SAML |
| `/v1/graph/presets` (+ `/{name}`) | POST/GET/DELETE | **hold** | No UI/CLI/MCP literals today | Defer product call until after graph work (#3664) |
| `/v1/graph/nhi/governance` | GET | **hold** | Demo estate bootstrap hits it; no UI/CLI/MCP | Defer product call until after graph work (#3664) |

## Soft-deprecation mechanics

- FastAPI route decorators set `deprecated=True`, which OpenAPI exports as
  `deprecated: true` on the operation.
- Routes stay registered and auth/RBAC unchanged — wire shape is untouched.
- Guard test: `tests/test_api_orphan_route_guard.py` fails if UI / CLI / MCP
  (or the MCP server entrypoint) reintroduce string literals for soft-deprecated
  paths, and asserts OpenAPI marks those operations deprecated while leaving
  SAML relay-state and held graph routes unmarked.

## Findings-list contract (item 1) — landed

Every finding-list surface now returns one canonical envelope, built by
`agent_bom.api.finding_list_envelope.finding_list_envelope()`
(`FINDING_LIST_ENVELOPE_KEYS` pins the key set; the UI mirror is
`FindingListEnvelope<T>` in `ui/lib/api-types.ts`):

```
{schema_version, findings, count, total, limit, offset, sort, scan_id,
 cursor, next_cursor, has_more, warnings, [total_approximate]}
```

| Route | Pagination | Notes |
|---|---|---|
| `GET /v1/findings` | keyset `cursor`/`next_cursor` (never OFFSET at scale) + `limit`/`offset` | Reference contract; default sort `effective_reach`. |
| `GET /v1/compliance/hub/findings` | `limit`/`offset`, ingest-order (`sort="ordinal"`) | External ingests + native scan projection. Scale keyset reads over the same durable store are available via `/v1/findings?cursor=`. |
| `GET /v1/governance/findings` | `limit`/`offset` over the materialized list (`cursor` stays empty) | Computed on demand from Snowflake; no keyset store to walk. |

Change is **additive** — legacy fields and legacy pagination are preserved
(`test_sqlite_backend_preserves_ingest_order` stays green; governance filters
unchanged). The three routes serve distinct data sources (scan+bulk / hub
external+native / Snowflake governance), so none is a duplicate/alias of
another — envelope unification, not route removal, is the consolidation.
Guarded by `tests/api/test_findings_contract_envelope.py`.

## Out of scope (later #3666 phases)

- Deleting soft-deprecated routes
- Hub-findings **keyset over ingest order** — needs an `ordinal`-keyset store
  fix (SQLite `ORDER BY ledger_ordinal` does not line up with the
  `(last_seen, canonical_id)` cursor predicate); ingest-order paging stays on
  `limit`/`offset` until then.
- Namespacing filtered views under `/v1/findings/...` (versioned migration)
- Changing response shapes on non-findings list surfaces

## How to revisit

1. Confirm no external SDK / partner traffic for a soft-deprecated path (or
   publish a removal window in the CHANGELOG).
2. Remove the route + OpenAPI entry + RBAC row in one PR.
3. Drop the path from `SOFT_DEPRECATED_ORPHAN_PATHS` in the guard test.
