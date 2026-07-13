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

## Out of scope (later #3666 phases)

- Deleting soft-deprecated routes
- Findings-list contract unification
- List-envelope / pagination standardization
- Changing response shapes

## How to revisit

1. Confirm no external SDK / partner traffic for a soft-deprecated path (or
   publish a removal window in the CHANGELOG).
2. Remove the route + OpenAPI entry + RBAC row in one PR.
3. Drop the path from `SOFT_DEPRECATED_ORPHAN_PATHS` in the guard test.
