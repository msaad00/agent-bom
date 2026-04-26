# Tenant resolution across HTTP / CLI / MCP surfaces

> Closes #1964. The single contract for "who is the caller?" across every
> entry point that can write tenant-scoped data.

agent-bom exposes three call surfaces — the FastAPI control plane, the
`agent-bom` CLI, and the MCP server — and each derives `tenant_id`
differently because each has a different authentication shape.

## HTTP control plane

Source of truth: authenticated identity at the request boundary.

| Auth mode | Where `tenant_id` comes from |
|---|---|
| API key (RBAC) | `KeyStore.verify(raw_key).tenant_id` — bound at key-create time |
| OIDC bearer | `AGENT_BOM_OIDC_TENANT_CLAIM` (default `tenant_id`) extracted from the JWT |
| OIDC tenant providers | The matching tenant from `AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON` issuer match |
| SAML | `Tenant ID` SAML attribute from the assertion |
| Trusted proxy | `X-Agent-Bom-Tenant-ID` header — only honoured when `AGENT_BOM_TRUST_PROXY_AUTH_SECRET` matches |
| SCIM | `AGENT_BOM_SCIM_TENANT_ID` (server-side, never from request payload) |

The middleware in `src/agent_bom/api/middleware.py` writes the resolved
value to `request.state.tenant_id` and to the Postgres session
(`SELECT set_config('app.tenant_id', ...)`) so RLS policies enforce the
boundary at the storage layer.

A missing tenant claim **fails closed by default** —
`AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1` is the explicit single-tenant
opt-in.

## CLI

The CLI runs out-of-band; there is no authenticated request to derive
identity from. Source of truth: operator intent, expressed via flag or env.

Resolution order (single sanctioned reader:
`src/agent_bom/cli/_tenant.py::resolve_cli_tenant_id`):

1. Explicit `--tenant TENANT` argument (wins).
2. `AGENT_BOM_TENANT_ID` env var.
3. Literal `"default"`.

When step 3 fires AND the deployment looks multi-tenant
(`AGENT_BOM_REQUIRE_TENANT_BOUNDARY=1` or
`AGENT_BOM_CONTROL_PLANE_REPLICAS > 1`), `resolve_cli_tenant_id` logs an
operator-visible warning so the silent default shows up in the build log.

Use `resolve_cli_tenant_id_strict()` on write paths where a silent
default would mean cross-tenant data contamination — it raises
`RuntimeError` instead of warning.

A static guardrail in `tests/test_cli_mcp_tenant_resolution.py` scans
`src/agent_bom/cli/` for any ad-hoc `os.environ.get("AGENT_BOM_TENANT_ID")`
call outside the central module and fails CI if a new one appears.

## MCP server

The MCP server is invoked by an MCP host (Claude Desktop, Cursor, Codex…)
that does not pass an authenticated tenant. The operator who launches
`agent-bom mcp server` decides which tenant context the tools execute
under.

Resolution order (single sanctioned reader:
`src/agent_bom/mcp_tenant.py::resolve_mcp_tenant_id`):

1. `AGENT_BOM_MCP_TENANT_ID` env var (MCP-specific override).
2. `AGENT_BOM_TENANT_ID` env var (shared with the CLI).
3. Literal `"default"`.

When step 3 fires under multi-tenant signals, `resolve_mcp_tenant_id`
logs a warning. The same static guardrail in
`tests/test_cli_mcp_tenant_resolution.py` covers `src/agent_bom/mcp_*.py`
and `src/agent_bom/mcp_tools/`.

## Why not push tenant context through MCP request headers?

MCP tool calls in the current MCP spec do not carry a tenant
identifier — they're invoked by the local MCP host on behalf of a single
user. Adding a "tenant" argument to every tool would put trust in the
MCP host (Claude Desktop, Cursor) to pass it correctly, which is the
wrong trust boundary for a security scanner. Operator-bound
`AGENT_BOM_MCP_TENANT_ID` keeps the trust at the process boundary
where it belongs.

## Multi-tenant readiness checklist

For an operator deploying `agent-bom` for more than one tenant:

- [ ] `AGENT_BOM_REQUIRE_TENANT_BOUNDARY=1` exported in every CLI and
  MCP launcher script.
- [ ] `AGENT_BOM_TENANT_ID` (and `AGENT_BOM_MCP_TENANT_ID` if running a
  per-tenant MCP server) set per environment.
- [ ] CLI write commands wrapped to call `resolve_cli_tenant_id_strict`
  via the central helper (see `cli/agents/_post.py`).
- [ ] HTTP control plane configured with one of OIDC-with-tenant-claim,
  SAML, or RBAC API keys — never `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1`.
- [ ] Postgres RLS policies enabled (`scripts/check_postgres_rls.py` or
  the integration tests in `tests/test_postgres_integration.py`).
