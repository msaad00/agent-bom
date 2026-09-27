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
| SAML | `Tenant ID` SAML attribute from the assertion (requires `pip install 'agent-bom[saml]'`) |
| Trusted proxy | `X-Agent-Bom-Tenant-ID` header — only honoured when `AGENT_BOM_TRUST_PROXY_AUTH_SECRET` matches |
| SCIM | `AGENT_BOM_SCIM_TENANT_ID` for the legacy single token, or `AGENT_BOM_SCIM_BEARER_TOKENS_JSON` for per-tenant bearer tokens (server-side, never from request payload) |

The middleware in `src/agent_bom/api/middleware.py` writes the resolved
value to `request.state.tenant_id` and to the Postgres session
(`SELECT set_config('app.tenant_id', ...)`) so RLS policies enforce the
boundary at the storage layer.

A missing OIDC tenant claim or SAML tenant attribute **fails closed by default**.
`AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1` and
`AGENT_BOM_SAML_ALLOW_DEFAULT_TENANT=1` are explicit single-tenant opt-ins.

After authentication establishes the tenant, middleware and RBAC dependencies
require a non-empty string. Missing, blank or non-string context returns HTTP 500
with `Authenticated tenant context is unavailable` before the request handler
or database read runs. Check the identity provider or stored key's tenant binding;
this error does not grant access to the `default` tenant. An explicitly resolved
`default` remains supported for single-tenant deployments and configured no-auth
mode.

Tenant-bound worker helpers apply the same validation before executing work or
submitting it to a pool. Invalid context raises `ValueError`; successful and failed
work restore the previous tenant context. Job producers must supply the tenant
established by their authentication or operator configuration boundary.

### API-key operation scopes and browser sessions

Use an administrative key with `auth:read` to inspect the enforced scope catalog:

```bash
curl --fail -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  "$AGENT_BOM_API_URL/v1/auth/scopes"
```

The JSON catalog lists each method, resource prefix, minimum role and required
scope. Grant the resource scopes needed by the integration, then verify its
first read or write with that key. For example, `scan:write` submits scans and
`scan:read` reads their results or SSE stream; `source:read` lists sources,
`source:write` manages them, and `runtime:read` opens proxy WebSocket streams.
The existing role and tenant checks also apply: a viewer with `fleet:write`
cannot perform an administrative fleet mutation.

Non-empty scope lists now fail closed with HTTP 403 on unrelated operations,
including operations that previously had only a role check. An unclassified
operation also returns 403 to a scoped key. Existing scoped integrations may
need additional explicit grants from the catalog. Empty scope lists retain the
legacy unrestricted-within-role contract, as does `*`; neither overrides role
or tenant restrictions. `GET /v1/auth/me` (and HEAD) is the exact self-identity
exception, available to authenticated callers without a resource scope.
HEAD uses GET policy. Only CORS preflight OPTIONS requests bypass authentication;
ordinary OPTIONS requests go through the credential and scope checks.

Key-backed browser cookies use the intersection of their signed grants and the
current key record. Downgrades and scope reductions take effect on the next
request; broadening a key does not broaden an existing cookie. Revoked, expired,
missing or foreign-tenant backing keys return 401. Disjoint session/key grants
return 403 rather than becoming unrestricted. The backing-key read runs under
the signed session tenant, including PostgreSQL RLS, and restores prior context.
Downstream handlers receive the effective role and intersected scopes, so key
delegation cannot use stale cookie privileges. Sign in again after an intentional
grant expansion.

Scan-progress and gateway-activity SSE streams, and proxy metrics/alerts
WebSockets, recheck their credentials every five seconds while active or idle.
The HTTP streams rerun the existing authentication and route policy against
fresh request state. A changed tenant, identity or role, revoked/expired key,
removed required scope, or failed revalidation terminates the stream. SSE emits
a `reconnect` event with reason `reauthenticate`; WebSockets close with code
4001. Clients must authenticate again before receiving further data. The
gateway's existing 30-second reconnect limit remains in place.

Authorization checks have a five-second timeout and fail closed on errors.
Data sends also time out after five seconds; stalled WebSocket consumers close
with code 1013 and SSE responses cancel their pending source read.
The five-second lease bounds cached authority; it does not retract previously
sent frames or cancel provider work already executing. Static deployment
configuration changes still require the owning server's normal reload/restart.

For upgrades, inspect the catalog and update narrowly scoped integration keys
before switching traffic. Rolling back restores the earlier scope gaps; prefer
correcting a missing explicit grant over reverting enforcement.

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

Remote MCP caller identity is separate from this process-bound tenant. Tool
dispatch reads the SDK-verified token on the current HTTP request for scopes,
rate-limit identity and the audit actor. Client metadata and tool arguments
cannot supply authority or override that actor. Transports without an HTTP
request use the SDK authentication context. Missing or expired verified grants
fail closed for write tools; local stdio reads retain the operator's OS boundary.

Saved scan results use the same current-request identity and a digest of the
token, rather than a client-provided name or a transport task's earlier token.
Unauthenticated HTTP callers cannot read saved results. Token rotation changes
result ownership, so clients must retain an unexpired original credential or
run a new scan. The server-bound tenant remains authoritative in both cases.
These changes require no storage migration. Reverting them restores the earlier
identity-resolution defects and is not an authorization rollback strategy.

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
  SAML-with-tenant-attribute, or RBAC API keys — never
  `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1` or
  `AGENT_BOM_SAML_ALLOW_DEFAULT_TENANT=1`.
- [ ] Postgres RLS policies enabled (`scripts/check_postgres_rls.py` or
  the integration tests in `tests/test_postgres_integration.py`).
