# Enterprise Controls Map

This page maps enterprise-facing `agent-bom` claims to the code that implements them.

It exists for a simple reason: the controls are real, but they should not require a repo archeology session to verify.

## What Is True Today

`agent-bom` is production-ready OSS and enterprise-adaptable. The current enterprise control plane is built around:

- API key auth with ordered RBAC route rules
- optional OIDC bearer auth with fail-closed tenant claims
- dedicated SCIM user/group provisioning for enterprise IdPs
- PostgreSQL-backed multi-tenant stores with row-level security
- HMAC-chained audit logging
- request tracing and `/health` observability contracts
- explicit storage/backend behavior for Postgres, Supabase, Snowflake, and ClickHouse

## Claim To Code Map

| Claim | What it means | Code |
|---|---|---|
| API key auth + RBAC | API keys carry `admin` / `analyst` / `viewer` roles and are checked per route prefix | `src/agent_bom/api/auth.py`, `src/agent_bom/api/middleware.py` |
| OIDC / SSO | Any standard OIDC provider can issue bearer tokens for API access | `src/agent_bom/api/oidc.py`, `src/agent_bom/api/middleware.py` |
| Fail-closed tenant claims | Missing tenant claims now fail closed by default; `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1` is the explicit single-tenant compatibility override | `src/agent_bom/api/oidc.py` |
| SCIM lifecycle provisioning | IdPs can create, list, patch, deactivate, and group users through a dedicated SCIM bearer surface | `src/agent_bom/api/routes/scim.py`, `src/agent_bom/api/scim_store.py`, `src/agent_bom/api/postgres_scim.py` |
| Postgres tenant isolation | The authenticated tenant is pushed into the DB session as `app.tenant_id` before request handling | `src/agent_bom/api/middleware.py`, `src/agent_bom/api/postgres_store.py` |
| PostgreSQL row-level security | Tenant-bearing tables have RLS policies keyed off the current tenant | `deploy/supabase/postgres/init.sql`, `src/agent_bom/api/postgres_store.py` |
| API keys persisted in Postgres | Keys move from in-memory to transactional storage when `AGENT_BOM_POSTGRES_URL` is set | `src/agent_bom/api/server.py`, `src/agent_bom/api/postgres_store.py`, `src/agent_bom/api/auth.py` |
| Exceptions and false positives persisted in Postgres | Exception workflow uses a tenant-aware Postgres store when configured | `src/agent_bom/api/server.py`, `src/agent_bom/api/postgres_store.py`, `src/agent_bom/api/routes/enterprise.py` |
| Audit log integrity | Audit entries are chain-signed with HMAC and can be verified via API | `src/agent_bom/api/audit_log.py`, `src/agent_bom/api/routes/enterprise.py` |
| Rate limiting | Read and scan endpoints have separate request budgets with shared Postgres-backed storage when configured | `src/agent_bom/api/middleware.py`, `src/agent_bom/api/postgres_store.py` |
| Request tracing | API preserves W3C trace context and exposes tracing state on `/health` | `src/agent_bom/api/tracing.py`, `src/agent_bom/api/middleware.py`, `src/agent_bom/api/server.py` |
| ClickHouse analytics backend | Server mode can buffer analytics writes and report backend state on `/health` | `src/agent_bom/api/server.py`, `src/agent_bom/api/clickhouse_store.py` |
| Snowflake backend | Snowflake has native stores for selected enterprise data paths, not full transactional parity | `src/agent_bom/api/server.py`, `src/agent_bom/api/snowflake_store.py` |

## RBAC Matrix

The API middleware uses ordered route rules. Narrower enterprise routes win over broad prefixes.

| Method | Route prefix | Minimum role |
|---|---|---|
| `GET` | `/v1/auth/keys` | `admin` |
| `GET` | `/scim/v2` | `admin` |
| `POST` | `/scim/v2` | `admin` |
| `PATCH` | `/scim/v2` | `admin` |
| `DELETE` | `/scim/v2` | `admin` |
| `POST` | `/v1/auth/keys` | `admin` |
| `POST` | `/v1/auth/keys/` | `admin` |
| `DELETE` | `/v1/auth/keys/` | `admin` |
| `POST` | `/v1/gateway/policies` | `admin` |
| `PUT` | `/v1/gateway/policies/` | `admin` |
| `DELETE` | `/v1/gateway/policies/` | `admin` |
| `POST` | `/v1/fleet/sync` | `admin` |
| `PUT` | `/v1/fleet/` | `admin` |
| `PUT` | `/v1/exceptions/` | `admin` |
| `DELETE` | `/v1/exceptions/` | `admin` |
| `POST` | `/v1/siem/test` | `admin` |
| `POST` | `/v1/shield/start` | `admin` |
| `POST` | `/v1/shield/unblock` | `admin` |
| `POST` | `/v1/shield/break-glass` | `admin` |
| `DELETE` | `/v1/scan/` | `admin` |
| `POST` | `/v1/exceptions` | `analyst` |
| `POST` | `/v1/findings/jira` | `analyst` |
| `POST` | `/v1/findings/false-positive` | `analyst` |
| `DELETE` | `/v1/findings/false-positive/` | `analyst` |
| `POST` | `/v1/scan` | `analyst` |
| `POST` | `/v1/gateway/evaluate` | `analyst` |
| `POST` | `/v1/traces` | `analyst` |
| `POST` | `/v1/results/push` | `analyst` |
| `POST` | `/v1/schedules` | `analyst` |
| `DELETE` | `/v1/schedules/` | `analyst` |
| `PUT` | `/v1/schedules/` | `analyst` |
| any unmatched route | everything else | `viewer` |

Implementation source: `src/agent_bom/api/middleware.py`

## Authentication Contract

`agent-bom api` and `agent-bom serve` support four runtime postures:

1. Loopback development
   - localhost binds are allowed without remote auth
2. API key enforcement
   - non-loopback binds require `AGENT_BOM_API_KEY` or stored API keys
   - set `AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS` and `AGENT_BOM_API_KEY_MAX_TTL_SECONDS`
     to enforce rotation windows on stored keys
   - rotate stored keys with `POST /v1/auth/keys/{key_id}/rotate`
3. OIDC bearer enforcement
   - set `AGENT_BOM_OIDC_ISSUER`, or use `AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON` for tenant-bound issuers
   - set `AGENT_BOM_OIDC_AUDIENCE`
   - map roles with `AGENT_BOM_OIDC_ROLE_CLAIM`
   - map tenants with `AGENT_BOM_OIDC_TENANT_CLAIM`
   - missing tenant claims fail closed by default
   - opt into single-tenant default mode only with `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1`
   - optionally set `AGENT_BOM_OIDC_REQUIRED_NONCE` when your IdP flow includes a nonce claim
4. SCIM lifecycle provisioning
   - set `AGENT_BOM_SCIM_BEARER_TOKEN` to enable `/scim/v2/Users`, `/scim/v2/Groups`, and `/scim/v2/ServiceProviderConfig`
   - set `AGENT_BOM_SCIM_TENANT_ID` to bind all inbound SCIM lifecycle writes to one tenant; tenant IDs supplied by the IdP payload are ignored
   - set `AGENT_BOM_SCIM_BASE_PATH` before API startup if your IdP requires a different SCIM path
   - use PostgreSQL or Supabase for clustered, multi-node, or EKS deployments; SQLite is only for single-node pilots
   - SCIM traffic uses the dedicated SCIM bearer token only and does not accept dashboard sessions or general API keys

Rate limiting also follows an explicit fail-closed contract for scaled control planes:

- single-process / single-replica API: in-memory limiter is allowed
- multi-replica API or `AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT=1`: PostgreSQL-backed shared limiter is required
- if shared rate limiting is required and `AGENT_BOM_POSTGRES_URL` is absent or broken, API startup now fails instead of silently falling back to process-local state

Implementation source: `src/agent_bom/api/middleware.py`, `src/agent_bom/api/oidc.py`

## Storage Compatibility

`agent-bom` uses different backends for different jobs. The short version is:

| Backend | Status | Best fit |
|---|---|---|
| PostgreSQL | Full transactional control-plane backend | team and enterprise API deployments |
| Supabase | Full transactional control-plane backend because it is PostgreSQL | managed Postgres deployments |
| SQLite | single-node / local persistence | local or small deployments; not for clustered SCIM identity state |
| ClickHouse | analytics backend | high-volume scan and posture analytics |
| Snowflake | selected enterprise stores, not full transactional parity | governance / warehouse-native environments |

Today, if you want the broadest transactional feature coverage, use PostgreSQL or Supabase.

For the explicit capability matrix and supported Snowflake deployment modes, see:

- `site-docs/deployment/backend-parity.md`
- `docs/ENTERPRISE_DEPLOYMENT.md`

## Multi-Tenant Reference Architecture

```mermaid
flowchart LR
    EP[Endpoints / CI / Repos] --> CLI[CLI / Action / Docker]
    EP --> API[agent-bom API / serve]
    CLI --> API
    API --> AUTH[API key auth / OIDC]
    AUTH --> MW[Middleware\nRBAC + rate limit + trace context]
    MW --> PG[(PostgreSQL / Supabase\ntransactional control plane)]
    MW --> CH[(ClickHouse\nanalytics)]
    MW --> SF[(Snowflake\npartial parity)]
    MW --> AUDIT[HMAC audit log]
    MW --> OBS[/health + /metrics + OTLP]

    PG --> RLS[RLS via app.tenant_id]
    API --> UI[Dashboard / JSON / MCP / reports]
```

## Related Docs

- `docs/ENTERPRISE_DEPLOYMENT.md`
- `docs/CONTROL_PLANE_TESTING.md`
- `docs/RUNTIME_MONITORING.md`
- `docs/PERMISSIONS.md`
- `docs/SECURITY_ARCHITECTURE.md`
- `docs/THREAT_MODEL.md`
- `docs/adr/005-no-rbac-custom-auth.md`
