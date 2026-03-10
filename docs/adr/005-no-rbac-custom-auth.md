# ADR-005: API auth without RBAC framework

## Status

Accepted

## Context

The agent-bom REST API (`/v1/*`) needs authentication and authorization.
Options considered:

1. **Full RBAC framework** — role-based access control with user/group/permission
   models, database-backed, like Django's auth or Casbin
2. **OIDC/JWT Bearer tokens** — leverage existing identity providers (Okta, Auth0,
   Azure AD) via standard OIDC token verification
3. **API key middleware** — simple `X-API-Key` header check, no external dependencies
4. **No auth** — rely on network-level security (VPN, private subnet)

## Decision

Implement a **layered auth approach** without an RBAC framework:

1. **API key middleware** (`api/server.py`) — `AGENT_BOM_API_KEY` env var, checked
   on every request via `APIKeyMiddleware`. Simple, stateless, no database.
2. **OIDC/JWT Bearer** (`api/oidc.py`) — optional upgrade path via
   `AGENT_BOM_OIDC_ISSUER` env var. Verifies RS256/ES256 JWTs against JWKS endpoint,
   maps claims to roles (`admin`, `viewer`). Requires `pip install agent-bom[oidc]`.
3. **JWKS proxy signature** (`proxy.py`) — runtime proxy verifies HMAC/RS256/ES256
   signatures on tool calls. JWKS endpoint with 1-hour cache, `none` algorithm rejected.

No user database. No permission tables. No RBAC models. Identity comes from the
token issuer, authorization comes from claims-to-role mapping.

## Consequences

### Positive

- No database dependency for auth — fully stateless, works in containers/serverless
- OIDC integration leverages enterprise identity providers users already have
- API key path is trivial to set up for single-user/CI scenarios
- JWKS verification is industry-standard (RFC 7517) with no custom crypto
- Claims-to-role mapping is configurable without code changes

### Negative

- No fine-grained permissions (can't restrict user A to read-only on specific scan types)
- No audit trail of who did what (beyond proxy JSONL logs)
- OIDC setup requires understanding JWT/JWKS concepts
- Two auth paths (API key vs OIDC) add complexity to middleware
