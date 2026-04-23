# UI, API, Auth, and Session Model

This page defines the control-plane trust model for `agent-bom`.

The short version:

- the **UI handles operator experience**
- the **API handles identity, authorization, tenancy, and audit**
- the browser is never the authorization source of truth

That split is what keeps the product usable without weakening the trust
boundary.

## Control-plane trust rule

For browser-driven workflows:

1. the user authenticates to the control plane
2. the API resolves identity, role, and tenant
3. the UI renders the allowed experience
4. every write or privileged read is re-authorized by the API
5. audit records the actor, tenant, request, and outcome

The UI can hide or disable actions for clarity, but the API must still reject
unauthorized requests with `401` or `403`.

## What the UI is allowed to do

The Node.js UI is the operator surface. It can:

- trigger scans and schedules
- review findings, graph, posture, fleet, and audit
- manage keys, policies, exceptions, and gateway settings when the actor has the right role
- surface health, auth mode, tenant scope, and runtime status

It does **not**:

- decide who the user is
- decide which tenant a request belongs to
- decide whether a protected action is allowed
- perform privileged collection directly from the browser

## What the API must own

The API/control plane is the trust anchor for:

- authentication
- tenant resolution
- RBAC
- request tracing
- audit
- persistence

In code, that boundary lives primarily in:

- [`src/agent_bom/api/middleware.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/api/middleware.py)
- [`src/agent_bom/api/routes/enterprise.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/api/routes/enterprise.py)
- [`src/agent_bom/api/oidc.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/api/oidc.py)
- [`src/agent_bom/api/saml.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/api/saml.py)
- [`src/agent_bom/rbac.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/rbac.py)

## Supported browser-facing auth modes today

These are the code-backed control-plane access modes today.

| Mode | Best fit | Where identity is established | Browser experience |
|---|---|---|---|
| **Trusted reverse proxy** | enterprise same-origin ingress | reverse proxy authenticates user, injects trusted `X-Agent-Bom-*` headers | best current operator UX |
| **OIDC bearer** | direct API/browser integration with corporate IdP | API verifies JWT issuer, audience, role, and tenant claim | secure, but more operator wiring |
| **SAML -> short-lived API key** | SAML-only environments | SAML assertion is verified, then converted into a short-lived control-plane key | workable, but not a full browser session framework |
| **Session-only API key fallback** | local single-user or pilot setups | browser stores an API key in `sessionStorage`, API verifies it on every request | convenience mode, not the preferred enterprise path |

The current UI auth helper lives in:

- [`ui/lib/auth.ts`](https://github.com/msaad00/agent-bom/blob/main/ui/lib/auth.ts)

That fallback is intentionally narrow:

- it uses `sessionStorage`
- it does not make the browser a trust anchor
- the API still verifies the key and role on every request

## Recommended self-hosted browser path

For the cleanest enterprise deployment, use:

- same-origin UI + API behind one ingress
- OIDC enforced at the reverse proxy or ingress tier
- trusted identity headers passed to the API only from that proxy
- backend RBAC and tenant enforcement on every route

That maps to the current runtime status surfaced by:

- `GET /v1/auth/policy`
- `GET /v1/auth/debug`

The current auth-policy endpoint already tells operators which UI mode is
recommended:

- `reverse_proxy_oidc`
- `oidc_bearer`
- `session_api_key`

## Request flow

### 1. Authenticate

The browser reaches the same-origin UI/API endpoint over TLS.

Depending on deployment mode:

- the reverse proxy authenticates the user and injects trusted headers
- or the browser sends a bearer token
- or the browser sends a session-only API key

### 2. Resolve identity and tenant

The API middleware resolves:

- `auth_method`
- `subject`
- `role`
- `tenant_id`
- request and trace identifiers

The important rule is:

> the server resolves `tenant_id`; the browser does not get to choose it

### 3. Authorize

The API applies route-level minimum roles in middleware.

Current examples:

- key management requires `admin`
- scan creation requires `analyst`
- most read-only posture/compliance surfaces allow `viewer`

If the actor is authenticated but lacks the required role:

- the API returns `403`

If the request is unauthenticated:

- the API returns `401`

### 4. Render operator state

The UI should use backend-provided auth/runtime state to drive experience:

- current auth mode
- resolved tenant
- role
- allowed actions
- current runtime policy mode

The browser may render a softer UX:

- hide unavailable actions
- disable buttons
- explain why an action is blocked

But that is convenience only. The API remains authoritative.

### 5. Audit and trace

Every request should be attributable through:

- `X-Request-ID`
- `X-Trace-ID`
- `X-Span-ID`
- actor identity
- tenant identity
- route/action
- allow/deny result

Those headers and trace fields are already set by the API middleware.

## Request integrity and session safety

What gives the control plane its actual request trust today:

- TLS
- same-origin deployment where practical
- backend token or header verification
- server-side RBAC
- tenant propagation into stores and Postgres RLS
- HMAC-chained audit records

Current response hardening already includes:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Cache-Control: no-store`

### About browser sessions

Today, `agent-bom` supports a practical pilot-friendly browser fallback:

- session-only API key storage in the browser

That is useful for:

- local single-user control plane access
- pilot demos
- operator debugging

It is **not** the highest-trust enterprise session model.

For a more seamless hosted or enterprise browser path, the stronger design is:

- `HttpOnly`, `Secure`, `SameSite` session cookies
- same-origin API requests
- CSRF protection on state-changing requests
- short-lived sessions with rotation and revocation

That is the right next-step browser-session design if `agent-bom` grows further
into a managed control plane. It does not replace backend RBAC; it just makes
the browser session safer and smoother.

## Attribution, audit, and non-repudiation

The honest current posture is:

- **strong attribution and tamper-evident audit today**
- **stronger cryptographic approval and non-repudiation later**

`agent-bom` already gives operators a strong security and compliance trail for
control-plane actions, but it does not overclaim legal-grade or cryptographic
non-repudiation for every browser click today.

What is real now:

- actor attribution
- tenant attribution
- request and trace identifiers
- role-aware action logging
- HMAC-chained audit records
- tenant-scoped audit filtering and export

That is strong enough for:

- incident review
- compliance evidence
- operator debugging
- tenant-scoped accountability in self-hosted deployments

What it is **not** yet:

- per-action user signatures
- signed human approval workflows for sensitive actions
- WebAuthn-backed step-up confirmation for destructive operations
- tenant-specific signing keys for every control-plane action or export

What would make this stronger later:

- WebAuthn or MFA step-up for sensitive actions
- signed approval workflows
- tenant-specific signing keys for exports
- immutable external audit sinks

So the simple product claim should stay:

> `agent-bom` has strong attribution and tamper-evident audit today. Stronger
> signed approvals and browser-grade non-repudiation are future hardening, not
> something the product overclaims now.

## UI and API checklist

If the control plane is behaving correctly, the UI should be able to answer:

- who am I authenticated as
- which tenant am I acting in
- what role do I currently have
- why is this action allowed or blocked
- what request or trace ID corresponds to the action I just took

And the API should be able to enforce:

- this actor belongs to this tenant
- this route requires this role
- this request is traceable and auditable
- this browser request never overrides tenant scope manually

## Short design rule

Use this rule when evaluating new UI work:

> The UI may decide how to present an action, but only the API may decide
> whether the action is authenticated, tenant-scoped, authorized, and auditable.

## Related docs

- [Self-Hosted Product Architecture](self-hosted-product-architecture.md)
- [Hosted Product Control Plane](hosted-product-spec.md)
- [Enterprise Auth and Tenant Isolation](../deployment/enterprise-auth-and-tenancy.md)
