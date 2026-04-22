# Enterprise Auth and Tenant Isolation

This page is the operator-facing contract for how `agent-bom` handles:

- API keys
- OIDC
- SAML SSO
- trusted reverse-proxy identity
- RBAC
- tenant propagation
- tenant defaults and fail-closed behavior

The goal is simple: identity, authorization, and tenant scoping should all
resolve onto the same control-plane model.

## What is especially strong

- **Tenant context is not UI-only.**
  It propagates from the authenticated request into the control-plane stores and
  Postgres row-level security.
- **Audit is tenant-scoped and tamper-evident.**
  Audit entries are HMAC-chained per tenant and can be filtered/exported by
  tenant.
- **SAML and OIDC converge onto the same RBAC + tenant model.**
  SAML does not invent a second authorization path; it mints short-lived
  control-plane keys that the existing middleware already understands.
- **Operators can introspect live auth resolution.**
  `GET /v1/auth/debug` shows auth method, subject, role, tenant, and trace IDs
  without exposing raw secrets.

## What is not perfect

- **SAML is intentionally narrow.**
  It is an assertion-verification path that returns a short-lived API key. It is
  not a full browser session framework with logout/session federation depth.
- **OIDC is strongest on the control-plane API today.**
  Per-user OAuth2 auth-code / PKCE for laptop-to-gateway flows is still a later
  runtime surface.
- **Good enterprise posture still depends on good IdP mapping.**
  Claim naming, tenant binding, and deployment configuration matter almost as
  much as the code paths.

## Auth modes

| Mode | Best for | Tenant source | Role source | Notes |
|---|---|---|---|---|
| API key | machine-to-machine, automation, internal service accounts | key metadata | key metadata | hashed at rest; role hierarchy enforced in middleware |
| OIDC | browser/API users behind corporate IdP | JWT tenant claim or tenant-bound issuer | JWT role claim / groups | issuer + audience verified; tenant defaults fail closed by default |
| SAML | enterprises that need SAML IdP compatibility | SAML attribute | SAML attribute | assertion is verified, then converted into a short-lived API key |
| Trusted proxy | same-origin ingress or auth gateway in front of API | `X-Agent-Bom-Tenant-ID` | `X-Agent-Bom-Role` | only when `AGENT_BOM_TRUST_PROXY_AUTH=1` |

## RBAC model

`agent-bom` keeps the role model intentionally small:

- `admin`
- `analyst`
- `viewer`

The permission matrix lives in
[`src/agent_bom/rbac.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/rbac.py)
and the route minimum-role map lives in
[`src/agent_bom/api/middleware.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/api/middleware.py).

Operationally:

- `admin` can manage keys, policies, fleet writes, and configuration
- `analyst` can run scans, push observability/runtime data, and create
  exceptions
- `viewer` is read-only

## Tenant propagation

The current tenant boundary is enforced in three places:

1. **Request state**
   - the auth middleware resolves `request.state.tenant_id`
2. **Store calls**
   - control-plane routes pass the request tenant into store reads/writes
3. **Postgres session + RLS**
   - `app.tenant_id` is set on the Postgres session and RLS policies enforce
     the same boundary at the database layer

That means tenant scoping is not just a UI filter. It is part of the control
plane and persistence contract.

## OIDC claim-to-tenant mapping

The OIDC knobs are:

```bash
export AGENT_BOM_OIDC_ISSUER="https://idp.example.com"
export AGENT_BOM_OIDC_AUDIENCE="agent-bom"
export AGENT_BOM_OIDC_ROLE_CLAIM="agent_bom_role"
export AGENT_BOM_OIDC_TENANT_CLAIM="tenant_id"
```

How tenant resolution works:

1. if the configured tenant claim exists in the JWT, use it
2. if the issuer is configured as a tenant-bound provider, use the bound tenant
3. if `AGENT_BOM_OIDC_REQUIRE_TENANT_CLAIM=1`, fail closed
4. otherwise, fail closed unless `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1`
5. only with that explicit opt-in does the request resolve to `default`

So the safe/default behavior is now:

- **missing tenant claim = reject**

Single-tenant compatibility mode is explicit, not silent.

### Tenant-bound issuer mode

For stronger enterprise separation, bind one issuer per tenant:

```bash
export AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON='{
  "tenant-alpha": {
    "issuer": "https://alpha.okta.example",
    "audience": "agent-bom",
    "tenant_claim": "tenant_id",
    "require_tenant_claim": true
  },
  "tenant-beta": {
    "issuer": "https://beta.okta.example",
    "audience": "agent-bom",
    "tenant_claim": "tenant_id",
    "require_tenant_claim": true
  }
}'
```

This mode gives you two protections:

- a token from the wrong issuer is rejected
- a token whose tenant claim does not match the bound tenant is rejected

## SAML mapping

SAML configuration is driven by:

- `AGENT_BOM_SAML_IDP_ENTITY_ID`
- `AGENT_BOM_SAML_IDP_SSO_URL`
- `AGENT_BOM_SAML_IDP_X509_CERT`
- `AGENT_BOM_SAML_SP_ENTITY_ID`
- `AGENT_BOM_SAML_SP_ACS_URL`
- `AGENT_BOM_SAML_ROLE_ATTRIBUTE`
- `AGENT_BOM_SAML_TENANT_ATTRIBUTE`

Recommended production posture:

- set `AGENT_BOM_SAML_REQUIRE_ROLE_ATTRIBUTE=1`
- set `AGENT_BOM_SAML_REQUIRE_TENANT_ATTRIBUTE=1`

That keeps SAML fail-closed in the same way OIDC is now fail-closed for tenant
resolution.

## API keys and rotation

API keys remain the best fit for:

- automation
- internal services
- gateway/control-plane machine-to-machine traffic

The control plane supports:

- tenant-scoped keys
- role-scoped keys
- enforced TTL policy
- rotation in place
- revoke/delete flows

Key rotation endpoints and policy introspection:

- `GET /v1/auth/policy`
- `GET /v1/auth/keys`
- `POST /v1/auth/keys`
- `POST /v1/auth/keys/{key_id}/rotate`
- `DELETE /v1/auth/keys/{key_id}`

## Operator debugging

Use:

```bash
curl -s https://agent-bom.example.com/v1/auth/debug \
  -H "Authorization: Bearer $TOKEN"
```

This returns:

- `auth_method`
- `subject`
- `role`
- `tenant_id`
- `oidc_issuer_suffix`
- `request_id`
- `trace_id`
- `span_id`

That endpoint is the fastest way to answer:

- why did this request get `403`
- which auth path was used
- which tenant was actually resolved
- whether the wrong issuer or tenant mapping was applied

## Recommended deployment posture

For enterprise control-plane users:

- prefer **OIDC** or **SAML**
- keep MFA at the IdP
- require explicit tenant claims or tenant-bound issuers

For machine-to-machine paths:

- use **tenant-scoped API keys**
- keep TTLs finite
- rotate under the published policy

For same-origin enterprise ingress:

- use **trusted proxy mode** only when your reverse proxy is already enforcing
  user identity and tenant headers

## Evidence and tests

- OIDC implementation:
  [`src/agent_bom/api/oidc.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/api/oidc.py)
- SAML implementation:
  [`src/agent_bom/api/saml.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/api/saml.py)
- auth middleware:
  [`src/agent_bom/api/middleware.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/api/middleware.py)
- RBAC:
  [`src/agent_bom/rbac.py`](https://github.com/msaad00/agent-bom/blob/main/src/agent_bom/rbac.py)
- auth/tenant tests:
  [`tests/test_api_oidc.py`](https://github.com/msaad00/agent-bom/blob/main/tests/test_api_oidc.py),
  [`tests/test_api_hardening.py`](https://github.com/msaad00/agent-bom/blob/main/tests/test_api_hardening.py),
  [`tests/test_api_cross_tenant_matrix.py`](https://github.com/msaad00/agent-bom/blob/main/tests/test_api_cross_tenant_matrix.py)
