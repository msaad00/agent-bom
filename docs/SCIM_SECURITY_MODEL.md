# SCIM Security Model

SCIM in agent-bom is a lifecycle and role-provisioning integration. It is not a
tenant authority by itself.

## Tenant Assignment

For a single IdP tenant, the server canonicalizes SCIM tenant assignment from
`AGENT_BOM_SCIM_TENANT_ID` and authenticates provisioning calls with
`AGENT_BOM_SCIM_BEARER_TOKEN`.

For a multi-tenant control plane, use `AGENT_BOM_SCIM_BEARER_TOKENS_JSON` to
bind each SCIM bearer token to a tenant server-side:

```bash
export AGENT_BOM_SCIM_BEARER_TOKENS_JSON='{
  "tenant-alpha": "alpha-scim-token",
  "tenant-beta": {"token": "beta-scim-token", "token_id": "entra-beta"}
}'
```

The first command for an IdP setup is then the IdP SCIM test call against
`/scim/v2/ServiceProviderConfig` with that tenant's bearer token. The visible
artifact is a tenant-bound SCIM user or group under `/scim/v2/Users` or
`/scim/v2/Groups`; the next step is to verify `/v1/auth/policy` reports
`payload_tenant_attributes_ignored=true`.

Tenant attributes in IdP payloads are accepted as normal SCIM profile data only
when needed for compatibility, but they are not trusted for tenant routing.
Token-to-tenant binding always comes from server configuration.

The code-generated boundary contract exposes this as:

```json
{
  "payload_tenant_attributes_ignored": true,
  "tenant_source": "AGENT_BOM_SCIM_TENANT_ID or AGENT_BOM_SCIM_BEARER_TOKENS_JSON"
}
```

That prevents a compromised or misconfigured IdP payload from assigning a user
to another tenant.

SCIM configuration fails closed when a mapped token is blank, when the same
token appears more than once, or when a configured tenant ID collides with the
reserved Agent BOM namespace (`admin`, `analyst`, `viewer`, `system`,
`__system__`). Error responses and posture output do not include token
material.

## Runtime Auth Boundary

SCIM can constrain runtime roles when configured, but authentication still comes
from API keys, OIDC, SAML session keys, or a trusted reverse proxy. SCIM
deactivation updates provisioned lifecycle state and narrows authenticated
runtime access when the subject matches a tenant-local SCIM user.

Long-lived service API keys remain governed by API-key lifecycle controls:
rotation, revocation, TTL, and admin-only key management.

## Operator Controls

Operators should:

- configure one SCIM token binding per control-plane tenant
- keep SCIM tokens in customer-managed secret storage
- require Postgres-backed shared state for multi-replica API deployments
- monitor SCIM lifecycle audit events
- use `/v1/auth/policy` and `agent-bom trust --format json` to verify the live
  tenant boundary contract
