# SCIM Security Model

SCIM in agent-bom is a lifecycle and role-provisioning integration. It is not a
tenant authority by itself.

## Tenant Assignment

The server canonicalizes SCIM tenant assignment from
`AGENT_BOM_SCIM_TENANT_ID`. Tenant attributes in IdP payloads are accepted as
normal SCIM profile data only when needed for compatibility, but they are not
trusted for tenant routing.

The code-generated boundary contract exposes this as:

```json
{
  "payload_tenant_attributes_ignored": true,
  "tenant_source": "AGENT_BOM_SCIM_TENANT_ID"
}
```

That prevents a compromised or misconfigured IdP payload from assigning a user
to another tenant.

## Runtime Auth Boundary

SCIM can constrain runtime roles when configured, but authentication still comes
from API keys, OIDC, SAML session keys, or a trusted reverse proxy. SCIM
deactivation updates provisioned lifecycle state and narrows authenticated
runtime access when the subject matches a tenant-local SCIM user.

Long-lived service API keys remain governed by API-key lifecycle controls:
rotation, revocation, TTL, and admin-only key management.

## Operator Controls

Operators should:

- configure one SCIM tenant source per control-plane tenant
- keep SCIM tokens in customer-managed secret storage
- require Postgres-backed shared state for multi-replica API deployments
- monitor SCIM lifecycle audit events
- use `/v1/auth/policy` and `agent-bom trust --format json` to verify the live
  tenant boundary contract
