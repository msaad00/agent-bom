# Authenticated Native App scan dispatch

The control-plane REST API supports dispatching a Snowflake account scan using the
service's injected SPCS workload identity. This is a separately configured path:
`core.trigger_scan()` and the prototype scanner service remain unsupported.
This contract has fixture coverage; consumer-account deployment and permission
validation must still be performed by the operator.

## Operator configuration

Configure authenticated control-plane access and mount an operator-owned JSON
binding file, readable by the API process, through
`AGENT_BOM_CONNECTION_WORKLOAD_BINDINGS_FILE`. The default service spec does not
provision this file. Use the authenticated caller's tenant ID and the exact
injected `SNOWFLAKE_ACCOUNT` value in the binding below. Set a deliberate future
expiry and revoke access with `enabled: false` or by removing the binding.

```json
{
  "bindings": {
    "native-account-read": {
      "tenant_id": "consumer-tenant",
      "provider": "snowflake",
      "auth_mode": "workload_identity",
      "role_ref": "INJECTED_ACCOUNT",
      "scope_id": "INJECTED_ACCOUNT",
      "inventory_scope": "account",
      "enabled": true,
      "expires_at": "2026-12-31T00:00:00Z"
    }
  }
}
```

Native App mode requires `AGENT_BOM_SNOWFLAKE_NATIVE_APP=true` and injected
`SNOWFLAKE_ACCOUNT` / `SNOWFLAKE_HOST`. The connector reads the rotating SPCS
OAuth token file when opening each connection; token contents are never stored
in the connection record. API callers cannot select another account, user,
role, warehouse, token file, or audience through this adapter. Operator bindings
are checked at connection creation and again at worker execution. Missing,
expired, revoked, or mismatched configuration fails closed without legacy
credential fallback. A binding delegates use of the service identity; it does
not prove read-only Snowflake grants. Review the service's actual privileges.

## Create, dispatch, retrieve

Inbound SPCS gateway identity is not automatically mapped to an Agent-Bom
principal by this adapter. Passing the Snowflake ingress gate alone does not
authenticate these REST requests. A gateway/service-function caller identity
adapter is still required for transparent Native App SQL or browser dispatch.

For an explicitly configured single-instance control plane, the existing
`AGENT_BOM_API_KEY` mode accepts that operator-provisioned secret as a bearer
credential and assigns the `default` tenant with admin access. In that mode,
change the example binding's `tenant_id` to `default`. Supply the key using the
deployment's secret-management mechanism, never a committed service spec.
Static-key mode is not the clustered-control-plane authentication contract.
For scoped deployments, use an existing tenant-bound API key or configured
OIDC authentication and bind its authenticated tenant instead. The SPCS OAuth
token is a provider credential, not an Agent-Bom API key.

Use an authenticated API credential with scan permission for the bound tenant.
The examples use a bearer credential; configure the deployment's supported API
auth mode independently of SPCS provider credentials. Do not expose a trusted
proxy secret to browser clients.

```bash
curl --fail-with-body "$API_URL/v1/cloud/connections" \
  -H "Authorization: Bearer $API_TOKEN" -H 'Content-Type: application/json' \
  --data '{"provider":"snowflake","display_name":"Native account","role_ref":"INJECTED_ACCOUNT","auto_scan_on_create":false,"auth_params":{"account":"INJECTED_ACCOUNT","auth_mode":"workload_identity","credential_binding":"native-account-read"}}'

# Copy the returned connection id, then dispatch explicitly.
curl --fail-with-body -X POST "$API_URL/v1/cloud/connections/$CONNECTION_ID/scan" \
  -H "Authorization: Bearer $API_TOKEN"

# Copy job_id from the 202 response and poll until done or failed.
curl --fail-with-body "$API_URL/v1/scan/$JOB_ID" \
  -H "Authorization: Bearer $API_TOKEN"
```

The existing scan workflow persists a tenant-scoped job before provider I/O,
revalidates the stored connection in the worker, and stores the completed scan
result through the configured job store. The result retains
`cloud_connection` / `cloud:snowflake` source metadata and feeds the configured
graph store. Empty inventory or failed collection is not proof of account-wide
coverage; inspect the result and provider permissions.

Job persistence, connection persistence, graph persistence, and worker recovery
are separate deployment requirements. This adapter adds none of those storage
backends and does not make the one-shot scanner a queue worker. The Native App
Snowflake job store does not implement the Postgres distributed queue lease
contract; a persisted queued job alone is not proof of automatic restart
recovery. Verify durable store configuration and graph retrieval after restart
before advertising persistent end-to-end operation.
