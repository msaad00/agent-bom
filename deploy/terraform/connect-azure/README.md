# connect-azure

Mints the **read-only** grant agent-bom's Azure connector needs — the exact
roles documented in [`docs/CLOUD_CONNECT.md`](../../../docs/CLOUD_CONNECT.md) §4 —
so a customer runs `terraform apply` instead of hand-running `az role assignment`
commands.

This is the **only** per-cloud difference in the connect flow: built-in RBAC
role assignments — **`Reader`** (+ optional **`Security Reader`**) — for a
service principal or managed identity at a subscription (or management-group)
scope. Both are read-only built-ins; no write/action permission is granted. The
connector calls only `list`/`get` ARM APIs.

## What it creates

- A **`Reader`** role assignment over the subscription (or a management-group
  scope via `scope_override`) for your principal.
- A **`Security Reader`** role assignment when `assign_security_reader = true`
  (default), for Microsoft Defender for Cloud posture.

It does **not** create the service principal or its credentials. Bring an
existing service principal (certificate auth, recommended) or managed identity
and pass its **object ID** as `principal_id`. No secrets live in this module.

## Usage

```hcl
module "agent_bom_connect" {
  source = "github.com/<org>/agent-bom//deploy/terraform/connect-azure"

  subscription_id = "00000000-0000-0000-0000-000000000000"
  principal_id    = "11111111-1111-1111-1111-111111111111" # SP/MI object ID
  principal_type  = "ServicePrincipal"
}
```

Tenant-wide (every subscription at once) — assign at the management group:

```hcl
module "agent_bom_connect" {
  source = "github.com/<org>/agent-bom//deploy/terraform/connect-azure"

  subscription_id = "00000000-0000-0000-0000-000000000000"
  principal_id    = "11111111-1111-1111-1111-111111111111"
  scope_override  = "/providers/Microsoft.Management/managementGroups/my-tenant-root"
}
```

## After apply

```bash
export AGENT_BOM_AZURE_INVENTORY=1            # opt-in, default-off
export AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS=1    # fan out across the tenant
agent-bom agents --preset enterprise --azure
```

Authenticate via `DefaultAzureCredential` (`az login`, an SP **certificate** —
not a secret — or a managed identity). With the flag unset, agent-bom does zero
Azure network I/O.

## Inputs (key)

| Variable | Default | Purpose |
|----------|---------|---------|
| `subscription_id` | — | Subscription to scope the grant to. |
| `principal_id` | — | Object ID of the SP / managed identity. |
| `principal_type` | `ServicePrincipal` | Principal kind for the assignment. |
| `assign_security_reader` | `true` | Also assign built-in Security Reader. |
| `scope_override` | `""` | Management-group scope to cover all subscriptions. |

## Outputs

`reader_role_assignment_id`, `security_reader_role_assignment_id`, `scope`,
`principal_id`, `assigned_roles`.
