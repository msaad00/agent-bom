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

By default it does **not** create the service principal or its credentials.
Bring an existing service principal (certificate auth, recommended) or managed
identity and pass its **object ID** as `principal_id`. No secrets live in this
module.

## Secure by default — keyless federated credential (optional)

When you opt in with `create_federated_credential = true`, the module attaches a
**federated identity credential** to your scanner application that is pinned to
an **exact issuer + subject + audience** (`api://AzureADTokenExchange`), so only
one specific external workload can exchange a token for the scanner SP — never a
wide-open trust. The plan **fails** if the issuer or subject is empty, or if the
subject contains a wildcard.

```hcl
module "agent_bom_connect" {
  source = "github.com/<org>/agent-bom//deploy/terraform/connect-azure"

  subscription_id = "00000000-0000-0000-0000-000000000000"
  principal_id    = "11111111-1111-1111-1111-111111111111"

  create_federated_credential         = true
  federated_credential_application_id = "22222222-2222-2222-2222-222222222222"
  federated_credential_issuer         = "https://token.actions.githubusercontent.com"
  federated_credential_subject        = "repo:my-org/my-repo:ref:refs/heads/main" # exact, no wildcard
  # audience defaults to api://AzureADTokenExchange
}
```

> **Threat note.** A federated credential with an empty or wildcard subject
> trusts *every* token from the issuer — any repo or workflow on that IdP could
> impersonate the scanner SP (**wide-open federation / confused-deputy**).
> Pinning issuer + subject + audience narrows the trust to one workload. Leave
> `create_federated_credential = false` to keep the prior certificate-auth flow
> unchanged.

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
| `create_federated_credential` | `false` | Pin a keyless federated credential (issuer+subject+audience). |
| `federated_credential_issuer` | `""` | OIDC issuer. **Required when the credential is created.** |
| `federated_credential_subject` | `""` | Exact subject (no wildcard). **Required when the credential is created.** |
| `federated_credential_audience` | `api://AzureADTokenExchange` | Token-exchange audience. |
| `assign_key_vault_reader` | `false` | **Opt-in** data-plane read: built-in `Key Vault Reader` for CIS 8.1/8.2 (key/secret expiry metadata). RBAC-model vaults only. Off by default, matching the AWS S3/deep-scan opt-in pattern. |
| `assign_acr_pull` | `false` | **Opt-in** data-plane read: built-in `AcrPull` for ACR image SBOM/CVE extraction. Off by default, matching the AWS S3/deep-scan opt-in pattern. |

## Known coverage limitations

- **Access-policy-model Key Vaults need a different grant.** `Key Vault Reader`
  only reads data-plane metadata on **RBAC-model** vaults. Vaults using the
  legacy **access-policy** permission model require a `List` access policy on
  keys/secrets instead (not managed here); CIS 8.1/8.2 read as silently-empty
  on those vaults until that policy is added out-of-band.

## Outputs

`reader_role_assignment_id`, `security_reader_role_assignment_id`, `scope`,
`principal_id`, `assigned_roles`, `federated_credential_id`,
`federated_credential_subject`.
