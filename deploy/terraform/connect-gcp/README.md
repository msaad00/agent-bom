# connect-gcp

Mints the **read-only** grant agent-bom's GCP connector needs, following the
same one-model connect pattern as
[`docs/CLOUD_CONNECT.md`](../../../docs/CLOUD_CONNECT.md), so a customer runs
`terraform apply` instead of hand-running `gcloud iam` commands.

This is the **only** per-cloud difference in the connect flow: a service account
with project IAM bindings **`roles/viewer`** + **`roles/iam.securityReviewer`** —
both read-only predefined roles. No write permission is granted. The connector
calls only `list`/`get` APIs.

## What it creates

- A read-only **service account** (`agent-bom-readonly@<project>.iam…`).
- Project IAM bindings: **`roles/viewer`** (inventory) and
  **`roles/iam.securityReviewer`** (read-only IAM policy access for CIEM/posture).
- **Optionally** (variable-gated) a **Workload Identity Federation** pool +
  OIDC provider, and an impersonation binding, so an external identity can
  assume the SA **keylessly** — no SA key is ever created.

**Keyless by design.** This module creates **no** service-account key (many orgs
disable SA keys org-wide). Prefer Workload Identity Federation or SA
impersonation. If you must use a key, mint it out-of-band; it is never written
into this module's state.

## Usage

### Keyless (Workload Identity Federation)

```hcl
module "agent_bom_connect" {
  source     = "github.com/<org>/agent-bom//deploy/terraform/connect-gcp"
  project_id = "my-project"

  enable_workload_identity_federation = true
  wif_issuer_uri          = "https://token.actions.githubusercontent.com"
  wif_attribute_condition = "assertion.repository == 'my-org/my-repo'"
  wif_attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
  wif_principal_set = "principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/agent-bom-pool/attribute.repository/my-org/my-repo"
}
```

### Roles only (impersonate the SA with your own identity)

```hcl
module "agent_bom_connect" {
  source     = "github.com/<org>/agent-bom//deploy/terraform/connect-gcp"
  project_id = "my-project"
}
```

## After apply

```bash
export AGENT_BOM_GCP_INVENTORY=1          # opt-in, default-off
# Authenticate keylessly via WIF / SA impersonation using the SA email below,
# or `gcloud auth application-default login`.
agent-bom agents --preset enterprise --gcp
```

`terraform output service_account_email` gives the SA to impersonate, and
`terraform output workload_identity_provider_name` gives the provider for the
external credential config. With the flag unset, agent-bom does zero GCP
network I/O.

## Inputs (key)

| Variable | Default | Purpose |
|----------|---------|---------|
| `project_id` | — | Project to scope the grant to. |
| `enable_workload_identity_federation` | `false` | Create a keyless WIF pool/provider. |
| `wif_issuer_uri` | `""` | OIDC issuer of the external IdP. |
| `wif_attribute_condition` | `""` | CEL condition restricting which identities may federate. |
| `wif_principal_set` | `""` | `principalSet://` member allowed to impersonate the SA. |

## Outputs

`service_account_email`, `service_account_name`, `granted_roles`,
`workload_identity_pool_name`, `workload_identity_provider_name`.
